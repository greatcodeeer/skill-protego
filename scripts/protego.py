#!/usr/bin/env python3
"""
Protego — Multi-language, multi-ecosystem security audit.

Detects 15 attack categories across 10 package ecosystems:

  A. Dependency supply-chain (scans installed/vendored deps)
     A1. Credential theft behavior
     A2. Suspicious code execution (eval+atob, monkey-patch, prototype pollution)
     A3. Suspicious exfiltration channels (webhooks, pastebins, DNS tunneling)
     A4. Build hook abuse (postinstall, setup.py, build.rs, pre_install ...)
     A5. Package structure anomalies (git commit refs, typosquatting)
     A6. Worm self-propagation + crypto clipper
     A7. Package manager hardening detection

  B. Project source code / configuration
     B1. Hardcoded secrets
     B2. Dangerous code sinks (per-language)
     B3. Configuration / credential exposure
     B4. Git history secret leaks
     B5. AI-era + architectural anti-patterns

  C. Agentic tooling supply-chain (MCP + Claude Code skills + Codex prompts)
     C1. MCP server tool poisoning (prompt injection in tool descriptions/
         schemas, hidden <IMPORTANT> directives, shell prefixes — Invariant
         Labs "Tool Poisoning", Trail of Bits "Line Jumping")
     C2. Malicious agentic-tool skills/prompts:
          - Claude Code SKILL.md (hidden directives, base64/unicode obfuscation,
            dangerous scripts/ — Snyk ToxicSkills found 37% of audited skills
            malicious)
          - Codex .codex/prompts/*.md (same patterns applied to Codex slash
            commands — each prompt file is fed directly to the LLM)
     C3. Agentic tooling config inventory (lists installed MCP servers,
         local Claude Code skills, and Codex prompts so the user can audit
         what's wired in)

This scanner is READ-ONLY. It never modifies, removes, or "fixes" anything.
Any remediation is suggested in the explanation field — actually doing it
must be a separate action explicitly authorized by the user.

Output: JSON to stdout. Exit 1 if blocking findings exist, else 0.

Heuristic by design — false positives are expected. Each finding includes
an explanation so a human (or the calling Claude) can judge.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Directories never scanned for source-code findings. These are vendored deps,
# build artifacts, or VCS internals. Supply-chain scans (A-layer) do enter
# vendored dep dirs explicitly.
SOURCE_EXCLUDE_DIRS = {
    "node_modules", ".pnpm", ".yarn", "bower_components",
    "vendor", "venv", ".venv", "env", "__pycache__", ".tox",
    "Pods", ".build",                      # iOS
    "target",                              # Rust/Java
    "build", "dist", "out", ".next", ".nuxt", ".svelte-kit",
    ".gradle", ".idea", ".vscode",
    ".git", ".hg", ".svn",
    "DerivedData",
    "coverage",
}

# Directory roots used to find vendored/installed deps to scan in A-layer.
DEP_ROOTS = {
    "npm":      ["node_modules"],
    "python":   ["venv", ".venv", "env", "site-packages"],
    "ruby":     ["vendor/bundle", ".bundle"],
    "cocoapods":["Pods"],
    "rust":     ["target"],          # build.rs scripts live in source dirs, but
    "go":       ["vendor"],
    "php":      ["vendor"],
    "dart":     [".dart_tool"],
    "dotnet":   ["packages"],
}

# Legitimate SDKs/libraries that have a legitimate reason to read sensitive
# paths or hit cloud metadata services. Findings under these paths are
# suppressed for A1/A3.
LEGITIMATE_SDK_PATH_FRAGMENTS = [
    "@aws-sdk/", "aws-sdk/", "@smithy/", "@aws-crypto/",
    "@google-cloud/", "google-auth-library/", "gcp-metadata/", "google-gax/",
    "@azure/", "azure-",
    "boto3/", "botocore/",
    "@aws-amplify/",
]

# Files inside dep dirs that we never report on — minified bundles, source
# maps, build artifacts, type-checker incremental caches, snapshot tests.
# Strings appearing in these files almost never represent attacker intent.
SKIP_DEP_FILE_FRAGMENTS = [
    ".min.js", ".min.css", ".min.map",
    ".bundle.js", "bundle.min.js",
    ".tsbuildinfo",
    ".snap",
    ".map",                  # source maps
    "/dist/", "/build/", "/browser/",
    "/docs/", "/example", "/README", ".md",
    "/test/", "/tests/", ".test.", ".spec.", "/__tests__/",
    ".d.ts",                 # TypeScript declarations
]


def should_skip_dep_file(file_path: str) -> bool:
    return any(frag in file_path for frag in SKIP_DEP_FILE_FRAGMENTS)

# File extensions that we actually scan inside (source code, configs).
SOURCE_EXTS = {
    # JS/TS
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    # Python
    ".py",
    # Ruby
    ".rb", ".erb",
    # iOS / macOS
    ".swift", ".m", ".mm", ".h",
    # Java / Kotlin / Android
    ".java", ".kt", ".kts", ".groovy", ".gradle",
    # Go
    ".go",
    # Rust
    ".rs",
    # PHP
    ".php",
    # Dart
    ".dart",
    # .NET
    ".cs", ".vb",
    # Config / data
    ".env", ".envrc", ".yaml", ".yml", ".json", ".toml", ".ini", ".conf",
    ".plist", ".xml", ".properties",
    # Shell / scripts
    ".sh", ".bash", ".zsh", ".fish",
}

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024   # skip > 2 MB files for source scan


# ─────────────────────────────────────────────────────────────────────────────
# Finding helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_finding(fid, dimension, severity, title, file="", line=0,
                 evidence="", explanation=""):
    return {
        "id": fid,
        "dimension": dimension,
        "severity": severity,          # "blocking" | "warning"
        "title": title,
        "file": file,
        "line": int(line) if line else 0,
        "evidence": (evidence or "")[:240],
        "explanation": explanation,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Ecosystem detection
# ─────────────────────────────────────────────────────────────────────────────

ECOSYSTEM_MANIFESTS = [
    ("npm",       ["package.json"]),
    ("python",    ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py"]),
    ("ruby",      ["Gemfile"]),
    ("ios_pods",  ["Podfile"]),
    ("swift_pm",  ["Package.swift"]),
    ("jvm",       ["pom.xml", "build.gradle", "build.gradle.kts"]),
    ("go",        ["go.mod"]),
    ("rust",      ["Cargo.toml"]),
    ("php",       ["composer.json"]),
    ("dart",      ["pubspec.yaml"]),
]

def detect_ecosystems(root: Path):
    detected = []
    for eco, manifests in ECOSYSTEM_MANIFESTS:
        for m in manifests:
            if (root / m).exists():
                detected.append(eco)
                break
    if list(root.glob("*.csproj")) or list(root.glob("*.fsproj")):
        detected.append("dotnet")
    return detected


# ─────────────────────────────────────────────────────────────────────────────
# Fast file iteration helpers
# ─────────────────────────────────────────────────────────────────────────────

def iter_source_files(root: Path):
    """Yield source files for B-layer scanning. Skips vendored/build dirs
    and protego's own source tree (self-exclude)."""
    for dirpath, dirnames, filenames in os.walk(root):
        # in-place prune
        dirnames[:] = [d for d in dirnames if d not in SOURCE_EXCLUDE_DIRS and not d.startswith(".")]
        # but keep .env / .gitignore etc files
        for fn in filenames:
            if fn.startswith(".") and fn not in {".env", ".envrc", ".gitignore", ".npmrc", ".yarnrc", ".yarnrc.yml"}:
                continue
            p = Path(dirpath) / fn
            if p.suffix not in SOURCE_EXTS and fn not in {".env", ".envrc", ".gitignore", ".npmrc", ".yarnrc", ".yarnrc.yml", "Dockerfile", "Makefile"}:
                continue
            if is_protego_self(p):
                continue
            try:
                if p.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def iter_dep_dirs(root: Path):
    """Yield (ecosystem, dep_dir) for A-layer scanning."""
    for eco, roots in DEP_ROOTS.items():
        for r in roots:
            cand = root / r
            if cand.is_dir():
                yield eco, cand


def grep_search(pattern: str, search_root: Path, flags="-rEn", extra_args=None):
    """Run grep, return list of (file, line_no, line_text)."""
    args = ["grep", flags, pattern, str(search_root)]
    if extra_args:
        args.extend(extra_args)
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=180,
                             errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    results = []
    for line in out.stdout.splitlines():
        # format: file:lineno:text
        m = re.match(r"^(.+?):(\d+):(.*)$", line)
        if m:
            results.append((m.group(1), int(m.group(2)), m.group(3)))
    return results


def is_legitimate_sdk_path(path: str) -> bool:
    return any(frag in path for frag in LEGITIMATE_SDK_PATH_FRAGMENTS)


def read_file_safe(path: Path, max_bytes=512 * 1024):
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:max_bytes]
    except (OSError, UnicodeDecodeError):
        return ""


def mask_markdown_code_blocks(text: str) -> str:
    """Replace fenced code blocks (```...```) and inline code (`...`) with
    spaces, preserving newlines and total length. Used by C2 so that the
    skill's *documentation examples* of attack markers (e.g. `<IMPORTANT>`
    written as a code-formatted token) aren't mis-reported as the markers
    themselves. Line numbers map 1:1 to the original file."""
    def repl_block(m):
        # Preserve newlines; replace everything else with spaces
        return re.sub(r"[^\n]", " ", m.group(0))
    text = re.sub(r"```[\s\S]*?```", repl_block, text)
    text = re.sub(r"`[^`\n]+`", lambda m: " " * len(m.group(0)), text)
    return text


def is_protego_self(file_path) -> bool:
    """True if this path is part of protego's own source tree. Used to skip
    self-match: protego's regex patterns inside its scanner source contain
    literal strings like `os.system(` that would otherwise be flagged by
    its own B2 / B5 detectors. Anchored by the canonical skill layout so
    third-party installs in any location are still self-skipped."""
    s = str(file_path).replace("\\", "/")
    return ("/skills/protego/scripts/" in s or
            "/skills/protego/SKILL.md" in s or
            "/skills/protego/references/" in s or
            s.endswith("skills/protego/scripts/protego.py") or
            s.endswith("skills/protego/SKILL.md"))


def build_tracked_files_set(root: Path):
    """Walk `root` and its subdirectories looking for git repos (any directory
    containing a `.git` marker — directory or worktree pointer file). For each
    repo found, run `git ls-files` and collect every tracked file path. Returns
    a set of absolute, resolved paths.

    Used by B1 to make the secret scan git-aware: a hardcoded secret in a file
    that's gitignored AND never tracked can't leak via VCS, so it downgrades
    from blocking to warning. A secret in a tracked file is the real risk.

    Handles nested git repos correctly — sub-projects under `projects/` each
    have their own git, so we scan each one separately and union the results."""
    tracked = set()
    for dirpath, dirnames, _ in os.walk(root):
        # Prune the same way iter_source_files does to avoid descending into
        # node_modules / .pnpm / vendored deps where bogus .git dirs hide.
        dirnames[:] = [
            d for d in dirnames
            if d not in SOURCE_EXCLUDE_DIRS and not d.startswith(".")
        ]
        git_marker = Path(dirpath) / ".git"
        if not git_marker.exists():
            continue
        repo_root = Path(dirpath)
        try:
            out = subprocess.run(
                ["git", "-C", str(repo_root), "ls-files"],
                capture_output=True, text=True, timeout=60, errors="replace"
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        if out.returncode != 0:
            continue
        for rel in out.stdout.splitlines():
            try:
                tracked.add(str((repo_root / rel).resolve()))
            except (OSError, RuntimeError):
                continue
        # Don't recurse into nested git repos found this way — they'll be
        # picked up by their own .git scan when os.walk reaches them.
    return tracked


def is_git_tracked(file_path: Path, tracked_set) -> bool:
    """True if the file is in any of the scanned git repos' tracked-file lists.
    If the file isn't in any git repo at all (no .git anywhere above it), this
    also returns False — caller should interpret False as "not protected by
    being tracked," not as definitive "gitignored." But for B1's purposes,
    "not in tracked set" == "won't leak via git", which is what matters."""
    try:
        return str(file_path.resolve()) in tracked_set
    except (OSError, RuntimeError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# A1. Credential theft behavior
# ─────────────────────────────────────────────────────────────────────────────

A1_PATTERNS = [
    # SSH private key paths
    (r"\.ssh/id_(rsa|ed25519|ecdsa|dsa)\b",
     "Reads SSH private key path"),
    # AWS credentials file (not env var, the file itself being parsed by non-SDK)
    (r"\.aws/credentials\b",
     "References AWS credentials file"),
    # GCP application default credentials
    (r"\.config/gcloud/application_default_credentials\.json",
     "References GCP ADC file"),
    # Code reading the user's .npmrc file (where npm registry _authToken lives).
    # We require the literal string ".npmrc" because bare `_authToken` is a
    # common property name in legitimate auth clients (neo4j-driver, etc.).
    (r"['\"~/][^'\"]*\.npmrc['\"]",
     "References .npmrc file path (potential npm token theft)"),
    # Generic netrc
    (r"['\"~/][^'\"]*\.netrc['\"]",
     "References .netrc file (host credentials)"),
    # Linux memdump (TanStack OIDC extraction technique)
    (r"/proc/\$?\{?\d|/proc/self/mem|/proc/[*\\$]+/mem",
     "Linux process memory dump (memdump attack vector)"),
    # Crypto wallet artifacts (UTC--... is Ethereum keystore filename format;
    # MetaMask extension storage path; wallet.dat is Bitcoin Core)
    (r"(MetaMask/[^'\"]*|wallet\.dat\b|UTC--[0-9T:.-]+--[0-9a-f]+)",
     "Reads crypto wallet artifacts"),
    # Whole process.env dump (shai-hulud worm hallmark)
    (r"JSON\.stringify\s*\(\s*process\.env\s*\)",
     "Serializes entire process.env (env dump)"),
    (r"Object\.entries\s*\(\s*process\.env\s*\)",
     "Enumerates entire process.env"),
    # Python os.environ dump
    (r"json\.dumps\s*\(\s*os\.environ",
     "Serializes entire os.environ (Python env dump)"),
    (r"dict\s*\(\s*os\.environ\s*\)",
     "Whole-environment capture (Python)"),
]


def scan_a1_credential_theft(root: Path, findings: list):
    for eco, dep_root in iter_dep_dirs(root):
        for pat, desc in A1_PATTERNS:
            for file, line, text in grep_search(pat, dep_root):
                if is_legitimate_sdk_path(file) or should_skip_dep_file(file):
                    continue
                rel = os.path.relpath(file, root)
                findings.append(make_finding(
                    fid=f"A1.credential_theft.{re.sub(r'[^a-z0-9]', '_', desc.lower())[:30]}",
                    dimension="A1",
                    severity="blocking",
                    title=f"Credential theft pattern in dependency: {desc}",
                    file=rel,
                    line=line,
                    evidence=text.strip(),
                    explanation=(
                        "A package in your dependency tree contains code that references "
                        "sensitive credential locations. Legitimate SDKs (@aws-sdk, etc.) "
                        "are allow-listed; a hit here usually means an unexpected package "
                        "is reaching into user credentials. Verify the package, audit its "
                        "publisher, and consider removing it."
                    ),
                ))


# ─────────────────────────────────────────────────────────────────────────────
# A2. Suspicious code execution
# ─────────────────────────────────────────────────────────────────────────────

A2_PATTERNS = [
    (r"eval\s*\(\s*atob\s*\(",
     "eval(atob(...)) classic obfuscation loader"),
    (r"eval\s*\(\s*Buffer\.from\s*\([^)]*['\"]base64",
     "eval(Buffer.from(...,'base64')) loader"),
    (r"new\s+Function\s*\(\s*['\"`][^'\"`]{500,}",
     "new Function() with extremely long string argument"),
    (r"require\s*\(\s*\[",
     "require([...]) array-joined module name (string-splitting evasion)"),
    (r"Object\.prototype\s*\[",
     "Prototype pollution write to Object.prototype"),
    (r"__proto__\s*\[\s*['\"]",
     "Prototype manipulation via __proto__"),
    # Python
    (r"exec\s*\(\s*(base64\.b64decode|codecs\.decode)",
     "Python exec() of base64-decoded payload"),
    (r"compile\s*\(\s*base64\.b64decode",
     "Python compile() of base64-decoded payload"),
    # Ruby
    (r"eval\s+Base64\.decode64",
     "Ruby eval of Base64-decoded payload"),
    # PHP
    (r"eval\s*\(\s*base64_decode\s*\(",
     "PHP eval(base64_decode(...))"),
    (r"eval\s*\(\s*gzinflate\s*\(",
     "PHP eval(gzinflate(...))"),
    # Monkey-patching builtins
    (r"fs\s*\.\s*(readFile|writeFile|readFileSync)\s*=\s*",
     "Reassigns fs builtin (monkey-patch attack)"),
    (r"child_process\s*\.\s*(spawn|exec|execSync)\s*=\s*",
     "Reassigns child_process builtin"),
    (r"http\s*\.\s*request\s*=\s*",
     "Reassigns http.request (network interceptor)"),
]


def scan_a2_suspicious_execution(root: Path, findings: list):
    for eco, dep_root in iter_dep_dirs(root):
        for pat, desc in A2_PATTERNS:
            for file, line, text in grep_search(pat, dep_root):
                if should_skip_dep_file(file):
                    continue
                rel = os.path.relpath(file, root)
                findings.append(make_finding(
                    fid=f"A2.suspicious_execution.{re.sub(r'[^a-z0-9]', '_', desc.lower())[:40]}",
                    dimension="A2",
                    severity="blocking",
                    title=desc,
                    file=rel,
                    line=line,
                    evidence=text.strip(),
                    explanation=(
                        "Dependency contains a code-execution pattern strongly "
                        "associated with malware loaders or runtime hijacking. "
                        "Real legitimate code rarely does this. Investigate the "
                        "package immediately."
                    ),
                ))
    # Long embedded base64 strings (>= 1000 chars on a single line)
    long_b64_re = re.compile(r"['\"]([A-Za-z0-9+/]{1000,}={0,2})['\"]")
    for eco, dep_root in iter_dep_dirs(root):
        try:
            out = subprocess.run(
                ["grep", "-rEn", r"['\"][A-Za-z0-9+/]{1000,}={0,2}['\"]", str(dep_root)],
                capture_output=True, text=True, timeout=180, errors="replace"
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        for line in out.stdout.splitlines()[:50]:  # cap
            m = re.match(r"^(.+?):(\d+):", line)
            if not m:
                continue
            file = m.group(1)
            if should_skip_dep_file(file):
                continue
            rel = os.path.relpath(file, root)
            findings.append(make_finding(
                fid="A2.suspicious_execution.long_base64",
                dimension="A2",
                severity="warning",
                title="Long embedded base64 string (possible payload)",
                file=rel,
                line=int(m.group(2)),
                evidence=line[m.end():m.end()+200],
                explanation=(
                    "Long inline base64 strings (>1000 chars) commonly hide "
                    "executable payloads. Some legitimate uses exist (embedded "
                    "fonts, certs), so verify intent before acting."
                ),
            ))


# ─────────────────────────────────────────────────────────────────────────────
# A3. Suspicious exfiltration channels
# ─────────────────────────────────────────────────────────────────────────────

A3_PATTERNS = [
    (r"discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]{20,}",
     "Hardcoded real Discord webhook URL"),
    (r"api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]{30,}",
     "Hardcoded Telegram bot token in URL"),
    (r"hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+",
     "Hardcoded Slack incoming webhook URL"),
    (r"(pastebin\.com|paste\.ee|hastebin\.com|0x0\.st|transfer\.sh|file\.io|bashupload\.com)/[A-Za-z0-9]",
     "Hardcoded paste-bin / temp-upload service URL"),
    (r"getsession\.org|oxen\.io|loki\.network",
     "Hardcoded Session/Oxen messenger network (used by TanStack 2026-05 attack)"),
    (r"https?://[a-z0-9]{32,}\.(?:com|net|io|to|tk|ml|cf|gq)",
     "Suspiciously long-subdomain URL (possible DNS-exfil endpoint)"),
    # WebSocket to non-standard host
    (r"new\s+WebSocket\s*\(\s*['\"]wss?://(?!localhost|127\.|\$\{)",
     "WebSocket connection to hardcoded external host (verify legitimacy)"),
]


def scan_a3_exfiltration(root: Path, findings: list):
    for eco, dep_root in iter_dep_dirs(root):
        for pat, desc in A3_PATTERNS:
            for file, line, text in grep_search(pat, dep_root):
                if is_legitimate_sdk_path(file) or should_skip_dep_file(file):
                    continue
                # placeholders in docs
                if any(p in text.lower() for p in ("xxxx", "your_webhook", "placeholder",
                                                    "example.com", "your-token")):
                    continue
                rel = os.path.relpath(file, root)
                severity = "warning" if "long-subdomain" in desc.lower() else "blocking"
                findings.append(make_finding(
                    fid=f"A3.exfiltration.{re.sub(r'[^a-z0-9]', '_', desc.lower())[:40]}",
                    dimension="A3",
                    severity=severity,
                    title=desc,
                    file=rel,
                    line=line,
                    evidence=text.strip(),
                    explanation=(
                        "Dependency contains hardcoded URL/host pattern matching "
                        "known data-exfiltration channels. Legitimate packages don't "
                        "ship hardcoded production webhooks of services like Discord/"
                        "Telegram/Slack. Investigate immediately."
                    ),
                ))


# ─────────────────────────────────────────────────────────────────────────────
# A4. Build hook abuse
# ─────────────────────────────────────────────────────────────────────────────

# Suspicious patterns inside lifecycle scripts.
LIFECYCLE_SUSPICIOUS = re.compile(
    r"curl\s+|wget\s+|nc\s+|netcat\s+|powershell|"
    r"base64\s+-d|bash\s+-c\s+|sh\s+-c\s+|"
    r"eval\s+\$|\$\(.*curl|\$\(.*wget|"
    r"/dev/tcp/|/proc/[*\d\$\{]+/mem|"
    r"~/\.ssh|~/\.aws|~/\.npmrc",
    re.IGNORECASE
)

LIFECYCLE_FIELDS = ("preinstall", "install", "postinstall", "prepare", "prepublish")


def scan_a4_build_hooks(root: Path, findings: list):
    # === JS/TS via package.json scripts inside dependencies ===
    node_modules = root / "node_modules"
    if node_modules.is_dir():
        for pkg_json in node_modules.rglob("package.json"):
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            scripts = data.get("scripts") or {}
            for hook in LIFECYCLE_FIELDS:
                cmd = scripts.get(hook)
                if not cmd:
                    continue
                if LIFECYCLE_SUSPICIOUS.search(cmd):
                    rel = os.path.relpath(pkg_json, root)
                    findings.append(make_finding(
                        fid="A4.build_hook.suspicious_command",
                        dimension="A4",
                        severity="blocking",
                        title=f"Suspicious command in {hook} hook of {data.get('name','?')}",
                        file=rel,
                        evidence=f"{hook}: {cmd[:200]}",
                        explanation=(
                            "Lifecycle hook contains commands typical of malware "
                            "loaders (curl|wget|base64 -d|nc|eval $|...). Legitimate "
                            "install hooks should only invoke build tools like "
                            "node-gyp, prebuild-install, etc."
                        ),
                    ))
                else:
                    # Also flag oversize install scripts (>5KB)
                    if hook in ("preinstall", "install", "postinstall") and len(cmd) > 5000:
                        rel = os.path.relpath(pkg_json, root)
                        findings.append(make_finding(
                            fid="A4.build_hook.oversize",
                            dimension="A4",
                            severity="warning",
                            title=f"Unusually long {hook} script in {data.get('name','?')}",
                            file=rel,
                            evidence=cmd[:200],
                            explanation=(
                                "Most install scripts are short (one shell command). "
                                "Multi-kilobyte scripts can hide complex logic."
                            ),
                        ))
    # === Python setup.py with arbitrary code ===
    for sp in root.rglob("setup.py"):
        if any(part in str(sp) for part in SOURCE_EXCLUDE_DIRS):
            # only flag deps; project's own setup.py is B-layer
            if "site-packages" not in str(sp) and ".venv" not in str(sp) and "venv" not in str(sp):
                continue
        text = read_file_safe(sp)
        if LIFECYCLE_SUSPICIOUS.search(text):
            rel = os.path.relpath(sp, root)
            findings.append(make_finding(
                fid="A4.build_hook.python_setup_py",
                dimension="A4",
                severity="blocking",
                title="setup.py runs suspicious shell commands at install time",
                file=rel,
                explanation=(
                    "Python `setup.py` runs at `pip install` time and can execute "
                    "arbitrary code. The same handful of patterns (curl|wget|"
                    "base64 -d|...) used by npm postinstall malware are equally "
                    "dangerous here."
                ),
            ))
    # === Cargo build.rs (Rust build scripts) ===
    for br in root.rglob("build.rs"):
        text = read_file_safe(br)
        if LIFECYCLE_SUSPICIOUS.search(text):
            rel = os.path.relpath(br, root)
            findings.append(make_finding(
                fid="A4.build_hook.cargo_build_rs",
                dimension="A4",
                severity="blocking",
                title="Cargo build.rs contains suspicious shell command",
                file=rel,
                explanation=(
                    "`build.rs` runs during `cargo build/install`. Use this for "
                    "C-binding setup, not for arbitrary shell exfiltration."
                ),
            ))
    # === CocoaPods pre_install / post_install ===
    podfile = root / "Podfile"
    if podfile.exists():
        text = read_file_safe(podfile)
        for hook in ("pre_install", "post_install"):
            m = re.search(rf"{hook}\s+do\s*\|.*?\|(.+?)\bend\b", text, re.DOTALL)
            if m and LIFECYCLE_SUSPICIOUS.search(m.group(1)):
                findings.append(make_finding(
                    fid=f"A4.build_hook.cocoapods_{hook}",
                    dimension="A4",
                    severity="blocking",
                    title=f"Podfile {hook} hook contains suspicious shell command",
                    file="Podfile",
                    explanation="CocoaPods hooks run during `pod install` and can do anything."
                ))


# ─────────────────────────────────────────────────────────────────────────────
# A5. Package structure anomalies
# ─────────────────────────────────────────────────────────────────────────────

def scan_a5_package_anomalies(root: Path, findings: list):
    # package.json: deps pointing to git commit / non-registry protocols
    for pkg_json in [root / "package.json"]:
        if not pkg_json.exists():
            continue
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        for field in ("dependencies", "devDependencies", "optionalDependencies",
                      "peerDependencies"):
            deps = data.get(field) or {}
            for name, ver in deps.items():
                if not isinstance(ver, str):
                    continue
                # github:owner/repo#commit-hash style
                if re.match(r"^(github:|git\+|git://|git@)", ver) or \
                   re.search(r"^[a-z0-9-]+/[a-z0-9._-]+#[a-f0-9]{20,}", ver):
                    findings.append(make_finding(
                        fid="A5.package_anomaly.git_commit_dep",
                        dimension="A5",
                        severity="warning",
                        title=f"{field}.{name} resolves via git protocol (bypasses npm registry audit)",
                        file="package.json",
                        evidence=f"{name}: {ver}",
                        explanation=(
                            "Dependencies fetched via git bypass npm registry audit/"
                            "integrity checks. The TanStack 2026-05 attack used a "
                            "github commit-hash optionalDependency to deliver payload. "
                            "Pin via registry version unless you have a strong reason."
                        ),
                    ))
                elif re.match(r"^(file:|http:|ftp:)", ver):
                    findings.append(make_finding(
                        fid="A5.package_anomaly.non_registry_protocol",
                        dimension="A5",
                        severity="warning",
                        title=f"{field}.{name} uses non-registry protocol",
                        file="package.json",
                        evidence=f"{name}: {ver}",
                        explanation="file:/http: protocol bypasses registry integrity checks."
                    ))
    # pnpm-lock.yaml / package-lock.json: resolved URLs outside npmjs.org
    for lf_name, search_pat in (
        ("package-lock.json", r'"resolved":\s*"(?!https://registry\.npmjs\.org)'),
        ("pnpm-lock.yaml",   r"resolved:\s*['\"]?(?!https://registry\.npmjs\.org)"),
    ):
        lf = root / lf_name
        if lf.exists():
            text = read_file_safe(lf, max_bytes=2 * 1024 * 1024)
            for m in re.finditer(search_pat, text):
                line_no = text[:m.start()].count("\n") + 1
                # snippet
                snippet = text[m.start():m.start() + 120].splitlines()[0]
                findings.append(make_finding(
                    fid="A5.package_anomaly.non_npmjs_resolved",
                    dimension="A5",
                    severity="warning",
                    title="Lockfile contains dependency resolved from non-npmjs URL",
                    file=lf_name,
                    line=line_no,
                    evidence=snippet,
                    explanation="Verify the source is trusted."
                ))
                break   # one per lockfile is enough


# ─────────────────────────────────────────────────────────────────────────────
# A6. Worm self-propagation + Crypto clipper
# ─────────────────────────────────────────────────────────────────────────────

A6_PATTERNS = [
    # Worm: package code that publishes packages
    (r"(child_process|subprocess)\..*?\b(npm|pnpm|yarn)\s+publish",
     "Dependency code shell-executes `npm publish` (worm self-propagation)"),
    (r"npm\s+whoami\b.*?(child_process|subprocess|spawn|exec)",
     "Dependency reads npm identity (likely worm reconnaissance)"),
    (r"gem\s+push\b.*?(system|backtick)",
     "Dependency code shell-executes `gem push` (Ruby worm)"),
    (r"cargo\s+publish\b.*?(Command::new|process::Command)",
     "Dependency code shell-executes `cargo publish` (Rust worm)"),
    # Crypto clipper
    (r"clipboardy|navigator\.clipboard\.read",
     "Clipboard access (potential crypto clipper)"),
    (r"\b(0x[a-fA-F0-9]{40})\b.*?\.replace\(",
     "Hardcoded Ethereum address followed by .replace (clipper pattern)"),
    (r"bc1[a-z0-9]{25,42}",
     "Hardcoded Bitcoin bech32 address (verify intent)"),
    (r"AddressType\s*[:=]\s*['\"]?(btc|eth|sol|trx|xmr)",
     "Wallet address-type switch (multi-chain clipper hallmark)"),
]


def scan_a6_worm_clipper(root: Path, findings: list):
    for eco, dep_root in iter_dep_dirs(root):
        for pat, desc in A6_PATTERNS:
            for file, line, text in grep_search(pat, dep_root):
                if is_legitimate_sdk_path(file) or should_skip_dep_file(file):
                    continue
                # Allowed: known wallet/clipboard libraries used legitimately
                if any(name in file for name in ("clipboardy/", "copy-paste/", "ethers/",
                                                  "web3/", "@solana/")):
                    # Only flag if it also contains a replace pattern nearby
                    if ".replace" not in text and "AddressType" not in text:
                        continue
                rel = os.path.relpath(file, root)
                findings.append(make_finding(
                    fid=f"A6.worm_clipper.{re.sub(r'[^a-z0-9]', '_', desc.lower())[:40]}",
                    dimension="A6",
                    severity="blocking",
                    title=desc,
                    file=rel,
                    line=line,
                    evidence=text.strip(),
                    explanation=(
                        "Pattern strongly associated with worm self-propagation "
                        "(reads publisher tokens + calls publish) or crypto-clipper "
                        "(intercepts clipboard wallet addresses)."
                    ),
                ))


# ─────────────────────────────────────────────────────────────────────────────
# A7. Package manager hardening detection
# ─────────────────────────────────────────────────────────────────────────────

def scan_a7_pm_hardening(root: Path, findings: list, ecosystems: list):
    if "npm" in ecosystems:
        # pnpm
        if (root / "pnpm-lock.yaml").exists() or (root / "pnpm-workspace.yaml").exists():
            wsp = root / "pnpm-workspace.yaml"
            if wsp.exists():
                text = read_file_safe(wsp)
                if "allowBuilds" not in text and "onlyBuiltDependencies" not in text:
                    findings.append(make_finding(
                        fid="A7.hardening.pnpm_no_allowbuilds",
                        dimension="A7",
                        severity="warning",
                        title="pnpm: no `allowBuilds` whitelist configured",
                        file="pnpm-workspace.yaml",
                        explanation=(
                            "pnpm 11+ uses `allowBuilds` to whitelist which packages "
                            "may run install/postinstall scripts. Without it, all "
                            "packages can run lifecycle hooks by default."
                        ),
                    ))
                if "minimumReleaseAge" not in text:
                    findings.append(make_finding(
                        fid="A7.hardening.pnpm_no_release_age",
                        dimension="A7",
                        severity="warning",
                        title="pnpm: no `minimumReleaseAge` gate configured",
                        file="pnpm-workspace.yaml",
                        explanation=(
                            "Without `minimumReleaseAge` (recommended ≥ 20160 / 14 days), "
                            "freshly-published malicious versions can be installed in the "
                            "narrow window before npm yanks them."
                        ),
                    ))
            else:
                findings.append(make_finding(
                    fid="A7.hardening.pnpm_missing_workspace_yaml",
                    dimension="A7",
                    severity="warning",
                    title="pnpm project missing pnpm-workspace.yaml (no defense gates)",
                    explanation="Add pnpm-workspace.yaml with allowBuilds + minimumReleaseAge."
                ))
        # plain npm
        elif (root / "package-lock.json").exists():
            npmrc = root / ".npmrc"
            ignore_scripts = False
            if npmrc.exists():
                ignore_scripts = "ignore-scripts=true" in read_file_safe(npmrc)
            if not ignore_scripts:
                findings.append(make_finding(
                    fid="A7.hardening.npm_scripts_default_on",
                    dimension="A7",
                    severity="warning",
                    title="npm: install scripts run by default for ALL packages",
                    file=".npmrc" if npmrc.exists() else "(no .npmrc)",
                    explanation=(
                        "npm does not have a per-package allowlist like pnpm's "
                        "allowBuilds. Best practice: set `ignore-scripts=true` "
                        "in .npmrc and manually `npm rebuild <whitelist>` only "
                        "the packages you trust. Or migrate to pnpm."
                    ),
                ))
        # plain yarn
        elif (root / "yarn.lock").exists():
            yrc = root / ".yarnrc.yml"
            if not (yrc.exists() and "enableScripts: false" in read_file_safe(yrc)):
                findings.append(make_finding(
                    fid="A7.hardening.yarn_scripts_default_on",
                    dimension="A7",
                    severity="warning",
                    title="yarn: install scripts run by default",
                    explanation="Set `enableScripts: false` in .yarnrc.yml."
                ))


# ─────────────────────────────────────────────────────────────────────────────
# B1. Hardcoded secrets
# ─────────────────────────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    ("openai_key",      r"sk-(?:proj-)?[A-Za-z0-9_-]{30,}",                          "OpenAI API key"),
    ("anthropic_key",   r"sk-ant-(?:api\d+-)?[A-Za-z0-9_-]{30,}",                    "Anthropic API key"),
    ("aws_access_key",  r"AKIA[0-9A-Z]{16}",                                          "AWS Access Key ID"),
    # Matches snake_case (AWS_SECRET_ACCESS_KEY=...) AND JS camelCase
    # (secretAccessKey: '...'). The `(?:aws[_-]?)?` prefix is optional so a
    # bare `secretAccessKey` token in a JS credentials object also triggers.
    ("aws_secret",      r"(?i)(?:aws[_-]?)?secret[_-]?access[_-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})",
                                                                                      "AWS Secret Access Key"),
    ("github_pat",      r"gh[pousr]_[A-Za-z0-9]{36,}",                                "GitHub PAT"),
    ("github_oauth",    r"github_pat_[A-Za-z0-9_]{20,}",                              "GitHub fine-grained PAT"),
    ("npm_token",       r"npm_[A-Za-z0-9]{36}",                                       "npm access token"),
    ("stripe_key",      r"sk_(?:live|test)_[A-Za-z0-9]{20,}",                         "Stripe secret key"),
    ("slack_token",     r"xox[baprs]-[A-Za-z0-9-]{20,}",                              "Slack token"),
    ("discord_bot",     r"[MNO][A-Za-z\d-]{23,28}\.[\w-]{6}\.[\w-]{27,40}",           "Discord bot token"),
    ("google_api",      r"AIza[0-9A-Za-z_-]{35}",                                     "Google API key"),
    # PEM blocks — require a real base64 body to avoid matching regex literals
    # that contain "BEGIN PRIVATE KEY" inside their own pattern definition.
    ("private_key",     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\n]+[A-Za-z0-9+/]{40,}",
                                                                                      "PEM private key block"),
    ("jwt_token",       r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
                                                                                      "JWT token"),
    ("db_conn_pass",    r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^/\s'\"]+:[^@/\s'\"]+@",
                                                                                      "DB connection string with password"),
    ("twilio_sid",      r"AC[a-f0-9]{32}",                                            "Twilio Account SID"),
    ("sendgrid",        r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,}",                "SendGrid API key"),
    ("xai_key",         r"xai-[A-Za-z0-9]{40,}",                                      "xAI / Grok API key"),
    ("digitalocean",    r"dop_v1_[a-f0-9]{64}",                                       "DigitalOcean PAT"),
]

SECRET_FALSE_POSITIVE_TOKENS = (
    "example", "placeholder", "your-", "your_", "xxx", "0000000000",
    "1234567890", "fake", "dummy", "<your", "redacted", "abc123",
)


def is_secret_storage_file(path: Path) -> bool:
    """Files conventionally used to hold secrets (.env*, config.json, etc.).
    Secrets here are reported as warning (since the file's purpose IS to hold
    them) rather than blocking. The actual blocking concern for these files
    is whether they're tracked in git — which dimension B3 handles separately."""
    name = path.name
    if name == ".env" or name.startswith(".env."):
        return True
    if name in {"config.json", "secrets.json", "credentials.json",
                ".envrc", ".env.local", ".env.production", ".env.development",
                "service-account.json", "firebase-config.json"}:
        return True
    return False


def scan_b1_secrets(root: Path, findings: list, tracked_files: set):
    for path in iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        rel = os.path.relpath(path, root)
        secret_storage = is_secret_storage_file(path)
        path_tracked = is_git_tracked(path, tracked_files)
        for sid, pat, label in SECRET_PATTERNS:
            for m in re.finditer(pat, text):
                snippet = m.group(0)
                if any(tok in snippet.lower() for tok in SECRET_FALSE_POSITIVE_TOKENS):
                    continue
                line_no = text[:m.start()].count("\n") + 1
                shown = snippet if len(snippet) < 80 else snippet[:40] + "...[redacted]"

                # Severity matrix (file_kind × git_tracking_status):
                #   - tracked source file       → blocking (real VCS leak risk)
                #   - tracked secret-storage    → warning  (B3 separately checks
                #                                 whether the tracking itself is wrong)
                #   - untracked source file     → warning  (no VCS leak risk —
                #                                 file is gitignored / never staged,
                #                                 but still verify local hygiene)
                #   - untracked secret-storage  → suppressed (legitimate, expected)
                if not path_tracked:
                    if secret_storage:
                        # gitignored .env / config.json with secrets is the
                        # intended pattern; don't even file a warning.
                        continue
                    severity = "warning"
                    explanation = (
                        f"Secret pattern found in `{path.name}` but this file is "
                        "not git-tracked (gitignored or never staged) — it cannot "
                        "leak via version control. Still verify the file's "
                        "local-machine handling is appropriate and that nothing "
                        "in your CI/CD or build artifacts copies it elsewhere."
                    )
                else:
                    if secret_storage:
                        severity = "warning"
                        explanation = (
                            f"Secret detected in `{path.name}` AND this file is "
                            "currently git-tracked. Rotate the secret, remove the "
                            "file from the index (git rm --cached) and add it to "
                            ".gitignore so future commits don't re-leak."
                        )
                    else:
                        severity = "blocking"
                        explanation = (
                            "Hardcoded credentials in tracked source code will be "
                            "stolen via git history, log scraping, or insider "
                            "access. Rotate the key, remove it from source, and "
                            "load from environment / secret manager. If this is a "
                            "placeholder, use a clearly-fake value."
                        )
                findings.append(make_finding(
                    fid=f"B1.secret.{sid}",
                    dimension="B1",
                    severity=severity,
                    title=f"Hardcoded {label} in {'config file' if secret_storage else 'source'}",
                    file=rel,
                    line=line_no,
                    evidence=shown,
                    explanation=explanation,
                ))


# ─────────────────────────────────────────────────────────────────────────────
# B2. Dangerous code sinks (per-language)
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: (pattern, language scope (extensions), description)
B2_PATTERNS = [
    # JS/TS — command/code injection
    (r"child_process\.(exec|execSync)\s*\(\s*[^'\"`]*[`'\"]\s*\+",
     {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"},
     "Shell command built by string concat (command injection risk)"),
    (r"\beval\s*\(\s*(?!['\"`])",
     {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"},
     "Dynamic eval() with non-literal argument"),
    (r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*[a-zA-Z_]",
     {".jsx", ".tsx"},
     "React dangerouslySetInnerHTML with dynamic value (XSS risk)"),
    (r"vm\.runIn(?:NewContext|ThisContext)\s*\(\s*(?!['\"`])",
     {".js", ".ts", ".mjs", ".cjs"},
     "Node vm runIn*Context with non-literal code (sandbox escape risk)"),
    # Python
    (r"os\.system\s*\(\s*(?!['\"])",
     {".py"}, "os.system() with non-literal argument"),
    (r"subprocess\.(Popen|run|call)\s*\([^)]*shell\s*=\s*True",
     {".py"}, "subprocess with shell=True (command injection risk)"),
    (r"pickle\.loads?\s*\(",
     {".py"}, "pickle.load(s) on untrusted data (deserialization RCE)"),
    (r"yaml\.load\s*\(\s*[^,)]*\)",
     {".py"}, "yaml.load() without SafeLoader (deserialization risk)"),
    # Ruby
    (r"\beval\s+[a-zA-Z_]",
     {".rb"}, "Ruby eval() with dynamic argument"),
    (r"Marshal\.load\s*\(",
     {".rb"}, "Ruby Marshal.load on untrusted data"),
    (r"\bsystem\s*\(\s*['\"][^'\"]*#\{",
     {".rb"}, "Ruby system() with string interpolation"),
    # PHP
    (r"\beval\s*\(\s*\$",
     {".php"}, "PHP eval() with variable"),
    (r"unserialize\s*\(\s*\$",
     {".php"}, "PHP unserialize() of user data"),
    (r"\b(system|exec|shell_exec|passthru)\s*\(\s*\$",
     {".php"}, "PHP shell command with variable"),
    # Go
    (r"exec\.Command\s*\(\s*[a-zA-Z_][^,)]*,\s*",
     {".go"}, "Go exec.Command with non-literal program name"),
    # iOS Swift
    (r"NSExpression\s*\(\s*format:",
     {".swift"}, "NSExpression(format:) — code-injection sink"),
    # Weak crypto (cross-language)
    (r"(?:MessageDigest|hashlib)\.getInstance\(['\"](MD5|SHA-?1)['\"]\)",
     {".java", ".kt"}, "Weak hash algorithm (MD5/SHA1)"),
    (r"hashlib\.(md5|sha1)\s*\(.*password",
     {".py"}, "Weak hash for password storage (MD5/SHA1)"),
    (r"crypto\.createHash\s*\(\s*['\"](md5|sha1)['\"]",
     {".js", ".ts"}, "Weak hash algorithm in JS (MD5/SHA1)"),
    # SQL string concat (heuristic)
    (r"(?:SELECT|INSERT|UPDATE|DELETE|FROM)\s+[A-Za-z_*]+.*?\+\s*[a-zA-Z_]",
     {".js", ".ts", ".py", ".rb", ".php", ".go", ".java"},
     "SQL query built by string concatenation (SQL injection risk)"),
]


def scan_b2_dangerous_sinks(root: Path, findings: list):
    by_ext = {}
    for pat, exts, desc in B2_PATTERNS:
        for ext in exts:
            by_ext.setdefault(ext, []).append((pat, desc))

    for path in iter_source_files(root):
        ext = path.suffix
        patterns = by_ext.get(ext)
        if not patterns:
            continue
        text = ""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        rel = os.path.relpath(path, root)
        for pat, desc in patterns:
            for m in re.finditer(pat, text):
                line_no = text[:m.start()].count("\n") + 1
                snippet = text[m.start():m.start() + 200].splitlines()[0]
                findings.append(make_finding(
                    fid=f"B2.dangerous_sink.{re.sub(r'[^a-z0-9]', '_', desc.lower())[:30]}",
                    dimension="B2",
                    severity="warning",
                    title=desc,
                    file=rel,
                    line=line_no,
                    evidence=snippet.strip(),
                    explanation=(
                        "Pattern matches a known dangerous sink. Heuristic — context "
                        "matters: literal arguments are usually safe, user-controlled "
                        "input is the real risk. Audit each hit."
                    ),
                ))


# ─────────────────────────────────────────────────────────────────────────────
# B3. Configuration / credential exposure
# ─────────────────────────────────────────────────────────────────────────────

SENSITIVE_CONFIG_NAMES = (
    ".env", ".env.local", ".env.production", ".env.development",
    "secrets.json", "credentials.json", "config.json",
    "service-account.json", "firebase-config.json",
    "id_rsa", "id_ed25519",
)

GITIGNORE_REQUIRED_PATTERNS = (".env", "*.pem", "*.key", "id_rsa", ".npmrc")


def get_git_tracked_files(root: Path):
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            capture_output=True, text=True, timeout=30
        )
        if out.returncode == 0:
            return set(out.stdout.splitlines())
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def scan_b3_config_exposure(root: Path, findings: list):
    tracked = get_git_tracked_files(root)
    if tracked is None:
        return   # not a git repo
    for tracked_path in tracked:
        name = os.path.basename(tracked_path)
        if name in SENSITIVE_CONFIG_NAMES:
            # double-check if it actually contains sensitive content
            p = root / tracked_path
            if not p.exists():
                continue
            text = read_file_safe(p)
            # quick heuristic: contains anything that looks like a secret
            looks_sensitive = bool(re.search(
                r"(?i)(secret|password|token|api[_-]?key|private[_-]?key)\s*[:=]",
                text,
            )) or "PRIVATE KEY" in text
            if name == ".env" or name.startswith(".env.") or looks_sensitive:
                findings.append(make_finding(
                    fid="B3.config_exposure.tracked_sensitive_file",
                    dimension="B3",
                    severity="blocking",
                    title=f"Sensitive file `{tracked_path}` is tracked in git",
                    file=tracked_path,
                    explanation=(
                        "Files containing secrets must not be checked into version "
                        "control. Even if you delete them later, they remain in git "
                        "history forever. Remove from index, rotate the secrets, and "
                        "add the file to .gitignore."
                    ),
                ))
    # .gitignore completeness
    gi = root / ".gitignore"
    if gi.exists():
        gi_text = read_file_safe(gi)
        missing = [pat for pat in GITIGNORE_REQUIRED_PATTERNS if pat not in gi_text]
        if missing:
            findings.append(make_finding(
                fid="B3.config_exposure.gitignore_gaps",
                dimension="B3",
                severity="warning",
                title=f".gitignore missing common secret patterns: {', '.join(missing)}",
                file=".gitignore",
                explanation=(
                    "Add these patterns to .gitignore so secret files cannot be "
                    "accidentally committed by future contributors."
                ),
            ))


# ─────────────────────────────────────────────────────────────────────────────
# B4. Git history secret leaks
# ─────────────────────────────────────────────────────────────────────────────

def scan_b4_git_history(root: Path, findings: list):
    if not (root / ".git").exists():
        return
    # Limit scope: scan only the last 200 commits to keep runtime reasonable
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "log", "-p", "-n", "200",
             "--no-color", "--no-merges"],
            capture_output=True, text=True, timeout=120, errors="replace"
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return
    if out.returncode != 0:
        return
    diff_text = out.stdout

    # Only consider added lines (+ at start, but not +++)
    added_lines = [ln for ln in diff_text.splitlines()
                   if ln.startswith("+") and not ln.startswith("+++")]

    # Sample the first hit per pattern to avoid flooding
    seen_patterns = set()
    for sid, pat, label in SECRET_PATTERNS:
        if sid in seen_patterns:
            continue
        for ln in added_lines:
            if any(tok in ln.lower() for tok in SECRET_FALSE_POSITIVE_TOKENS):
                continue
            if re.search(pat, ln):
                findings.append(make_finding(
                    fid=f"B4.git_history.{sid}",
                    dimension="B4",
                    severity="warning",
                    title=f"Possible {label} found in recent git history",
                    explanation=(
                        "A pattern matching a real secret format appears in your "
                        "git log (last 200 commits). Even if removed from current "
                        "code, history still exposes it — anyone who can clone "
                        "the repo can recover it. Rotate the secret regardless of "
                        "current state."
                    ),
                ))
                seen_patterns.add(sid)
                break


# ─────────────────────────────────────────────────────────────────────────────
# B5. AI-era + architectural anti-patterns
# ─────────────────────────────────────────────────────────────────────────────

B5_PATTERNS = [
    # AI prompt injection — system_prompt or systemPrompt specifically (not
    # generic "message" which fires on every error string), built by string
    # interpolation with a variable. Catches the case where untrusted input
    # gets concatenated into the system prompt.
    (r"(?i)\b(system[_-]?prompt|systemPrompt)\s*[:=]\s*[`'\"][^`'\"]*?\$\{[a-zA-Z_]",
     {".js", ".ts", ".py", ".rb"},
     "AI system prompt built by string template with variable (prompt injection risk)"),
    # HTTP listen on 0.0.0.0 (public exposure)
    (r"\.listen\s*\(\s*\d+\s*,\s*['\"]0\.0\.0\.0",
     {".js", ".ts", ".py"},
     "HTTP server binds 0.0.0.0 (public exposure — verify auth/firewall)"),
    (r"app\.run\s*\([^)]*host\s*=\s*['\"]0\.0\.0\.0",
     {".py"},
     "Flask app.run(host=0.0.0.0) (public exposure)"),
    # CORS *
    (r"['\"]Access-Control-Allow-Origin['\"]\s*[,:]\s*['\"]\*['\"]",
     {".js", ".ts", ".py", ".rb", ".go", ".php"},
     "CORS Access-Control-Allow-Origin: *"),
    (r"cors\s*\(\s*\{\s*origin\s*:\s*['\"]\*['\"]",
     {".js", ".ts"},
     "express-cors origin: '*'"),
    # Weak default password
    (r"(?i)password\s*[:=]\s*['\"](admin|password|123456|root|secret|test|changeme)['\"]",
     {".js", ".ts", ".py", ".rb", ".java", ".kt", ".go", ".php"},
     "Hardcoded weak default password"),
    # Debug mode in prod
    (r"DEBUG\s*=\s*True\b",
     {".py"}, "DEBUG = True (verify not deployed to production)"),
    # iOS ATS bypass
    (r"<key>NSAllowsArbitraryLoads</key>\s*<true/>",
     {".plist"}, "iOS ATS disabled (NSAllowsArbitraryLoads=true)"),
]


def scan_b5_arch_antipatterns(root: Path, findings: list):
    by_ext = {}
    for pat, exts, desc in B5_PATTERNS:
        for ext in exts:
            by_ext.setdefault(ext, []).append((pat, desc))
    for path in iter_source_files(root):
        ext = path.suffix
        patterns = by_ext.get(ext)
        if not patterns:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        rel = os.path.relpath(path, root)
        for pat, desc in patterns:
            for m in re.finditer(pat, text):
                line_no = text[:m.start()].count("\n") + 1
                snippet = text[m.start():m.start() + 160].splitlines()[0]
                findings.append(make_finding(
                    fid=f"B5.arch.{re.sub(r'[^a-z0-9]', '_', desc.lower())[:30]}",
                    dimension="B5",
                    severity="warning",
                    title=desc,
                    file=rel,
                    line=line_no,
                    evidence=snippet.strip(),
                    explanation="Architectural anti-pattern — verify the context."
                ))


# ─────────────────────────────────────────────────────────────────────────────
# C1. MCP server tool poisoning
# ─────────────────────────────────────────────────────────────────────────────

# Hidden LLM-directive tags and prompt-injection phrases that should NEVER
# appear inside a legitimate MCP tool description or schema. Sources: Invariant
# Labs (April 2025) "Tool Poisoning Attacks" + Trail of Bits "Line Jumping".
C1_INJECTION_PATTERNS = [
    # XML/HTML-style directive tags planted to be picked up by the LLM
    (r"<IMPORTANT>|<SYSTEM>|<INSTRUCTIONS?>|<\|im_start\|>|<\|endoftext\|>|<\|system\|>",
     "Hidden LLM-directive tag (prompt injection marker)"),
    # Classic instruction-override phrases
    (r"(?i)\b(ignore (all |the )?previous|disregard (the )?above|forget (all )?prior)\b",
     "Prompt-injection override phrase"),
    # Tool description instructing LLM to read sensitive files
    (r"(?i)(read|cat|open|load) [`'\"]?~?/?\.?(ssh/id_|aws/credentials|cursor/mcp|claude/mcp)",
     "Tool description instructs LLM to read user credentials/config"),
    # Tool description with shell-style command prefix (Line Jumping)
    (r"(chmod\s+[-0-9]+\s+~|curl\s+[^\s]+\s*\|\s*(bash|sh)|wget\s+[^\s]+\s*\|\s*(bash|sh))",
     "Tool description contains shell command prefix (Line Jumping attack)"),
]

# Zero-width / invisible Unicode characters used to hide instructions
ZERO_WIDTH_CHARS = re.compile(r"[​‌‍‎‏  ‪-‮⁦-⁩﻿]")


def find_mcp_package_dirs(root: Path):
    """Locate dependency directories that look like MCP servers."""
    dirs = []
    nm = root / "node_modules"
    if nm.is_dir():
        for pkg_json in nm.rglob("package.json"):
            if "/.bin/" in str(pkg_json):
                continue
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            name = data.get("name", "") or ""
            desc = (data.get("description") or "").lower()
            deps = list((data.get("dependencies") or {}).keys()) + \
                   list((data.get("devDependencies") or {}).keys())
            if ("@modelcontextprotocol" in name or
                any("modelcontextprotocol" in d for d in deps) or
                "mcp server" in desc or
                "model context protocol" in desc):
                dirs.append(pkg_json.parent)
    # Python: site-packages with mcp dependency
    for candidate in (root / "venv" / "lib", root / ".venv" / "lib", root / "env" / "lib"):
        if candidate.is_dir():
            for sp in candidate.rglob("site-packages"):
                for meta in sp.glob("*.dist-info/METADATA"):
                    text = read_file_safe(meta, max_bytes=8192)
                    if "Requires-Dist: mcp" in text or "Name: mcp" in text:
                        dirs.append(meta.parent.parent)
    return dirs


def scan_c1_mcp_tool_poisoning(root: Path, findings: list):
    mcp_dirs = find_mcp_package_dirs(root)
    for mcp_dir in mcp_dirs:
        for path in mcp_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in {".js", ".ts", ".mjs", ".cjs", ".py", ".json"}:
                continue
            if should_skip_dep_file(str(path)):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            rel = os.path.relpath(path, root)
            # 1) Injection-pattern hits
            for pat, desc in C1_INJECTION_PATTERNS:
                for m in re.finditer(pat, text):
                    line_no = text[:m.start()].count("\n") + 1
                    snippet = text[m.start():m.start() + 200].splitlines()[0]
                    findings.append(make_finding(
                        fid=f"C1.mcp_injection.{re.sub(r'[^a-z0-9]', '_', desc.lower())[:40]}",
                        dimension="C1",
                        severity="blocking",
                        title=f"MCP server tool description / schema contains: {desc}",
                        file=rel,
                        line=line_no,
                        evidence=snippet.strip(),
                        explanation=(
                            "An MCP server package contains a pattern matching tool-"
                            "poisoning attacks documented by Invariant Labs (April 2025) "
                            "and Trail of Bits 'Line Jumping' (April 2025). Malicious "
                            "MCP servers plant hidden LLM directives in tool descriptions "
                            "so any LLM that connects to them is hijacked. This is a "
                            "supply-chain compromise of the MCP server package — audit "
                            "the publisher and remove from your MCP config."
                        ),
                    ))
            # 2) Zero-width characters inside string literals
            for m in re.finditer(r"['\"`]([^'\"`\n]{10,})['\"`]", text):
                literal = m.group(1)
                if ZERO_WIDTH_CHARS.search(literal):
                    line_no = text[:m.start()].count("\n") + 1
                    findings.append(make_finding(
                        fid="C1.mcp_injection.zero_width_unicode",
                        dimension="C1",
                        severity="blocking",
                        title="MCP server contains zero-width/invisible Unicode characters in string literal",
                        file=rel,
                        line=line_no,
                        evidence=repr(literal)[:200],
                        explanation=(
                            "Zero-width Unicode characters (U+200B–U+200D, BOM, "
                            "bidirectional override) are invisible in normal UI but "
                            "are seen by the LLM. They hide prompt-injection payloads "
                            "or fool security review."
                        ),
                    ))


# ─────────────────────────────────────────────────────────────────────────────
# C2. Malicious agentic-tool skills/prompts
#     - Claude Code skills (local skills/*/SKILL.md tree)
#     - Codex prompts (.codex/prompts/*.md files)
# ─────────────────────────────────────────────────────────────────────────────

SKILL_DANGEROUS_SCRIPT_PATTERNS = [
    (r"curl\s+[^\s|]+\s*\|\s*(bash|sh|zsh)\b",
     "Pipes downloaded content into a shell (curl | bash backdoor)"),
    (r"wget\s+[^\s|]+\s*\|\s*(bash|sh|zsh)\b",
     "Pipes downloaded content into a shell (wget | sh backdoor)"),
    (r"eval\s+\$\(\s*(curl|wget)",
     "Eval of network-downloaded content (remote-code execution)"),
    (r"(curl|wget)\s+[^\s]+\s+-o\s+/tmp/[^\s]+\s*(&&|;|\n)\s*(bash|sh|chmod\s+\+x)",
     "Download-then-execute remote payload"),
    (r"base64\s+-d\s*\|\s*(bash|sh)",
     "base64-decode piped to shell (obfuscated payload)"),
]


def scan_c2_skill_poisoning(root: Path, findings: list):
    # Local skills can live in a few locations
    skill_roots = []
    for candidate in (root / "skills", root / ".claude" / "skills"):
        if candidate.is_dir():
            skill_roots.append(candidate)
    if not skill_roots:
        return

    for skills_root in skill_roots:
        for skill_md in skills_root.glob("*/SKILL.md"):
            skill_name = skill_md.parent.name
            try:
                text = skill_md.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            rel = os.path.relpath(skill_md, root)
            # Directive detection runs against the markdown with code blocks
            # masked out, so documentation examples inside backticks don't
            # falsely trigger. Line numbers still map to the original file.
            masked = mask_markdown_code_blocks(text)

            # 1) Hidden LLM-directive tags (use masked text to ignore code-block examples)
            for pat, desc in C1_INJECTION_PATTERNS:
                for m in re.finditer(pat, masked):
                    line_no = text[:m.start()].count("\n") + 1
                    snippet = text[m.start():m.start() + 200].splitlines()[0]
                    findings.append(make_finding(
                        fid=f"C2.skill_injection.{re.sub(r'[^a-z0-9]', '_', desc.lower())[:40]}",
                        dimension="C2",
                        severity="blocking",
                        title=f"Skill '{skill_name}' SKILL.md contains: {desc}",
                        file=rel,
                        line=line_no,
                        evidence=snippet.strip(),
                        explanation=(
                            "Snyk's ToxicSkills audit (Feb 2026) found 37% of community-"
                            "uploaded Claude Code skills contain prompt-injection payloads "
                            "in SKILL.md. The directive tag found here is exactly that "
                            "pattern (and it's outside of any code-fenced documentation "
                            "example, so it's a real instruction). Inspect the skill "
                            "source carefully; if you didn't author it, remove it."
                        ),
                    ))

            # 2) Zero-width / invisible Unicode in SKILL.md
            zw_matches = list(ZERO_WIDTH_CHARS.finditer(text))
            if zw_matches:
                line_no = text[:zw_matches[0].start()].count("\n") + 1
                # Sample the codepoints found
                codepoints = sorted({f"U+{ord(c):04X}" for c in [text[m.start()] for m in zw_matches[:5]]})
                findings.append(make_finding(
                    fid="C2.skill_injection.zero_width_unicode",
                    dimension="C2",
                    severity="blocking",
                    title=f"Skill '{skill_name}' SKILL.md contains zero-width / invisible Unicode",
                    file=rel,
                    line=line_no,
                    evidence=f"Found {len(zw_matches)} hidden codepoints: {', '.join(codepoints)}",
                    explanation=(
                        "Invisible Unicode in a SKILL.md hides instructions that the "
                        "LLM still reads. ToxicSkills (Snyk Feb 2026) documents this as "
                        "a primary obfuscation technique for malicious skills."
                    ),
                ))

            # 3) Long base64-looking strings (potential obfuscated instruction)
            for m in re.finditer(r"[A-Za-z0-9+/]{80,}={0,2}", text):
                blob = m.group(0)
                # Skip if it's clearly a hash/checksum (short and standalone)
                # base64-decode test: is there printable text inside?
                try:
                    import base64
                    decoded = base64.b64decode(blob + "==", validate=False).decode("utf-8", errors="ignore")
                    if any(kw in decoded.lower() for kw in
                           ("ignore", "system", "instruction", "you must",
                            "ssh", "credentials", "exfil", "curl", "/bin/")):
                        line_no = text[:m.start()].count("\n") + 1
                        findings.append(make_finding(
                            fid="C2.skill_injection.base64_payload",
                            dimension="C2",
                            severity="blocking",
                            title=f"Skill '{skill_name}' SKILL.md contains base64 payload with suspicious decoded content",
                            file=rel,
                            line=line_no,
                            evidence=f"base64({blob[:40]}...) decodes to: {decoded[:120]}",
                            explanation=(
                                "Base64-encoded text inside a SKILL.md is unusual to "
                                "begin with — but when the decoded content contains "
                                "LLM-instruction keywords, it's almost certainly a "
                                "hidden prompt-injection payload."
                            ),
                        ))
                except Exception:
                    pass

        # 4) Suspicious scripts in skills/*/scripts/ and skills/*/agents/
        for script_path in skills_root.rglob("*"):
            if not script_path.is_file():
                continue
            if script_path.suffix not in {".sh", ".bash", ".py", ".js", ".ts", ".mjs"}:
                continue
            # Only flag scripts inside individual skill folders
            try:
                rel_to_skills = script_path.relative_to(skills_root)
            except ValueError:
                continue
            parts = rel_to_skills.parts
            if len(parts) < 2:
                continue
            skill_name = parts[0]
            try:
                stext = script_path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            rel = os.path.relpath(script_path, root)
            for pat, desc in SKILL_DANGEROUS_SCRIPT_PATTERNS:
                for m in re.finditer(pat, stext):
                    line_no = stext[:m.start()].count("\n") + 1
                    findings.append(make_finding(
                        fid=f"C2.skill_script.{re.sub(r'[^a-z0-9]', '_', desc.lower())[:40]}",
                        dimension="C2",
                        severity="blocking",
                        title=f"Skill '{skill_name}' script: {desc}",
                        file=rel,
                        line=line_no,
                        evidence=stext[m.start():m.start()+160].splitlines()[0],
                        explanation=(
                            "Skill scripts run with the full privileges of your shell. "
                            "Patterns that download and execute remote content are "
                            "the most common backdoor mechanism in malicious skills "
                            "(ToxicSkills Snyk Feb 2026)."
                        ),
                    ))


def scan_c2_codex_prompt_poisoning(root: Path, findings: list):
    """C2 extension: scan Codex prompts (.codex/prompts/*.md) for the same
    prompt-injection patterns we check Claude Code skills for. Each prompt
    file becomes a slash command (e.g. /protego), so a poisoned prompt is
    a direct LLM-instruction injection."""
    prompts_root = root / ".codex" / "prompts"
    if not prompts_root.is_dir():
        return

    for prompt_md in prompts_root.glob("*.md"):
        if not prompt_md.is_file():
            continue
        try:
            text = prompt_md.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        prompt_name = prompt_md.stem
        rel = os.path.relpath(prompt_md, root)
        masked = mask_markdown_code_blocks(text)

        # 1) Hidden LLM-directive tags (use masked text to ignore code-block examples)
        for pat, desc in C1_INJECTION_PATTERNS:
            for m in re.finditer(pat, masked):
                line_no = text[:m.start()].count("\n") + 1
                snippet = text[m.start():m.start() + 200].splitlines()[0]
                findings.append(make_finding(
                    fid=f"C2.codex_prompt_injection.{re.sub(r'[^a-z0-9]', '_', desc.lower())[:40]}",
                    dimension="C2",
                    severity="blocking",
                    title=f"Codex prompt '/{prompt_name}' contains: {desc}",
                    file=rel,
                    line=line_no,
                    evidence=snippet.strip(),
                    explanation=(
                        "Codex loads every .md file in ~/.codex/prompts/ as a slash "
                        "command and feeds its content directly to the model. A "
                        "directive tag here is a prompt-injection vector with the "
                        "same severity as a poisoned Claude Code SKILL.md "
                        "(ToxicSkills Snyk Feb 2026 documents the equivalent "
                        "attack on Claude skills). If you didn't author this "
                        "prompt, remove it."
                    ),
                ))

        # 2) Zero-width / invisible Unicode in the prompt
        zw_matches = list(ZERO_WIDTH_CHARS.finditer(text))
        if zw_matches:
            line_no = text[:zw_matches[0].start()].count("\n") + 1
            codepoints = sorted({f"U+{ord(c):04X}" for c in [text[m.start()] for m in zw_matches[:5]]})
            findings.append(make_finding(
                fid="C2.codex_prompt_injection.zero_width_unicode",
                dimension="C2",
                severity="blocking",
                title=f"Codex prompt '/{prompt_name}' contains zero-width / invisible Unicode",
                file=rel,
                line=line_no,
                evidence=f"Found {len(zw_matches)} hidden codepoints: {', '.join(codepoints)}",
                explanation=(
                    "Invisible Unicode in a Codex prompt hides instructions that "
                    "the LLM still reads when the slash command runs. This is the "
                    "same obfuscation technique documented by Invariant Labs and "
                    "Snyk against MCP tools and Claude Code skills."
                ),
            ))

        # 3) Long base64-looking strings with suspicious decoded content
        for m in re.finditer(r"[A-Za-z0-9+/]{80,}={0,2}", text):
            blob = m.group(0)
            try:
                import base64
                decoded = base64.b64decode(blob + "==", validate=False).decode("utf-8", errors="ignore")
                if any(kw in decoded.lower() for kw in
                       ("ignore", "system", "instruction", "you must",
                        "ssh", "credentials", "exfil", "curl", "/bin/")):
                    line_no = text[:m.start()].count("\n") + 1
                    findings.append(make_finding(
                        fid="C2.codex_prompt_injection.base64_payload",
                        dimension="C2",
                        severity="blocking",
                        title=f"Codex prompt '/{prompt_name}' contains base64 payload with suspicious decoded content",
                        file=rel,
                        line=line_no,
                        evidence=f"base64({blob[:40]}...) decodes to: {decoded[:120]}",
                        explanation=(
                            "Base64 inside a Codex prompt is unusual on its own — "
                            "when it decodes to LLM-instruction keywords, it's "
                            "almost certainly a hidden prompt-injection payload "
                            "that activates the moment the user runs the slash "
                            "command."
                        ),
                    ))
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# C3. Agentic tooling config inventory (informational)
# ─────────────────────────────────────────────────────────────────────────────

MCP_CONFIG_FILE_PATTERNS = [
    ".claude/mcp.json",
    ".claude/mcp_servers.json",
    ".cursor/mcp.json",
    "mcp.json",
    "mcp-config.json",
    "mcp_servers.json",
    "data/mcp-ask-user-config.json",
]


def scan_c3_agentic_inventory(root: Path, findings: list):
    # Inventory MCP configs
    mcp_configs = []
    for pat in MCP_CONFIG_FILE_PATTERNS:
        p = root / pat
        if p.is_file():
            mcp_configs.append(p)
    # Also glob for any .claude/*.json or .cursor/*.json
    for sub in (".claude", ".cursor"):
        d = root / sub
        if d.is_dir():
            for j in d.glob("*.json"):
                if j not in mcp_configs:
                    mcp_configs.append(j)

    for cfg in mcp_configs:
        try:
            data = json.loads(cfg.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        # MCP config schema usually: {"mcpServers": {"name": {...}}}
        servers = data.get("mcpServers") or data.get("servers") or {}
        if isinstance(servers, dict) and servers:
            names = list(servers.keys())
            rel = os.path.relpath(cfg, root)
            findings.append(make_finding(
                fid="C3.agentic_inventory.mcp_servers",
                dimension="C3",
                severity="warning",
                title=f"{len(names)} MCP server(s) configured: {', '.join(names[:8])}{'...' if len(names) > 8 else ''}",
                file=rel,
                explanation=(
                    "MCP servers run with your shell privileges and see your tool "
                    "I/O. Confirm each entry is one you intentionally installed and "
                    "trust — every server connected to your agent is a potential "
                    "tool-poisoning vector (Invariant Labs / Trail of Bits 2025)."
                ),
            ))

    # Inventory local Claude Code skills
    for skills_root in (root / "skills", root / ".claude" / "skills"):
        if skills_root.is_dir():
            skill_count = sum(1 for _ in skills_root.glob("*/SKILL.md"))
            if skill_count > 0:
                rel = os.path.relpath(skills_root, root)
                findings.append(make_finding(
                    fid="C3.agentic_inventory.local_skills",
                    dimension="C3",
                    severity="warning",
                    title=f"{skill_count} Claude Code skill(s) installed under {rel}/",
                    file=rel,
                    explanation=(
                        "Snyk's ToxicSkills audit (Feb 2026) found 37% of community-"
                        "uploaded skills are malicious. C2 has scanned each SKILL.md "
                        "and its scripts/ for known patterns, but skills are an "
                        "actively-evolving attack surface — periodically audit which "
                        "skills you have installed and remove any you don't recognize."
                    ),
                ))

    # Inventory local Codex prompts (slash commands)
    codex_prompts_dir = root / ".codex" / "prompts"
    if codex_prompts_dir.is_dir():
        prompt_files = list(codex_prompts_dir.glob("*.md"))
        if prompt_files:
            names = sorted(p.stem for p in prompt_files)
            rel = os.path.relpath(codex_prompts_dir, root)
            findings.append(make_finding(
                fid="C3.agentic_inventory.codex_prompts",
                dimension="C3",
                severity="warning",
                title=f"{len(names)} Codex slash command(s) installed under {rel}/: /{', /'.join(names[:8])}{'...' if len(names) > 8 else ''}",
                file=rel,
                explanation=(
                    "Each .md under .codex/prompts/ is loaded into the LLM the "
                    "instant the user types /<name>. C2 has scanned each file for "
                    "known prompt-injection patterns, but the same caution as for "
                    "Claude Code skills applies — periodically audit which slash "
                    "commands you have installed and remove any you don't recognize."
                ),
            ))


# ─────────────────────────────────────────────────────────────────────────────
# Aggregation and CLI entry
# ─────────────────────────────────────────────────────────────────────────────

def aggregate(findings: list):
    summary = {
        "blocking": sum(1 for f in findings if f["severity"] == "blocking"),
        "warning":  sum(1 for f in findings if f["severity"] == "warning"),
        "by_dimension": {},
    }
    for f in findings:
        summary["by_dimension"][f["dimension"]] = summary["by_dimension"].get(f["dimension"], 0) + 1
    return summary


def main():
    if len(sys.argv) > 1:
        root = Path(sys.argv[1]).resolve()
    else:
        root = Path.cwd().resolve()

    if not root.is_dir():
        print(json.dumps({"error": f"Not a directory: {root}"}), file=sys.stderr)
        sys.exit(2)

    ecosystems = detect_ecosystems(root)

    # Build the set of git-tracked files once up front — used by B1 to make
    # severity decisions context-aware (a secret in an untracked file can't
    # leak via VCS). Handles nested sub-repos under projects/ correctly.
    tracked_files = build_tracked_files_set(root)

    findings = []

    # A-layer (dependency supply-chain)
    scan_a1_credential_theft(root, findings)
    scan_a2_suspicious_execution(root, findings)
    scan_a3_exfiltration(root, findings)
    scan_a4_build_hooks(root, findings)
    scan_a5_package_anomalies(root, findings)
    scan_a6_worm_clipper(root, findings)
    scan_a7_pm_hardening(root, findings, ecosystems)

    # B-layer (source code / config)
    scan_b1_secrets(root, findings, tracked_files)
    scan_b2_dangerous_sinks(root, findings)
    scan_b3_config_exposure(root, findings)
    scan_b4_git_history(root, findings)
    scan_b5_arch_antipatterns(root, findings)

    # C-layer (agentic tooling supply-chain)
    scan_c1_mcp_tool_poisoning(root, findings)
    scan_c2_skill_poisoning(root, findings)
    scan_c2_codex_prompt_poisoning(root, findings)
    scan_c3_agentic_inventory(root, findings)

    summary = aggregate(findings)
    exit_code = 1 if summary["blocking"] > 0 else 0

    report = {
        "scan_root": str(root),
        "ecosystems_detected": ecosystems,
        "findings": findings,
        "summary": summary,
        "exit_code": exit_code,
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
