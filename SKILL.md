---
name: protego
description: Multi-language, multi-ecosystem READ-ONLY security audit. 15 attack-pattern dimensions across 3 layers — dependency supply-chain (credential theft, install-script abuse, exfiltration, worm propagation, crypto clippers, typosquatting across 10 package ecosystems), project source-code (hardcoded secrets, dangerous code sinks, .env in VCS, git history exposure, AI prompt-injection), and agentic-tooling supply-chain (MCP tool poisoning, malicious Claude Code SKILL.md files, malicious Codex .codex/prompts/ slash commands, base64/zero-width-unicode obfuscation, curl|bash backdoors). Invoke when user asks for any security check, audit, vulnerability scan, malware check, or supply-chain inspection in ANY language — 中文 安全扫描/审计, EN security scan/audit, JA セキュリティスキャン, KO 보안 검사, ES auditoría de seguridad, FR audit de sécurité, DE Sicherheitsscan, or equivalent. Semantic understanding, not keyword matching. Always confirm before scanning, mirror user's language, greet with the Protego Shield Charm. READ-ONLY — remediation needs explicit user authorization.
license: Apache-2.0
metadata:
  author: codeeer
  version: "1.0.0"
  homepage: https://github.com/greatcodeeer/skill-protego
---

# Protego — Multi-Language Security Audit Shield Charm

`Protego` is the defensive shield charm from the Wizarding World. This skill conjures that shield around the user's project to protect against the Dark Arts — supply-chain poison, hardcoded secrets, dangerous code sinks, exfiltration channels, worm-style propagation, crypto clippers, MCP tool poisoning, malicious agentic-tool skills, prompt injection, and a dozen other modern attack patterns.

The skill supports 10 ecosystems (npm/PyPI/RubyGems/CocoaPods/Swift PM/Maven/Cargo/Composer/pub/NuGet) and detects attack patterns across all of them. The user's project can be a monorepo with multiple ecosystems mixed — all of them get scanned.

This file is the Claude Code adapter. The same scanner is exposed to Codex via `codex/protego.md` (installed as `~/.codex/prompts/protego.md`), and any agent that can run a Python CLI can invoke `scripts/protego.py` directly. The five-step workflow below applies to every adapter — only the invocation surface differs.

## Read-only guarantee

**Protego scans and reports. It never modifies anything.** The Python scanner only opens files for reading and runs `grep` / `git log` — no writes, no deletes, no auto-fixes. The report contains *suggestions* (rotate this key, add this to .gitignore, remove this package), but actually carrying any of them out must be a separate, explicitly-authorized action by the user. If the user agrees to a fix, do it as a normal code change with their consent on each file you touch.

## When to invoke

Invoke ANY time the user expresses intent to do a security review. This is intentionally cast wide because most users don't know to ask for "Protego" specifically — they'll say things like:

- 中文: 安全扫描 / 安全检查 / 安全审计 / 扫描漏洞 / 风险检测 / 看下安不安全 / 项目安全吗 / 帮我审一下安全
- English: security scan / security check / security audit / vulnerability scan / supply chain audit / scan for malware / dependency audit / check for vulnerabilities
- 日本語: セキュリティスキャン / セキュリティチェック / セキュリティ監査 / 脆弱性スキャン / 依存関係監査
- 한국어: 보안 검사 / 보안 스캔 / 보안 감사 / 취약점 스캔 / 종속성 감사
- Español: escaneo de seguridad / auditoría de seguridad / buscar vulnerabilidades / análisis de seguridad
- Français: analyse de sécurité / audit de sécurité / scanner les vulnérabilités / audit des dépendances
- Deutsch: Sicherheitsscan / Sicherheitsprüfung / Schwachstellenanalyse / Abhängigkeitsprüfung
- … or any equivalent in any other language.

Use semantic understanding, not strict keyword matching. If the user even hints at wanting a security review of their project, invoke this skill.

## The five-step workflow

### Step 1 — Detect the user's language

Identify the language of the user's latest message. Every subsequent piece of output (the confirmation prompt, the Protego incantation, the scan report) MUST be in that same language. The only thing that stays untranslated is the charm name `Protego` itself — it's pseudo-Latin, treated like a proper noun, never translated across the entire wizarding canon.

### Step 2 — Confirm before running (anti-mistrigger)

Before doing anything else, ask the user to confirm. The scan can take 30s–3min and reads through the entire project tree, so accidental triggering is bad UX. Phrase the confirmation in the user's language, and include:

- What will be scanned: the current working directory
- Roughly how long it takes
- The three layers being checked: dependency supply-chain (A: 7 dimensions) + project source code (B: 5 dimensions) + agentic tooling supply-chain (C: 3 dimensions)

Then wait for an affirmative response (yes / 是 / oui / sí / はい / 네 / ja / ok / 好 / 行 / go ahead). If the user declines or hesitates, simply acknowledge and stop. Do not proceed without explicit confirmation.

Example confirmation (English):

> ⚠️ Protego security audit ready to cast over `/Users/.../my-project`.
>
> Scope:
> - A. Dependency supply-chain — 7 dimensions across npm/PyPI/Cargo/etc.
> - B. Project source code — 5 dimensions (secrets, injection sinks, config exposure, git history, architectural anti-patterns)
>
> Estimated time: 30s – 3min depending on project size. Confirm to proceed? (yes/no)

Same content in 中文:

> ⚠️ 准备对 `/Users/.../my-project` 施展 Protego 安全审计。
>
> 扫描范围：
> - A. 依赖供应链 — 跨 npm/PyPI/Cargo 等 7 个维度
> - B. 项目源码 — 5 个维度（密钥、注入 sink、配置暴露、git 历史、架构反模式）
>
> 预计耗时：30 秒 – 3 分钟，视项目规模而定。确认开始吗？（yes / no）

### Step 3 — Cast the shield incantation

Once confirmed, output the opening incantation in the user's language. Use the templates in `references/incantations.md` for the 7 pre-translated languages. For other languages, follow the same "✨ Protego! ✨ → shimmering shield rises → searching for Dark Arts" three-line structure, keeping the charm name `Protego` in Latin form.

### Step 4 — Run the scanner

Invoke the Python scanner. It outputs structured JSON.

```bash
python3 "$(dirname "${BASH_SOURCE[0]:-$0}")/scripts/protego.py" "$(pwd)"
```

In practice from your Claude tools, run:

```bash
python3 <SKILL_PATH>/scripts/protego.py <project_root_absolute_path>
```

The scanner output schema (see `references/detection-patterns.md` for full details):

```json
{
  "scan_root": "/abs/path",
  "ecosystems_detected": ["npm", "python", "ios"],
  "findings": [
    {
      "id": "A1.credential_theft.aws",
      "dimension": "A1",
      "severity": "blocking" | "warning",
      "title": "...",
      "file": "...",
      "line": 42,
      "evidence": "...(truncated)",
      "explanation": "Why this is suspicious"
    }
  ],
  "summary": {
    "blocking": 0,
    "warning": 3,
    "by_dimension": { "A4": 2, "B1": 1 }
  },
  "exit_code": 0
}
```

### Step 5 — Render the report in the user's language

Translate the JSON findings into a human-readable report in the user's language. Structure:

1. **Verdict line** — one of:
   - 🟢 PASS (no findings)
   - 🟡 WARNINGS ONLY (n issues, non-blocking)
   - 🔴 BLOCKED (n blocking + m warnings — must address blocking before deploy/publish)

2. **Section A: Dependency supply-chain** — list findings by dimension (A1–A7)
3. **Section B: Project source code** — list findings by dimension (B1–B5)
4. **Recommendations** — concrete next actions if anything was found

Use 🔴 for blocking, 🟡 for warning, 🟢 for clean. Each finding shows: file:line, evidence (truncated), and why-it-matters explanation in the user's language.

If `exit_code == 1`, EXPLICITLY tell the user the audit BLOCKED — they should not deploy, publish, or commit until blocking findings are addressed.

The report templates in 7 languages are in `references/incantations.md`. For other languages, follow the same structure and translate accurately.

## The 15 dimensions (overview)

Full per-dimension detection logic is in `references/detection-patterns.md`. Quick reference:

**A — Dependency supply-chain (severity defaults shown)**
- A1 🔴 Credential theft (SSH/AWS/GCP/Azure/NPM-token/process.env-dump/crypto-wallet reads)
- A2 🔴 Suspicious code execution (eval+atob/base64, monkey-patching builtins, prototype pollution, decrypt-then-eval)
- A3 🔴 Suspicious exfiltration channels (webhooks, pastebins, DNS tunneling, non-typical public IPs)
- A4 🟡 Build hook abuse (npm postinstall / Python setup.py / Ruby native ext / Cargo build.rs / CocoaPods pre_install)
- A5 🟡 Package structure anomalies (git commit refs in optionalDeps, non-registry URLs, typosquatting)
- A6 🔴 Worm self-propagation + Crypto clipper (calls publish + reads publisher tokens; clipboard wallet-address replace)
- A7 🟡 Package manager hardening (per-ecosystem checks: pnpm allowBuilds, yarn enableScripts, pip --no-deps habits)

**B — Project source code / configuration**
- B1 🔴 Hardcoded secrets (API keys, private keys, DB conn strings, JWT secret, LLM provider keys)
- B2 🟡 Dangerous code sinks (per-language: command/eval/SQLi/SSRF/path-traversal/weak-crypto/ReDoS/XXE/SSTI/deserialization)
- B3 🔴 Configuration / credential exposure (.env or config.json in VCS, missing .gitignore for secret files)
- B4 🟡 Git history secret leaks (gitleaks-style sweep of `git log -p`)
- B5 🟡 AI-era + architectural anti-patterns (prompt-injection in system prompt templates, 0.0.0.0 binding without auth, CORS `*`, weak defaults, ATS disabled on iOS)

**C — Agentic tooling supply-chain (LLM-era specific)**
- C1 🔴 MCP server tool poisoning — hidden `<IMPORTANT>` / `<SYSTEM>` directives in tool descriptions, shell prefixes (Trail of Bits "Line Jumping" Apr 2025), zero-width Unicode in string literals (Invariant Labs "Tool Poisoning" Apr 2025). Scans dependency packages identified as MCP servers.
- C2 🔴 Malicious agentic-tool skills/prompts — applied to both surfaces:
  - **Claude Code SKILL.md** — hidden directives, zero-width / invisible Unicode, base64-encoded payload with LLM-instruction keywords, `curl | bash` backdoors in skill `scripts/`. Snyk's ToxicSkills audit (Feb 2026) found 37% of community skills malicious.
  - **Codex `.codex/prompts/*.md`** — same three content checks applied to Codex slash commands. Each prompt file is loaded into the LLM the moment the user runs `/name`, so a poisoned prompt is a direct injection vector.
- C3 🟡 Agentic tooling inventory — lists MCP servers configured in `.claude/mcp*.json` / `.cursor/mcp.json`, local Claude Code skills, and Codex slash commands. Informational; lets the user audit what's wired into their agent.

## Ecosystem auto-detection

The scanner detects which ecosystems are present by looking at manifest files:

| Manifest | Ecosystem | Lockfile |
|---|---|---|
| `package.json` | JS/TS (npm/pnpm/yarn/bun) | `pnpm-lock.yaml` / `package-lock.json` / `yarn.lock` / `bun.lock` |
| `Podfile` / `Package.swift` | iOS / macOS | `Podfile.lock` / `Package.resolved` |
| `Gemfile` | Ruby | `Gemfile.lock` |
| `requirements.txt` / `pyproject.toml` / `Pipfile` | Python | `poetry.lock` / `Pipfile.lock` |
| `pom.xml` / `build.gradle(.kts)` | Java / Kotlin / Android | (Gradle uses verification metadata) |
| `go.mod` | Go | `go.sum` |
| `Cargo.toml` | Rust | `Cargo.lock` |
| `composer.json` | PHP | `composer.lock` |
| `pubspec.yaml` | Dart / Flutter | `pubspec.lock` |
| `*.csproj` / `packages.config` | .NET | `packages.lock.json` |

A monorepo with multiple ecosystems is fully supported — all of them get scanned.

## Important guidelines

- **Always confirm before running.** No surprise scans.
- **Mirror the user's language for the entire interaction.** Confirmation, incantation, scan output, report, follow-up — all in the user's language. The charm name `Protego` itself stays in Latin form (just like in the books, where every translation keeps the original spells).
- **READ-ONLY.** The scanner never writes, never auto-fixes, never deletes. If findings exist, the report describes what would need to change — but actually making any change requires the user to explicitly authorize each modification afterwards. Don't volunteer to "fix everything" in one go; walk through findings with them.
- **The scanner is heuristic.** False positives can happen — official SDKs (`@aws-sdk`, `@google-cloud/*`, etc.) reading `~/.aws/credentials` is legitimate and gets allow-listed. When in doubt, explain the finding clearly and let the user judge.
- **Don't replace professional scanners.** Protego complements but doesn't replace Snyk / Socket.dev / Phylum / Aikido. For production-critical projects, recommend professional audit alongside.
- **Respect exit code.** Exit 1 means blocking findings present — make that loud in your report so the user doesn't deploy poisoned code.

## Files in this skill

```
protego/
├── SKILL.md (this file)        — Claude Code adapter
├── codex/
│   └── protego.md              — Codex adapter (→ ~/.codex/prompts/protego.md)
├── scripts/
│   └── protego.py              — Core scanner (15 dimensions, all ecosystems)
└── references/
    ├── incantations.md         — Multilingual incantations + report templates
    └── detection-patterns.md   — Per-dimension detection logic & rationale
```
