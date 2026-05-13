# Detection Patterns — Per-Dimension Rationale

This reference file explains the *why* behind each of Protego's 12 dimensions. When rendering the report to the user, draw on these explanations (translated to their language) so findings come with context, not just raw matches.

For the actual regex patterns and code, see `scripts/protego.py`. This file is human-readable rationale only.

---

## A1 — Credential Theft Behavior (🔴 blocking)

**What it catches:** A package in your dependency tree contains code that references sensitive credential locations users keep on disk.

**Why it matters:** Real-world malware (TanStack 2026-05, shai-hulud npm worm 2025-09, lottiefiles 2024) consistently does the same thing: harvest credentials, then exfiltrate. SSH keys, AWS credentials, npm tokens, GCP service accounts, browser-stored crypto wallets — all live in predictable paths. Legitimate libraries that *do* need to read these (e.g. `@aws-sdk`, `boto3`, `google-auth-library`) are allow-listed by name.

**Patterns detected:**
- SSH private keys: `~/.ssh/id_(rsa|ed25519|...)`
- Cloud SDK creds files: `~/.aws/credentials`, GCP ADC JSON
- npm registry token: code that reads the user's `.npmrc` file
- Linux memdump: `/proc/<pid>/mem` access (the TanStack OIDC extraction technique)
- Crypto wallets: MetaMask storage paths, Ethereum keystore filenames
- **shai-hulud signature**: whole-`process.env` serialization (`JSON.stringify(process.env)`)

**How to act on a finding:** Audit the package. Look up its publisher and recent version history on the registry. If you don't recognize why it would need any of these paths, treat as malicious until proven otherwise — remove from your tree.

---

## A2 — Suspicious Code Execution (🔴 blocking)

**What it catches:** Obfuscation loaders, runtime hijacking, and decrypt-then-eval patterns inside dependencies.

**Why it matters:** Malware authors don't want their payload to be readable. The canonical loader is `eval(atob(...))` in JS, `exec(base64.b64decode(...))` in Python, `eval(base64_decode(...))` in PHP. Modern variants use XOR/AES decryption first. Prototype pollution (`Object.prototype[...]`) and reassigning Node builtins (`fs.readFile = ...`, `child_process.spawn = ...`) are runtime hijack signatures used to silently intercept I/O.

**Patterns detected:**
- `eval(atob(...))` and `eval(Buffer.from(...,'base64'))`
- `new Function('<huge string>')` constructor invocation
- `require([...].join(''))` — string-splitting evasion
- Prototype pollution writes to `Object.prototype` or `__proto__`
- Reassigning `fs.readFile` / `child_process.exec` / `http.request` (builtin monkey-patch)
- Cross-language equivalents: Python `exec(base64.b64decode(...))`, Ruby `eval Base64.decode64(...)`, PHP `eval(base64_decode(...))`, PHP `eval(gzinflate(...))`
- Long embedded base64 strings (> 1000 chars on a single line) — possible payload

**How to act:** None of these are normal in published library code. Investigate the offending package immediately. Open-source maintainers don't ship obfuscated loaders.

---

## A3 — Suspicious Exfiltration Channels (🔴 blocking)

**What it catches:** Hardcoded URLs/hosts matching well-known data-exfiltration channels.

**Why it matters:** After credential harvest, malware must phone home. Legitimate libraries don't ship hardcoded production webhooks. The TanStack 2026-05 attack used the Session/Oxen messenger network specifically because it's end-to-end encrypted and hides the attacker.

**Patterns detected:**
- Real Discord/Telegram/Slack webhook URLs (placeholders like `xxxx` are filtered out)
- Pastebin family (pastebin.com, paste.ee, hastebin.com, 0x0.st, transfer.sh, file.io)
- Session/Oxen network (`getsession.org`, `oxen.io`, `loki.network`)
- Suspiciously-long subdomain on commodity TLDs (DNS exfiltration indicator) — *warning* level
- WebSockets to non-localhost hardcoded hosts

**How to act:** Trace the data flow. If a URL is in dependency code, find the function that uses it and see what data goes there. Real production webhooks in published packages = compromise.

---

## A4 — Build Hook Abuse (🟡 warning)

**What it catches:** `preinstall` / `install` / `postinstall` / `prepare` hooks (and equivalents in Python's `setup.py`, Cargo's `build.rs`, CocoaPods `pre_install`/`post_install`) that contain commands typical of malware loaders.

**Why it matters:** Install hooks run with the user's full credentials at the time `npm install` (or `pip install`, `cargo build`, `pod install`, etc.) happens. The TanStack 2026-05 and lottiefiles 2024-10 attacks both landed via this vector. Legitimate hooks invoke `node-gyp`, `prebuild-install`, platform-specific binary downloads from the official registry — nothing more.

**Suspicious commands flagged:** `curl`, `wget`, `nc`/`netcat`, `base64 -d`, `eval $...`, command substitution that pipes from curl/wget, `/dev/tcp/...`, `/proc/.../mem`, references to `~/.ssh` or `~/.aws` or `~/.npmrc`.

**Also flagged:** Install scripts longer than 5 KB (legitimate hooks are short).

**How to act:** Most hits should be benign — node-gyp wrappers, etc. But anything reading user-home paths or downloading from a non-registry URL is a serious red flag.

---

## A5 — Package Structure Anomalies (🟡 warning)

**What it catches:** Dependencies fetched via channels that bypass the registry's audit/integrity checks.

**Why it matters:** The npm registry adds tamper-evident `integrity` hashes and a published-version history. Git-protocol dependencies don't — the resolved tarball can change at any time without trace. The TanStack 2026-05 attack specifically used `optionalDependencies` pointing to a GitHub commit ref to deliver its payload.

**Patterns detected:**
- `dependencies` / `optionalDependencies` / `peerDependencies` using `git+`, `github:`, `git://`, `git@`
- Same fields using `file:`, `http:`, `ftp:` protocols
- `package-lock.json` or `pnpm-lock.yaml` entries with `resolved` URLs outside `registry.npmjs.org`

**How to act:** If you need a git dep (e.g. a fork), pin to a tag plus a vendor-checked commit hash, and audit the repo before adding. Better: publish your fork to the registry under your scope.

---

## A6 — Worm Self-Propagation + Crypto Clipper (🔴 blocking)

**What it catches:** Two distinct but related malware patterns:

1. **Worm**: dependency code that itself calls `npm publish` / `pnpm publish` / `gem push` / `cargo publish` after harvesting publisher tokens. This is how the shai-hulud npm worm (2025-09) spread across hundreds of packages.

2. **Crypto clipper**: dependency code that monitors clipboard and substitutes wallet addresses (BTC/ETH/SOL/...). The event-stream (2018) attack and Solana web3.js (2024-12) compromise both used this.

**Patterns detected:**
- Child-process call to `npm publish` / `gem push` / `cargo publish`
- `npm whoami` invocation (reconnaissance)
- `clipboardy` / `navigator.clipboard.read` usage
- Hardcoded Ethereum/Bitcoin addresses with `.replace(...)` nearby (clipper signature)
- Multi-chain wallet-type switches (`AddressType: btc|eth|sol|...`)

Allow-listed: clipboardy/copy-paste/ethers.js/web3/@solana legitimate libraries — but only if they don't also contain a `.replace(...)` of a hardcoded address.

**How to act:** Worm pattern = compromise propagation. Pull the package and rotate any publisher credentials this machine has touched. Crypto clipper = active asset theft. Same response, plus check on-chain whether anything moved.

---

## A7 — Package Manager Hardening (🟡 warning)

**What it catches:** Package manager configuration that leaves the default-permissive install behavior in place.

**Why it matters:** npm defaults to "all packages can run install scripts." That's the same default that landed the TanStack attack inside thousands of CI systems. pnpm 11+ has `allowBuilds` (default-deny + explicit allowlist). yarn 2+ has `enableScripts: false`. Using these moves you from "everything trusted" to "explicitly trusted only."

**What's recommended per manager:**
- **pnpm**: `pnpm-workspace.yaml` with `allowBuilds` + `minimumReleaseAge: 20160` (14 days)
- **npm**: `.npmrc` with `ignore-scripts=true` + manual `npm rebuild <whitelist>`
- **yarn**: `.yarnrc.yml` with `enableScripts: false`
- All: use `--frozen-lockfile` (npm `ci`, pnpm `install --frozen-lockfile`, yarn `install --immutable`) in deploys

**How to act:** Adopt the recommended hardening for your manager. The 14-day release-age gate alone would have blocked every major npm supply-chain attack of 2024-2026 (all were detected and yanked within hours).

---

## B1 — Hardcoded Secrets (🔴 blocking in source, 🟡 warning in config files)

**What it catches:** Real secret-format strings (API keys, private keys, DB connection strings, JWT tokens) embedded directly in files.

**Severity logic:**
- In source code files (`.js`, `.py`, `.go`, etc.): **🔴 blocking** — secrets in source get leaked via git history, log scraping, insider access.
- In `.env*` / `config.json` / similar dedicated config files: **🟡 warning** — these files *exist* to hold secrets, the actual risk is git tracking, which dimension B3 checks separately.

**Patterns detected:** OpenAI/Anthropic/xAI/Google/AWS/Stripe/GitHub/npm/Slack/Discord/Twilio/SendGrid/DigitalOcean keys; PEM private key blocks (with body, not just header); JWT tokens (three-part base64url); database URLs with embedded password.

**False-positive filter:** values containing common placeholder strings (`example`, `your-`, `xxx`, `fake`, `placeholder`, `redacted`, `<your`) are ignored.

**How to act:** Rotate the secret immediately. Even if you remove from source, anyone who cloned the repo at any point has it. Then move it to your environment / secret manager. If it was a placeholder, use a clearly-fake value (`sk-EXAMPLE-...`).

---

## B2 — Dangerous Code Sinks (🟡 warning)

**What it catches:** Per-language patterns matching known dangerous APIs being called with non-literal arguments.

**Why warning, not blocking:** Most of these are heuristic. `child_process.exec(someVar)` is genuinely dangerous if `someVar` is user input; perfectly fine if it's a hardcoded string. Static analysis can't fully resolve data flow — so we flag and let the human/Claude judge.

**Sinks covered:**
- JS/TS: `child_process.exec` with concat, dynamic `eval()`, React `dangerouslySetInnerHTML` with variable, Node `vm.runIn*Context` with non-literal
- Python: `os.system` with non-literal, `subprocess` with `shell=True`, `pickle.load(s)`, `yaml.load` without `SafeLoader`
- Ruby: `eval` with variable, `Marshal.load`, `system` with interpolation
- PHP: `eval($var)`, `unserialize($var)`, `system/exec/shell_exec/passthru` with variable
- Go: `exec.Command` with non-literal program name
- Swift: `NSExpression(format:)`
- Cross-language: SQL string concatenation, weak hash (MD5/SHA1) for passwords

**How to act:** Open each finding. If the value going into the dangerous API is user-controlled, fix it. If it's a literal/constant, it's safe and can be suppressed (rename the regex hit to false-positive list).

---

## B3 — Configuration / Credential Exposure (🔴 blocking)

**What it catches:** Sensitive files that are tracked in git, and missing `.gitignore` entries for common secret-file names.

**Why it matters:** A `.env` file in git history is worse than a hardcoded key in source — it's purpose-built to hold credentials, so it's a one-stop-shop for any attacker who clones the repo. Once in git history, the only fix is force-push history rewrite (rarely practical for shared repos) and assume the secrets are leaked.

**Patterns detected:**
- `.env` / `.env.local` / `.env.production` / `secrets.json` / `credentials.json` / `service-account.json` / `firebase-config.json` / `id_rsa` / `id_ed25519` tracked by git
- Sensitive-looking content (`secret=`, `password=`, `api_key=`, `PRIVATE KEY`) inside `config.json` that's tracked
- `.gitignore` missing entries for `.env`, `*.pem`, `*.key`, `id_rsa`, `.npmrc`

**How to act:** Rotate every secret in the tracked file. Remove the file from the index (`git rm --cached`). Add to `.gitignore`. Force-push only if the repo is private and you control all clones (otherwise treat secrets as already compromised).

---

## B4 — Git History Secret Leaks (🟡 warning)

**What it catches:** Secret-format strings found in the last 200 commits' diffs (added lines only).

**Why warning, not blocking:** Even one hit is bad — but by the time you're scanning, the damage is already in history. You can't "un-blocking" history. The action is "rotate the leaked secret," not "stop deploying."

**Patterns checked:** Same secret formats as B1. Limited to 200 most-recent commits for runtime budget (a deep historical sweep would need a dedicated tool like `gitleaks` / `trufflehog`).

**How to act:** Rotate the matched secret. Don't bother trying to scrub git history unless the repo is private and you control all clones — assume leaked.

---

## B5 — AI-Era + Architectural Anti-Patterns (🟡 warning)

**What it catches:** Newer threat classes that emerged in 2024-2026 plus a few perennial architectural footguns.

**AI-era:**
- System prompt built by string template with a variable (`system_prompt: \`...${userInput}...\``) → **prompt injection risk**

**Network exposure:**
- HTTP servers binding `0.0.0.0` (Express `app.listen(port, '0.0.0.0')`, Flask `app.run(host='0.0.0.0')`) — verify auth/firewall
- CORS `Access-Control-Allow-Origin: *` or express-cors `origin: '*'` — production permissive CORS

**Defaults:**
- Hardcoded weak default passwords (`admin`, `password`, `123456`, `root`, `secret`, `changeme`)
- Python `DEBUG = True` — verify not in production
- iOS `Info.plist` with `NSAllowsArbitraryLoads=true` (ATS disabled)

**How to act:** Each one is context-dependent. `0.0.0.0` is fine for a container behind a load balancer with authentication; bad for a developer's laptop exposed on a public Wi-Fi. CORS `*` is fine on a truly-public API but a hole on anything else. Audit per finding.

---

## C1 — MCP Server Tool Poisoning (🔴 blocking)

**What it catches:** Hidden LLM directives, prompt-injection markers, and shell-command prefixes embedded inside MCP server packages' tool descriptions / schemas.

**Why it matters:** Two distinct attack lines have been published in 2025 against MCP:

1. **Invariant Labs (April 2025) — "Tool Poisoning Attacks":** Malicious MCP servers plant `<IMPORTANT>...</IMPORTANT>` tagged instructions inside tool *descriptions*. The description is invisible to the user in MCP client UIs, but the LLM reads it on connection and obeys it — commanded to read `~/.ssh/id_rsa`, `~/.cursor/mcp.json`, WhatsApp chat history, and exfiltrate via a "sidenote" argument disguised as legitimate math output. Live tests on Cursor leaked SSH keys.

2. **Trail of Bits (April 2025) — "Line Jumping":** Same attack surface, different payload — descriptions begin with shell command prefixes like `chmod -R 0666 ~;` so any tool listing makes the home directory world-readable *before* the user ever invokes a tool. Effectively a zero-click MCP attack.

**Patterns detected:**
- Hidden directive tags: `<IMPORTANT>`, `<SYSTEM>`, `<INSTRUCTIONS>`, `<|im_start|>`, `<|endoftext|>`, `<|system|>`
- Override phrases: "ignore previous", "disregard above", "forget prior"
- Instructions to read sensitive paths: tool description containing "read ~/.ssh/...", "open ~/.aws/credentials", "load .cursor/mcp.json"
- Shell-command prefixes in description: `chmod`, `curl | bash`, `wget | sh`
- **Zero-width / invisible Unicode characters** inside string literals (U+200B–U+200D, BOM, bidirectional overrides) — invisible to humans, fully visible to LLMs

**Scope:** Only packages identified as MCP servers — those with `@modelcontextprotocol/sdk` as a dep, or `Requires-Dist: mcp` in Python metadata, or `"mcp server"` / `"model context protocol"` in package description.

**How to act:** Pull the package, audit the publisher, scrub from your MCP config. Treat any MCP server with these patterns as compromised — there is no legitimate reason to put XML directive tags or shell prefixes in a tool description.

---

## C2 — Malicious Agentic-Tool Skills / Prompts (🔴 blocking)

**What it catches:** Hidden prompt injections in two attack surfaces:

1. **Claude Code skills** — `SKILL.md` files and the `scripts/` directories alongside them.
2. **Codex slash commands** — `.md` files under `.codex/prompts/`, each of which is loaded directly into the LLM the moment the user types `/<name>`.

Both surfaces are checked against the same three obfuscation patterns (directive tags, zero-width Unicode, base64-encoded payloads). Skill `scripts/` get the additional `curl | bash`-class backdoor check; Codex prompts don't have an equivalent script tree, so that check is skipped there.

**Why it matters:** Snyk's **ToxicSkills audit (February 2026)** examined 3,984 community-uploaded Claude Code / OpenClaw / Cursor skills:
- **1,467 (37%) contained malicious code** — most via prompt injection in `SKILL.md`
- 91% used base64 or Unicode obfuscation in `SKILL.md` to hide instructions
- 76 skills were confirmed actively malicious with file/shell/API access (no sandbox)
- Payloads: AWS key theft, RCE via `curl | bash`, malware ZIP downloads, crypto-targeted theft
- Some skills were uploaded by week-old GitHub accounts and still trusted because of marketplace pull

Skills, unlike npm packages, run as the user's shell, see the user's conversation, and can invoke any tool the LLM has access to. There's no audit, no sandbox, no signature verification (yet) on most skill marketplaces.

**Patterns detected in `SKILL.md`:**
- Same hidden-directive markers as C1 (`<IMPORTANT>`, override phrases)
- **Zero-width / invisible Unicode** — every found codepoint reported
- **Base64-decoded payload containing instruction keywords**: long base64 strings (≥80 chars) that decode to text containing "ignore", "system", "instruction", "you must", "ssh", "credentials", "exfil", "curl", "/bin/"

**Patterns detected in skill `scripts/`:**
- `curl <url> | bash` / `wget <url> | sh` (the classic backdoor)
- `eval $(curl ...)` — remote code execution
- Download-then-execute: `curl -o /tmp/x && bash /tmp/x` / `chmod +x` + run
- `base64 -d | bash` — obfuscated payload

**Scope:**
- Claude Code: `./skills/*/SKILL.md` and `./.claude/skills/*/SKILL.md`, plus the `scripts/`, `agents/`, etc. subdirs of each skill.
- Codex: `./.codex/prompts/*.md` (each file is one slash command).

**How to act:** If you didn't write the skill/prompt or recognize its source, remove it. If you got it from a marketplace or community repo, report it. The 91% obfuscation rate from ToxicSkills means any hidden encoding in a skill or prompt file should be treated as deliberate — legitimate ones have no reason to embed base64 or zero-width Unicode.

---

## C3 — Agentic Tooling Config Inventory (🟡 warning)

**What it catches:** This dimension is informational. It lists:
- All MCP servers currently configured in `.claude/mcp*.json`, `.cursor/mcp.json`, `mcp-config.json`, etc.
- The count of local Claude Code skills installed under `./skills/` or `./.claude/skills/`
- All Codex slash commands installed under `./.codex/prompts/`

**Why warning, not blocking:** Having MCP servers, skills, and slash commands installed isn't itself dangerous — but every entry is a potential C1/C2 attack vector. The warning prompts the user to *audit* what's wired in: does each MCP server come from a trusted source? Is each skill / slash command one they intentionally installed?

**How to act:** Walk down the list. For each MCP server, confirm the package source. For each Claude Code skill, confirm authorship. For each Codex slash command, confirm where the prompt came from. Anything you don't recognize, remove. This is the kind of audit that should happen quarterly, not just at scan time.

---

## On false positives

Protego is intentionally heuristic. The goal is not to be a perfect SAST — it's to give the user a starting point that catches the >90% of real attacks at the cost of some noise. When a finding looks like a false positive:

1. Verify the context (is the matched pattern actually in dangerous use?).
2. If genuinely false-positive, the user can suppress by editing the regex / adding the path to an allow-list in `scripts/protego.py`.
3. Real findings always win — if you can't immediately tell, treat as real.
