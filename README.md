# Protego — Multi-Language Security Audit Shield Charm

> A defensive agent skill that scans your project for supply-chain attacks and source-code vulnerabilities — in any human language you speak. **Works with [Claude Code](https://docs.claude.com/en/docs/claude-code/skills) and [Codex](https://github.com/openai/codex)** out of the box, and with any agent that can invoke a Python CLI.
>
> Named after the Wizarding World's protective shield charm: it raises a ward around your codebase against the Dark Arts. ✨

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE.txt)
[![Claude Code](https://img.shields.io/badge/Claude_Code-skill-7C3AED.svg)](#install-for-claude-code)
[![Codex](https://img.shields.io/badge/Codex-prompt-10A37F.svg)](#install-for-codex)
[![Ecosystems: 10](https://img.shields.io/badge/Ecosystems-10-green.svg)](#ecosystem-auto-detection)
[![Dimensions: 15](https://img.shields.io/badge/Detection_Dimensions-15-orange.svg)](#what-it-does)
[![Read-only](https://img.shields.io/badge/Read--only-yes-brightgreen.svg)](#read-only-by-design)

**English** · [简体中文 ↓](#中文简介)

---

## Why this exists

On **2026-05-09**, the TanStack team disclosed a [supply-chain compromise](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem) that pushed malicious versions of **84 versions across 42 packages** through a chained `pull_request_target` + cache poisoning + OIDC memdump attack. `@tanstack/react-query` alone has tens of millions of weekly installs. Anyone who ran `npm install` during the window without lock-file pinning could have leaked tokens.

That was the seventh major npm-side compromise in twelve months — TanStack, axios, the shai-hulud worm, lottiefiles, Ultralytics on PyPI, the XZ Utils backdoor, plus the LLM-era pattern of poisoned MCP servers and malicious Claude Code skills. The frequency stopped being noise and started being signal.

**Protego is the audit I wanted to be able to run with one sentence.** No config, no API key, no upload. Just say "scan my project" in your language — Claude does the rest, read-only, and explains every finding in the same language you asked in.

---

## What it does

Read-only security audit across **15 attack-pattern dimensions** spanning **10 package ecosystems**.

| Layer | Dimensions | Examples |
|---|---|---|
| **A — Dependency supply-chain** | 7 | Credential theft, install-script abuse, exfiltration channels, build-hook abuse, package anomalies, worm self-propagation + crypto clippers, package-manager hardening |
| **B — Project source / config** | 5 | Hardcoded secrets, dangerous code sinks, `.env` exposure in VCS, git history secret leaks, AI-era + architectural anti-patterns |
| **C — Agentic tooling supply-chain** | 3 | MCP server tool poisoning (Invariant Labs / Trail of Bits 2025), malicious agentic-tool skills — both Claude Code `SKILL.md` (Snyk ToxicSkills 2026 — 37% of audited skills malicious) and Codex `.codex/prompts/*.md`, agentic tooling inventory |

Supports **npm / PyPI / RubyGems / CocoaPods / Swift PM / Maven / Cargo / Composer / pub / NuGet**. Monorepos with mixed ecosystems get all of them scanned.

---

## Quick start

### 1. Clone

```bash
git clone https://github.com/greatcodeeer/skill-protego.git ~/.protego
```

Then wire it into whichever agent(s) you use:

### Install for Claude Code

Drop the directory into your Claude Code skills location — global or project-local:

```bash
# Global (available everywhere)
mkdir -p ~/.claude/skills && ln -sf ~/.protego ~/.claude/skills/protego

# OR project-local (only this project)
mkdir -p .claude/skills && ln -sf ~/.protego .claude/skills/protego
```

Claude Code reads `~/.protego/SKILL.md` and picks up the skill on its next session.

### Install for Codex

Drop the prompt file into your Codex prompts directory:

```bash
mkdir -p ~/.codex/prompts && ln -sf ~/.protego/codex/protego.md ~/.codex/prompts/protego.md
```

Codex exposes it as the `/protego` slash command. (Plain `cp` works if you don't want symlinks.)

### Use with any other agent

The scanner is a standalone Python script — point any tool-capable agent at it:

```bash
python3 ~/.protego/scripts/protego.py "$PWD"
```

Output is structured JSON (schema in [SKILL.md](SKILL.md#step-4--run-the-scanner)). Pair it with the multilingual report templates in [references/incantations.md](references/incantations.md) if you want the same UX.

### 2. Invoke

Ask Claude for a security check **in any language** — Protego understands intent, not strict keywords:

| Language | Example phrase |
|---|---|
| 🇨🇳 中文 | 帮我做个安全扫描 / 安全审计 / 检测下漏洞 |
| 🇺🇸 English | run a security audit / scan for malware / supply-chain check |
| 🇯🇵 日本語 | セキュリティスキャンして / 脆弱性チェック |
| 🇰🇷 한국어 | 보안 검사 / 취약점 스캔 |
| 🇪🇸 Español | hacer una auditoría de seguridad |
| 🇫🇷 Français | lance un audit de sécurité |
| 🇩🇪 Deutsch | mach einen Sicherheitsscan |

Protego will:

1. **Confirm** before scanning (prevents accidental triggers).
2. **Greet** with the shield-charm incantation in your language:

   > ✨ Protego! ✨
   > A shimmering shield rises around your project.
   > Searching for the Dark Arts within…

3. **Scan** the current directory (30 s – 3 min depending on size).
4. **Report** findings in your language — grouped by dimension, with each finding tagged 🔴 blocking or 🟡 warning.

---

## Sample output

```
🔴 BLOCKED — 2 blocking, 4 warnings

Section A — Dependency supply-chain
  🔴 A1  Credential theft: package `<redacted>` reads ~/.ssh/id_ed25519
        node_modules/<redacted>/dist/index.js:1842
  🟡 A4  Build hook: postinstall script fetches remote URL
        node_modules/<redacted>/package.json:23

Section B — Project source code
  🔴 B1  Hardcoded secret: AWS access key
        src/config/aws.ts:14
  🟡 B3  .env file tracked in git history
        .env (commit abc123)

Section C — Agentic tooling supply-chain
  🟡 C3  Inventory: 3 MCP servers configured, 7 local skills

Recommendations
  1. Remove `<redacted>` from package.json and audit installed versions.
  2. Rotate the AWS key on line 14 of src/config/aws.ts. Move to env var.
  3. Run `git filter-repo` to purge the .env file from history.
```

---

## What "blocking" vs "warning" means

| Tag | Meaning | Exit code |
|---|---|---|
| 🔴 **Blocking** | Real attack surface (e.g. hardcoded secret in tracked source). The scanner exits `1`. Do not deploy / publish / commit until addressed. |
| 🟡 **Warning** | Heuristic match that deserves human review (e.g. `eval()` with non-literal argument — could be safe, could be RCE). Exit code stays `0`. |
| 🟢 **Pass** | No findings at all. |

## Read-only by design

Protego **never modifies, deletes, or "fixes" anything**. The Python scanner only opens files for reading and runs `grep` / `git log` — no writes, no deletes, no auto-fixes.

The report contains remediation suggestions ("rotate this key", "add this to .gitignore"), but actually doing any of them must be a separate, explicitly-authorized action by you. If you ask Claude to follow up on a finding, expect Claude to confirm each file change with you.

## Heuristic, not exhaustive

This is a pattern-based scanner — it catches the >90% of common attack patterns at the cost of some false positives. Real legitimate code can match heuristics; verify each finding before acting on it. For production-critical projects, run Protego **alongside** professional scanners like [Snyk](https://snyk.io), [Socket.dev](https://socket.dev), [Phylum](https://phylum.io), or [Aikido](https://aikido.dev) — not as a replacement.

## Ecosystem auto-detection

The scanner picks up which ecosystems are present by manifest file. No config required.

| Manifest | Ecosystem | Lockfile |
|---|---|---|
| `package.json` | JS/TS (npm/pnpm/yarn/bun) | `pnpm-lock.yaml` / `package-lock.json` / `yarn.lock` / `bun.lock` |
| `Podfile` / `Package.swift` | iOS / macOS | `Podfile.lock` / `Package.resolved` |
| `Gemfile` | Ruby | `Gemfile.lock` |
| `requirements.txt` / `pyproject.toml` / `Pipfile` | Python | `poetry.lock` / `Pipfile.lock` |
| `pom.xml` / `build.gradle(.kts)` | Java / Kotlin / Android | (Gradle verification metadata) |
| `go.mod` | Go | `go.sum` |
| `Cargo.toml` | Rust | `Cargo.lock` |
| `composer.json` | PHP | `composer.lock` |
| `pubspec.yaml` | Dart / Flutter | `pubspec.lock` |
| `*.csproj` / `packages.config` | .NET | `packages.lock.json` |

Monorepos with multiple ecosystems mixed are fully supported — all of them get scanned in one pass.

## Repository structure

```
protego/
├── SKILL.md                          # Claude Code entry point (Agent Skills spec)
├── codex/
│   └── protego.md                    # Codex entry point — copy to ~/.codex/prompts/protego.md
├── scripts/
│   └── protego.py                    # Core scanner — portable, agent-agnostic
├── references/
│   ├── incantations.md               # Multilingual incantations + report templates
│   └── detection-patterns.md         # Per-dimension detection rationale + real-world incidents
├── LICENSE.txt                       # Apache 2.0
└── README.md                         # This file
```

The Python scanner is the portable core. `SKILL.md` and `codex/protego.md` are thin adapters that teach each agent the multilingual UX. Adding a new agent is a single-file PR.

## Real incidents this catches

Each dimension is grounded in real 2024-2026 supply-chain attacks documented by major security teams:

- **[TanStack 2026-05](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)** — pull_request_target + cache poisoning + OIDC memdump → 84 versions across 42 packages
- **axios 2026-03** — maintainer phishing → malicious sub-dependency `plain-crypto-js`
- **shai-hulud npm worm 2025-09** — `process.env` whole-dump + npm-token self-propagation
- **Invariant Labs MCP Tool Poisoning 2025-04** — hidden `<IMPORTANT>` directives in tool descriptions
- **Trail of Bits "Line Jumping" 2025-04** — shell-command prefix in MCP tool descriptions
- **Snyk ToxicSkills 2026-02** — 37% of community Claude Code skills found malicious (base64 / unicode obfuscation, `curl|bash` backdoors)
- **Ultralytics PyPI 2024** — `setup.py` arbitrary code at install time
- **XZ Utils 2024** — multi-stage backdoor in build script
- **lottiefiles 2024-10** — maintainer phishing → wallet drainer
- **event-stream 2018** — crypto wallet hijack, the original prior art

See [references/detection-patterns.md](references/detection-patterns.md) for which dimension catches which technique and the underlying detection logic.

## Contributing

Issues and PRs welcome — especially:

- New attack patterns from disclosed CVEs / postmortems
- Additional ecosystem coverage
- Translations of the incantation and report templates into more languages
- False-positive reports (please include the matched file/line and why it's legitimate)

## License

Apache License 2.0 — see [LICENSE.txt](LICENSE.txt).

---

## 中文简介

**Protego（呼神护卫）** 是一个为 AI 编码代理设计的只读安全审计 skill —— 同时支持 **Claude Code** 和 **Codex**。用任何语言对 AI 说一句"帮我做个安全扫描"，它就会：

1. 自动识别项目用的 **10 种包管理生态**（npm / PyPI / Cargo / Maven / CocoaPods / Swift PM / RubyGems / Composer / pub / NuGet），monorepo 混用也全覆盖
2. 在 **15 个攻击面维度**上做静态扫描 —— 依赖供应链投毒、硬编码密钥、危险代码 sink、`.env` 入库、git 历史泄密、MCP 工具中毒、恶意 Claude Code skill、恶意 Codex prompt 等
3. **用你的母语**输出报告，🔴 阻断 / 🟡 警告 分级，每条结论附原因与处置建议
4. **全程只读**，发现问题只给建议，不会自动改你一行代码（任何修复都要你单独确认）

### 为什么做这个

2026-05-09 [TanStack 供应链投毒事件](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)：通过 `pull_request_target` + cache poisoning + OIDC memdump 三连击，**42 个包共 84 个版本**被植入恶意代码。`@tanstack/react-query` 周下载量数千万。这是 12 个月内第 7 起重大 npm 投毒事件（TanStack、axios、shai-hulud 蠕虫、lottiefiles、Ultralytics 在 PyPI、XZ Utils 后门，再加上 LLM 时代的 MCP 中毒和恶意 skill）。

频次到这个程度，**得有一句话就能在本地跑的审计**——不要 API key、不要上传代码、不要配置文件。Protego 就是这个一句话。

### 30 秒安装

```bash
git clone https://github.com/greatcodeeer/skill-protego.git ~/.protego

# Claude Code 用户
ln -sf ~/.protego ~/.claude/skills/protego

# Codex 用户
ln -sf ~/.protego/codex/protego.md ~/.codex/prompts/protego.md
```

之后对 Claude 或 Codex 说："**帮我做个安全扫描**" / "**安全审计**" / "**检测下漏洞**" —— 任何意思相近的中文都能触发。Protego 会先确认、再施咒、最后用中文回报。

### 注意

- 启发式扫描：覆盖 90%+ 常见攻击模式，**会有少量误报**，每条 finding 都需要人工判断
- 不替代专业扫描器（Snyk / Socket.dev / Phylum / Aikido），生产关键项目建议**并行使用**
- License: Apache 2.0

[↑ 返回顶部](#protego--multi-language-security-audit-shield-charm)
