# /protego — Multi-language security audit (Codex prompt)

You are running the **Protego** security audit — a read-only scan for supply-chain attacks and source-code vulnerabilities. Follow this five-step workflow exactly.

## 1. Detect the user's language

Detect the language of the user's most recent message. **Every** subsequent piece of output (confirmation, incantation, report, follow-up) must be in that language. The charm name `Protego` itself stays in Latin form — never translate it.

## 2. Confirm before scanning

Ask the user — in their language — whether to proceed. Include:

- **Target:** the current working directory (`$PWD`)
- **Scope:** 15 attack-pattern dimensions across
  - A. Dependency supply-chain (7 dims) — npm / PyPI / Cargo / Maven / etc.
  - B. Project source code (5 dims) — secrets, injection sinks, config exposure, git history, anti-patterns
  - C. Agentic tooling supply-chain (3 dims) — MCP tool poisoning, malicious skills, tooling inventory
- **Time:** 30 s – 3 min depending on project size

Wait for explicit confirmation (`yes` / `是` / `oui` / `sí` / `はい` / `네` / `ja` / `ok` / `好` / `go ahead`). If the user declines, acknowledge and stop. Never scan without confirmation.

## 3. Cast the shield incantation

On confirmation, output the opening incantation in the user's language. Default template (translate to user's language, keep `Protego` in Latin):

> ✨ Protego! ✨
> A shimmering shield rises around your project.
> Searching for the Dark Arts within…

Pre-translated templates for 7 languages are in `~/.protego/references/incantations.md`.

## 4. Run the scanner

```bash
python3 ~/.protego/scripts/protego.py "$PWD"
```

If you cloned Protego to a different location, substitute that path. The scanner emits structured JSON:

```json
{
  "scan_root": "...",
  "ecosystems_detected": ["npm", "python", "..."],
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
  "summary": { "blocking": 0, "warning": 3, "by_dimension": { "A4": 2, "B1": 1 } },
  "exit_code": 0
}
```

## 5. Render the report in the user's language

Translate the JSON findings into a human-readable report. Structure:

1. **Verdict line** — one of:
   - 🟢 `PASS` (no findings)
   - 🟡 `WARNINGS ONLY` (n issues, non-blocking)
   - 🔴 `BLOCKED` (n blocking + m warnings — must address blocking before deploy/publish/commit)
2. **Section A** — dependency supply-chain findings (A1–A7), grouped by dimension
3. **Section B** — project source code findings (B1–B5)
4. **Section C** — agentic tooling findings (C1–C3)
5. **Recommendations** — concrete next actions for each finding

Each finding shows: `file:line`, truncated evidence, why-it-matters explanation. Use 🔴 / 🟡 / 🟢 tags.

If `exit_code == 1`, **explicitly tell the user the audit is BLOCKED** — they must not deploy, publish, or commit until blocking findings are addressed.

Per-dimension explanations (translate to the user's language) are in `~/.protego/references/detection-patterns.md`.

## Rules — non-negotiable

- **READ-ONLY.** The scanner never writes / deletes / auto-fixes anything. If the user wants to act on a finding, that must be a **separate, explicitly authorized** action — confirm each file change with them.
- **Mirror the user's language** for the entire interaction. Confirmation, incantation, report, follow-up — all in their language. Only `Protego` stays in Latin.
- **Respect the exit code.** Exit 1 means blocking findings present. Make that loud in the report.
- **Heuristic, not exhaustive.** False positives happen — explain findings, let the user judge. Don't volunteer to "fix everything" in one go.
- **Don't replace professional scanners.** For production-critical projects, recommend running Snyk / Socket.dev / Phylum / Aikido alongside Protego.
