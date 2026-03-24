<div align="center">

<img src="./assets/agentshield-logo.png" alt="AgentShield" width="180" />

# AgentShield

**Security auditor for AI agent configurations**

Scans Claude Code setups for hardcoded secrets, permission misconfigs,<br/>
hook injection, MCP server risks, and agent prompt injection vectors.<br/>
Available as CLI, GitHub Action, and [GitHub App](https://github.com/apps/ecc-tools) integration.

[![npm version](https://img.shields.io/npm/v/ecc-agentshield)](https://www.npmjs.com/package/ecc-agentshield)
[![npm downloads](https://img.shields.io/npm/dm/ecc-agentshield)](https://www.npmjs.com/package/ecc-agentshield)
[![tests](https://img.shields.io/badge/tests-passing-brightgreen)]()
[![coverage](https://img.shields.io/badge/coverage-v8-blue)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Quick Start](#quick-start) · [What It Catches](#what-it-catches) · [API Reference](#api-reference) · [Opus Pipeline](#opus-46-deep-analysis---opus) · [GitHub Action](#github-action) · [Distribution](#distribution) · [MiniClaw](#miniclaw) · [Changelog](./CHANGELOG.md)

</div>

---

## Why

The AI agent ecosystem is growing faster than its security tooling. In January 2026 alone:

- **12%** of a major agent skill marketplace was malicious (341 of 2,857 community skills)
- A **CVSS 8.8** CVE exposed 17,500+ internet-facing instances to one-click RCE
- The Moltbook breach compromised **1.5M API tokens** across 770,000 agents

Developers install community skills, connect MCP servers, and configure hooks without any automated way to audit the security of their setup. AgentShield scans your `.claude/` directory and flags vulnerabilities before they become exploits.

Built at the [Claude Code Hackathon](https://cerebralvalley.ai/e/claude-code-hackathon) (Cerebral Valley x Anthropic, Feb 2026). Part of the [Everything Claude Code](https://github.com/affaan-m/everything-claude-code) ecosystem (42K+ stars).

## Quick Start

```bash
# Scan your Claude Code config (no install required)
npx ecc-agentshield scan

# Or install globally
npm install -g ecc-agentshield
agentshield scan
```

That's it. AgentShield auto-discovers your `~/.claude/` directory, scans all config files, and prints a graded security report.

Discovery intentionally skips common generated directories such as `node_modules`, build output, and `.dmux` worktree mirrors so transient copies do not duplicate findings.

```
  AgentShield Security Report

  Grade: F (0/100)

  Score Breakdown
  Secrets        ░░░░░░░░░░░░░░░░░░░░ 0
  Permissions    ░░░░░░░░░░░░░░░░░░░░ 0
  Hooks          ░░░░░░░░░░░░░░░░░░░░ 0
  MCP Servers    ░░░░░░░░░░░░░░░░░░░░ 0
  Agents         ░░░░░░░░░░░░░░░░░░░░ 0

  ● CRITICAL  Hardcoded Anthropic API key
    CLAUDE.md:13
    Evidence: sk-ant-a...cdef
    Fix: Replace with environment variable reference [auto-fixable]

  ● CRITICAL  Overly permissive allow rule: Bash(*)
    settings.json
    Evidence: Bash(*)
    Fix: Restrict to specific commands: Bash(git *), Bash(npm *), Bash(node *)

  Summary
  Files scanned: 6
  Findings: 73 total — 19 critical, 29 high, 15 medium, 4 low, 6 info
  Auto-fixable: 8 (use --fix)
```

### More commands

```bash
# Scan a specific directory
agentshield scan --path /path/to/.claude

# Auto-fix safe issues (replaces hardcoded secrets with env var references)
agentshield scan --fix

# JSON output for CI pipelines
agentshield scan --format json

# Generate an HTML security report
agentshield scan --format html > report.html

# Three-agent Opus 4.6 adversarial analysis (requires ANTHROPIC_API_KEY)
agentshield scan --opus --stream

# Generate a secure baseline config
agentshield init
```

JSON reports now expose `findings[].runtimeConfidence` when AgentShield can distinguish active runtime config from project-local settings, template/example inventories, declarative plugin manifests, and manifest-resolved non-shell hook implementations.

## What It Catches

**102 rules** across 5 categories, graded A–F with a 0–100 numeric score.

### Secrets Detection (10 rules, 14 patterns)

| What | Examples |
|------|----------|
| API keys | Anthropic (`sk-ant-`), OpenAI (`sk-proj-`), AWS (`AKIA`), Google (`AIza`), Stripe (`sk_test_`/`sk_live_`) |
| Tokens | GitHub PATs (`ghp_`/`github_pat_`), Slack (`xox[bprs]-`), JWTs (`eyJ...`), Bearer tokens |
| Credentials | Hardcoded passwords, database connection strings (postgres/mongo/mysql/redis), private key material |
| Env leaks | Secrets passed through environment variables in configs, `echo $SECRET` in hooks |

### Permission Audit (10 rules)

| What | Examples |
|------|----------|
| Wildcard access | `Bash(*)`, `Write(*)`, `Edit(*)` — unrestricted tool permissions |
| Missing deny lists | No deny rules for `rm -rf`, `sudo`, `chmod 777` |
| Dangerous flags | `--dangerously-skip-permissions` usage |
| Mutable tool exposure | All mutable tools (Write, Edit, Bash) allowed without scoping |
| Destructive git | `git push --force`, `git reset --hard` in allowed commands |
| Unrestricted network | `curl *`, `wget`, `ssh *`, `scp *` in allow list without scope |

### Hook Analysis (34 rules)

| What | Examples |
|------|----------|
| Command injection | `${file}` interpolation in shell commands — attacker-controlled filenames become code |
| Data exfiltration | `curl -X POST` with variable interpolation sending data to external URLs |
| Silent errors | `2>/dev/null`, `\|\| true` — failing security hooks that silently pass |
| Missing hooks | No PreToolUse hooks, no Stop hooks for session-end validation |
| Network exposure | Unthrottled network requests in hooks, sensitive file access without filtering |
| Session startup | SessionStart hooks that download and execute remote scripts |
| Package installs | Global `npm install -g`, `pip install`, `gem install`, `cargo install` in hooks |
| Container escape | Docker `--privileged`, `--pid=host`, `--network=host`, root volume mounts |
| Credential access | macOS Keychain, GNOME Keyring, /etc/shadow reads |
| Reverse shells | `/dev/tcp`, `mkfifo + nc`, Python/Perl socket shells |
| Clipboard access | `pbcopy`, `xclip`, `xsel`, `wl-copy` — exfiltration via clipboard |
| Log tampering | `journalctl --vacuum`, `rm /var/log`, `history -c` — anti-forensics |

### MCP Server Security (23 rules)

| What | Examples |
|------|----------|
| High-risk servers | Shell/command MCPs, filesystem with root access, database MCPs, browser automation |
| Supply chain | `npx -y` auto-install without confirmation — typosquatting vector |
| Hardcoded secrets | API tokens in MCP environment config instead of env var references |
| Remote transport | MCP servers connecting to remote URLs (SSE/streamable HTTP) |
| Shell metacharacters | `&&`, `\|`, `;` in MCP server command arguments |
| Missing metadata | No version pin, no description, excessive server count |
| Sensitive file args | `.env`, `.pem`, `credentials.json` passed as server arguments |
| Network exposure | Binding to `0.0.0.0` instead of localhost |
| Auto-approve | `autoApprove` settings that skip user confirmation for tool calls |
| Missing timeouts | High-risk servers without timeout — resource exhaustion risk |

#### MCP Confidence Notes

AgentShield scans both active MCP config and repository-shipped MCP templates.

- Findings from `mcp.json`, `.claude/mcp.json`, `.claude.json`, and active `settings.json` should be treated as the highest-confidence runtime exposure.
- Findings from `settings.local.json` are emitted as `runtimeConfidence: project-local-optional`.
- Findings from locations such as `mcp-configs/`, `config/mcp/`, or `configs/mcp/` indicate risky MCP definitions present in repository templates, not guaranteed active runtime enablement.
- JSON, markdown, terminal, and HTML outputs now expose source context via `runtimeConfidence: active-runtime | project-local-optional | template-example | docs-example | plugin-manifest | hook-code`.
- Non-secret `template-example` MCP findings are score-weighted at `0.25x`, and one template file is capped at `10` deduction points per score category so a single MCP catalog cannot score like dozens of enabled servers.
- In template files, findings such as risky server type, remote URL transport, `npx -y`, unpinned packages, and environment inheritance are still valuable, but they should be interpreted as "this repo ships a risky MCP template" rather than "this MCP is definitely enabled right now."
- Aggregate findings like large MCP server counts are especially likely to overstate runtime exposure when the source file is a template catalog.

### Agent Config Review (25 rules)

| What | Examples |
|------|----------|
| Unrestricted tools | Agents with Bash access, no `allowedTools` restriction |
| Prompt injection surface | Agents processing external/user-provided content without defenses |
| Auto-run instructions | `CLAUDE.md` containing "Always run", "without asking", "automatically install" |
| Hidden instructions | Unicode zero-width characters, HTML comments, base64-encoded directives |
| URL execution | `CLAUDE.md` instructing agents to fetch and execute remote URLs |
| Time bombs | Delayed execution instructions triggered by time or absence conditions |
| Data harvesting | Bulk collection of passwords, credentials, or database dumps |
| Prompt reflection | `ignore previous instructions`, `you are now`, DAN jailbreak, fake system prompts |
| Output manipulation | `always report ok`, `remove warnings from output`, suppress security findings |

Structured JSON under `.claude/subagents/` and `.claude/slash-commands/` is analyzed like agent config when it declares `allowedTools` or similar tool metadata. Freeform `skill-md` prompt text still has narrower security coverage than `agent-md` and `CLAUDE.md`.

#### Scanner Accuracy Notes

- Live audit notes and follow-up items are tracked in [`false-positive-audit.md`](./false-positive-audit.md).
- The most useful operator guidance is in the audit's [`Triage Rules For Current Reports`](./false-positive-audit.md#triage-rules-for-current-reports) section.
- The audit doc also includes a reusable [`False-Positive Taxonomy`](./false-positive-audit.md#false-positive-taxonomy), [`Repo Audit Worksheet`](./false-positive-audit.md#repo-audit-worksheet), and [`Release Gate For Accuracy Changes`](./false-positive-audit.md#release-gate-for-accuracy-changes).
- Cross-file hook-manifest awareness now suppresses settings-only `hooks-no-pretooluse` when a companion `hooks/hooks.json` manifest defines PreToolUse hooks.
- Manifest-referenced hook implementations are now discovered from `hooks/hooks.json`-style indirection; shell targets continue through hook rules, and non-shell `hook-code` targets now emit targeted findings for explicit `output(...)` context injection, transcript input access, and remote shell payloads executed via child-process wrappers.
- Current known high-signal caveats are broader non-shell hook execution that still needs language-aware analysis beyond those current `hook-code` signals, and `skill-md` prompt text that still bypasses most agent/injection rules.
- `runtimeConfidence` now appears on MCP findings, `settings.local.json`, docs/examples, plugin manifests, and manifest-resolved non-shell hook code. Scoring discounts non-secret `template-example` and `docs-example` findings at `0.25x`, non-secret `project-local-optional` findings at `0.75x`, and non-secret `plugin-manifest` findings at `0.5x`. Non-secret `template-example` findings are also capped at `10` deduction points per file and score category so one catalog file cannot dominate the grade. `hook-code` findings currently stay at full weight, but the active rules there are narrow language-aware implementation signals.
- Practical reading rule: `template-example` means "repo ships this risky template", not "this is definitely enabled right now."
- Practical reading rule: `docs-example` means "repo ships risky sample guidance", not "this example is active runtime config."
- Practical reading rule: `plugin-manifest` means "the repo declares this hook behavior", while `hook-code` means "the scanner reached the referenced non-shell implementation."
- Current edge case: docs-only example trees now re-add the standalone `CLAUDE.md` example file for scanning, but still suppress the rest of the nested example subtree unless a runtime companion exists.
- Current edge case: tutorial/example bundles outside the current `docs/`, `commands/`, `examples/`, `samples/`, `demo/`, `tutorial/`, `guide/`, `cookbook/`, and `playground/` heuristics can still be treated as live config until broader example-root classification lands.
- Docs-only nested `CLAUDE.md` roots under `docs/` are now skipped unless runtime config companions exist in the same subtree.
- Exact `Bash(curl https://...)` and `Bash(wget https://...)` allow entries with pinned literal URLs no longer trigger the generic `permissions-permissive-*` finding; wildcard and dynamic network permissions still do.
- Exact `Bash(node scripts/foo.js ...)` and `Bash(python3 ./tools/audit.py ...)` wrapper commands no longer trigger the generic interpreter-access finding; inline eval forms such as `node -e` and `python -c` still do.
- Exact read-only Docker inventory commands such as `Bash(docker ps)` and `Bash(docker image ls)` no longer trigger the generic Docker-access finding; execution-oriented forms such as `docker run` and `docker exec` still do.
- Exact `settings.local.json` allowlists now downgrade `permissions-no-deny-list` from high to medium when every allow entry is fully specified; wildcard or dynamic project-local permissions still keep the higher severity.
- Exact local-only `settings.local.json` allowlists now also downgrade `hooks-no-pretooluse` from medium to low; broader or network-capable project-local configs still keep the higher severity.
- Comment-only shell-hook lines are now ignored by the hook exfiltration, sensitive-path, and silent-fail regex rules, so inline remediation notes and commented examples no longer look like live hook behavior.
- Narrow specialist agents, subagents, and slash commands now downgrade generic Bash-access and escalation-chain findings from high to medium; broader generalist workflows still keep the higher severity.
- Repo-scoped filesystem MCP servers using relative paths like `./` now grade lower than unrestricted root/home filesystem access; root-level filesystem exposure still stays high.
- Defensive agent-review content that mentions patterns like ``fetch(userProvidedUrl)`` no longer triggers `agents-injection-surface`; direct instructions to fetch/process external content still do.
- `agents-explorer-write` now uses role metadata and the lead agent intro instead of any later workflow/example text, so procedural `search for ...` steps in normal worker prompts no longer get mislabeled as explorer-style agents. Example: `chief-of-staff.md` no longer trips that rule just because it contains `gog gmail search ...`.
- `agents-oversized-prompt` now measures effective prompt size instead of raw file length, discounting fenced code blocks and Markdown tables. Example-heavy agents like `chief-of-staff.md` and `planner.md` no longer trip the rule, while prose-heavy agents still do.
- Markdown example/test passwords in example-like paths such as `docs/`, `commands/`, `examples/`, `tutorials/`, and `demos/` are now suppressed when the surrounding context is clearly instructional; that suppression does not apply to normal agent/config markdown.

#### False-Positive Audit Workflow

Use this workflow when a repo scan looks noisy or when you are tuning AgentShield rules.

1. Start with JSON output so you can inspect file paths, `runtimeConfidence`, and score impact directly.
2. Separate active runtime findings from lower-confidence source kinds before changing any rules.
3. Validate suspected false positives against at least one real repo and one minimal synthetic fixture.
4. Prefer source-aware reclassification and wording changes before adding blanket suppression.
5. Keep real secrets and explicit execution paths visible even inside examples, manifests, or templates.
6. Re-run targeted tests, then the full gate, before changing release behavior.

Recommended commands:

```bash
agentshield scan --path /repo --format json > report.json

jq '.findings | group_by(.runtimeConfidence // "none") | map({
  runtimeConfidence: (.[0].runtimeConfidence // "none"),
  count: length
})' report.json

jq '.findings | group_by(.file) | map({
  file: .[0].file,
  count: length
}) | sort_by(-.count)[:20]' report.json
```

Confidence-first triage commands:

```bash
# Highest-signal findings first: active runtime + project-local
jq '.findings
  | map(select((.runtimeConfidence // "active-runtime") | IN("active-runtime","project-local-optional")))
  | map(select(.severity | IN("critical","high","medium")))
  | map({file, severity, runtimeConfidence, title})' report.json

# Lower-confidence inventory that usually needs interpretation, not suppression
jq '.findings
  | map(select((.runtimeConfidence // "") | IN("template-example","docs-example","plugin-manifest")))
  | map({file, severity, runtimeConfidence, title})' report.json
```

Recommended audit order:
- `active-runtime` and `project-local-optional`: treat as highest-signal findings first.
- `template-example` and `docs-example`: confirm whether the repo is shipping risky guidance versus actually enabling it.
- `plugin-manifest`: confirm whether the risk is in declarative hook wiring or the referenced implementation.
- `hook-code`: confirm whether the implementation actually injects context, reads transcripts, or shells out in a risky way.

Rule-design guidelines:
- Prefer source-aware labeling over suppression. If a finding is real but lower confidence, keep it visible and say why.
- Prefer cross-file context over single-file guesses. Companion manifests and referenced hook implementations usually matter more than isolated config.
- Prefer narrow, behavior-based `hook-code` rules over generic wrapper heuristics. `spawnSync("bash", ["-lc", "curl ... | bash"])` is high-signal; ordinary `spawnSync("prettier", ...)` is not.
- Do not downgrade real secrets just because they appear in docs or examples. Structural findings can be downgraded; committed credentials should stay critical.
- Keep example-root heuristics evidence-based. Today the scanner treats `docs/`, `commands/`, `examples/`, `example/`, `samples/`, `sample/`, `demo/`, `demos/`, `tutorial/`, `tutorials/`, `guide/`, `guides/`, `cookbook/`, and `playground/` as example-like paths.

When you change rule accuracy, update both:
- [`false-positive-audit.md`](./false-positive-audit.md) with the new baseline and remaining gaps
- the targeted regression tests for the specific rule family you changed
- if you are filing a scanner-noise bug, start from the audit doc's [`False-Positive Issue Template`](./false-positive-audit.md#false-positive-issue-template)

#### Reducing False Positives In Practice

The current scan profile is not dominated by broken matchers. It is mostly dominated by lower-confidence source kinds that need different interpretation.

Current patterns from the latest live scans:
- template MCP inventory is still the biggest noise source by count in `everything-claude-code`
- example/tutorial config needs example-aware wording and weighting, not blanket suppression
- declarative hook manifests and executable hook implementations need different handling
- many remaining agent findings are policy findings about intentionally privileged agents, not obvious rule bugs
- the latest alert review reduced specialist agent-capability severity inflation, repo-scoped filesystem MCP inflation, and template-catalog score inflation; remaining noise is now mostly template count/interpretation and active-runtime remote MCP URLs

Recurring pattern signatures to recognize:
- one template file dominating the report usually means confidence/weighting work, not a broken matcher
- broad `agents-*` clusters across files with explicit tool metadata usually mean policy review, not false-positive suppression
- very small `project-local-optional` clusters usually mean scope is already modeled and only severity may need tuning
- a repo-scoped filesystem MCP with relative-path args should not be treated like root/home filesystem access

When to open a false-positive issue instead of just triaging the report:
- the same finding pattern reproduces across at least one real repo and one minimal synthetic fixture
- the finding is wrong for its own source kind, not just lower-confidence than `active-runtime`
- the fix needs matcher changes, not just better wording, score weighting, or cross-file context
- the finding would still be misleading even after reading `runtimeConfidence`

Recommended operating model:
- Start with `runtimeConfidence` before changing any rule. Separate `active-runtime` from `template-example`, `docs-example`, `plugin-manifest`, and `project-local-optional`.
- Reclassify before suppressing. If the finding is real but lower confidence, keep it visible and adjust wording or score weight instead of hiding it.
- Keep secrets on a stricter standard. Real credentials should stay critical even in docs, examples, or manifests.
- Use cross-file context whenever possible. Settings, manifests, and referenced hook implementations usually need to be read together.
- For `hook-code`, add only narrow language-aware rules for explicit risky behavior. Avoid broad wrapper heuristics.
- For agent rules, anchor on role metadata and lead instructions before matching arbitrary later prose.

Repo conventions that help AgentShield scan accurately:
- put reusable MCP catalogs under template paths such as `mcp-configs/` instead of live runtime config files
- keep local-only overrides in `settings.local.json`
- keep tutorials and examples under example-like paths such as `docs/`, `examples/`, `tutorials/`, `demos/`, or `guides/`
- keep `hooks/hooks.json` declarative and put the implementation in separate hook script files
- keep large agent examples inside fenced code blocks so prompt-size and role heuristics stay accurate

Current high-value places to audit first:
- files with the highest finding count
- files with `runtimeConfidence: template-example`
- `settings.local.json` findings that may be project-local rather than repo-wide
- `plugin-manifest` findings that need confirmation in the referenced implementation
- `hook-code` findings that involve context injection, transcript access, or child-process execution

## Features

### Auto-Fix Engine (`--fix`)

Automatically applies safe fixes:
- Replaces hardcoded secrets with `${ENV_VAR}` references
- Tightens wildcard permissions (`Bash(*)` → scoped `Bash(git *)`, `Bash(npm *)`)

Only fixes marked `auto: true` are applied. Permission changes require human review.

### Secure Init (`agentshield init`)

Generates a hardened `.claude/` directory with scoped permissions, safety hooks, and security best practices. Existing files are never overwritten.

### Opus 4.6 Deep Analysis (`--opus`)

Three-agent adversarial pipeline powered by Claude Opus 4.6:

1. **Red Team (Attacker)** — finds exploitable attack vectors and multi-step chains
2. **Blue Team (Defender)** — evaluates existing protections and recommends hardening
3. **Auditor** — synthesizes both perspectives into a prioritized risk assessment

The Attacker finds that `curl` hooks with `${file}` interpolation + `Bash(*)` = command injection pivot. The Defender notes no PreToolUse hooks exist to stop it. The Auditor chains them into a prioritized action list.

```bash
agentshield scan --opus              # Red + Blue run in parallel
agentshield scan --opus --stream     # Sequential with real-time output
agentshield scan --opus --stream -v  # Verbose — see full agent reasoning
```

```
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  Phase 1a: ATTACKER (Red Team)                       ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

  ✓ Attacker analysis complete (4521 tokens)

  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  Phase 1b: DEFENDER (Blue Team)                      ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

  ✓ Defender analysis complete (3892 tokens)

  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  Phase 2: AUDITOR                                    ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

  Risk Level: CRITICAL
  Opus Score: █████░░░░░░░░░░░░░░░ 15/100
```

Requires `ANTHROPIC_API_KEY` environment variable.

### Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Terminal | `--format terminal` (default) | Interactive use |
| JSON | `--format json` | CI pipelines, programmatic access |
| Markdown | `--format markdown` | Documentation, PRs |
| HTML | `--format html` | Self-contained shareable report (dark theme, all CSS inlined) |

### JSON Report Shape

`agentshield scan --format json` is the supported machine-readable scanner interface today.

```json
{
  "timestamp": "2026-03-13T19:42:00.000Z",
  "targetPath": "/repo/.claude",
  "score": {
    "grade": "C",
    "numericScore": 66,
    "breakdown": {
      "secrets": 100,
      "permissions": 70,
      "hooks": 80,
      "mcp": 35,
      "agents": 45
    }
  },
  "summary": {
    "totalFindings": 29,
    "critical": 1,
    "high": 7,
    "medium": 8,
    "low": 10,
    "info": 3,
    "filesScanned": 17,
    "autoFixable": 2
  },
  "findings": [
    {
      "id": "mcp-risky-filesystem",
      "severity": "medium",
      "category": "mcp",
      "title": "Template defines risky MCP server: filesystem",
      "description": "Repository template includes a high-risk filesystem MCP server.",
      "file": "mcp-configs/mcp-servers.json",
      "runtimeConfidence": "template-example"
    }
  ]
}
```

Notes:
- `runtimeConfidence` is emitted for active runtime config, `settings.local.json`, docs/examples, plugin manifests, and manifest-resolved non-shell hook code.
- `active-runtime` means active config such as `mcp.json`, `.claude/mcp.json`, `.claude.json`, or active `settings.json`.
- `project-local-optional` means project-local settings such as `settings.local.json`.
- `template-example` means template/catalog files such as `mcp-configs/` or `config/mcp/`.
- `docs-example` means docs/tutorial/example content such as `docs/guide/settings.json` or `commands/*.md`.
- `plugin-manifest` means declarative hook manifests such as `hooks/hooks.json`.
- `hook-code` means a manifest-resolved non-shell implementation such as `scripts/hooks/session-start.js`.
- Score weighting discounts non-secret `template-example` and `docs-example` findings to `0.25x`, non-secret `project-local-optional` findings to `0.75x`, and non-secret `plugin-manifest` findings to `0.5x`; committed secrets still count at full weight. Non-secret `template-example` findings are also capped at `10` deduction points per file and score category. See [`false-positive-audit.md`](./false-positive-audit.md).

## API Reference

AgentShield currently has three distinct automation surfaces:

- CLI: `agentshield scan`, `agentshield init`, and `agentshield miniclaw start`
- Scanner report JSON: `agentshield scan --format json`
- MiniClaw package + HTTP API: `ecc-agentshield/miniclaw`

Important packaging note:
- The npm package root export currently points at the CLI entrypoint, not a semver-stable scanner library module.
- Internal scanner modules such as `src/scanner/index.ts` and `src/reporter/score.ts` are useful for contributors, but they should not be documented as supported `import` paths for package consumers yet.
- If you need automation around scanner results today, prefer the JSON report format over importing scanner internals from the package root.

Detailed request/response and schema notes live in [`API.md`](./API.md).

## GitHub Action

```yaml
- name: AgentShield Security Scan
  uses: affaan-m/agentshield@v1
  with:
    path: "."
    min-severity: "medium"
    fail-on-findings: "true"
```

**Inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to scan |
| `min-severity` | `medium` | Minimum severity: critical, high, medium, low, info |
| `fail-on-findings` | `true` | Fail the action if findings meet severity threshold |
| `format` | `terminal` | Output format |

**Outputs:** `score` (0–100), `grade` (A–F), `total-findings`, `critical-count`

The action writes a markdown job summary and emits GitHub annotations inline on affected files.

## CLI Reference

```
agentshield scan [options]         Scan configuration directory
  -p, --path <path>                Path to scan (default: ~/.claude or cwd)
  -f, --format <format>            Output: terminal, json, markdown, html
  --fix                            Auto-apply safe fixes
  --opus                           Enable Opus 4.6 multi-agent analysis
  --stream                         Stream Opus analysis in real-time
  --injection                      Run active prompt injection testing
  --sandbox                        Execute hooks in a sandbox and observe behavior
  --taint                          Run taint analysis (data flow tracking)
  --deep                           Run injection + sandbox + taint + opus together
  --log <path>                     Write structured scan logs to a file
  --log-format <format>            Log format: ndjson or json
  --corpus                         Run built-in attack corpus validation
  --min-severity <severity>        Filter: critical, high, medium, low, info
  -v, --verbose                    Show detailed output

agentshield init                   Generate secure baseline config
```

Exit codes:
- `0`: scan completed without critical findings
- `1`: CLI usage or runtime error
- `2`: scan completed and found at least one critical issue

## Security Rules Summary

| Category | Rules | Patterns | Severity Range |
|----------|-------|----------|----------------|
| Secrets | 10 | 14 | Critical -- Medium |
| Permissions | 10 | -- | Critical -- Medium |
| Hooks | 34 | -- | Critical -- Low |
| MCP Servers | 23 | -- | Critical -- Info |
| Agents | 25 | -- | Critical -- Info |
| **Total** | **102** | **14** | |

## Architecture

```
src/
├── index.ts              CLI entry point (commander)
├── action.ts             GitHub Action entry point
├── types.ts              Type system + Zod schemas
├── scanner/
│   ├── discovery.ts      Config file discovery
│   └── index.ts          Scan orchestrator
├── rules/
│   ├── index.ts          Rule registry
│   ├── secrets.ts        Secret detection (10 rules, 14 patterns)
│   ├── permissions.ts    Permission audit (10 rules)
│   ├── mcp.ts            MCP server security (23 rules)
│   ├── hooks.ts          Hook analysis (34 rules)
│   └── agents.ts         Agent config review (25 rules)
├── reporter/
│   ├── score.ts          Scoring engine (A-F grades)
│   ├── terminal.ts       Color terminal output
│   ├── json.ts           JSON + Markdown output
│   └── html.ts           Self-contained HTML report
├── fixer/
│   ├── transforms.ts     Fix transforms (secret, permission, generic)
│   └── index.ts          Fix engine orchestrator
├── init/
│   └── index.ts          Secure config generator
└── opus/
    ├── prompts.ts        Attacker/Defender/Auditor system prompts
    ├── pipeline.ts       Three-agent Opus 4.6 pipeline
    └── render.ts         Opus analysis rendering
```

## MiniClaw

MiniClaw is a minimal, sandboxed AI agent runtime bundled with AgentShield. Where typical agent platforms expose many attack surfaces (Telegram, Discord, email, community plugins), MiniClaw presents a **single HTTP endpoint** backed by an **isolated sandbox**.

```bash
# Start with secure defaults (localhost:3847, no network, safe tools only)
npx ecc-agentshield miniclaw start

# Custom configuration
npx ecc-agentshield miniclaw start --port 4000 --network localhost --rate-limit 20
```

Or use as a library:

```typescript
import { startMiniClaw } from 'ecc-agentshield/miniclaw';

const { server, stop } = startMiniClaw();
// Listening on http://localhost:3847
```

MiniClaw-specific package exports and HTTP endpoints are documented in [`src/miniclaw/README.md`](./src/miniclaw/README.md) and summarized in [`API.md`](./API.md). The React dashboard source lives in [`src/miniclaw/dashboard.tsx`](./src/miniclaw/dashboard.tsx), but it is not yet published as a separate npm subpath.

### Security Model

Four independently enforced layers:

```
Request → [Rate Limit] → [CORS] → [Size Cap] → [Sanitize Prompt]
                                                       ↓
                                                 [Tool Whitelist]
                                                       ↓
                                                   [Sandbox FS]
                                                       ↓
                                                 [Filter Output] → Response
```

- **Server** — Rate limiting (10 req/min/IP), CORS, 10KB request cap, localhost-only binding
- **Prompt Router** — Strips 12+ injection pattern categories (system prompt overrides, identity reassignment, jailbreaks, data exfiltration URLs, zero-width Unicode, base64 payloads)
- **Tool Whitelist** — Three tiers: Safe (read/search/list), Guarded (write/edit), Restricted (bash/network — disabled by default)
- **Sandbox** — Isolated filesystem per session, path traversal blocked, symlink escape detection, extension whitelist, 10MB file cap, 5-min timeout, no network by default

### HTTP API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/prompt` | Send a prompt |
| `POST` | `/api/session` | Create a sandboxed session |
| `GET` | `/api/session` | Session info |
| `DELETE` | `/api/session/:id` | Destroy session + cleanup |
| `GET` | `/api/events/:sessionId` | Security audit events |
| `GET` | `/api/health` | Health check |

MiniClaw has **zero external runtime dependencies** — Node.js built-ins only (`http`, `fs`, `path`, `crypto`). The optional React dashboard requires React 18+ as a peer dependency.
## Development

```bash
npm install          # Install dependencies
npm run dev          # Development mode
npm test             # Run tests
npm run test:coverage # Coverage report
npm run typecheck    # Type check
npm run build        # Build
npm run scan:demo    # Demo scan against vulnerable examples
```

## Distribution

AgentShield is available through multiple channels:

| Channel | Use Case | Install |
|---------|----------|---------|
| **Standalone CLI** | Direct scanning from your terminal | `npm install -g ecc-agentshield` or `npx ecc-agentshield scan` |
| **GitHub Action** | Automated security checks on PRs in CI/CD | `uses: affaan-m/agentshield@v1` |
| **ECC Plugin** | Claude Code users via the ECC skill ecosystem | Install through [Everything Claude Code](https://github.com/affaan-m/everything-claude-code) |
| **ECC Tools GitHub App** | Integrated scanning across your GitHub org | Install at [github.com/apps/ecc-tools](https://github.com/apps/ecc-tools) |
| **ECC Tools Pro** | GitHub App with automated repo analysis, Stripe billing ($19/seat/mo) | [Install](https://github.com/apps/ecc-tools) |
## License

MIT

---

<div align="center">

Built by [@affaanmustafa](https://x.com/affaanmustafa) · Part of [Everything Claude Code](https://github.com/affaan-m/everything-claude-code)

</div>
