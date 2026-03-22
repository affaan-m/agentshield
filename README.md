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

[Quick Start](#quick-start) · [What It Catches](#what-it-catches) · [Opus Pipeline](#opus-46-deep-analysis---opus) · [GitHub Action](#github-action) · [Distribution](#distribution) · [Changelog](./CHANGELOG.md)

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
  --min-severity <severity>        Filter: critical, high, medium, low, info
  -v, --verbose                    Show detailed output

agentshield init                   Generate secure baseline config
```

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

## Development

```bash
npm install          # Install dependencies
npm run dev          # Development mode
npm test             # Run tests (1609 tests)
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
