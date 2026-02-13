<div align="center">

# AgentShield

**Security auditor for AI agent configurations**

Scans Claude Code setups for hardcoded secrets, permission misconfigs,<br/>
hook injection, MCP server risks, and agent prompt injection vectors.

[![npm version](https://img.shields.io/npm/v/ecc-agentshield)](https://www.npmjs.com/package/ecc-agentshield)
[![npm downloads](https://img.shields.io/npm/dm/ecc-agentshield)](https://www.npmjs.com/package/ecc-agentshield)
[![tests](https://img.shields.io/badge/tests-520%20passed-brightgreen)]()
[![coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Quick Start](#quick-start) · [What It Catches](#what-it-catches) · [Opus Pipeline](#opus-46-deep-analysis---opus) · [GitHub Action](#github-action) · [MiniClaw](#miniclaw)

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

**48 rules** across 5 categories, graded A–F with a 0–100 numeric score.

### Secrets Detection (4 rules, 14 patterns)

| What | Examples |
|------|----------|
| API keys | Anthropic (`sk-ant-`), OpenAI (`sk-proj-`), AWS (`AKIA`), Google (`AIza`), Stripe (`sk_test_`/`sk_live_`) |
| Tokens | GitHub PATs (`ghp_`/`github_pat_`), Slack (`xox[bprs]-`), JWTs (`eyJ...`), Bearer tokens |
| Credentials | Hardcoded passwords, database connection strings (postgres/mongo/mysql/redis), private key material |
| Env leaks | Secrets passed through environment variables in configs, `echo $SECRET` in hooks |

### Permission Audit (5 rules)

| What | Examples |
|------|----------|
| Wildcard access | `Bash(*)`, `Write(*)`, `Edit(*)` — unrestricted tool permissions |
| Missing deny lists | No deny rules for `rm -rf`, `sudo`, `chmod 777` |
| Dangerous flags | `--dangerously-skip-permissions` usage |
| Mutable tool exposure | All mutable tools (Write, Edit, Bash) allowed without scoping |
| Destructive git | `git push --force`, `git reset --hard` in allowed commands |

### Hook Analysis (9 rules)

| What | Examples |
|------|----------|
| Command injection | `${file}` interpolation in shell commands — attacker-controlled filenames become code |
| Data exfiltration | `curl -X POST` with variable interpolation sending data to external URLs |
| Silent errors | `2>/dev/null`, `\|\| true` — failing security hooks that silently pass |
| Missing hooks | No PreToolUse hooks, no Stop hooks for session-end validation |
| Network exposure | Unthrottled network requests in hooks, sensitive file access without filtering |
| Session startup | SessionStart hooks that download and execute remote scripts |

### MCP Server Security (10 rules)

| What | Examples |
|------|----------|
| High-risk servers | Shell/command MCPs, filesystem with root access, database MCPs, browser automation |
| Supply chain | `npx -y` auto-install without confirmation — typosquatting vector |
| Hardcoded secrets | API tokens in MCP environment config instead of env var references |
| Remote transport | MCP servers connecting to remote URLs (SSE/streamable HTTP) |
| Shell metacharacters | `&&`, `\|`, `;` in MCP server command arguments |
| Missing metadata | No version pin, no description, excessive server count |

### Agent Config Review (7 rules)

| What | Examples |
|------|----------|
| Unrestricted tools | Agents with Bash access, no `allowedTools` restriction |
| Prompt injection surface | Agents processing external/user-provided content without defenses |
| Auto-run instructions | `CLAUDE.md` containing "Always run", "without asking", "automatically install" |
| Hidden instructions | Unicode zero-width characters, HTML comments, base64-encoded directives |
| URL execution | `CLAUDE.md` instructing agents to fetch and execute remote URLs |

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

agentshield miniclaw start [opts]  Launch MiniClaw secure agent server
  -p, --port <port>                Port (default: 3847)
  -H, --hostname <host>            Hostname (default: localhost)
  --network <policy>               Network: none, localhost, allowlist
  --rate-limit <n>                 Max req/min per IP (default: 10)
  --sandbox-root <path>            Root path for sandboxes
  --max-duration <ms>              Max session duration (default: 300000)
```

## Security Rules Summary

| Category | Rules | Patterns | Severity Range |
|----------|-------|----------|----------------|
| Secrets | 4 | 14 | Critical – High |
| Permissions | 5 | — | Critical – Medium |
| Hooks | 9 | — | Critical – Medium |
| MCP Servers | 10 | — | Critical – Info |
| Agents | 7 | — | High – Info |
| **Total** | **35** | **14** | |

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
│   ├── secrets.ts        Secret detection (14 patterns)
│   ├── permissions.ts    Permission audit (5 rules)
│   ├── mcp.ts            MCP server security (10 rules)
│   ├── hooks.ts          Hook analysis (9 rules)
│   └── agents.ts         Agent config review (7 rules)
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
├── opus/
│   ├── prompts.ts        Attacker/Defender/Auditor system prompts
│   ├── pipeline.ts       Three-agent Opus 4.6 pipeline
│   └── render.ts         Opus analysis rendering
└── miniclaw/
    ├── types.ts          Core type system (immutable, readonly)
    ├── sandbox.ts        Sandbox lifecycle + path validation
    ├── router.ts         Prompt sanitization + output filtering
    ├── tools.ts          Whitelist-based tool authorization
    ├── server.ts         HTTP server with rate limiting + CORS
    ├── dashboard.tsx     React dashboard component
    └── index.ts          Entry point and re-exports
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

### API

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
npm test             # Run tests (683 tests)
npm run test:coverage # Coverage report
npm run typecheck    # Type check
npm run build        # Build
npm run scan:demo    # Demo scan against vulnerable examples
```

## License

MIT

---

<div align="center">

Built by [@affaanmustafa](https://x.com/affaanmustafa) · Part of [Everything Claude Code](https://github.com/affaan-m/everything-claude-code)

</div>
