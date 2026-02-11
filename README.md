# AgentShield

Security auditor for AI agent configurations. Scans Claude Code setups for vulnerabilities, misconfigs, and injection risks.

The AI agent ecosystem is growing fast — but security isn't keeping pace. 12% of one major agent marketplace contains malicious skills. A CVSS 8.8 CVE affected 17,500+ internet-facing instances. Developers install community skills, connect MCP servers, and configure hooks without any automated way to audit the security of their setup.

AgentShield scans your `.claude/` directory and agent configuration files to detect vulnerabilities before they become exploits.

Built at the [Claude Code Hackathon](https://cerebralvalley.ai/e/claude-code-hackathon) (Cerebral Valley x Anthropic, Feb 2026).

## Quick Start

```bash
# Scan your Claude Code config (no install required)
npx agentshield scan

# Or install globally
npm install -g agentshield
agentshield scan

# Scan a specific directory
agentshield scan --path /path/to/.claude

# Auto-fix safe issues
agentshield scan --fix

# Generate an HTML security report
agentshield scan --format html > report.html

# Run Opus 4.6 adversarial analysis with real-time streaming
agentshield scan --opus --stream

# Generate a secure baseline config
agentshield init
```

## Features

### Static Analysis (`agentshield scan`)

Rule-based scanning with 16 rules across 5 categories, graded A-F with a 0-100 numeric score.

### Auto-Fix Engine (`--fix`)

Automatically applies safe fixes for detected issues:
- Replaces hardcoded secrets with `${ENV_VAR}` references
- Tightens wildcard permissions (`Bash(*)` → scoped `Bash(git *)`, `Bash(npm *)`)
- Generic string-replacement transforms for other fixable patterns

Only `auto: true` fixes are applied. Files are never overwritten without a matching pattern.

### Secure Init (`agentshield init`)

Generates a hardened `.claude/` directory with:
- **settings.json** — scoped permissions (no `Bash(*)`) and safety hooks
- **CLAUDE.md** — security best practices for the AI agent
- **mcp.json** — empty MCP config placeholder

Existing files are never overwritten.

### Opus 4.6 Deep Analysis (`--opus`)

Three-agent adversarial pipeline powered by Claude Opus 4.6:

1. **Red Team (Attacker)** — finds exploitable attack vectors
2. **Blue Team (Defender)** — recommends concrete hardening measures
3. **Auditor** — synthesizes both perspectives into a final risk assessment

```bash
# Run with Opus analysis
agentshield scan --opus

# Stream Opus analysis in real-time
agentshield scan --opus --stream
```

Requires `ANTHROPIC_API_KEY` environment variable.

### GitHub Action

Add AgentShield to your CI pipeline:

```yaml
- name: AgentShield Security Scan
  uses: affaan-m/agentshield@main
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
| `fail-on-findings` | `true` | Fail the action if findings are detected |
| `format` | `terminal` | Output format |

**Outputs:**

| Output | Description |
|--------|-------------|
| `score` | Numeric security score (0-100) |
| `grade` | Letter grade (A-F) |
| `total-findings` | Total number of findings |
| `critical-count` | Number of critical findings |

The action writes a markdown job summary and emits GitHub annotations (warnings/errors) inline on affected files.

## What It Catches

### Secrets Detection
- Hardcoded API keys (Anthropic, OpenAI, AWS, GitHub, Slack)
- Exposed database connection strings
- Bearer tokens and private key material
- Environment variables echoed to terminal

### Permission Audit
- Overly permissive allow rules (`Bash(*)`, `Write(*)`)
- Missing deny lists for dangerous operations
- `--dangerously-skip-permissions` usage
- Contradictory allow/deny entries

### MCP Server Security
- High-risk servers (filesystem, shell, database, browser)
- Hardcoded secrets in MCP environment configs
- `npx -y` supply chain risks (auto-install without confirmation)
- Missing server descriptions

### Hook Analysis
- Command injection via variable interpolation (`${file}`)
- Data exfiltration through external HTTP requests
- Silent error suppression (`2>/dev/null`, `|| true`)
- Missing PreToolUse security hooks

### Agent Config Review
- Agents with unnecessary Bash access
- Auto-run instructions in CLAUDE.md (prompt injection vector)

## Example Output

```
  AgentShield Security Report
  2026-02-11

  Grade: F (0/100)

  Score Breakdown
  Secrets        ░░░░░░░░░░░░░░░░░░░░ 0
  Permissions    █████░░░░░░░░░░░░░░░ 23
  Hooks          ░░░░░░░░░░░░░░░░░░░░ 0
  MCP Servers    ██░░░░░░░░░░░░░░░░░░ 10
  Agents         ████████████████░░░░ 80

  Summary
  Files scanned: 4
  Findings: 35 total — 10 critical, 12 high, 8 medium, 1 low, 4 info
  Auto-fixable: 1 (use --fix)
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Terminal | `--format terminal` (default) | Interactive use, demos |
| JSON | `--format json` | CI pipelines, programmatic use |
| Markdown | `--format markdown` | Documentation, PRs |
| HTML | `--format html` | Self-contained dark-themed report |

## CLI Reference

```
agentshield scan [options]      Scan a configuration directory
  -p, --path <path>             Path to scan (default: ~/.claude or cwd)
  -f, --format <format>         Output: terminal, json, markdown, html
  --fix                         Auto-apply safe fixes
  --opus                        Enable Opus 4.6 multi-agent analysis
  --stream                      Stream Opus analysis in real-time
  --min-severity <severity>     Filter: critical, high, medium, low, info
  -v, --verbose                 Show detailed output

agentshield init [options]      Generate secure baseline config
```

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
│   ├── secrets.ts        Secret detection (11 patterns)
│   ├── permissions.ts    Permission audit (3 rules)
│   ├── mcp.ts            MCP server security (4 rules)
│   ├── hooks.ts          Hook security analysis
│   └── agents.ts         Agent config review
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

## Security Rules

| Category | Rules | Severity Range |
|----------|-------|----------------|
| Secrets | 2 (11 patterns) | Critical - High |
| Permissions | 3 | Critical - Medium |
| MCP Servers | 4 | Critical - Info |
| Hooks | 4 | Critical - Medium |
| Agents | 2 | High - Info |

## Development

```bash
# Install dependencies
npm install

# Development mode
npm run dev scan --path examples/vulnerable

# Run tests (202 tests)
npm test

# Run tests with coverage
npm run test:coverage

# Type check
npm run typecheck

# Build
npm run build

# Demo scan (vulnerable examples)
npm run scan:demo
```

## License

MIT
