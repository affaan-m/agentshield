# AgentShield

Security auditor for AI agent configurations. Scans Claude Code setups for vulnerabilities, misconfigs, and injection risks.

The AI agent ecosystem is growing fast — but security isn't keeping pace. 12% of one major agent marketplace contains malicious skills. A CVSS 8.8 CVE affected 17,500+ internet-facing instances. Developers install community skills, connect MCP servers, and configure hooks without any automated way to audit the security of their setup.

AgentShield scans your `.claude/` directory and agent configuration files to detect vulnerabilities before they become exploits.

Built at the [Claude Code Hackathon](https://cerebralvalley.ai/e/claude-code-hackathon) (Cerebral Valley x Anthropic, Feb 2026).

## Quick Start

```bash
# Install
npm install -g agentshield

# Scan your Claude Code config
agentshield scan

# Scan a specific directory
agentshield scan --path /path/to/.claude

# Output as JSON
agentshield scan --format json

# Auto-fix safe issues
agentshield scan --fix
```

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

## CI Integration

AgentShield exits with code 2 when critical findings are detected, making it easy to integrate into CI pipelines:

```yaml
- name: Security audit
  run: npx agentshield scan --min-severity high
```

## Architecture

```
src/
├── index.ts              CLI entry point (commander)
├── types.ts              Type system (Finding, Rule, Report, Score)
├── scanner/
│   ├── discovery.ts      Config file discovery
│   └── index.ts          Main scan orchestrator
├── rules/
│   ├── index.ts          Rule registry
│   ├── secrets.ts        Secret detection (11 patterns)
│   ├── mcp.ts            MCP server security (4 rules)
│   ├── permissions.ts    Permission audit (3 rules)
│   ├── agents.ts         Agent config review
│   └── hooks.ts          Hook security analysis
└── reporter/
    ├── index.ts           Report orchestrator
    ├── terminal.ts        Color terminal output
    ├── json.ts            JSON + Markdown output
    └── score.ts           Security scoring (A-F grades)
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

# Type check
npm run typecheck

# Build
npm run build

# Run tests
npm test

# Demo scan (vulnerable examples)
npm run scan:demo
```

## License

MIT
