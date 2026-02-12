# AgentShield

Security auditor for AI agent configurations. Scans Claude Code setups for vulnerabilities, misconfigs, and injection risks.

The AI agent ecosystem is growing fast — but security isn't keeping pace. 12% of one major agent marketplace contains malicious skills. A CVSS 8.8 CVE affected 17,500+ internet-facing instances. Developers install community skills, connect MCP servers, and configure hooks without any automated way to audit the security of their setup.

AgentShield scans your `.claude/` directory and agent configuration files to detect vulnerabilities before they become exploits. It also includes **MiniClaw** — a minimal, sandboxed AI agent runtime that demonstrates what a secure-by-default agent looks like.

Built at the [Claude Code Hackathon](https://cerebralvalley.ai/e/claude-code-hackathon) (Cerebral Valley x Anthropic, Feb 2026).

## Quick Start

```bash
# Scan your Claude Code config (no install required)
npx ecc-agentshield scan

# Or install globally
npm install -g ecc-agentshield
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

# Launch MiniClaw secure agent server
npx ecc-agentshield miniclaw start
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

1. **Red Team (Attacker)** — finds exploitable attack vectors and multi-step attack chains
2. **Blue Team (Defender)** — recommends concrete hardening measures with exact config changes
3. **Auditor** — synthesizes both perspectives into a final risk assessment with a numeric score

In non-streaming mode, Red Team and Blue Team run in **parallel** via `Promise.all` for speed. In streaming mode (`--stream`), agents run sequentially with real-time token output — live spinners show progress, verbose mode (`-v`) streams every token to stdout.

```bash
# Run with Opus analysis
agentshield scan --opus

# Stream Opus analysis in real-time
agentshield scan --opus --stream

# Verbose streaming (see full agent reasoning)
agentshield scan --opus --stream -v
```

Requires `ANTHROPIC_API_KEY` environment variable.

### MiniClaw — Secure Agent Runtime

A minimal, sandboxed AI agent that demonstrates secure-by-default design. Single HTTP endpoint, isolated filesystem, whitelist-based tool authorization, prompt injection filtering. See the [MiniClaw section](#miniclaw) below for full documentation.

```typescript
import { startMiniClaw } from 'ecc-agentshield/miniclaw';

const { server, stop } = startMiniClaw();
// Listening on http://localhost:3847
```

### GitHub Action

Add AgentShield to your CI pipeline:

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
- Agents with unnecessary Bash access or write permissions
- Prompt injection surface in agent definitions that process external content
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
| HTML | `--format html` | Shareable self-contained report |

### HTML Report (`--format html`)

Generates a single self-contained HTML file with all CSS inlined — no external dependencies. Dark theme inspired by GitHub dark mode. Includes grade badge, score breakdown bars, categorized findings with severity indicators, and auto-fix status.

```bash
agentshield scan --format html > report.html
open report.html
```

## CLI Reference

```
agentshield scan [options]         Scan a configuration directory
  -p, --path <path>                Path to scan (default: ~/.claude or cwd)
  -f, --format <format>            Output: terminal, json, markdown, html
  --fix                            Auto-apply safe fixes
  --opus                           Enable Opus 4.6 multi-agent analysis
  --stream                         Stream Opus analysis in real-time
  --min-severity <severity>        Filter: critical, high, medium, low, info
  -v, --verbose                    Show detailed output

agentshield init [options]         Generate secure baseline config

agentshield miniclaw start [opts]  Launch MiniClaw secure agent server
  -p, --port <port>                Port to listen on (default: 3847)
  -H, --hostname <hostname>        Hostname to bind to (default: localhost)
  --network <policy>               Network policy: none, localhost, allowlist
  --rate-limit <limit>             Max requests per minute per IP (default: 10)
  --sandbox-root <path>            Root path for sandboxes
  --max-duration <ms>              Max session duration in ms (default: 300000)
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
│   ├── hooks.ts          Hook security analysis (4 rules)
│   └── agents.ts         Agent config review (3 rules)
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

## Security Rules

| Category | Rules | Severity Range |
|----------|-------|----------------|
| Secrets | 2 (11 patterns) | Critical - High |
| Permissions | 3 | Critical - Medium |
| MCP Servers | 4 | Critical - Info |
| Hooks | 4 | Critical - Medium |
| Agents | 3 | High - Info |
| **Total** | **16** | |

## MiniClaw

MiniClaw is a minimal, secure, sandboxed AI agent runtime — the antithesis of multi-channel orchestration platforms. Where platforms like OpenClaw expose many attack surfaces (Telegram, Discord, email, community plugins), MiniClaw presents a **single HTTP endpoint** backed by an **isolated sandbox**.

**Design mantra**: Minimal attack surface, maximum security, simple to deploy.

| Principle | Typical Agent Platform | MiniClaw |
|-----------|----------------------|----------|
| Access points | Many (Telegram, X, Discord, email) | One (single HTTP endpoint) |
| Execution | Host machine, broad access | Containerized, sandboxed |
| Skills | Unvetted community marketplace | Manually audited, local only |
| Network exposure | Multiple ports, services | Minimal, single entry point |
| Blast radius | Everything agent can access | Sandboxed to session directory |

### Quick Start (CLI)

Launch MiniClaw with a single command — no code required:

```bash
# Start with secure defaults (localhost:3847, no network, safe tools only)
npx ecc-agentshield miniclaw start

# Custom port and network policy
npx ecc-agentshield miniclaw start --port 4000 --network localhost

# Full configuration
npx ecc-agentshield miniclaw start \
  --port 4000 \
  --hostname 127.0.0.1 \
  --network localhost \
  --rate-limit 20 \
  --sandbox-root /tmp/my-sandboxes \
  --max-duration 600000
```

### Quick Start (Library)

Use MiniClaw programmatically in your Node.js application:

```typescript
import { startMiniClaw } from 'ecc-agentshield/miniclaw';

// Start with secure defaults (localhost:3847, no network, safe tools only)
const { server, stop } = startMiniClaw();

// Or customize configuration
const { server, stop } = startMiniClaw({
  sandbox: { networkPolicy: 'localhost' },
  server: { port: 4000, rateLimit: 20 },
});

// Embed in an existing app (no HTTP server)
import { createMiniClawSession, routePrompt } from 'ecc-agentshield/miniclaw';
const session = await createMiniClawSession();
const response = await routePrompt({ sessionId: session.id, prompt: 'Read index.ts' }, session);
```

### Security Model

**Defense in depth** — four independently enforced layers:

```
  Request → [Rate Limit] → [CORS] → [Size Cap] → [Sanitize Prompt]
                                                        ↓
                                                  [Tool Whitelist]
                                                        ↓
                                                    [Sandbox FS]
                                                        ↓
                                                  [Filter Output] → Response
```

1. **Server Layer** — Rate limiting (10 req/min per IP), CORS restriction to configured origins, request size cap (10KB), security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store`), localhost-only binding by default.

2. **Prompt Router** — Strips 12+ injection pattern categories before processing:
   - System prompt override attempts ("ignore previous instructions")
   - Identity reassignment ("you are now DAN")
   - Jailbreak and roleplay attacks
   - Direct tool invocation syntax
   - Data exfiltration URLs and encoded payloads
   - Zero-width Unicode hidden instructions
   - Base64-encoded command injection
   - Output filtering removes any leaked system prompt content from responses.

3. **Tool Whitelist** — Three-tier authorization (fail-closed for unknown tools):

   | Tier | Tools | Behavior |
   |------|-------|----------|
   | **Safe** | read, search, list | Auto-approved, sandbox-scoped |
   | **Guarded** | write, edit, glob | Requires session-level opt-in |
   | **Restricted** | bash, network, external API | Disabled by default, explicit config required |

4. **Sandbox** — Isolated filesystem per session:
   - Unique directory per session under configurable root
   - Path traversal (`../`) blocked at validation layer
   - Symlink escape detection (resolves real paths before access)
   - Allowed file extensions whitelist (no `.sh`, `.exe`, `.bat`)
   - 10MB max file size (prevents resource exhaustion)
   - 5-minute session timeout (prevents runaway processes)
   - No network access by default (prevents data exfiltration)

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/prompt` | Send a prompt, receive a response |
| `POST` | `/api/session` | Create a new sandboxed session |
| `GET` | `/api/session` | Get current session info |
| `DELETE` | `/api/session/:id` | Destroy session and cleanup sandbox |
| `GET` | `/api/events/:sessionId` | Retrieve security audit events |
| `GET` | `/api/health` | Health check |

**Example: Create a session and send a prompt**

```bash
# Create a session
curl -X POST http://localhost:3847/api/session

# Send a prompt (use the sessionId from the response above)
curl -X POST http://localhost:3847/api/prompt \
  -H "Content-Type: application/json" \
  -d '{"sessionId": "SESSION_ID", "prompt": "Read the file src/index.ts"}'

# Check security events
curl http://localhost:3847/api/events/SESSION_ID

# Destroy session when done
curl -X DELETE http://localhost:3847/api/session/SESSION_ID
```

### Dashboard

MiniClaw includes a React dashboard component for interactive use:

```tsx
import { MiniClawDashboard } from 'ecc-agentshield/miniclaw/dashboard';

<MiniClawDashboard endpoint="http://localhost:3847" />
```

Features: dark theme, prompt input, streaming response display, session status indicator, security events panel, tool whitelist categorized by risk level. Requires React 18+ as a peer dependency.

### Configuration Defaults

All defaults follow the principle of **maximum security posture** — users relax them as needed, never the reverse.

```typescript
// Sandbox defaults
{
  rootPath: '/tmp/miniclaw-sandboxes',
  maxFileSize: 10_485_760,          // 10MB
  allowedExtensions: ['.ts', '.tsx', '.js', '.jsx', '.json', '.md', '.txt',
                      '.css', '.html', '.yaml', '.yml', '.toml', '.xml',
                      '.csv', '.svg', '.env.example'],
  networkPolicy: 'none',            // No network access — no exfiltration possible
  maxDuration: 300_000,             // 5 minutes
}

// Server defaults
{
  port: 3847,
  hostname: 'localhost',            // Never 0.0.0.0 by default
  corsOrigins: ['http://localhost:3847', 'http://localhost:3000'],
  rateLimit: 10,                    // 10 req/min per IP
  maxRequestSize: 10_240,           // 10KB — plenty for a prompt
}
```

### Architecture

```
src/miniclaw/
├── types.ts          Core type system (all readonly, all immutable)
├── sandbox.ts        Sandbox lifecycle, path validation, symlink detection
├── router.ts         Prompt sanitization (12+ injection patterns) + output filtering
├── tools.ts          Tool registry, whitelist creation, call validation + scoping
├── server.ts         HTTP server (native Node.js http, no frameworks)
├── dashboard.tsx     React dashboard component
└── index.ts          Entry point, re-exports, startMiniClaw() convenience function
```

MiniClaw has **zero external runtime dependencies** — it uses only Node.js built-in modules (`http`, `fs`, `path`, `crypto`). The dashboard requires React 18+ as a peer dependency.

## Development

```bash
# Install dependencies
npm install

# Development mode
npm run dev scan --path examples/vulnerable

# Run tests (342 tests)
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
