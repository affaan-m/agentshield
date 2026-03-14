# AgentShield API Reference

This document separates the currently supported automation surfaces from internal contributor modules.

## Support Levels

### Stable for users

- CLI: `agentshield scan`, `agentshield init`, `agentshield miniclaw start`
- Scanner JSON output: `agentshield scan --format json`
- MiniClaw package API: `ecc-agentshield/miniclaw`
- MiniClaw HTTP API: `/api/*` endpoints exposed by `startMiniClaw()`

### Internal for contributors

- `src/scanner/index.ts`
- `src/reporter/score.ts`
- `src/reporter/index.ts`
- `src/rules/*`

These source modules are useful inside the repository, but the npm package root export currently points to the CLI entrypoint. Treat them as implementation details unless the package exports change.

## Contributor Scanner Modules

These are the source-level entrypoints contributors use inside this repository today.

They are documented here for extension work and tests, not as stable npm import paths.

### `src/scanner/index.ts`

```ts
interface ScanResult {
  target: ScanTarget;
  findings: Finding[];
}

function scan(targetPath: string): ScanResult;
function discoverConfigFiles(targetPath: string): ScanTarget;
```

- `discoverConfigFiles()` finds Claude/AgentShield-relevant files under a target path
- `scan()` runs built-in rules against the discovered files and returns sorted findings

### `src/reporter/score.ts`

```ts
function calculateScore(result: ScanResult): SecurityReport;
```

- wraps findings with timestamp, summary counts, and numeric/category scoring

### `src/reporter/index.ts`

```ts
function renderTerminalReport(report: SecurityReport): string;
function renderJsonReport(report: SecurityReport): string;
function renderMarkdownReport(report: SecurityReport): string;
function renderHtmlReport(report: SecurityReport): string;
```

- reporters consume a `SecurityReport`
- `renderJsonReport()` returns formatted JSON text
- `renderMarkdownReport()` and `renderHtmlReport()` also expose `runtimeConfidence` when present on findings

## CLI API

Primary commands:

```bash
agentshield scan [options]
agentshield init
agentshield miniclaw start [options]
```

High-value `scan` options:
- `--format terminal|json|markdown|html`
- `--fix`
- `--opus`
- `--stream`
- `--injection`
- `--sandbox`
- `--taint`
- `--deep`
- `--corpus`
- `--min-severity critical|high|medium|low|info`
- `--log <path>`
- `--log-format ndjson|json`

Exit codes:
- `0`: scan completed without critical findings
- `1`: CLI usage error or runtime failure
- `2`: scan completed and at least one critical finding was reported

Structured scan logs:

```ts
interface ScanLogEntry {
  timestamp: string;
  level: "info" | "warn" | "error" | "debug";
  phase: string;
  message: string;
  data?: Record<string, unknown>;
}
```

## Scanner Report JSON

The supported machine-readable scanner contract today is the JSON report returned by:

```bash
agentshield scan --format json
```

Top-level shape:

```ts
interface SecurityReport {
  timestamp: string;
  targetPath: string;
  findings: Finding[];
  score: SecurityScore;
  summary: ReportSummary;
}
```

Finding shape:

```ts
interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category:
    | "secrets"
    | "permissions"
    | "hooks"
    | "mcp"
    | "agents"
    | "injection"
    | "exposure"
    | "exfiltration"
    | "misconfiguration";
  title: string;
  description: string;
  file: string;
  line?: number;
  evidence?: string;
  runtimeConfidence?:
    | "active-runtime"
    | "project-local-optional"
    | "template-example"
    | "docs-example"
    | "plugin-manifest"
    | "hook-code";
  fix?: {
    description: string;
    before: string;
    after: string;
    auto: boolean;
  };
}
```

### `runtimeConfidence`

`runtimeConfidence` is emitted when AgentShield can distinguish active runtime config from lower-confidence source kinds such as project-local settings, templates/examples, declarative manifests, and manifest-resolved non-shell hook implementations.

- `active-runtime`: active config such as `mcp.json`, `.claude/mcp.json`, `.claude.json`, or active `settings.json`
- `project-local-optional`: project-local files such as `settings.local.json`
- `template-example`: template or catalog files such as `mcp-configs/`, `config/mcp/`, or `configs/mcp/`
- `docs-example`: docs/tutorial/example config such as `docs/guide/settings.json` or `commands/*.md`
- `plugin-manifest`: declarative hook manifests such as `hooks/hooks.json`
- `hook-code`: manifest-resolved non-shell implementations such as `scripts/hooks/session-start.js`

Current caveat:
- report output now distinguishes example docs, plugin manifests, and non-shell hook implementations from active runtime findings
- scoring discounts non-secret `template-example` findings to `0.25x` and caps them at `10` deduction points per file and score category to reduce template-catalog inflation
- scoring discounts non-secret `docs-example` findings to `0.25x` to reduce example-config inflation
- scoring discounts non-secret `project-local-optional` findings to `0.75x` to reduce project-local score inflation
- scoring discounts non-secret `plugin-manifest` findings to `0.5x` to reduce declarative-manifest inflation
- `hook-code` findings currently keep full weight, but the active rules there are still narrow language-aware implementation signals
- committed real secrets still count at full weight even inside template files
- docs-only example trees now re-add the standalone `CLAUDE.md` example file for scanning, while the rest of the nested subtree stays suppressed unless a runtime companion exists
- example bundles outside the current `docs/`, `commands/`, `examples/`, `samples/`, `demo/`, `tutorial/`, `guide/`, `cookbook/`, and `playground/` path heuristics can still be treated as live config until broader example-root classification lands

Concrete examples:
- `docs-example`: `docs/guide/settings.json` or `docs/guide/CLAUDE.md` when that subtree has a runtime companion
- `plugin-manifest`: `hooks/hooks.json`
- `hook-code`: `scripts/hooks/session-start.js`

For the current false-positive and scoring follow-up queue, see [`false-positive-audit.md`](./false-positive-audit.md), especially [`Pattern Signatures In Recent Alerts`](./false-positive-audit.md#pattern-signatures-in-recent-alerts), [`Common Noisy File Archetypes`](./false-positive-audit.md#common-noisy-file-archetypes), and [`Triage Rules For Current Reports`](./false-positive-audit.md#triage-rules-for-current-reports).

## MiniClaw Package API

MiniClaw is the stable programmatic API exposed by this package today:

```ts
import {
  startMiniClaw,
  createMiniClawSession,
  routePrompt,
  createSafeWhitelist,
  createGuardedWhitelist,
  createCustomWhitelist,
  createMiniClawServer,
} from "ecc-agentshield/miniclaw";
```

High-value entrypoints:

- `startMiniClaw(config?)`: start the MiniClaw HTTP server with secure defaults
- `createMiniClawSession(config?)`: create an isolated sandbox session for embedding MiniClaw into an existing app
- `routePrompt(request, session)`: sanitize and process a prompt against a session
- `createSafeWhitelist()`, `createGuardedWhitelist()`, `createCustomWhitelist()`: build tool policy sets
- `createMiniClawServer(config)`: create a server handle without the convenience wrapper

Current packaging caveat:
- the React dashboard source exists at `src/miniclaw/dashboard.tsx`
- there is not yet a published `ecc-agentshield/miniclaw/dashboard` subpath export
- if you want the dashboard today, vendor the source component from the repository instead of importing a non-existent subpath

Core MiniClaw types are exported from `ecc-agentshield/miniclaw`, including:

- `PromptRequest`
- `PromptResponse`
- `MiniClawSession`
- `MiniClawConfig`
- `SandboxConfig`
- `SecurityEvent`

For the complete MiniClaw architecture notes, see [`src/miniclaw/README.md`](./src/miniclaw/README.md).

## MiniClaw HTTP API

Endpoints exposed by the built-in server:

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/session` | Create a new sandboxed session |
| `GET` | `/api/session` | List active sessions |
| `DELETE` | `/api/session/:id` | Destroy a session and clean up its sandbox |
| `POST` | `/api/prompt` | Submit a prompt for a session |
| `GET` | `/api/events/:sessionId` | Read security events for a session |
| `GET` | `/api/health` | Health check |

Create-session response:

```json
{
  "sessionId": "uuid",
  "createdAt": "2026-03-13T19:42:00.000Z",
  "allowedTools": ["read", "search", "list"],
  "maxDuration": 300000
}
```

List-sessions response:

```json
{
  "sessions": [
    {
      "id": "uuid",
      "createdAt": "2026-03-13T19:42:00.000Z",
      "allowedTools": ["read", "search", "list"],
      "maxDuration": 300000
    }
  ]
}
```

Prompt request:

```json
{
  "sessionId": "uuid",
  "prompt": "Read src/index.ts",
  "context": {
    "traceId": "optional"
  }
}
```

Prompt response:

```json
{
  "sessionId": "uuid",
  "response": "File contents: ...",
  "toolCalls": [
    {
      "tool": "read",
      "args": {
        "path": "src/index.ts"
      },
      "result": "...",
      "duration": 14
    }
  ],
  "duration": 1234,
  "tokenUsage": {
    "input": 100,
    "output": 200
  }
}
```

Error format:

```json
{
  "error": "Rate limit exceeded. Please try again later."
}
```

Additional responses:

```json
{
  "sessionId": "uuid",
  "events": [
    {
      "type": "prompt_injection_detected",
      "details": "Removed hidden instruction",
      "timestamp": "2026-03-13T19:42:01.000Z",
      "sessionId": "uuid"
    }
  ]
}
```

```json
{
  "status": "ok",
  "sessions": 1
}
```
