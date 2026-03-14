# MiniClaw Subpath API and Architecture

This file documents the MiniClaw runtime specifically. Scanner report JSON and package-surface notes for AgentShield live in the repo-level [`README.md`](../../README.md) and [`API.md`](../../API.md).

## Overview

MiniClaw is a lightweight, secure, sandboxed AI agent — the antithesis of multi-channel orchestration platforms like OpenClaw. Where OpenClaw exposes many attack surfaces (Telegram, Discord, email, community plugins), MiniClaw presents a single HTTP endpoint backed by an isolated filesystem sandbox with scoped tools and network policy.

**Design mantra**: Minimal attack surface, maximum security, simple to deploy.

## Philosophy

| Principle | OpenClaw | MiniClaw |
|-----------|----------|----------|
| Access points | Many (Telegram, X, Discord, email) | One (single HTTP endpoint) |
| Execution | Host machine, broad access | Sandboxed session, scoped filesystem + tools |
| Skills | Unvetted community marketplace | Manually audited, local only |
| Network exposure | Multiple ports, services | Minimal, single entry point |
| Blast radius | Everything agent can access | Sandboxed to project directory |
| Interface | Complex dashboard | Clean, simple prompt UI |

## Component Diagram

```
                    +-------------------+
                    |   Dashboard UI    |
                    | (React Component) |
                    +--------+----------+
                             |
                        HTTP POST /api/prompt
                             |
                    +--------v----------+
                    |   HTTP Server     |
                    | (Rate Limited,    |
                    |  CORS Restricted, |
                    |  Size Limited)    |
                    +--------+----------+
                             |
                    +--------v----------+
                    |  Prompt Router    |
                    | (Input Sanitize,  |
                    |  Output Filter)   |
                    +--------+----------+
                             |
              +--------------+--------------+
              |                             |
     +--------v----------+      +-----------v--------+
     |  Tool Whitelist    |      |  Sandbox Manager   |
     | (Validate, Scope)  |      | (Isolated FS,      |
     +--------+-----------+      |  Path Validation)  |
              |                  +--------------------+
              |
     +--------v----------+
     |  Tool Executor     |
     | (Scoped to sandbox)|
     +--------------------+
```

## Security Model

### Input Sanitization
- All prompts pass through `sanitizePrompt()` before processing
- Known prompt injection patterns are stripped:
  - System prompt override attempts ("ignore previous instructions")
  - Hidden instructions via zero-width Unicode characters
  - Base64-encoded command injection
  - Direct tool invocation syntax
- Sanitization is logged as SecurityEvents for audit

### Output Filtering
- Responses pass through `filterResponse()` before returning to client
- System prompt content is detected and redacted
- Internal error details are replaced with safe messages
- Stack traces are never exposed to clients

### Tool Restrictions
- Three risk levels: `safe`, `guarded`, `restricted`
- Safe tools (Read, Search) work within sandbox scope only
- Guarded tools (Edit, Write) require explicit session configuration
- Restricted tools (Bash, Network) are disabled by default and require opt-in
- Every tool call is path-validated against the sandbox root before execution

### No Shell Access by Default
- Bash/shell execution is in the `restricted` tier
- Even when enabled, commands are scoped and time-limited
- No access to host system paths outside sandbox

## Package API

Stable import surface:

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

High-value exports:
- `startMiniClaw(config?)` starts the built-in HTTP server with secure defaults
- `createMiniClawSession(config?)` creates a sandbox session for embedding
- `routePrompt(request, session)` sanitizes and executes a prompt against an existing session
- `createSafeWhitelist()`, `createGuardedWhitelist()`, and `createCustomWhitelist()` define tool policies
- `createMiniClawServer(config)` exposes the lower-level server factory

Core exported types include `PromptRequest`, `PromptResponse`, `MiniClawSession`, `MiniClawConfig`, `SandboxConfig`, and `SecurityEvent`.

## HTTP API

Single HTTP server with one prompt-processing endpoint and a small session/control surface:

### `POST /api/prompt`
Primary endpoint. Accepts a prompt and returns a response.
```json
// Request
{
  "sessionId": "uuid",
  "prompt": "Read the file src/index.ts",
  "context": { "key": "optional metadata" }
}

// Response
{
  "sessionId": "uuid",
  "response": "File contents: ...",
  "toolCalls": [{ "tool": "read", "args": { "path": "src/index.ts" }, "result": "..." }],
  "duration": 1234,
  "tokenUsage": { "input": 100, "output": 200 }
}
```

### `POST /api/session`
Creates a new sandboxed session.

Example response:
```json
{
  "sessionId": "uuid",
  "createdAt": "2026-03-13T19:42:00.000Z",
  "allowedTools": ["read", "search", "list"],
  "maxDuration": 300000
}
```

### `GET /api/session`
Returns the current active session list.

Example response:
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

### `DELETE /api/session/:id`
Destroys a session and cleans up its sandbox.

### `GET /api/events/:sessionId`
Returns the security event log for a session.

### `GET /api/health`
Returns a basic health payload:

```json
{
  "status": "ok",
  "sessions": 1
}
```

### Error format

Errors are returned as JSON:

```json
{
  "error": "Session \"uuid\" not found"
}
```

## Sandbox Architecture

### Isolated Filesystem Scope
- Each session gets a unique directory under a configurable root
- All file operations are resolved and validated against the sandbox root
- Symlinks that escape the sandbox are rejected
- Path traversal (`../`) is detected and blocked

### No Network by Default
- `networkPolicy: 'none'` is the default
- Optional `localhost` mode allows local service communication
- `allowlist` mode permits specific whitelisted hosts only

### Resource Limits
- Maximum file size (default: 10MB) prevents resource exhaustion
- Maximum session duration (default: 5 minutes) prevents runaway processes
- Maximum request size (10KB) prevents payload attacks

### Cleanup
- Sessions are destroyed on explicit DELETE or timeout
- Sandbox directories are recursively removed on cleanup
- No session data persists after cleanup

## Dashboard UI Specification

The dashboard source lives in `src/miniclaw/dashboard.tsx` and can be vendored into a React application.

It is not currently exported as a separate npm subpath such as `ecc-agentshield/miniclaw/dashboard`.

### Features
- Dark theme, minimal aesthetic
- Prompt input with submit button
- Streaming response display area (placeholder for SSE/WebSocket upgrade)
- Session status indicator (active / idle / error)
- Security events panel (blocked injections, denied tools)
- Tool whitelist display (categorized by risk level)

### Usage
```tsx
import { MiniClawDashboard } from "./MiniClawDashboard";

<MiniClawDashboard endpoint="http://localhost:3847" />
```

### Peer Dependencies
- React 18+ (not bundled, must be provided by consumer)
- No other external dependencies

## Directory Structure

```
src/miniclaw/
  README.md        # This file
  types.ts         # Core type system
  sandbox.ts       # Sandbox lifecycle and path validation
  router.ts        # Prompt sanitization and routing
  tools.ts         # Tool whitelist and scoped execution
  server.ts        # HTTP server with rate limiting
  dashboard.tsx    # React dashboard component
  index.ts         # Entry point and re-exports
```
