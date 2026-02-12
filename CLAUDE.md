# AgentShield

Security auditor for AI agent configurations (Claude Code, MCP servers, hooks, agents).

## Build & Test

```bash
npm run build      # tsc + tsup → dist/
npm test           # vitest (602 tests)
npm run dev        # tsx watch mode
```

## Architecture

```
src/
  index.ts          # CLI entry (commander)
  types.ts          # Core types + Zod schemas
  scanner/
    discovery.ts    # File discovery (CLAUDE.md, settings.json, mcp.json, agents/, etc.)
    index.ts        # Orchestrates discovery → rules → sorted findings
  rules/
    index.ts        # Barrel export of all rule modules
    secrets.ts      # 4 rules, 23 patterns — API keys, tokens, passwords, env exposure, CLAUDE.md secrets
    permissions.ts  # 7 rules — allow/deny analysis, dangerous flags, destructive git, mutable tools, sensitive paths, wildcard roots
    hooks.ts        # 16 rules — injection, exfiltration, background processes, error suppression, world-readable output, cron persistence, file deletion
    mcp.ts          # 13 rules — risky servers, env override, npx supply chain, url transport, root paths, shell wrappers, git deps
    agents.ts       # 10 rules — tool restrictions, prompt injection, unicode tricks, CLAUDE.md injection, escalation chain, model cost
  reporter/
    score.ts        # Scoring engine (severity deductions, grade A-F, category breakdown)
    terminal.ts     # Colored terminal output
    json.ts         # JSON + Markdown report formats
    index.ts        # Format dispatcher
  opus/
    prompts.ts      # System prompts for Attacker/Defender/Auditor
    pipeline.ts     # Opus 4.6 three-agent adversarial pipeline
    render.ts       # Opus analysis terminal + markdown rendering
    index.ts        # Pipeline entry point
  miniclaw/
    types.ts        # Core types (immutable, readonly)
    sandbox.ts      # Sandbox lifecycle + path validation
    router.ts       # Prompt sanitization + output filtering
    tools.ts        # Whitelist-based tool authorization
    server.ts       # HTTP server with rate limiting + CORS
    dashboard.tsx   # React dashboard component
    index.ts        # Entry point + startMiniClaw()
```

## Key Patterns

- **Rules**: Each rule module exports `ReadonlyArray<Rule>`. Each `Rule` has `check(file: ConfigFile): ReadonlyArray<Finding>`.
- **Immutability**: All arrays typed as `ReadonlyArray`, all interfaces use `readonly` fields.
- **No RegExp .prototype methods**: Use `String.matchAll()` via `findAllMatches()` helper to avoid security hook conflicts.
- **False positive prevention**: `parsePermissionLists()` JSON-parses settings to check only the allow array. Negation-aware context checking downgrades prohibitive mentions to `info`.

## Severity Scoring

| Severity | Deduction | Example |
|----------|-----------|---------|
| critical | -25 | Hardcoded API key, Bash(*) |
| high     | -15 | Shell MCP server, no deny list |
| medium   | -5  | Unrestricted curl, missing denials |
| low      | -2  | No model specified in agent |
| info     | 0   | Missing description, good practice |

Grades: A (>=90), B (>=75), C (>=60), D (>=40), F (<40)

## CLI

```bash
agentshield scan [path]              # Static analysis
agentshield scan --opus              # + Opus 4.6 adversarial pipeline
agentshield scan --format json|md    # Output format
agentshield scan --fix               # Show auto-fix suggestions
agentshield miniclaw start           # Launch MiniClaw secure agent server
agentshield miniclaw start --port N  # Custom port
```

## Testing

Tests in `tests/` mirror `src/` structure. Use `makeFinding()`, `makeSettings()`, etc. helper factories.
Run specific suite: `npx vitest run tests/rules/mcp.test.ts`

## Conventions

- TypeScript strict mode, ESM modules
- No mutation, no `any`, no `console.log` in src
- Zod for config validation at boundaries
- Conventional commits: feat/fix/test/refactor/docs
