---
name: add-new-security-rule
description: Workflow command scaffold for add-new-security-rule in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-new-security-rule

Use this workflow when working on **add-new-security-rule** in `agentshield`.

## Goal

Adds one or more new security detection rules to the scanner (e.g., for agents, hooks, permissions, MCP, secrets), including implementation and associated tests.

## Common Files

- `src/rules/agents.ts`
- `src/rules/hooks.ts`
- `src/rules/mcp.ts`
- `src/rules/permissions.ts`
- `src/rules/secrets.ts`
- `tests/rules/agents.test.ts`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Implement new rule(s) in the appropriate src/rules/*.ts file(s) (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts)
- Update or create corresponding test(s) in tests/rules/*.test.ts
- Update README.md with new rule counts and descriptions
- Optionally update CLAUDE.md and/or scripts/record-demo.sh with new examples or demo material

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.