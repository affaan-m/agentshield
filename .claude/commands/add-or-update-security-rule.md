---
name: add-or-update-security-rule
description: Workflow command scaffold for add-or-update-security-rule in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-or-update-security-rule

Use this workflow when working on **add-or-update-security-rule** in `agentshield`.

## Goal

Adds or updates a security rule, typically for agent, hook, mcp, permission, or secret scanning.

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

- Edit or add rule implementation in src/rules/{area}.ts (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts)
- Add or update corresponding tests in tests/rules/{area}.test.ts
- Optionally update README.md to reflect new rule counts or document the rule
- Optionally update types in src/types.ts if new rule categories or types are added

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.