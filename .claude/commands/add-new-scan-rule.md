---
name: add-new-scan-rule
description: Workflow command scaffold for add-new-scan-rule in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-new-scan-rule

Use this workflow when working on **add-new-scan-rule** in `agentshield`.

## Goal

Adds a new security scan rule to the codebase, including implementation and corresponding tests.

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

- Implement new rule logic in src/rules/{category}.ts (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts)
- Add or update corresponding test cases in tests/rules/{category}.test.ts
- Update README.md with new rule counts or descriptions
- Optionally update CLAUDE.md or scripts/record-demo.sh with new examples or documentation

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.