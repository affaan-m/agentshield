---
name: add-new-security-rule
description: Workflow command scaffold for add-new-security-rule in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-new-security-rule

Use this workflow when working on **add-new-security-rule** in `agentshield`.

## Goal

Adds a new security rule to the scanning engine, including implementation, tests, and documentation/statistics updates.

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

- Implement new rule logic in appropriate src/rules/*.ts file (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts).
- Add or update corresponding test in tests/rules/*.test.ts.
- Update README.md to reflect new rule count and details.
- Optionally update CLAUDE.md and/or scripts/record-demo.sh with new examples or documentation.
- Update dist/ files if applicable (for CLI/GitHub Action builds).

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.