---
name: feature-or-rule-implementation-with-tests
description: Workflow command scaffold for feature-or-rule-implementation-with-tests in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /feature-or-rule-implementation-with-tests

Use this workflow when working on **feature-or-rule-implementation-with-tests** in `agentshield`.

## Goal

Implements a new feature or rule and adds or updates corresponding tests.

## Common Files

- `src/rules/*.ts`
- `tests/rules/*.test.ts`
- `src/skills/*.ts`
- `tests/skills/*.test.ts`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Implement or update rule/feature logic in src/rules/*.ts or similar source file.
- Add or update tests in tests/rules/*.test.ts or tests/skills/*.test.ts.
- Commit both implementation and tests together.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.