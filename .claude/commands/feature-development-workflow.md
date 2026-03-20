---
name: feature-development-workflow
description: Workflow command scaffold for feature-development-workflow in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /feature-development-workflow

Use this workflow when working on **feature-development-workflow** in `agentshield`.

## Goal

Documents or implements feature development workflows, including test-driven development and feature implementation.

## Common Files

- `.claude/commands/feature-development.md`
- `.claude/commands/test-driven-development.md`
- `.claude/commands/feature-or-rule-implementation-with-tests.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create or update a markdown file in .claude/commands/ describing the feature development process.
- Optionally, create related files for test-driven development or feature/rule implementation.
- Commit the changes.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.