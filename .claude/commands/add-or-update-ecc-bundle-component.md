---
name: add-or-update-ecc-bundle-component
description: Workflow command scaffold for add-or-update-ecc-bundle-component in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-or-update-ecc-bundle-component

Use this workflow when working on **add-or-update-ecc-bundle-component** in `agentshield`.

## Goal

Adds or updates a component of the agentshield ECC bundle, such as commands, skills, or rules.

## Common Files

- `.claude/commands/add-or-update-ecc-bundle-component.md`
- `.claude/commands/feature-development.md`
- `.claude/commands/feature-development-workflow.md`
- `.claude/commands/add-or-update-feature-development-workflow.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Edit or add the relevant .claude/commands/*.md file (e.g., add-or-update-ecc-bundle-component.md, feature-development.md)
- Optionally, update related documentation or workflow files

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.