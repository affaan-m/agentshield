---
name: add-or-update-command-workflow
description: Workflow command scaffold for add-or-update-command-workflow in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-or-update-command-workflow

Use this workflow when working on **add-or-update-command-workflow** in `agentshield`.

## Goal

Adds or updates a command workflow documentation for agentshield ECC bundle.

## Common Files

- `.claude/commands/*.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create or update a markdown file in .claude/commands/ with the workflow details.
- Commit the file with a message referencing the workflow.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.