---
name: add-or-update-team-config
description: Workflow command scaffold for add-or-update-team-config in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-or-update-team-config

Use this workflow when working on **add-or-update-team-config** in `agentshield`.

## Goal

Adds or updates the team configuration for agentshield, typically in JSON format.

## Common Files

- `.claude/team/agentshield-team-config.json`
- `.claude/commands/add-or-update-team-config.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create or update .claude/team/agentshield-team-config.json
- Optionally update .claude/commands/add-or-update-team-config.md
- Commit the changes

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.