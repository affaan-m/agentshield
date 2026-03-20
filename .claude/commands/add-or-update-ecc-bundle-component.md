---
name: add-or-update-ecc-bundle-component
description: Workflow command scaffold for add-or-update-ecc-bundle-component in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-or-update-ecc-bundle-component

Use this workflow when working on **add-or-update-ecc-bundle-component** in `agentshield`.

## Goal

Adds or updates a component in the agentshield ECC bundle, such as configuration files, skills, rules, team configs, or tools.

## Common Files

- `.claude/commands/add-or-update-codex-agent-config.md`
- `.claude/commands/add-or-update-ecc-bundle-component.md`
- `.claude/commands/feature-development.md`
- `.claude/commands/feature-development-workflow.md`
- `.claude/commands/add-or-update-command-workflow.md`
- `.claude/commands/add-or-update-team-config.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create or update a relevant markdown or json file under .claude/commands/, .claude/team/, .claude/research/, .claude/rules/, .claude/skills/, .claude/enterprise/, .claude/ecc-tools.json, or .agents/skills/agentshield/
- Commit the change with a message referencing the ECC bundle and the specific file

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.