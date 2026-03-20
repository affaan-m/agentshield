---
name: add-or-update-ecc-bundle-component
description: Workflow command scaffold for add-or-update-ecc-bundle-component in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-or-update-ecc-bundle-component

Use this workflow when working on **add-or-update-ecc-bundle-component** in `agentshield`.

## Goal

Adds or updates a component of the agentshield ECC bundle, such as commands, rules, skills, team config, or research playbooks.

## Common Files

- `.claude/commands/*.md`
- `.claude/rules/*.md`
- `.claude/skills/agentshield/SKILL.md`
- `.claude/team/agentshield-team-config.json`
- `.claude/research/agentshield-research-playbook.md`
- `.claude/enterprise/controls.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create or update a markdown or JSON file in the relevant .claude or .codex subdirectory (e.g., .claude/commands/, .claude/rules/, .claude/skills/, .claude/team/, .claude/research/).
- Commit the file with a message referencing the ECC bundle and the specific component.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.