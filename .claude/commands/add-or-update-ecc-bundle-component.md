---
name: add-or-update-ecc-bundle-component
description: Workflow command scaffold for add-or-update-ecc-bundle-component in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-or-update-ecc-bundle-component

Use this workflow when working on **add-or-update-ecc-bundle-component** in `agentshield`.

## Goal

Add or update a component of the agentshield ECC bundle, such as commands, team config, research playbooks, guardrails, or skills.

## Common Files

- `.claude/commands/*.md`
- `.claude/team/agentshield-team-config.json`
- `.claude/research/agentshield-research-playbook.md`
- `.claude/rules/agentshield-guardrails.md`
- `.claude/skills/agentshield/SKILL.md`
- `.agents/skills/agentshield/SKILL.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create or update the relevant markdown or JSON file in the appropriate .claude or .agents directory.
- Commit the file with a message indicating the addition or update of the ECC bundle component.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.