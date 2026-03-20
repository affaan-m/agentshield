---
name: ecc-bundle-component-addition
description: Workflow command scaffold for ecc-bundle-component-addition in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /ecc-bundle-component-addition

Use this workflow when working on **ecc-bundle-component-addition** in `agentshield`.

## Goal

Adds or updates a component of the agentshield ECC bundle, such as commands, skills, rules, team configs, research playbooks, or agent configs.

## Common Files

- `.claude/commands/*.md`
- `.claude/skills/agentshield/SKILL.md`
- `.claude/rules/*.md`
- `.claude/team/agentshield-team-config.json`
- `.claude/research/*.md`
- `.claude/enterprise/controls.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create or update a file in one of the ECC bundle directories (e.g., .claude/commands/, .claude/skills/, .claude/rules/, .claude/team/, .claude/research/, .codex/agents/, .agents/skills/agentshield/).
- Commit the file with a message in the format: 'feat: add agentshield ECC bundle (<file path>)'.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.