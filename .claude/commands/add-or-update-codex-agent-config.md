---
name: add-or-update-codex-agent-config
description: Workflow command scaffold for add-or-update-codex-agent-config in agentshield.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-or-update-codex-agent-config

Use this workflow when working on **add-or-update-codex-agent-config** in `agentshield`.

## Goal

Add or update agent configuration files for Codex agents (docs-researcher, reviewer, explorer).

## Common Files

- `.codex/agents/docs-researcher.toml`
- `.codex/agents/reviewer.toml`
- `.codex/agents/explorer.toml`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create or update the relevant .toml file in the .codex/agents directory.
- Commit the file with a message indicating the addition or update.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.