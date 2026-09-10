# AgentShield v1.6.0

The release that modernizes the scanner. Every open issue closed, every open pull request landed or superseded, current Claude Code, Codex CLI, Hermes, Cursor, Gemini, Copilot, OpenCode, Cline, and Roo layouts understood, and defenses credited instead of penalized.

## Scoring no longer penalizes defenses

- Deny and ask rules that block a dangerous flag are info findings labeled good practice (#102, #103).
- PreToolUse guard scripts that grep for mkfs, dd, rm -rf, or pipe-to-shell in order to deny them are reported as guard patterns at info severity, across 21 hook rules, failing closed when the quoted text reaches a shell sink (#113).
- Printed or commented flags are mentions, not usages (#100, #104).
- Reports list recognized defenses across every supported harness. They never deduct and never add points.

## Permission analysis sees the broad grants

- Bash(sudo:*), Bash(rm:*), Bash(bash:*), and path-spelled interpreters are normalized and flagged (#115).
- A prefix rule that shadows a narrower flagged entry is reported, and the env, network, and destructive git rules also name the covering rule (#116).

## Modernized to current agent ecosystems

- New discovery and rule modules for Claude Code 2026 settings, hooks, plugins, skills, and subagents; Codex CLI config.toml, agent roles, and hooks; Hermes profiles; Cursor, Gemini, Copilot, OpenCode, Cline, and Roo; remote MCP with OAuth, stdio bridges, and cross-harness auto-approval. 268 rule ids in total.
- LLM analysis on claude-opus-5 and claude-sonnet-5, with an opt-in OrcaRouter provider (#121).
- docs/BENCHMARK.md: where AgentShield stands against thirteen comparable scanners and the plan to close the gaps.

## Fixed

- Slash commands typed command-md and scanned for injection instead of skill hygiene (#117), comment-injection scoped per comment (#119), sandbox stage parses the standard hooks schema (#120), dangling skill symlinks no longer crash scans (#114), Windows path normalization plus a Windows CI job (#125), explicit bearer placeholders (#124).

## Added

- --rule-pack external rule packs (#107, closes #101), verify-after-fix with rollback and attestation (#108), --compliance control mapping (#109), opt-in Pro footer (#105), README FAQ (#97), OpenFGA design note (#106).

## Validation

- typecheck, lint, build, corpus gate; 2403 tests across 82 files on macOS, Linux (Node 20 and 22), and Windows (Node 22).

## Upgrade Notes

- Configs that scored A on 1.5.0 may score lower because of the new rules; each finding names the construct and the fix.
- Move action pins from @v1.5.0 to @v1.6.0. The floating v1 tag points at this release.

Full changelog: https://github.com/affaan-m/agentshield/blob/v1.6.0/CHANGELOG.md
