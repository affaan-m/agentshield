# AgentShield v1.8.0

This release turns AgentShield from a point-in-time scanner into a release gate and runtime guardrail for Claude Code configurations.

## Highlights

- Added a built-in CVE database and MCP tool-poisoning detection for known-malicious or compromised packages.
- Added supply-chain verification for MCP npm packages, including typosquat checks and optional npm registry metadata lookup.
- Added watch mode for continuous config drift detection with debounce control, terminal alerts, webhook alerts, and CI-style blocking.
- Added runtime monitoring install/uninstall commands for PreToolUse policy enforcement inside live Claude Code sessions.
- Added baseline save/compare flows plus a PR-style security gate that fails on new high/critical findings or score regressions.
- Added organization-wide policy enforcement with `--policy` evaluation and `agentshield policy init`.
- Hardened the GitHub Action test workflow so local-action test jobs build the action bundle before executing it.

## Validation

- `npm run typecheck`
- `npm test`
- `npm run build`

## Upgrade Notes

- The pushed tag must match `package.json` exactly: `v1.8.0`.
- The release workflow rebuilds `dist/`, verifies `action.yml` and generated artifacts are committed, publishes to npm, and creates the GitHub release from this draft.
