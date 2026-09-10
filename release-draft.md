# AgentShield v1.5.0

Fixes the GitHub Action startup failure shipped in 1.4.0, closes the `.mcp.json` discovery gap, and adds evidence-pack, policy-pack, and supply-chain surfaces.

## Fixed

- The GitHub Action now bundles its runtime dependencies. Every `v1.4.0` action run failed before scanning with `ERR_MODULE_NOT_FOUND: zod` (#118).
- Project-root `.mcp.json` is discovered and fed to the 23 MCP rules. Repos whose only Claude artifact was `.mcp.json` previously scanned as grade A with zero files (#123, closes #112 and #122).
- Docs and example MCP configs are labeled as examples; real hardcoded secrets in them keep critical severity.

## Added

- Evidence packs with integrity manifests, remediation plans, CI context, fleet summaries, review items, approval IDs, and operator readback.
- Policy packs: enterprise exceptions, action policy gate, SARIF policy violations, presets, `policy export`, and `policy promote` with SHA-256 manifest verification.
- Supply chain: npm manifest scanning, provenance reporting, action supply-chain gate, package-manager hardening drift, npx shell execution detection in MCP servers.
- Threat intel: Mini Shai-Hulud IOCs, `gh-token-monitor` persistence, AI developer-tool persistence IOCs, workflow secrets serialization, expanded enterprise token detection and redaction.
- SARIF code scanning output, executive HTML summary, corpus accuracy gate, baseline write CLI and drift outputs, harness adapter registry (Claude Code, Zed, VS Code), `runtime status`, and the `prompt-defense-posture` rule.

## Changed

- Action runtime is Node.js 24. Workflow actions are SHA pinned and CI installs use `--ignore-scripts`.
- Build config moved to `tsup.config.ts` with separate library and action targets.

## Validation

- `npm run typecheck`, `npm run lint`, `npm test` (1841 tests), `npm run build`, `npm run corpus:gate`
- `dist/action.js` executed from a directory with no `node_modules`

## Upgrade Notes

- Move action pins from `@v1.4.0` to `@v1.5.0`. The floating `v1` tag points at this release.

Full changelog: https://github.com/affaan-m/agentshield/blob/v1.5.0/CHANGELOG.md
