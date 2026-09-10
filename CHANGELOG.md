# Changelog

All notable changes to this project will be documented in this file.

## [1.5.0] - 2026-09-10

This release fixes the GitHub Action startup failure shipped in 1.4.0, closes the `.mcp.json` discovery gap, and adds the evidence-pack, policy-pack, and supply-chain surfaces that landed on `main` between March and September 2026.

### Fixed

- The GitHub Action now bundles its runtime dependencies into `dist/action.js`. Every `v1.4.0` action run failed before scanning with `ERR_MODULE_NOT_FOUND: zod` because the runner executes the checkout without `node_modules`. Library and CLI entries keep dependencies external (#118).
- Project-root `.mcp.json` is now discovered, typed as `mcp-json`, and counted as a Claude root, so the 23 MCP rules run against the standard project MCP config. Previously a repo whose only Claude artifact was `.mcp.json` scanned as grade A with zero files (#123, closes #112 and #122).
- MCP findings under strong documentation paths (`docs/`, `examples/`) are labeled as docs examples; placeholder secrets there are skipped while real hardcoded secrets keep critical severity. Packages merely named `demo` stay active runtime (#123).
- Defensive IOC entries in `permissions.deny` are no longer flagged as the attack they block.
- Context-rule false positives reduced; CLI `--version` now tracks the package version (#43).

### Added

- **Evidence packs**: `agentshield evidence-pack` output with an integrity manifest and verification (#67, #74, #75), remediation plan artifact and workflow phases, CI context (#86), fleet summaries and inspection (#88, #89), fleet review items, remediation review metadata, deterministic approval IDs and ticket external IDs, and fleet `operatorReadback` with promotion status, review digest, owner counts, and approval routes.
- **Policy packs**: enterprise policy exceptions with lifecycle audit (#54, #62), action policy gate (#55), policy violations in SARIF (#56), policy pack presets (#57), `agentshield policy export`, and `agentshield policy promote` which verifies exported manifests by SHA-256 digest, rejects tampered JSON, and supports dry-run and JSON review modes.
- **Supply chain**: npm manifest scanning, provenance reporting (#58), an action supply-chain gate (#85), package-manager hardening drift checks with action outputs and job-summary evidence, and detection of npx shell execution in MCP servers.
- **Threat intel**: Mini Shai-Hulud campaign IOC coverage across hooks, filenames, and evidence packs (#83, #84), `gh-token-monitor` token-store persistence detection, AI developer-tool persistence IOCs across Claude Code hooks, VS Code tasks, GitHub workflow drop-ins, LaunchAgents, and systemd units, workflow secrets serialization detection, and expanded enterprise token detection and redaction for OpenAI legacy, xAI, Linear, and labeled Cloudflare tokens (#68).
- **Reporting and CI**: SARIF code scanning output (#50), executive HTML report summary, corpus accuracy gate with regression benchmark and recommendations (#80), baseline write CLI (#64), baseline drift as an action output (#63), hashed baseline fingerprints, and action policy-promotion review outputs.
- **Harness adapters**: a harness adapter registry with Claude Code, Zed, and VS Code coverage.
- **Runtime**: `agentshield runtime status`, hardened runtime install recovery, and an honest MiniClaw fallback responder.
- **Rules**: `prompt-defense-posture` rule covering 12 missing-defense checks for `CLAUDE.md`, agent prompts, and `.claude/rules/*` (#45). Severity scoring and reporter output tightened (#42).
- ECC bundle for AgentShield (#49).

### Changed

- The GitHub Action runs on the Node.js 24 runtime ahead of the Node.js 20 runner deprecation.
- Workflow actions are pinned by SHA and CI installs run with `--ignore-scripts`.
- Build configuration moved from inline `tsup` flags to `tsup.config.ts` with separate library and action targets.

### Validation

- `npm run typecheck`
- `npm run lint`
- `npm test` (1841 tests across 68 files)
- `npm run build` and `git diff --exit-code -- dist action.yml`
- `npm run corpus:gate`
- `dist/action.js` executed from a directory with no `node_modules`

### Upgrade Notes

- Action consumers pinned to `@v1.4.0` should move to `@v1.5.0`. The floating `v1` tag now points at this release.
- The GitHub Action bundle under `dist/` must be committed before tagging a release.
- The release workflow verifies that the pushed tag matches `package.json`, reruns the full gate, rebuilds `dist/`, and refuses to publish if generated action artifacts are out of sync.

## [1.4.0] - 2026-03-20

This release focuses on scan accuracy, source-aware scoring, and safer interpretation of example and manifest-heavy repositories.

### Highlights

- Added first-class source confidence for `docs-example`, `plugin-manifest`, and `hook-code` findings alongside existing `template-example` and `project-local-optional` output.
- Downgraded structural findings from docs/example config and rewrote report wording so risky shipped examples no longer read like confirmed active runtime exposure.
- Extended example classification beyond `docs/` and `commands/` to `examples/`, `example/`, `samples/`, and `sample/`.
- Re-added standalone docs/example `CLAUDE.md` files to scanning so real secrets in example guidance are not silently missed.
- Improved hook analysis for manifest-resolved non-shell implementations, including explicit context injection, transcript access, and remote shell payloads executed via child-process wrappers.
- Tightened hook-manifest handling so declarative config is distinguished from executable hook implementations.
- Expanded structured agent coverage for `.claude/subagents/*.json` and `.claude/slash-commands/*.json`.
- Refined report scoring so template, project-local, docs/example, and plugin-manifest findings no longer inflate grades like active runtime exposure.

### Validation

- `npm run typecheck`
- `npm test`
- `npm run build`
- Live rescans of `everything-claude-code`, `PMX-backend`, and `basket-trader`

### Upgrade Notes

- The GitHub Action bundle under `dist/` must be committed before tagging a release.
- The release workflow verifies that the pushed tag matches `package.json`, reruns the full gate, rebuilds `dist/`, and refuses to publish if generated action artifacts are out of sync.
