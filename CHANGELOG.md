# Changelog

All notable changes to this project will be documented in this file.

## [1.6.0] - 2026-09-10

1.5.0 shipped six months of accumulated work, but it did not touch the thing people actually run into first: the scanner only understood the Claude Code layout of early 2026, it penalized the defenses it recommended, and it missed the broadest grants while flagging the narrow ones. 1.6.0 is the release that addresses that. It closes every issue that was open on the tracker, lands or supersedes every open pull request, moves the scanner to the September 2026 shape of Claude Code, Codex CLI, Hermes, Cursor, Gemini CLI, Copilot, OpenCode, Cline, and Roo, and adds a benchmark against the comparable scanners so the gaps are written down rather than guessed at.

### Scoring no longer penalizes defenses

- A permissions deny or ask rule that blocks a dangerous flag is an info finding labeled good practice, not a CRITICAL (#102, #103 by sky64).
- A PreToolUse guard script that greps for mkfs, dd, rm -rf, or a pipe to a shell in order to deny it is reported as a guard pattern at info severity. The new guard-context helper recognizes quoted arguments to grep, rg, awk, sed match forms, jq, case patterns, [[ =~ ]] tests, JSON deny lists, and deny-message echoes, and fails closed when the quoted text reaches a shell sink such as eval, exec, source, xargs, or a pipe to sh. Twenty-one hook rules use it (#113).
- A dangerous flag printed in help text or a comment is a mention, not a usage, as long as nothing on that line executes it (#100, #104).
- Reports now list recognized defenses: deny and ask lists, bypass disabled, sandbox settings, managed-only switches, blocking hooks, narrow skill and agent tool grants, Codex sandbox and approval policy, Hermes manual approvals, Gemini and OpenCode guards, Cursor fail-closed hooks. They are shown in terminal, markdown, JSON, and HTML output. They deduct nothing and add no points, so the score cannot be gamed by decorative deny rules, and the score engine has tests proving info findings never deduct.

### False negatives in permission analysis

- Allow entries are normalized before matching, so the colon prefix form and path-spelled commands are seen: Bash(sudo:*), Bash(rm:*), Bash(bash:*), and Bash(/opt/homebrew/bin/node -e *) now flag at the severity their space-form equivalents always had. Shell interpreters are critical, su and doas join sudo, and ruby, perl, php, deno, bun, podman, and socat join their groups (#115).
- A new permissions-shadowed-allow rule reports a prefix rule that already grants everything a narrower entry grants, and the env, network, and destructive git rules also report the covering prefix rule, so deleting the narrow entry alone no longer looks like an improvement (#116).

### Modernized to current agent ecosystems

- New config types and discovery for AGENTS.md and its relatives (GEMINI.md, copilot-instructions.md, .cursorrules, .windsurfrules, .clinerules, .cursor/rules, .github/agents and instructions, .roo/rules), Codex config.toml and .codex agent roles and hooks, Hermes config.yaml and profiles, Claude plugin manifests and marketplaces, Gemini and OpenCode settings, Cursor hooks, and the MCP configs of Cursor, Windsurf, Cline, and Roo. Instruction files for every harness get the same injection scanning as CLAUDE.md. Lenient TOML, YAML, JSONC, and frontmatter parsers fail closed.
- Claude Code 2026 rules (34): bypass and dontAsk default modes, helper commands that execute at session start, env overrides that redirect traffic or disable TLS, literal secrets in env, sandbox escape hatches and wildcard network allowlists, insecure marketplaces, login redirects, hook entries that auto-allow, rewrite permissions or input, or ship transcript data to HTTP endpoints, skill dynamic-context shell execution and broad allowed-tools, and subagent bypass modes, inline MCP servers, and unrestricted spawning.
- Codex CLI rules (17) and Hermes rules: danger-full-access, approval never, network without a proxy allowlist, broad writable roots, trusted home directories, project configs that escalate policy, MCP header secrets and plaintext URLs, bridged and unpinned servers, shell-executing notify commands, provider redirects, agent roles with full access; Hermes approvals off or smart, cron auto-approve, broad command allowlists, unattended local terminals, shell toolsets exposed to chat platforms, open DM gateways.
- Plugin, Gemini, OpenCode, Cursor, Copilot, and import rules (25): marketplace command sources, unpinned or insecure sources, path traversal, relative hook scripts, Gemini yolo mode and trusted servers, OpenCode allow-all permissions and auto share, Cursor hooks that auto-allow, Copilot agents with shell plus inline remote MCP, and CLAUDE.md or AGENTS.md imports that reach outside the repo or into secret files.
- Remote MCP rules (16): literal tokens in headers, tokens in URLs, plaintext http, ws, and sse transports, private and metadata address ranges, inline OAuth client secrets and wildcard scopes, insecure OAuth endpoints, headers helpers, mcp-remote and supergateway bridges with the real URL re-checked, shell and inline-code stdio commands, proxy and TLS env overrides, host secrets mirrored to third-party servers, auto-approve wildcards across harnesses, tool-description injection in cached tool lists, cross-server tool shadowing, and unpinned docker images.
- LLM analysis runs on current models: the Opus pipeline defaults to claude-opus-5 and the injection tester to claude-sonnet-5, with an opt-in OrcaRouter provider (#121 by JinhaoSong322) that never changes the default path.

### Fixed

- Slash commands are typed command-md, the two skill hygiene rules are gated to files named SKILL.md, and injection rules now run on commands; a hundred benign commands no longer zero the Agents subscore (#117).
- The suspicious-comment rule tests each HTML comment body in isolation with an imperative-shaped pattern, so a match can no longer span two comments (#119).
- The sandbox stage parses the standard nested hooks schema and warns when a settings file defines hooks but none parsed (#120).
- A dangling symlink under skills/ no longer crashes the scan; it becomes a low finding (#114).
- Discovered paths are normalized to forward slashes, chmod-dependent tests skip on Windows, the MiniClaw sandbox uses the platform separator, and a Windows CI job now runs the full suite (#125).
- Explicit YOUR_*_HERE bearer placeholders are not secrets (#124 by Ayo-Fam).

### Added

- agentshield scan --rule-pack loads external JSON rule packs alongside the built-ins, failing closed on bad JSON, schema violations, duplicate ids within or across packs, and uncompilable patterns (#107, closes #101).
- agentshield scan --fix re-scans after applying fixes and rolls back if the score regressed or a new high or critical finding appeared, printing a sha256 attestation on success (#108).
- agentshield scan --compliance maps findings to SOC 2, PCI DSS, and ISO 27001 controls (#109).
- An opt-in ECC Tools Pro footer, off by default, enabled with AGENTSHIELD_CTA=1 (#105).
- docs/BENCHMARK.md compares AgentShield with thirteen scanners and lists the prioritized gaps: live MCP tool enumeration, tool-definition fingerprints for rug pulls, cross-server shadowing, enterprise settings parity, a normalization pre-pass, OSV lookups, deeper skill bundles, and a public benchmark harness.
- docs/research/openfga-agent-authorization.md answers #106 with a design note; nothing ships in the scanner.
- README FAQ (#97 by meichuanyi).

### Changed

- vitest 4 and the test batches run through a glob-free Node runner so they work under cmd.exe. Node 20 is now the minimum supported runtime; vitest 4 does not start on Node 18, which reached end of life in April 2025.
- smol-toml is a new runtime dependency for Codex configs.

### Validation

- npm run typecheck, npm run lint, npm run build, npm run corpus:gate
- npm test: 2403 tests across 82 files, on macOS locally and on Linux (Node 20 and 22) and Windows (Node 22) in CI
- 268 rule ids across 14 modules

### Upgrade Notes

- Rule ids added in 1.6.0 mean a config that scored A on 1.5.0 can score lower; every new finding names the construct and the fix. Guard patterns, prohibitions, and mentions are info and never deduct.
- Action consumers on @v1.5.0 should move to @v1.6.0. The floating v1 tag points at this release.
- The dist/ bundle must be committed before tagging; the release workflow refuses to publish when it is out of sync.

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
