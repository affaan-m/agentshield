# AgentShield benchmark: where we stand (2026-09-10)

Source: this repository at the 1.6.0 release train. Competitor data from the GitHub API and each project's README or docs, fetched 2026-09-10. Anything not read from source or a README is marked UNVERIFIED. Competitor data from the GitHub API and each project's README or docs, fetched today. Web search was unavailable; anything not read from source or README is marked UNVERIFIED.

## 1. AgentShield detection surface (from source, 1.6.0)

| Module (`src/rules/`) | Unique ids | Focus |
|---|---|---|
| agents.ts | 41 | subagent and instruction prompts: injection, exfil, persistence, obfuscation, tool escalation |
| hooks.ts | 40 | hook commands: reverse shells, cron, env exfil, credential access, IOCs, guard-pattern aware |
| claude-code.ts | 34 | Claude Code 2026 settings, hook entries, skills, subagent frontmatter |
| mcp.ts | 26 | MCP config hygiene: npx supply chain, transports, env, CORS, bind-all |
| harnesses.ts | 25 | plugin manifests, Gemini, OpenCode, Cursor hooks, Copilot agents, instruction imports |
| permissions.ts | 17 | normalized allow and deny analysis, shadowing, skip-permissions, sensitive paths |
| codex.ts | 17 | Codex CLI approval and sandbox policy, MCP tables, hooks, providers |
| mcp-remote.ts | 16 | remote MCP auth, OAuth, bridges, auto-approve wildcards, tool-description injection, shadowing |
| package-manager.ts | 15 | lifecycle scripts, release-age gates, registry credentials |
| prompt-defense.ts | 13 | missing defenses in CLAUDE.md, agent prompts, rules |
| secrets.ts | 10 | hardcoded keys, URL creds, private keys, webhooks |
| hermes.ts | 8 | Hermes approvals, allowlists, terminal backends, platform toolsets, gateways |
| mcp-tool-poisoning.ts | 5 | description poisoning, exfil URLs in env and args (config text only) |
| mcp-cve.ts | 2 | known vulnerable or malicious MCP packages |
| skills.ts | 2 | observation hooks, version rollback metadata (SKILL.md only) |
| **Total** | **268** | 15 modules |

File types (`ConfigFileType` in `src/types.ts`, discovery in `src/scanner/discovery.ts`): `claude-md`, `settings-json` (settings.json, settings.local.json, .vscode/tasks.json, .zed/*, LaunchAgents plist, CodeQL workflow), `mcp-json` (mcp.json, .mcp.json, .claude.json), `agent-md`, `skill-md`, `hook-script` (.sh/.bash/.zsh), `hook-code` (.js/.ts), `package-manager-config` (package.json, lockfiles, .npmrc, .yarnrc, pnpm-workspace), `rule-md`, `context-md`. Harness adapters: claude-code, codex, gemini, opencode, zed, vscode, dmux, generic-terminal, project-local-template.

CLI (`src/index.ts`): `scan`, `init`, `evidence-pack`, `inspect`, `fleet`, `verify`, `baseline write`, `watch`, `runtime install|uninstall|status|repair`, `policy init|export|promote`, `miniclaw start`. Formats: text, json, markdown, html, sarif. Extras: taint analyzer, injection tester, Opus pipeline, npm supply-chain verify (typosquat, postinstall, package age, maintainers, downloads, unpinned git).

GitHub Action (`action.yml`): 19 inputs, 32 outputs covering score/grade, sarif-path, baseline drift (7), policy (2), supply chain (4), package-manager hardening (7), evidence pack (3), policy promotion (5).

One structural fact drives the comparison: **AgentShield never connects to an MCP server.** 1.6.0 adds config-side tool-description injection and cross-server shadowing checks, but live tool lists are still out of scope. No `tools/list`, `listTools`, or MCP SDK usage exists in `src/` outside miniclaw. Poisoning rules run over config JSON, not live tool descriptions.

## 2. Comparable tools

| Tool | Stars | Last push | License | Mode | Scans |
|---|---|---|---|---|---|
| [snyk/agent-scan](https://github.com/snyk/agent-scan) (was invariantlabs mcp-scan; old repo redirects) | 3,029 | 2026-09-10 | Apache-2.0 | live MCP connect + cloud API (SNYK_TOKEN) | MCP tools/prompts/resources, skills, 12 harnesses |
| [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | 1,070 | 2026-09-08 | Apache-2.0 | live or offline JSON; YARA + LLM + Cisco API + tree-sitter | MCP servers, server source, PyPI deps |
| [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | 2,511 | 2026-09-05 | none stated | static + dataflow + LLM + CEL | skills only |
| [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) | 16,838 | 2026-09-10 | Apache-2.0 | static (71 patterns) + optional LLM | skills only |
| [Tencent/AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | 6,220 | 2026-09-10 | Apache-2.0 | platform: MCP, skills, OpenClaw, jailbreak evals | MCP + skills + infra |
| [highflame-ai/ramparts](https://github.com/highflame-ai/ramparts) | 96 | 2026-09-10 | Apache-2.0 | live MCP + static skills; 40 YARA + LLM | MCP servers, Claude Code commands, agentskills.io bundles |
| [getagentseal/agentseal](https://github.com/getagentseal/agentseal) | 371 | 2026-06-11 | none stated | local static + live `scan-mcp` + watcher | skills, MCP configs, prompts |
| [gabrielsoltz/clauditor](https://github.com/gabrielsoltz/clauditor) | 45 | 2026-09-07 | Apache-2.0 | static, 51 YAML checks | Claude Code settings, all four scopes |
| [Pantheon-Security/medusa](https://github.com/Pantheon-Security/medusa) | 979 | 2026-08-10 | AGPL-3.0 | static, 40k patterns | repos, `.claude/` hooks, chat histories |
| [trailofbits/mcp-context-protector](https://github.com/trailofbits/mcp-context-protector) | 223 | 2026-04-14 | Apache-2.0 | runtime proxy | one MCP server |
| [riseandignite/mcp-shield](https://github.com/riseandignite/mcp-shield) | 554 | 2025-04-26 (stale) | MIT | live connect + optional Claude | MCP configs |
| [HeadyZhang/agent-audit](https://github.com/HeadyZhang/agent-audit) | 227 | 2026-07-04 | MIT | static, 72 rules, OWASP Agentic Top 10 | agent source, MCP configs |
| [ykdojo/cc-safe](https://github.com/ykdojo/cc-safe) | 60 | 2025-12-10 | none stated | regex | `permissions.allow` only |

Adjacent only: [lasso mcp-gateway](https://github.com/lasso-security/mcp-gateway) (runtime proxy), [pipelock](https://github.com/luckyPipewrench/pipelock) (egress firewall), [promptfoo](https://github.com/promptfoo/promptfoo) (dynamic red team), [agentic-radar](https://github.com/splx-ai/agentic-radar) (framework code graphs), [semgrep/mcp](https://github.com/semgrep/mcp) (runs Semgrep, not a scanner), garak. Not on GitHub, UNVERIFIED: Prisma AIRS, HiddenLayer, Pillar.

Anthropic's [security doc](https://code.claude.com/docs/en/security) recommends managed settings, `ConfigChange` hooks, sandbox `denyRead`, and OTel monitoring, and says Anthropic "does not security-audit or manage any MCP server".

## 3. Per-tool deltas

**snyk/agent-scan.** They have, we don't: live `tools/list` enumeration, tool shadowing across servers (E002), toxic-flow classification (untrusted content, private data, destructive capabilities), skill risks for direct money access and unverifiable remote dependencies, MDM background mode, a `snyk-agent-guard` PreToolUse hook, SBOM and signed checksums on releases, discovery of Windsurf, Cursor, Kiro, Antigravity, Amp, OpenClaw. We have, they don't: fully offline operation (theirs starts stdio servers and posts to Snyk's API), 38 hook rules, permission analysis, package-manager hardening, evidence packs, policy packs, SARIF, GitHub Action, HTML report.

**cisco mcp-scanner.** They have: YARA packs (10 files), tree-sitter behavioural analysis with call graphs, pip-audit CVEs, VirusTotal hash lookups on bundled binaries, OAuth for SSE/HTTP, Docker-sandboxed PyPI scans, readiness checks, REST mode. They never read `settings.json`, hooks, or agents.

**cisco skill-scanner, SkillSpector.** They have: deep bundle analysis (scripts, nested archives, .pyc), OSV.dev lookups, published accuracy (skill-scanner: F1 47.73%, recall 31.43% on MaliciousSkillBench), pre-commit hook, baseline suppression. We have two skill rules. Skills are our thinnest module.

**ramparts.** They have: NFKC and zero-width normalisation rescan before YARA, cross-origin tool analysis, content-fingerprint rug-pull detection for tool definitions and skill files, OSV lookups for npx/uvx servers, `allowed-tools` overbreadth, name-vs-directory deception, OWASP MCP Top 10 tags on every finding. No hooks, permissions, or CI evidence layer.

**agentseal.** They have: SHA-256 config baselines for rug pulls, a 6,600-server trust registry, 225 prompt probes, notify-and-quarantine watcher, YAML custom rules. We have `watch`, fleet, and policy; our injection tester has no published probe count. Pipeline internals UNVERIFIED.

**clauditor.** 51 settings checks we lack: sandbox enable and filesystem/network allowlists (CC010 to CC016, CC031, CC044, CC049), managed-only hooks/MCP/permissions (CC003, CC006, CC017), SSO (CC007, CC008), plugin marketplaces (CC018, CC048), OTel (CC034 to CC041, CC050), `apiKeyHelper` / `awsAuthRefresh` / `awsCredentialExport` in project scope (CC027, CC042, CC043), transcript retention, CODEOWNERS on `.claude/` and `.mcp.json`, and `generate` for hardened managed settings. Nothing outside `settings.json`.

**medusa.** Chat-history secret scanning with purge, 200 CVE signatures, 28 editor config types. Their 40k paper-harvested patterns are noisier than our hand-written rules.

**mcp-context-protector.** Runtime only: TOFU pinning with semantic diff of tool schemas, ANSI sanitisation, LlamaFirewall guardrails, quarantine. Complementary to our PreToolUse evaluator.

**mcp-shield, cc-safe, agent-audit.** Stale or narrow. cc-safe is a subset of `permissions.ts`; agent-audit adds OWASP mapping and Python taint we lack.

## 4. Capability matrix

| Capability | AgentShield | snyk | cisco mcp | ramparts | agentseal | clauditor | SkillSpector | ToB protector |
|---|---|---|---|---|---|---|---|---|
| Offline, no account | yes | no | partial | yes | yes | yes | yes | yes |
| Live MCP tool enumeration | **no** | yes | yes | yes | yes | no | no | yes |
| Tool shadowing / cross-server | **no** | yes | yes | yes | UNVERIFIED | no | n/a | no |
| Rug-pull fingerprint of tool defs | **no** (findings baseline only) | no | no | yes | yes | no | no | yes |
| Unicode/homoglyph normalisation | partial (`unicode-attack`) | UNVERIFIED | yes | yes | yes | no | yes | ANSI only |
| Claude Code hooks rules | 38 | guard hook | no | no | partial | 3 | no | no |
| `permissions.allow/deny` analysis | 13 | no | no | no | no | yes | no | no |
| Managed / sandbox / OTel / SSO checks | **no** | no | no | no | no | 51 | no | no |
| Agent (.md) prompt rules | 41 | no | no | no | no | no | no | no |
| Skill bundle depth | 2 rules | 10 risks | no | yes | yes | no | 71 patterns | no |
| npm supply chain (typosquat, age, maintainers) | yes | no | PyPI | OSV | registry | no | OSV | no |
| Live CVE lookup (OSV) | **no** (static, 21 CVEs) | no | pip-audit | yes | no | no | yes | no |
| Package-manager hardening | yes | no | no | no | no | no | no | no |
| LLM deep analysis | Opus pipeline | cloud | yes | yes | optional | no | optional | guardrail |
| SARIF | yes | no | UNVERIFIED | yes | yes | no | yes | no |
| Baseline drift gate | yes | no | no | yes | yes | no | yes | n/a |
| Evidence pack with digests | yes | no | no | no | no | no | no | no |
| Org policy packs + promotion | yes | Evo (paid) | no | no | YAML rules | base-level flag | no | no |
| Published accuracy benchmark | corpus of 22 | skills report | evals dir | no | no | no | no | n/a |
| GitHub Action outputs | 32 | no | reusable workflow | SARIF | no | exit code | no | no |

## 5. Where we stand

AgentShield is the only tool here that treats the whole Claude Code configuration as one surface and wraps it in CI plumbing: baselines, SARIF, evidence packs, policy promotion, fleet views. Nobody else has 38 hook rules, 41 agent-prompt rules, or package-manager hardening. On MCP we are behind: Snyk, Cisco, ramparts, agentseal and mcp-shield all connect to the server, inspect real tool descriptions, detect shadowing, and fingerprint tool definitions for rug pulls. We read config text only, so a poisoned tool description never reaches our rules. On skills we have 2 rules against SkillSpector's 71 patterns and Cisco's benchmarked pipeline. On `settings.json`, clauditor's 51 enterprise checks (sandbox, managed-only, OTel, SSO, marketplaces) are absent from ours. Stars: 1,159, ahead of Cisco mcp-scanner and ramparts, behind Snyk (3k), Tencent (6k), SkillSpector (17k).

## 6. Gap-closure plan (prioritised)

| # | Gap | Effort | Lands in |
|---|---|---|---|
| 1 | Opt-in live MCP inspection with explicit consent: capture `tools/list`, `prompts/list`, `resources/list`, run poisoning rules over real descriptions | L | new `src/scanner/mcp-inspect.ts`; feed `src/rules/mcp-tool-poisoning.ts`; flag in `src/index.ts scan` |
| 2 | Tool-definition fingerprints: hash instructions, tool names, descriptions, input schemas; diff against baseline; alert in `watch` | M | `src/baseline/compare.ts`, `src/watch/diff.ts`, `src/fingerprint.ts` |
| 3 | Cross-server shadowing and cross-origin tools | S after #1 | `src/rules/mcp-tool-poisoning.ts` (uses existing `allFiles` arg on `Rule.check`) |
| 4 | Enterprise settings parity with clauditor: sandbox, managed-only hooks/MCP/permissions, SSO, marketplaces, OTel, `apiKeyHelper`/`awsAuthRefresh` in project scope | M | new `src/rules/enterprise-settings.ts`; scope detection in `src/scanner/discovery.ts` |
| 5 | Normalisation pre-pass: strip zero-width, fold NFKC homoglyphs, decode base64/hex once, rerun text rules | S/M | new `src/scanner/normalize.ts`, called from `src/scanner/index.ts` |
| 6 | OSV.dev lookups for npx/uvx MCP packages and skill deps, offline fallback to static table | M | `src/supply-chain/verify.ts`, `src/threat-intel/cve-database.ts` |
| 7 | Skill bundle depth: `scripts/` and `references/`, `allowed-tools` overbreadth, name-vs-directory mismatch, sensitive `@path` refs, embedded payloads, runtime remote fetch, payment access | M | `src/rules/skills.ts`; subdir discovery in `src/scanner/discovery.ts` |
| 8 | Public benchmark harness: run MaliciousSkillBench, NotInject, MCPTox and Cisco evals through the corpus gate; publish precision/recall | M | `src/corpus/`, `tests/corpus.test.ts`, README |

Smaller: SBOM on npm releases (S), OWASP tags on `Rule` in `src/types.ts` (S), fix README rule count (S).

## 7. Benchmarks and corpora

- MaliciousSkillBench (5,256 malicious, 1,338 benign skills), HarmfulSkillBench (200), OpenSkillRisk, NotInject (339 hard negatives): cited with numbers in [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner); hosting UNVERIFIED.
- [MCPTox-Benchmark](https://github.com/zhiqiangwang4/MCPTox-Benchmark): tool poisoning on real MCP servers; README fetched empty, contents UNVERIFIED.
- SkillTrustBench (Tencent, linked from [AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)).
- [invariantlabs-ai/mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments): reproducible poisoning servers.
- [aminrj-labs/mcp-attack-labs](https://github.com/aminrj-labs/mcp-attack-labs): poisoning and cross-server shadowing labs.
- Snyk skills report (`.github/reports/skills-report.pdf` in agent-scan) for ecosystem base rates.
- Our `src/corpus/vulnerable-configs.ts` (22 configs) is the only Claude Code config corpus found. Publishing it as a labelled set would give the field a benchmark we define.
