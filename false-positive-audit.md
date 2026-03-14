# AgentShield False Positive Audit

This note captures the current false-positive, miss, and confidence-scoring state of AgentShield after live validation on March 14, 2026.

Audit method:
- real scans were run with `npx tsx src/index.ts scan --format json`
- repos were chosen to cover template-heavy, hook-heavy, and cleaner baseline configs
- targeted synthetic scans were used to validate source-kind behavior that the live repos no longer exercise directly
- findings below distinguish three states: raw false positive, real miss, and true signal with the wrong score weight

Validation repos used:
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code`
- `/Users/affoon/Documents/GitHub/PMX-backend`
- `/Users/affoon/Documents/GitHub/basket-trader`

Current scan snapshots:
- `everything-claude-code`: `103` files, `88` findings, grade `B (75)`, now with only `7` high findings after specialist agent-capability severity downgrades, `51` findings with `runtimeConfidence: template-example`, and `3` info-level `hook-code` findings
- `PMX-backend`: `17` files, `27` findings, grade `C (72)`, now with only `1` high finding after structured agent-capability downgrades and repo-scoped filesystem MCP grading
- `basket-trader`: `3` files, `2` findings, grade `A (99)`, now split into `1` medium and `1` low after the project-local exact-allowlist downgrade for `hooks-no-pretooluse`

Recent alerts reviewed on the current scanner:
- `everything-claude-code/mcp-configs/mcp-servers.json` remains the largest alert cluster at `51` findings, but those all carry `runtimeConfidence: template-example`; the score model now caps that one file at `10` MCP deduction points, so the remaining issue is report interpretation and count volume, not raw grade distortion
- `PMX-backend/.claude/settings.json` remains the hottest active-runtime file at `11` findings, but its repo-scoped filesystem MCP is now graded `medium` instead of `high`
- `basket-trader/launch-video/.claude/settings.local.json` now emits only `2` findings, both `project-local-optional`; those are still worth surfacing, but they now read as scope-limited exposure rather than repo-wide runtime risk
- conclusion from this pass: the strongest remaining score inflation was template-catalog MCP debt, and that is now reduced; the main remaining noise is template count/interpretation and active-runtime remote MCP URLs

Targeted source-kind confirmation scans:
- a synthetic `docs/guide/settings.json` example now emits `runtimeConfidence: docs-example`, rewrites titles as `Example config: ...`, and downgrades structural severities one level (`Bash(*)` moved from `critical` to `high`, `permissions-no-deny-list` from `high` to `medium`, `hooks-no-pretooluse` from `medium` to `low`)
- a docs-only `docs/guide/CLAUDE.md` with a real `ghp_...` token now scans as a standalone `docs-example` file and still emits a `critical` secret finding
- a synthetic `examples/demo/CLAUDE.md` plus `examples/demo/settings.json` example bundle now emits `runtimeConfidence: docs-example` instead of looking like live runtime config
- a synthetic `tutorials/demo-app/CLAUDE.md` plus `tutorials/demo-app/settings.json` tutorial bundle now emits `runtimeConfidence: docs-example` instead of looking like live runtime config
- a synthetic `hooks/hooks.json` manifest now emits `runtimeConfidence: plugin-manifest` and manifest-aware titles such as `Plugin hook manifest: Hook sends data to external service`
- manifest-resolved non-shell implementations continue to emit `runtimeConfidence: hook-code` with narrow language-aware findings, such as `Hook code injects content into Claude context`, and now also flag explicit remote shell payloads executed via child-process wrappers

High-signal evidence from the refresh scan:
- `everything-claude-code` still has `51/88` findings concentrated in `mcp-configs/mcp-servers.json`, but the MCP category now lands at `90` and the overall grade improves to `B (75)` because non-secret `template-example` findings are both score-weighted at `0.25x` and capped at `10` deduction points per file and score category
- `commands/kotlin-test.md` no longer emits any secret findings after markdown example-password suppression landed
- docs-only nested trees under `docs/` no longer emit agent noise, but standalone example `CLAUDE.md` files are now still inventoried; `everything-claude-code` gained `4` extra scanned files (`docs/ja-JP/examples/CLAUDE.md`, `docs/ko-KR/examples/CLAUDE.md`, `docs/zh-CN/CLAUDE.md`, and `docs/zh-CN/examples/CLAUDE.md`) without adding findings
- `hooks/hooks.json` now emits `0` findings; direct manifest false positives for `permissions-no-block`, `hooks-silent-fail-*`, and `hooks-chained-commands-*` are fixed
- `.claude/settings.local.json` no longer emits `hooks-no-pretooluse` when companion `hooks/hooks.json` defines real PreToolUse hooks, so the remaining hook gap is language-aware review of `hook-code`, not manifest awareness
- `.claude/settings.local.json` in `everything-claude-code` is now down to a single `permissions-no-deny-list` finding; the prior four `permissions-permissive-Bash(curl ...)` findings for exact npmjs URLs are gone
- exact interpreter wrapper permissions such as `Bash(node scripts/build.js --check)` and `Bash(python3 ./tools/audit.py --format json)` now stay quiet in synthetic audits; inline eval forms such as `node -e` and `python -c` still trigger `permissions-permissive-*`
- exact read-only Docker inventory permissions such as `Bash(docker ps --format '{{.Names}}')` and `Bash(docker image ls)` now stay quiet in synthetic audits; `docker run` and `docker exec` still trigger `permissions-permissive-*`
- `everything-claude-code` now resolves `hooks/hooks.json` into `20` discovered `hook-code` files under `scripts/hooks/` plus `2` shell hook implementations (`scripts/hooks/run-with-flags-shell.sh` and `skills/continuous-learning-v2/hooks/observe.sh`)
- those non-shell implementations now emit `3` narrow info findings: `session-start.js` for explicit `output(...)` context injection, and `session-end.js` plus `evaluate-session.js` for direct transcript input access
- comment-only shell-hook lines such as `# curl https://...`, `# tsc 2>/dev/null`, or `# avoid ~/.ssh/id_rsa` now stay quiet in synthetic audits; the hook rules only flag those patterns when they appear in executable hook code
- `agents/security-reviewer.md` no longer emits `agents-injection-surface`; the old hit was caused by defensive example text such as ``fetch(userProvidedUrl)`` inside a security review checklist
- `agents-explorer-write-*` no longer fires on non-explorer workflows such as `chief-of-staff.md`, `database-reviewer.md`, `e2e-runner.md`, `security-reviewer.md`, `.claude/subagents/e2e-tester.json`, or `.claude/slash-commands/test-coverage.json`; the rule now uses role metadata and lead intro text instead of matching any later occurrence of `search`
- `agents-oversized-prompt-*` no longer fires on example-heavy agents such as `chief-of-staff.md` and `planner.md`; the rule now measures effective prompt size instead of raw file size, discounting fenced code blocks and markdown tables
- narrow specialist agent, subagent, and slash-command Bash/escalation findings now downgrade from `high` to `medium`; `everything-claude-code` dropped from `29` to `7` high findings and `PMX-backend` dropped from `18` to `1`
- `settings.local.json` findings now emit `runtimeConfidence: project-local-optional` outside MCP too, and non-secret project-local findings now score at `0.75x` instead of full runtime weight
- `PMX-backend` now emits `9` findings from structured slash-command JSON, which confirms that part of the previous miss is fixed
- `PMX-backend/.claude/settings.json` now grades the repo-scoped `filesystem` MCP at `medium` instead of `high`; the only remaining `high` active-runtime MCP finding there is the remote URL transport server
- `basket-trader` remains a useful baseline sanity check because its `2` findings are plausible and not obviously inflated
- `basket-trader` now grades `A (99)` because its narrow `settings.local.json` allowlist downgrades `permissions-no-deny-list` from high to medium and its project-local findings now score at `0.75x` instead of full runtime weight
- `basket-trader/launch-video/.claude/settings.local.json` now downgrades `hooks-no-pretooluse` from medium to low because the config is project-local and narrowly scoped to exact local commands
- `PMX-backend` still emits one `hooks-no-pretooluse` from `.claude/settings.json`, which also looks legitimate because there is no companion manifest to suppress it

Behavior validation edge cases confirmed in targeted scans:
- a docs-only example tree like `docs/guide/CLAUDE.md` now scans as a standalone example file, so a real GitHub PAT there emits a `critical` `docs-example` secret finding instead of disappearing
- a docs/example tree with a runtime companion does the right thing: real secrets still stay `critical` and structural policy findings downgrade one severity level under `runtimeConfidence: docs-example`
- an example bundle under `examples/`, such as `examples/demo/CLAUDE.md` plus `examples/demo/settings.json`, now emits `runtimeConfidence: docs-example` and downgraded structural severities instead of looking like live config
- a tutorial bundle under `tutorials/`, such as `tutorials/demo-app/CLAUDE.md` plus `tutorials/demo-app/settings.json`, now also emits `runtimeConfidence: docs-example` instead of looking like live config
- a manifest-resolved non-shell hook implementation that shells out via `spawnSync('bash', ['-lc', 'curl ... | bash'])` now emits a `high` `hook-code` finding for a remote shell payload executed through a child process

## Summary

| Pattern | Class | Evidence | Current Status | Next Step |
| --- | --- | --- | --- | --- |
| MCP template catalogs | Confidence / scoring gap | `mcp-configs/mcp-servers.json` in `everything-claude-code` | Fixed for MCP scoring: template findings are relabeled, severity-adjusted, emit `runtimeConfidence: template-example`, structural non-secret findings score at `0.25x`, and one template file is capped at `10` deduction points per score category | Extend the same high-confidence language-aware treatment to non-MCP executable sources |
| Docs/example roots treated as live config | False positive | `docs/zh-CN/CLAUDE.md` in `everything-claude-code` | Fixed: docs-only example `CLAUDE.md` files are inventoried as standalone examples while noisy nested subtrees stay suppressed | Extend source-aware handling if other tutorial/example bundle names show up beyond the current path set |
| Example passwords in command docs | False positive | `commands/kotlin-test.md` in `everything-claude-code` | Fixed: example/test markdown context now suppresses the hardcoded-password rule in docs/command paths | Extend fixtures as new doc/example patterns appear |
| Exact network allow rules mislabeled as overly permissive | False positive | `.claude/settings.local.json` in `everything-claude-code` | Fixed: exact `curl`/`wget` commands with pinned URLs no longer trigger `permissions-permissive-*` | Keep the exact-vs-broad allowlist distinction covered in tests |
| Exact interpreter wrapper permissions graded like arbitrary interpreter access | False positive | synthetic `Bash(node scripts/build.js --check)` and `Bash(python3 ./tools/audit.py --format json)` | Fixed: exact script-wrapper commands no longer trigger `permissions-permissive-*`; inline eval/REPL forms such as `node -e` and `python -c` still do | Keep the distinction narrow so exact script paths stay quiet without muting real interpreter abuse |
| Read-only Docker inventory commands graded like container execution | False positive | synthetic `Bash(docker ps --format '{{.Names}}')` and `Bash(docker image ls)` | Fixed: exact read-only inventory commands no longer trigger `permissions-permissive-*`; `docker run` and `docker exec` still do | Extend only if future live repos show other truly read-only forms worth allowlisting |
| Project-local no-deny-list severity too high for exact allowlists | Severity inflation | `launch-video/.claude/settings.local.json` in `basket-trader` | Fixed: exact `settings.local.json` allowlists now downgrade `permissions-no-deny-list` from high to medium, emit `runtimeConfidence: project-local-optional`, and score at `0.75x` for non-secret findings | Keep project-local weighting aligned with future source kinds |
| Project-local missing PreToolUse overstated for exact local-only allowlists | Severity inflation | `launch-video/.claude/settings.local.json` in `basket-trader` | Fixed: `hooks-no-pretooluse` now downgrades from medium to low for exact local-only `settings.local.json` allowlists | Keep broader or network-capable project-local configs at medium |
| Specialist agent/subagent/slash-command capability findings overstated as high | Severity inflation | `agents/security-reviewer.md` in `everything-claude-code`; `.claude/subagents/e2e-tester.json` in `PMX-backend` | Fixed: narrow specialist configs now downgrade Bash-access and escalation-chain findings from high to medium | Keep broader/generalist configs such as `chief-of-staff.md` at high |
| Repo-scoped filesystem MCP graded like unrestricted filesystem access | Severity inflation | `.claude/settings.json` in `PMX-backend` with `filesystem` server rooted at `./` | Fixed: repo-scoped relative filesystem MCP now grades as medium while root/home path access stays high | Revisit HTTPS vendor MCP URL grading separately if live evidence justifies it |
| Defensive security-review prompts mislabeled as injection surface | False positive | `agents/security-reviewer.md` in `everything-claude-code` | Fixed: defensive examples like ``fetch(userProvidedUrl)`` no longer trigger `agents-injection-surface` | Add source/context metadata if future agent-review prompts need different confidence handling |
| Explorer/search write rule matched generic workflow text | False positive | `agents/chief-of-staff.md`, `agents/security-reviewer.md` in `everything-claude-code`; `.claude/subagents/e2e-tester.json` in `PMX-backend` | Fixed: `agents-explorer-write` now uses path/name/description plus lead intro text instead of any later `search` mention in examples or workflow steps | Keep the heuristic scoped to explicit role signals so procedural `search for ...` text does not regress |
| Oversized prompt rule counted examples and templates as live prompt size | False positive | `agents/chief-of-staff.md`, `agents/planner.md` in `everything-claude-code` | Fixed: `agents-oversized-prompt` now uses effective prompt size, discounting fenced code blocks and markdown tables | Keep the heuristic focused on actual prompt prose, not embedded examples |
| Hook manifest direct structural findings | False positive | `hooks/hooks.json` in `everything-claude-code` | Fixed: settings-only and wrapper-noise findings no longer fire directly on the manifest | Keep regression coverage and avoid reintroducing settings-only checks on plugin manifests |
| Missing-hook logic ignores plugin manifests | False positive + miss | `.claude/settings.local.json` plus `hooks/hooks.json` in `everything-claude-code` | Fixed for companion manifests: settings-only `hooks-no-pretooluse` is now suppressed when plugin manifests define PreToolUse hooks, and manifest findings emit `runtimeConfidence: plugin-manifest` | Extend language-aware manifest handling beyond missing-hook suppression |
| Plugin hook implementations behind manifests | Miss reduced to partial coverage | `scripts/hooks/session-start.js`, `session-end.js`, `evaluate-session.js` in `everything-claude-code` | Fixed for discovery and initial analysis: manifest references now resolve into repo-local `hook-code` and shell `hook-script` files, and non-shell hook code now emits low-noise info findings for explicit context injection and transcript access with `runtimeConfidence: hook-code` | Extend language-aware coverage carefully for non-shell execution and external I/O |
| Docs/example configs still looked like live critical findings when intentionally scanned | False positive / presentation inflation | synthetic `docs/guide/settings.json` fixture | Fixed: docs/example findings now emit `runtimeConfidence: docs-example`, use example-aware titles, and downgrade structural severities one level while preserving full weight for real secrets | Extend source-path coverage if other tutorial/example roots appear outside `docs/` and `commands/` |
| Plugin hook manifests lacked declarative-context wording | Confidence / interpretation gap | synthetic `hooks/hooks.json` fixture | Fixed: manifest findings now emit `runtimeConfidence: plugin-manifest` and render with manifest-aware titles/descriptions | Tune severity only if future live repos show persistent manifest-only noise |
| Docs-only example trees could hide real secrets | Miss introduced by false-positive suppression | synthetic `docs/guide/CLAUDE.md` with a real `ghp_...` token and no runtime companion | Fixed: docs-only example `CLAUDE.md` files now scan as standalone examples, and real secrets still stay `critical` | Keep the subtree suppression narrow so only the standalone example file is added back, not the whole translated/example tree |
| Tutorial/example bundles outside `docs/` and `commands/` still looked like live config | False positive boundary | synthetic `tutorials/demo-app/CLAUDE.md` + `tutorials/demo-app/settings.json` | Fixed for the expanded current path set: `examples/`, `example/`, `samples/`, `sample/`, `demo/`, `demos/`, `tutorial/`, `tutorials/`, `guide/`, `guides/`, `cookbook/`, and `playground/` now classify as `docs-example` | Extend source-kind classification to additional example-root names only when evidence justifies it |
| Non-shell hook code missed child-process execution chains | Miss | synthetic `scripts/hooks/post-edit-format.js` calling `spawnSync('bash', ['-lc', 'curl ... | bash'])` | Fixed for explicit remote shell payloads: `hook-code` now flags child-process downloads piped into shell interpreters | Extend language-aware child-process analysis beyond remote shell payloads without flagging ordinary wrappers |
| Structured slash-command JSON with `allowedTools` | Miss | `.claude/slash-commands/*.json` in `PMX-backend` | Fixed | Keep regression coverage and monitor other structured config types |
| Generated `.dmux` worktree mirrors | False positive | `.dmux/worktrees/...` in `everything-claude-code` | Fixed | Keep generated-workspace exclusions narrow and evidence-based |
| Placeholder connection-string docs | False positive | `commands/update-docs.md` in `everything-claude-code` | Fixed | Extend example-vs-real secret fixtures as new markdown cases appear |
| Benign hook probe suppression | Severity inflation | `.claude/hooks/onEdit.sh`, `.claude/hooks/onStop.sh` in `PMX-backend` | Fixed | Keep `/dev/null` suppression high-signal for real concealment, not harmless probes |
| Comment-only shell-hook examples matched as live behavior | False positive | synthetic hook scripts with `# curl https://...`, `# tsc 2>/dev/null`, and `# avoid ~/.ssh/id_rsa` | Fixed: comment-only lines are now ignored by hook exfiltration, silent-fail, and sensitive-path regex rules | Keep shell comment suppression line-scoped so inline executable behavior still flags |

## Dominant Patterns In Current Reports

These are the current high-frequency patterns from the latest live scans, ordered by how much they distort first-pass report reading.

### 0.1 Source-Confidence Mismatch Dominates More Than Rule Bugs

Current evidence:
- `everything-claude-code` still carries `51/88` findings from `mcp-configs/mcp-servers.json`
- those findings are mostly legitimate template inventory findings, not active runtime exposure
- this is why the scanner now emits `runtimeConfidence: template-example`, discounts non-secret template findings to `0.25x`, and caps one template file at `10` deduction points per score category

Interpretation:
- the main source of scan noise is still "real but lower-confidence" inventory, not obviously wrong matching logic
- the right fix is source-aware labeling, wording, and weighting before suppression

### 0.2 Example And Tutorial Content Needs Different Treatment Than Runtime Config

Current evidence:
- docs/example `CLAUDE.md` files are now inventoried as standalone example files, not full live roots
- `examples/demo/CLAUDE.md` plus `examples/demo/settings.json` now lands as `docs-example` rather than full-severity runtime config
- example/test passwords in `commands/kotlin-test.md` no longer create critical secret findings

Interpretation:
- examples are a real source of shipped risk, but they are not the same thing as active runtime enablement
- structural findings should usually be downgraded and relabeled; committed real secrets should still stay critical

### 0.3 Hook Definition Versus Hook Implementation Is A Persistent Source Of Noise

Current evidence:
- direct `hooks/hooks.json` false positives are fixed
- manifest findings now emit `runtimeConfidence: plugin-manifest`
- `hook-code` findings are still intentionally narrow: context injection, transcript access, and explicit remote shell payloads through child-process wrappers

Interpretation:
- declarative manifests and executable implementations are different source kinds and should not be scored or worded the same way
- broad shell-style pattern matching on non-shell hook code is still the main thing to avoid

### 0.4 Agent Findings Often Reflect Intentional Capability, Not A Matcher Bug

Current evidence:
- after the recent fixes, `everything-claude-code` agent findings are mostly medium-severity capability findings plus a small set of broader/higher-risk generalist agents
- the previous high-confidence false positives were heuristic bugs: `agents-explorer-write`, defensive injection examples, and raw-file-size prompt inflation
- those are now fixed, and narrow specialist capability findings are now severity-adjusted rather than reported as uniformly high

Interpretation:
- many remaining agent findings are policy findings, not false positives
- the right question is often "is this agent intentionally privileged?" rather than "is the scanner wrong?"

### 0.5 What Should Not Be Counted As A False Positive

These cases still need analyst attention, but they usually do not justify weakening a rule.

- `template-example`, `docs-example`, and `plugin-manifest` findings that accurately describe shipped risk with lower-confidence wording are not false positives. They are visibility findings with adjusted confidence.
- `project-local-optional` findings in committed `settings.local.json` are not false positives. They are narrower-scope exposure and should stay visible unless the underlying matcher is wrong.
- agent findings on intentionally privileged workflows are not false positives just because the repo author meant to grant those capabilities. That is a product and policy decision, not a scanner bug.
- real secrets found in docs, examples, manifests, or local settings are not false positives. Those should continue to stay critical.

### 0.6 Current Remaining Alert Noise Is Mostly Interpretive

Current evidence:
- the latest live scan did not produce a new repeated bad matcher pattern
- the biggest remaining noisy cluster is still template MCP inventory with `runtimeConfidence: template-example`, but it no longer dominates the score the way it used to
- the smallest remaining scope-noise cluster is project-local config in `settings.local.json`

Interpretation:
- current audit work should stay focused on wording, confidence, and score modeling before inventing new suppressions
- if a future scan produces a new high-count cluster outside those source kinds, that is the point to revisit rule logic first

## Pattern Signatures In Recent Alerts

These signatures come from the latest real-repo scans and are a faster way to recognize likely false-positive patterns before changing rules.

| Pattern signature | Seen in current scans | Likely meaning | First action |
| --- | --- | --- | --- |
| one file dominates the report and almost all findings share `runtimeConfidence: template-example` | `everything-claude-code/mcp-configs/mcp-servers.json` with `51` findings | shipped template or catalog inventory is being read as live runtime by the operator, not by the scanner | keep the findings visible, but review wording, weighting, and runtime confirmation first |
| many `agents-*` findings spread across agent, subagent, and slash-command files with explicit tool metadata | `everything-claude-code` and `PMX-backend` agent clusters | this is usually a policy cluster about intentionally privileged workflows, not a false-positive cluster | verify the role metadata and tool list before weakening the rule |
| a very small cluster in `settings.local.json` with `runtimeConfidence: project-local-optional` | `basket-trader/launch-video/.claude/settings.local.json` | scope is already modeled; the remaining question is severity, not whether the finding should exist | tune severity or score only if the allowlist is exact and local-only |
| info-only findings in manifest-resolved non-shell hook files | `scripts/hooks/session-start.js`, `session-end.js`, `evaluate-session.js` | the scanner has reached real implementation code but is intentionally using narrow rules | add behavior-specific language-aware rules only when a new explicit risky action is confirmed |

## Common Noisy File Archetypes

These file types recur in false-positive investigations. Use the file archetype before the finding count as the first hint for how to interpret alerts.

| File archetype | Typical `runtimeConfidence` | Common noise pattern | Recommended review approach |
| --- | --- | --- | --- |
| `mcp-configs/*.json`, `config/mcp/*.json` | `template-example` | many MCP findings from one inventory file | confirm whether the same servers are actually enabled in runtime config |
| `settings.local.json` | `project-local-optional` | small clusters of permission or hook findings that look harsher than their real scope | verify whether the allowlist is exact, local-only, and committed for team use |
| `hooks/hooks.json` | `plugin-manifest` | declarative metadata looks like direct execution | follow the referenced implementation before changing the rule |
| `scripts/hooks/*.js`, `scripts/hooks/*.ts` reached through manifests | `hook-code` | real implementation code with intentionally narrow findings | only add behavior-specific rules when a concrete risky action is present |
| `.claude/subagents/*.json`, `.claude/slash-commands/*.json` | usually none | broad `agents-*` clusters on structured tool definitions | treat as policy review first, then check for actual heuristic bugs |

## Recommendations For Reducing False Positives

These recommendations are based on the current live scan profile, not hypothetical scanner behavior.

### 1. Reduce Noise By Source Kind Before Touching Rules

- Group findings by `runtimeConfidence` first.
- Review `template-example`, `docs-example`, and `plugin-manifest` findings separately from `active-runtime`.
- Only change matching logic when the finding is wrong for its own source kind, not merely lower confidence.

### 2. Prefer Reclassification Over Suppression

- If a finding is real but lower confidence, relabel it and adjust score weight instead of hiding it.
- Examples: `template-example`, `docs-example`, and `plugin-manifest` are the current successful model.
- This preserves operator visibility while reducing grade distortion.

### 3. Keep Secrets On A Different Standard

- Do not blanket-suppress secrets in docs, examples, or manifests.
- Structural policy findings can be downgraded in examples; real committed credentials should stay critical.
- The recent docs-only `CLAUDE.md` fix exists specifically to avoid losing real secrets while suppressing example subtree noise.

### 4. Use Cross-File Context Before Inventing New Heuristics

- Companion manifests, referenced hook implementations, and project-local settings context matter more than isolated string matches.
- The `hooks-no-pretooluse` fix worked because it looked across settings and manifest files, not because the core rule got weaker.

### 5. For Hook Code, Add Narrow Language-Aware Rules Only

- Match explicit risky behavior such as context injection, transcript access, or child-process remote shell payloads.
- Do not treat every `spawnSync`, `execFileSync`, or wrapper helper as suspicious by default.
- This is the clearest path to reducing noise without reopening the older hook false positives.

### 6. For Agent Rules, Anchor On Role Metadata Before Body Text

- Prefer path, agent name, description, and lead instructions over arbitrary later prose.
- This is what fixed `agents-explorer-write` and reduced defensive-review false positives.
- Treat remaining Bash-access findings as policy questions unless a matcher bug is obvious.

## Repo Authoring Conventions That Improve Accuracy

These conventions reduce false-positive interpretation risk without weakening the scanner.

- keep reusable MCP inventories under `mcp-configs/`, `config/mcp/`, or similar template directories instead of mixing them into live runtime config
- keep project-local overrides in `settings.local.json`, and prefer exact local-only allow entries when possible
- keep sample/tutorial bundles under example-like paths such as `docs/`, `examples/`, `tutorials/`, `demos/`, `guides/`, or `cookbook/`
- keep declarative hook manifests in `hooks/hooks.json` and the actual implementation code in separate `scripts/hooks/` or `skills/**/hooks/` files
- keep large agent examples inside fenced code blocks and keep the lead role metadata concise, so the scanner can distinguish live instructions from examples
- clearly mark sample credentials as examples or fixtures and keep them in example-like paths rather than operational config directories

## False-Positive Reduction Playbook

Use this before changing rule code. Most current scan noise is better solved by confidence modeling than by weakening detection.

| Scan symptom | Most likely cause | Preferred fix | Avoid |
| --- | --- | --- | --- |
| one file dominates the report and most findings share `runtimeConfidence: template-example` | template inventory is being read like active runtime config | relabel, reweight, and keep findings visible | suppressing the file entirely |
| docs or tutorial paths emit structural config findings | example content is being treated like live runtime config | classify as `docs-example`, downgrade structural severity, keep secrets strict | blanket ignore for `docs/` or markdown |
| `hooks/hooks.json` emits shell-style findings | declarative manifest is being evaluated like executable shell | apply `plugin-manifest` wording and cross-file context | reusing `settings.json` hook rules directly on manifests |
| `settings.local.json` looks overly severe | project-local scope is not being modeled | mark as `project-local-optional` and adjust score weight or severity | hiding local config findings entirely |
| agent rule triggers from examples, code fences, or later workflow text | heuristic is reading too much body text and too little role metadata | anchor on path, name, description, and lead intro | broad regexes over the full prompt body |
| non-shell hook implementation looks suspicious but shell rules do not apply | `hook-code` needs language-aware analysis | add one narrow behavior rule with regression tests | flagging every `spawnSync` or wrapper helper |

## Evidence Checklist Before Changing A Rule

Treat a rule change as justified only when most of these checks pass.

- Confirm the same pattern in at least one real repo scan, not just a synthetic fixture.
- Confirm the finding is wrong for its own source kind, not merely lower-confidence than `active-runtime`.
- Verify whether cross-file context would solve it before changing the matcher.
- Check whether the fix should be reclassification, severity adjustment, score weighting, or true suppression.
- Add one synthetic fixture that proves the false positive and one fixture that preserves nearby true positives.
- Re-run at least the targeted tests for that rule family and confirm the grade delta on the real repo that exposed the issue.

## Analyst Decision Rules

Use these rules to decide whether the scanner is noisy or the repo is simply risky.

- If the finding title is directionally correct and `runtimeConfidence` already says `template-example`, `docs-example`, or `plugin-manifest`, prefer documentation and score changes over rule suppression.
- If a finding disappears when the source file is moved from `settings.json` to `settings.local.json`, that is probably a scope issue, not a matcher bug.
- If a finding depends on whether another file exists, such as `hooks/hooks.json` or a referenced hook implementation, fix it with cross-file context first.
- If the finding is driven by examples, tables, or fenced code blocks inside an agent prompt, narrow the heuristic to effective prompt prose instead of lowering severity globally.
- If the finding is a real secret, do not treat it as false-positive work even when it lives in docs or examples.

## Preferred Fix Order By Finding Kind

Use this order when deciding how to reduce scanner noise. It keeps accuracy work focused on the right intervention.

| Finding kind | First response | Acceptable change | Avoid |
| --- | --- | --- | --- |
| `active-runtime` | assume the finding may be real | matcher narrowing only if the behavior itself is misidentified | downgrading just because the repo author intended the risk |
| `project-local-optional` | check whether scope, exactness, or local-only behavior is overstated | severity or score adjustment tied to project-local scope | suppressing the finding entirely |
| `template-example` / `docs-example` | treat as shipped-risk inventory, not live runtime | relabel, reweight, and downgrade structural findings | hiding real secrets or collapsing the finding into nothing |
| `plugin-manifest` | verify whether the manifest is declarative or the implementation is the real risk | cross-file context, manifest-aware wording, implementation follow-through | applying shell-execution rules directly to manifest JSON |
| `hook-code` | ask whether the code performs one explicit risky behavior | add one narrow language-aware rule with tests | generic child-process or wrapper matching |
| agent capability findings | decide whether this is policy or a scanner bug | role-metadata heuristics, prompt-size normalization, or better wording | treating all privileged agents as false positives |

## Triage Rules For Current Reports

Use these rules when reading current AgentShield output before more source-aware scoring lands.

| If the finding comes from | Treat it as | What to verify manually |
| --- | --- | --- |
| `mcp-configs/`, `config/mcp/`, `configs/mcp/` with `runtimeConfidence: template-example` | template debt, not confirmed runtime exposure | whether the same MCP server is actually enabled in `mcp.json`, `.claude/mcp.json`, `.claude.json`, or active `settings.json` |
| `settings.local.json` with `runtimeConfidence: project-local-optional` | real but project-local exposure | whether the file is checked in, distributed to teammates, or only used locally |
| findings with `runtimeConfidence: docs-example` under `docs/`, `commands/`, translated bundles, or tutorial trees | risky example or instructional config, not confirmed active runtime exposure | whether the path is operational config or just reference content |
| findings with `runtimeConfidence: plugin-manifest` in `hooks/hooks.json` | active declarative manifest with lower confidence than executable hook code | whether the risk comes from manifest metadata or from the referenced script implementation |
| referenced shell hook files under `scripts/hooks/` or `skills/**/hooks/` | high-confidence executable logic | whether the scanner found risky shell behavior in the implementation itself |
| findings with `runtimeConfidence: hook-code` under `scripts/hooks/*.js` or similar | real implementation logic with narrow language-aware review only | whether the code path injects data back into Claude context, consumes transcript input, executes remote shell payloads through child processes, or does additional non-shell execution that still needs deeper language-aware rules |

## 1. What Triggers False Positives

### 1.1 MCP Templates Still Need Confidence-Aware Interpretation

Observed in:
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/mcp-configs/mcp-servers.json`

Current behavior:
- template findings are rewritten with template-aware titles
- severities are lowered relative to active runtime config
- findings now include `runtimeConfidence: "template-example"` in JSON, markdown, terminal, and HTML output
- non-secret template findings now score at `0.25x` relative to active runtime findings

Example findings:
- `Template defines risky MCP server: filesystem`
- `Template MCP server "vercel" connects to external URL`
- `Template MCP server "github" uses npx -y (auto-install)`

Why this still matters:
- the wording is now correct and the score impact is no longer equivalent to active runtime exposure
- in the refreshed `everything-claude-code` scan, `mcp-configs/mcp-servers.json` is still the single largest finding source, but the MCP category now lands at `68` instead of being pinned to `0`
- this is no longer a scoring bug, but it is still an interpretation problem because template catalogs remain visible and need manual runtime confirmation

### 1.2 Nested Documentation Trees Were Being Mistaken for Live Claude Roots

Observed in:
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/docs/zh-CN/CLAUDE.md`

Previous impact included translated docs under:
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/docs/zh-CN/agents/build-error-resolver.md`
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/docs/zh-CN/agents/security-reviewer.md`

Why this was a false positive:
- the localized docs bundle is not the repo's active runtime config
- once a nested `CLAUDE.md` is found, the scanner treats that subtree like a real Claude root and emits agent findings such as Bash access and escalation chain

Current status:
- fixed for the current example path set: docs/example trees that only carry `CLAUDE.md` guidance no longer turn the whole subtree into a live Claude root, but the standalone example `CLAUDE.md` file is still scanned
- the refreshed `everything-claude-code` scan now emits `0` findings under `docs/zh-CN/agents/*`, while still inventorying `docs/zh-CN/CLAUDE.md` as an example file

Remaining follow-up:
- broaden source-aware handling beyond the current `docs/`, `commands/`, `examples/`, `samples/`, `demo/`, `tutorial/`, `guide/`, `cookbook/`, and `playground/` path set if similar tutorial/example bundles appear under other top-level names
- keep docs-only example discovery narrow so only the standalone example file is added back, not the whole translated/example subtree

### 1.3 Example Passwords in Markdown Test Fixtures Were a Noisy False Positive

Observed in:
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/commands/kotlin-test.md`

Previous impact:
- the file triggered multiple critical `secrets-hardcoded-password-*` findings on example values like `SecureP@ss1` and `short`
- before the fix, `commands/kotlin-test.md` was one of the noisiest files in the scan with `5` critical findings by itself

Why it was a false positive:
- these are sample values in documentation/test instructions, not committed operational credentials
- unlike the placeholder DB URL fix, password-like sample literals in markdown code examples are not yet source-aware

Current status:
- fixed for markdown files in example-like paths such as `docs/`, `commands/`, `examples/`, `tutorials/`, and `demos/` when surrounding context clearly indicates examples or tests
- the refreshed `everything-claude-code` scan now emits `0` findings from `commands/kotlin-test.md`

Guardrails on the fix:
- non-doc markdown such as agent prompts still triggers the hardcoded-password rule
- doc files without example/test context still trigger the rule

### 1.4 Hook Plugin Manifests Needed Targeted False-Positive Suppression

Observed in:
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/hooks/hooks.json`

Previous impact:
- `hooks/hooks.json` used to trigger findings like `permissions-no-block`, even though it is a plugin hook manifest rather than a normal permissions/settings file
- session-start wrapper logic in that manifest triggered `hooks-silent-fail-*` on benign path-resolution logic such as `find ... 2>/dev/null | head -n 1`
- long wrapper commands in the manifest triggered `hooks-chained-commands-*` even though the complexity belonged to dispatch logic rather than the actual hook implementation

Why that was a false positive:
- plugin manifests are active in a different way than `settings.json`
- rule logic written for classic hook/settings layouts can overstate risk when applied directly to manifest JSON

Current status:
- fixed for direct manifest findings
- the refreshed scan now emits `0` findings from `hooks/hooks.json`

What remains open:
- non-shell hook implementations are now discovered, but they intentionally do not run through the shell-pattern hook rules
- the next step is language-aware review for `hook-code` files rather than more manifest resolution work

### 1.5 Exact Network Allow Entries Were Being Misread As Arbitrary Network Access

Observed in:
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/.claude/settings.local.json`

Previous impact:
- the file triggered four `permissions-permissive-Bash(curl ...)` findings for exact npmjs download-stat commands
- those entries were pinned to literal `https://api.npmjs.org/...` URLs and did not contain wildcards, shell expansion, or arbitrary host selection

Why it was a false positive:
- the rule text said "agent can make arbitrary HTTP requests," but the matched permission entries were fixed commands, not general curl access
- a pinned `curl` or `wget` command is still network exposure, but it is not the same thing as `Bash(curl *)` or a wildcard URL permission

Current status:
- fixed for exact `curl`/`wget` allow entries with literal URLs and no shell expansion
- the refreshed `everything-claude-code` scan now emits only one finding from `.claude/settings.local.json`: `permissions-no-deny-list`
- repo impact: `everything-claude-code` dropped from `96` findings / `C (65)` to `92` findings / `C (69)`

Guardrails on the fix:
- wildcard URLs like `Bash(curl https://api.example.com/*)` still flag as overly permissive
- dynamic network permissions using shell expansion or command substitution still flag
- unrestricted entries such as `Bash(curl *)`, `Bash(wget)`, `Bash(ssh *)`, and `Bash(scp *)` still flag through the network-permissions rules

### 1.6 Project-Local Missing-Deny Findings Were Overstated For Exact Allowlists

Observed in:
- `/Users/affoon/Documents/GitHub/basket-trader/launch-video/.claude/settings.local.json`

Previous impact:
- the file triggered `permissions-no-deny-list` at high severity
- its allowlist contained exact `ffprobe ... | python3 -c ...` commands pinned to local files, not wildcards or arbitrary shell access

Why it was severity inflation:
- `settings.local.json` is already project-local rather than repo-wide runtime config
- the allowlist was narrow and literal, so the old severity overstated the exposure compared with a broad allowlist or wildcard Bash permissions

Current status:
- fixed by downgrading `permissions-no-deny-list` to medium for `settings.local.json` files whose allowlists are entirely exact entries
- `basket-trader` now grades `A (98)` instead of `A (96)`
- broader project-local cases like `everything-claude-code/.claude/settings.local.json` still stay high when wildcard access remains present

Guardrails on the fix:
- wildcard entries such as `Bash(gh api:*)` still keep the finding at high severity
- dynamic entries using shell expansion or command substitution still keep the finding at high severity
- normal `settings.json` files still keep the original high-severity behavior

### 1.7 Defensive Security Review Content Was Being Misread As Prompt-Injection Surface

Observed in:
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/agents/security-reviewer.md`

Previous impact:
- the file triggered `agents-injection-surface-agents/security-reviewer.md`
- the match came from defensive checklist/examples, not an actual instruction for the agent to fetch or trust external content

Why it was a false positive:
- the old matcher used very broad patterns like `fetch.*url`, which also matched example code such as ``fetch(userProvidedUrl)``
- the agent is a security review workflow describing suspicious patterns to flag, not a prompt telling the agent to process hostile web content

Current status:
- fixed by tightening the matcher toward imperative/natural-language external-content instructions
- the refreshed `everything-claude-code` scan now emits `0` `agents-injection-surface` findings
- repo impact: `everything-claude-code` dropped from `92` findings / `C (69)` to `91` findings / `C (69)`

Guardrails on the fix:
- direct instructions like `Fetch URLs and parse HTML from web pages` still trigger
- explicit agent workflows that say to read user-provided input or process external content still trigger
- defensive examples, checklists, and code-pattern references no longer trigger by themselves

### 1.8 Explorer/Search Write Detection Was Reading Too Much Of The Prompt Body

Observed in:
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/agents/chief-of-staff.md`
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/agents/security-reviewer.md`
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/agents/database-reviewer.md`
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/agents/e2e-runner.md`
- `/Users/affoon/Documents/GitHub/PMX-backend/.claude/subagents/e2e-tester.json`
- `/Users/affoon/Documents/GitHub/PMX-backend/.claude/slash-commands/test-coverage.json`

Previous impact:
- the rule emitted `agents-explorer-write-*` for files that were not explorer/search agents at all
- the false positives were caused by generic workflow text such as `gog gmail search "is:unread"` or `Search for hardcoded secrets`
- `everything-claude-code` carried `4` spurious medium findings from this rule alone
- `PMX-backend` carried `2` more spurious medium findings on structured JSON configs

Why it was a false positive:
- the old heuristic scanned the entire file body for terms like `search`, `read-only`, or `readonly`
- many legitimate non-explorer agents mention search operations inside examples, commands, or checklists
- that is not the same thing as the agent's actual role being an explorer-style, read-mostly workflow

Current status:
- fixed by narrowing the heuristic to stronger role signals only: file path, structured `name`, structured `description`, and the lead intro text
- the scanner no longer treats later workflow examples or command snippets as explorer-role evidence
- repo impact:
  - `everything-claude-code`: `94` findings -> `90`
  - `PMX-backend`: `29` findings -> `27`
  - `basket-trader`: unchanged

Concrete before/after examples:

| File | Old trigger text | New interpretation |
| --- | --- | --- |
| `agents/chief-of-staff.md` | ``gog gmail search "is:unread" --json`` | command example only, not explorer role metadata |
| `agents/security-reviewer.md` | `Search for hardcoded secrets` | review workflow step, not an explorer/read-only agent |
| `.claude/slash-commands/test-coverage.json` | `Search coverage gaps and write tests` | procedural task description, not search-only role metadata |

Guardrails on the fix:
- explicit explorer roles such as `codebase explorer`, `read-only explorer`, or configs whose name/description/path says `explorer` still trigger
- the positive test coverage still includes body-intro cases like `Fast codebase explorer for searching files`
- Bash access and escalation-chain findings are unaffected; only the explorer-role inference was narrowed

### 1.9 Oversized Prompt Detection Was Counting Example Blocks As Live Prompt Text

Observed in:
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/agents/chief-of-staff.md`
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/agents/planner.md`

Previous impact:
- the rule emitted `agents-oversized-prompt-*` based on raw file size alone
- large fenced examples, output templates, and markdown tables pushed otherwise reasonable agent prompts over the `5000` character threshold

Why it was a false positive:
- embedded examples help users understand how to invoke the agent, but they are not the same as additional live prompt instructions
- `chief-of-staff.md` and `planner.md` were long mainly because of example-heavy markdown, not because the actual prose instructions were unusually large

Current status:
- fixed by switching the heuristic from raw file length to effective prompt size
- fenced code blocks and markdown tables are now discounted before applying the threshold
- repo impact:
  - `everything-claude-code`: `90` findings -> `88`
  - `agents/chief-of-staff.md` no longer emits `agents-oversized-prompt`
  - `agents/planner.md` no longer emits `agents-oversized-prompt`

What still flags, correctly:
- `agents/architect.md` still flags at `5514 effective characters (6291 raw)`
- `agents/code-reviewer.md` still flags at `6296 effective characters (8747 raw)`
- `agents/kotlin-reviewer.md` still flags at `5223 effective characters (6612 raw)`

Guardrails on the fix:
- genuinely large prose-heavy prompts still trigger even if they contain examples
- the rule still applies only to `agent-md` files, not `CLAUDE.md`
- evidence now shows both effective and raw size so users can see why a prompt still flags

## 2. What Gets Missed

### 2.1 Structured Slash Commands With `allowedTools` Were a Real Blind Spot

Observed in:
- `/Users/affoon/Documents/GitHub/PMX-backend/.claude/slash-commands/build-and-fix.json`
- `/Users/affoon/Documents/GitHub/PMX-backend/.claude/slash-commands/refactor-clean.json`
- `/Users/affoon/Documents/GitHub/PMX-backend/.claude/slash-commands/test-coverage.json`

Previous behavior:
- these files were discovered as `skill-md`
- they produced `0` findings despite explicit `allowedTools` entries containing `Bash`, `Write`, `Edit`, `Glob`, and `Grep`

Current status:
- fixed in this audit pass
- the scanner now treats structured JSON under `.claude/slash-commands/` as agent-like tool config for Bash, missing-tools, and escalation-style checks
- `PMX-backend` now emits `9` slash-command findings instead of `0`

Example new findings:
- `Slash command has Bash access: .claude/slash-commands/build-and-fix.json`
- `Slash command has full escalation chain: .claude/slash-commands/refactor-clean.json`

### 2.2 Manifest-Referenced Hook Implementations Are Now Discovered, And Non-Shell Analysis Has Started

Observed in:
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/scripts/hooks/session-start.js`
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/scripts/hooks/session-end.js`
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/scripts/hooks/evaluate-session.js`
- `/Users/affoon/Documents/GitHub/ECC/everything-claude-code/skills/continuous-learning-v2/hooks/observe.sh`

Current state:
- `discoverConfigFiles()` now resolves repo-local manifest targets into discovered files
- in `everything-claude-code`, that currently surfaces `20` `hook-code` files under `scripts/hooks/` plus `2` shell hook implementations
- shell implementations continue through existing hook rules
- non-shell `hook-code` now emits narrow language-aware findings for three explicit behaviors:
  - `output(...)` calls that inject additional content back into Claude context
  - direct transcript input access via `input.transcript_path`, `process.env.CLAUDE_TRANSCRIPT_PATH`, and equivalent language-specific accessors
  - remote downloads piped into `bash`/`sh` through child-process wrappers such as `spawnSync("bash", ["-lc", "curl ... | bash"])`

Current live findings from `everything-claude-code`:
- `scripts/hooks/session-start.js` now emits `hooks-code-context-output`
- `scripts/hooks/session-end.js` now emits `hooks-code-transcript-access`
- `scripts/hooks/evaluate-session.js` now emits `hooks-code-transcript-access`

Security-relevant behaviors still outside static coverage:
- non-shell wrappers that use `spawnSync`, `execFileSync`, or similar child-process execution are still quiet unless they also match the explicit context/transcript/remote-shell rules
- `observe.sh` parses stdin JSON, inspects `agent_id`, sources shared scripts, and writes observations under `~/.claude/homunculus`

### 2.3 Remaining Accuracy Work, With Concrete Examples

These are the highest-value follow-ups after the current false-positive fixes.

| Remaining work | Concrete example | Desired behavior |
| --- | --- | --- |
| Broader `hook-code` language-aware coverage | `scripts/hooks/post-edit-format.js`, `scripts/hooks/post-edit-typecheck.js`, `scripts/hooks/quality-gate.js` in `everything-claude-code` | keep generic `spawnSync` / `execFileSync` wrappers quiet unless they also do risky external I/O, context injection, or unsafe shell composition |
| Broader example-root classification beyond the current path set | synthetic tutorial/example bundles outside `docs/`, `commands/`, `examples/`, `samples/`, `demo/`, `tutorial/`, `guide/`, `cookbook/`, and `playground/` | keep obvious examples downgraded and labeled without misclassifying real runtime config |
| Skill prompt coverage | freeform `skill-md` prompts that are not structured slash-command JSON | analyze more of the real agent-like skill prompts without treating ordinary reference markdown as executable config |

## 3. Confidence and Scoring Improvements Needed

### 3.1 Runtime Confidence Now Covers Active, Project-Local, Example, Manifest, And Hook-Code Sources

Current output now includes `runtimeConfidence` on MCP findings:
- `active-runtime`
- `project-local-optional`
- `template-example`
- `docs-example`
- `plugin-manifest`
- `hook-code`

Current mapping:
- `mcp.json`, `.claude/mcp.json`, `.claude.json`, and active `settings.json` style MCP findings map to `active-runtime`
- `settings.local.json` MCP findings map to `project-local-optional`
- template catalogs such as `mcp-configs/` map to `template-example`
- docs and tutorial config such as `docs/guide/settings.json` map to `docs-example`
- declarative hook manifests such as `hooks/hooks.json` map to `plugin-manifest`
- manifest-resolved non-shell implementations such as `scripts/hooks/session-start.js` map to `hook-code`

This is the correct direction and should remain the baseline for future source-aware scoring.

### 3.2 Score Weighting Now Respects Template, Docs, Project-Local, And Manifest Confidence

Current behavior:
- non-secret `template-example` findings now score at `0.25x`
- non-secret `template-example` findings are also capped at `10` deduction points per file and score category
- non-secret `docs-example` findings now score at `0.25x`
- non-secret `project-local-optional` findings now score at `0.75x`
- non-secret `plugin-manifest` findings now score at `0.5x`
- `hook-code` findings currently stay at full weight, but the active rules there are intentionally narrow and language-aware
- committed real secrets still stay at full score weight even if they appear in a template file
- `everything-claude-code` still carries `51` template-example findings in the report, but now lands at `B (75)` with `mcp: 90` and `permissions: 83`
- `basket-trader` now lands at `A (99)` instead of `A (98)` because its `settings.local.json` findings are clearly marked project-local and slightly discounted in score weight
- the synthetic docs-example fixture now lands at `A (99)` instead of looking like a live broken runtime config
- the synthetic plugin-manifest fixture lands at `A (98)` with visible, but correctly contextualized, manifest findings

Current weighting:

| Source kind | Example | Current/default score weight |
| --- | --- | --- |
| `active-runtime` | `mcp.json`, `.claude/mcp.json`, active `settings.json` | `1.0x` |
| `project-local-optional` | `settings.local.json` | `0.75x` for structural non-secret findings, `1.0x` for committed real secrets |
| `template-example` | `mcp-configs/mcp-servers.json` | `0.25x` for structural findings, capped at `10` deduction points per file and score category, `1.0x` for committed real secrets |
| `docs-example` | `docs/guide/settings.json`, `commands/kotlin-test.md` | `0.25x` for structural findings, `1.0x` for committed real secrets |
| `plugin-manifest` | `hooks/hooks.json` | `0.5x` for structural findings, `1.0x` for committed real secrets |
| `hook-code` | `scripts/hooks/session-start.js` | `1.0x`, but current findings are narrow language-aware signals only |

Remaining follow-up:
- decide whether any future high-confidence `hook-code` rules should carry their own weighting, or whether rule severity alone is sufficient

### 3.3 Docs Examples And Plugin Manifests Now Get Source-Aware Wording

Current behavior:
- docs/example findings now emit `runtimeConfidence: docs-example`
- structural docs/example findings downgrade one severity level and render with `Example config: ...` titles
- plugin manifest findings now emit `runtimeConfidence: plugin-manifest`
- plugin manifest findings render with `Plugin hook manifest: ...` titles and manifest-aware descriptions
- non-shell hook implementations continue to emit `runtimeConfidence: hook-code`

Confirmed examples:
- synthetic `docs/guide/settings.json` now emits:
  - `Example config: Overly permissive allow rule: Bash(*)` with severity `high`
  - `Example config: No deny list configured` with severity `medium`
  - `Example config: No PreToolUse security hooks configured` with severity `low`
- synthetic `hooks/hooks.json` now emits:
  - `Plugin hook manifest: Hook sends data to external service`
  - `Plugin hook manifest: No Stop hooks for session-end verification`

Interpretation rule:
- docs/example findings are now visible but clearly presented as risky shipped guidance, not confirmed live runtime exposure
- plugin-manifest findings stay visible because the manifest is operational config, but they are now clearly distinguished from the referenced executable hook implementation

Remaining follow-up:
- expand example-path detection if tutorial/example bundles appear outside the current `docs/`, `commands/`, `examples/`, `samples/`, `demo/`, `tutorial/`, `guide/`, `cookbook/`, and `playground/` path set
- keep real committed secrets at full weight even when they appear in examples or manifests
- continue to prefer rule-specific suppression over blanket source-based hiding

### 3.4 Hook Confidence Now Distinguishes Definition From Implementation

Current behavior:
- declarative manifests emit `runtimeConfidence: plugin-manifest`
- shell implementations emit findings directly from executable hook logic
- non-shell implementations emit `runtimeConfidence: hook-code`
- non-shell `hook-code` remains outside shell-pattern scoring unless a language-aware rule matches

This is now the right baseline:
- manifest entries can stay visible without looking like direct shell execution
- executable shell hooks remain the highest-confidence hook findings
- non-shell hook implementations are visible as implementation logic, but only through narrow language-aware rules today: explicit context injection, transcript access, and remote shell payloads executed via child-process wrappers

Current output model:

| Hook source | Example | Confidence |
| --- | --- | --- |
| declarative manifest | `hooks/hooks.json` | medium, emitted as `plugin-manifest` |
| shell implementation | `skills/**/hooks/observe.sh`, `scripts/hooks/run-with-flags-shell.sh` | high |
| non-shell implementation | `scripts/hooks/session-start.js`, `scripts/hooks/session-end.js` | medium-high, emitted as `hook-code` and reviewed with narrow language-aware rules |
| missing-control inference | `hooks-no-pretooluse` emitted from a settings-only view with no companion manifest evidence | low until manifest references are resolved |

## 4. Fixed During This Audit

These issues were present earlier in the audit cycle and are now fixed:
- MCP template findings now emit a first-class `runtimeConfidence` field and render it in JSON, markdown, terminal, and HTML output
- score weighting now discounts non-secret `template-example` findings while preserving full weight for committed secrets
- `settings.local.json` findings now emit `runtimeConfidence: project-local-optional`, and non-secret project-local findings score at `0.75x`
- structured `.claude/slash-commands/*.json` files with `allowedTools` are now analyzed for Bash access and escalation chains
- docs-only nested `CLAUDE.md` roots under `docs/` are no longer treated as live Claude roots unless runtime config companions exist
- generated `.dmux/worktrees/...` mirrors are excluded from discovery
- hook manifests such as `hooks/hooks.json` no longer trigger the `permissions-no-block` settings-only finding
- hook manifests such as `hooks/hooks.json` no longer trigger wrapper-style `hooks-silent-fail-*` and `hooks-chained-commands-*` findings
- missing-hook inference now consults companion plugin manifests before reporting `hooks-no-pretooluse`
- hook manifests now resolve repo-local executable targets into discovered shell `hook-script` and non-shell `hook-code` files
- docs/example findings now emit `runtimeConfidence: docs-example`, downgrade structural severity one level, and render with example-aware titles/descriptions
- plugin manifest findings now emit `runtimeConfidence: plugin-manifest` and render with manifest-aware titles/descriptions
- manifest-resolved `hook-code` now emits targeted findings for explicit `output(...)` context injection, transcript input access, and remote shell payloads executed through child-process wrappers instead of staying inventory-only
- markdown example/test passwords in `docs/` and `commands/` no longer trigger hardcoded-password findings when the surrounding context is clearly instructional
- placeholder DB connection strings like `postgres://user:pass@host:5432/db` no longer raise critical secret findings
- benign `/dev/null` probe patterns in hooks are now suppressed and same-line duplicates are deduplicated

## Follow-Up Queue

- Expand language-aware analysis for manifest-resolved `hook-code` beyond explicit context injection, transcript access, and remote shell payloads without reintroducing wrapper noise
- Broaden example-path detection if risky tutorial bundles appear outside the current `docs/`, `commands/`, `examples/`, `samples/`, `demo/`, `tutorial/`, `guide/`, `cookbook/`, and `playground/` path set
- Revisit `plugin-manifest` severity only if future live repos show persistent manifest-only noise that survives the current wording and score weighting

## Rule-Change Acceptance Criteria

A false-positive fix is ready to land when it meets all of the following:

- It reduces noise in a real repo scan that previously demonstrated the problem.
- It does not hide committed secrets or obvious execution behavior.
- It preserves or improves `runtimeConfidence` clarity instead of collapsing multiple source kinds together.
- It comes with targeted regression tests for both the false-positive case and the closest true-positive neighbor.
- It improves the operator reading experience in the report, not just the raw finding count.

## False-Positive Taxonomy

Use this taxonomy when classifying a noisy finding. It keeps audit notes consistent and makes it easier to choose the right fix.

| Type | Meaning | Typical fix | Example from this audit |
| --- | --- | --- | --- |
| matcher bug | the rule matched the wrong behavior entirely | narrow the matcher and add true-positive guard tests | `agents-explorer-write` matching generic workflow text |
| source-confidence inflation | the finding is directionally right but presented like active runtime | add or refine `runtimeConfidence`, wording, and score weight | MCP template catalogs under `mcp-configs/` |
| severity inflation | the finding is real but the severity overstates likely impact | lower severity only for the narrower source or narrower pattern | `permissions-no-deny-list` on exact `settings.local.json` allowlists |
| missing context | the rule lacks cross-file or structural evidence | use manifest, companion config, or referenced implementation context | `hooks-no-pretooluse` before manifest awareness |
| presentation noise | the finding is technically correct but explained poorly for operators | rewrite title/description before touching detection | `Plugin hook manifest: ...` wording |
| coverage miss | risky behavior is absent from static detection | add a narrow new rule and prove it does not reopen old noise | `hook-code` remote shell payloads via child-process wrappers |

## Repo Audit Worksheet

Use this worksheet when reviewing a new scan. Copy it into an issue or PR description if the scan is noisy.

| Question | Record |
| --- | --- |
| repo scanned | |
| date | |
| files scanned | |
| total findings / grade | |
| top 5 files by finding count | |
| findings by `runtimeConfidence` | |
| top source kind causing noise | |
| likely false positives | |
| likely real misses | |
| suspected severity inflation | |
| proposed fix type | matcher / confidence / severity / context / docs only |
| real-repo proof path | |
| synthetic fixture added | |
| score delta after fix | |

Recommended interpretation:
- If the top noisy file is template- or docs-heavy, start with confidence modeling.
- If the top noisy file is active runtime config, assume the findings are more likely to be real until proven otherwise.
- If the issue disappears only when a companion file is present, classify it as missing context, not a bad matcher.

## False-Positive Issue Template

Use this template when opening a scanner-accuracy issue. It keeps future audit work reproducible.

```md
## False-Positive Report

- Repo:
- Scanner commit/version:
- File:
- Finding ID(s):
- Severity:
- runtimeConfidence:

### Why this looks wrong
- [fill in]

### Evidence
- real repo reproduction:
- minimal synthetic reproduction:
- nearby true-positive that must keep working:

### Preferred fix shape
- matcher narrowing / confidence / severity / score / docs only

### Notes
- [fill in]
```

Required evidence before treating it as a rule bug:
- one real repo reproduction
- one minimal fixture
- one nearby true-positive guard case
- explanation for why `runtimeConfidence` and current wording are still insufficient

## Release Gate For Accuracy Changes

Before including false-positive work in a release, verify all of the following:

- The affected rule family has targeted regression coverage.
- At least one real repo used in this audit shows a measurable improvement.
- No committed-secret detection regressed in docs, examples, manifests, or local settings.
- The fix improves report readability through title, severity, or `runtimeConfidence`, not only raw count reduction.
- The audit note and README guidance are updated so operators understand the new behavior.

## Recommended Documentation Surface

To keep user expectations aligned with current scanner behavior, the main docs should continue to say:
- `runtimeConfidence` is now emitted for MCP findings, `settings.local.json`, docs/examples, plugin manifests, and manifest-resolved non-shell hook code
- template findings are useful evidence of shipped risk, not proof of active enablement
- docs/example findings are intentionally visible as risky shipped guidance, but they are downgraded and labeled as examples rather than active runtime exposure
- template MCP catalogs and plugin hook manifests still need manual interpretation
- manifest-resolved `hook-code` files are now discovered and emit targeted findings for explicit context injection, transcript handling, and remote shell payloads, but broader language-aware implementation coverage is still pending
- docs-only example trees are now inventoried as standalone example `CLAUDE.md` files, while noisy nested subtrees remain suppressed unless runtime companions exist
- example bundles outside the current `docs/`, `commands/`, `examples/`, `samples/`, `demo/`, `tutorial/`, `guide/`, `cookbook/`, and `playground/` heuristics may still need manual interpretation until broader example-root classification is added
- the audit document is the source of truth for the remaining accuracy caveats, which are now mainly about broader `hook-code` analysis rather than missing source metadata
