# Working Context

Last updated: 2026-04-08

## Purpose

AgentShield is the security scanner and supply-chain defense layer for agent configurations and related ECC surfaces.

## Current Truth

- Default branch: `main`
- CI and self-scan posture are already present and should remain green
- Primary role in the wider ECC program:
  - keep the scanner trustworthy
  - feed supply-chain and configuration guardrails back into ECC and ECC Tools
- The CVE-aware MCP rules, MCP tool-poisoning detection, runtime monitor, and org-policy surfaces are already present on `main`

## Current Constraints

- Security regressions take priority over feature work.
- Findings and signatures should stay grounded in reproducible repo behavior.

## Active Queues

- preserve green CI and self-scan coverage
- harden rule coverage for shipped ECC surfaces
- inform ECC Tools and ECC merge policy with concrete scanner learnings

## Interfaces

- Public truth: GitHub issues and PRs
- Internal execution truth: linked Linear items when security work is actively scheduled
- Current linked Linear items:
  - `ECC-206` ecosystem CI baseline
  - `ECC-208` context hygiene

## Update Rule

Keep only the live scanner, release, and integration context here. Historical investigation detail belongs in repo docs or dated snapshots.

## Latest Execution Notes

- 2026-04-08: Finished the lingering repo-tooling/security maintenance lane directly on `main`.
- Landed the transitive `vite` patch bump (`7.3.1 -> 7.3.2`) that was still sitting in open PR `#46`.
- Completed the missing ESLint 9 flat-config migration:
  - added checked-in `eslint.config.mjs`
  - added TypeScript-aware lint tooling (`@eslint/js`, `typescript-eslint`, `globals`)
  - fixed the handful of real regex/annotation lint findings in shipped source instead of weakening the ruleset
- Validation status for that lane:
  - full test suite: green
  - typecheck: green
  - lint: green
  - build: green
  - CLI smoke (`node dist/index.js --help`): green
- 2026-04-05: Implemented prompt-defense posture audit coverage directly on `main` for issue `#45`.
- Added a new built-in `prompt-defense-posture` rule covering 12 missing-defense checks for real prompt surfaces (`CLAUDE.md`, agent prompts, and `.claude/rules/*` markdown), while intentionally excluding generic `context-md` files to avoid noisy findings against archival or planning docs.
- Validation status for that lane:
  - targeted rule/discovery tests: green
  - typecheck: green
  - lint: green
- 2026-04-05: Re-audited the stale feature branches:
  - `feat/cve-db-and-mcp-poisoning`
  - `feat/issue-14-runtime-monitor`
  - `feat/issue-17-org-policy`
- Result: their core capabilities are already represented on `main`, so they are no longer merge candidates. Future cleanup should prune or archive those branches rather than replaying them.
- 2026-04-05: Re-audited the remaining old release branches:
  - `feat/v1.6.0-false-positives`
  - `release/v1.8.0`
- Result: both were behind `main` and only carried older release/review variants of fixes already merged separately. They should be pruned rather than treated as pending feature work.
