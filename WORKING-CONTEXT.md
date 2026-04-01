# Working Context

Last updated: 2026-03-31

## Purpose

AgentShield is the security scanner and supply-chain defense layer for agent configurations and related ECC surfaces.

## Current Truth

- Default branch: `main`
- CI and self-scan posture are already present and should remain green
- Primary role in the wider ECC program:
  - keep the scanner trustworthy
  - feed supply-chain and configuration guardrails back into ECC and ECC Tools

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
