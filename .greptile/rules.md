## Review Priorities

- Focus on bugs, security issues, false-positive reductions, and backwards compatibility for the CLI and GitHub Action.
- Prefer high-signal feedback over style nitpicks. This repo already has automated formatting and type/test coverage for most routine issues.
- Treat `dist/**` as generated output. Only flag it when a source change should have updated the generated artifact surface or when the committed output appears inconsistent with `src/` or `action.yml`.

## Workflow Expectations

- For GitHub Actions changes, verify least-privilege permissions, correct npm caching, and that CI runs on both `push` and `pull_request`.
- CI changes should keep Node 18, 20, and 22 covered unless the repository's engine support changes.

## Product-Specific Guidance

- AgentShield is a security scanner. Flag changes that could silently reduce rule coverage, weaken severity handling, or make scans less deterministic.
- For scanner, baseline, and reporter changes, prioritize correctness of findings and output compatibility over refactor suggestions.
