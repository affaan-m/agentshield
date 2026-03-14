# AgentShield v1.4.0

This release focuses on scan accuracy, source-aware scoring, and safer interpretation of example and manifest-heavy repositories.

## Highlights

- Added first-class source confidence for `docs-example`, `plugin-manifest`, and `hook-code` findings alongside existing `template-example` and `project-local-optional` output.
- Downgraded structural findings from docs/example config and rewrote report wording so risky shipped examples no longer read like confirmed active runtime exposure.
- Extended example classification beyond `docs/` and `commands/` to `examples/`, `example/`, `samples/`, and `sample/`.
- Re-added standalone docs/example `CLAUDE.md` files to scanning so real secrets in example guidance are not silently missed.
- Improved hook analysis for manifest-resolved non-shell implementations, including explicit context injection, transcript access, and remote shell payloads executed via child-process wrappers.
- Tightened hook-manifest handling so declarative config is distinguished from executable hook implementations.
- Expanded structured agent coverage for `.claude/subagents/*.json` and `.claude/slash-commands/*.json`.
- Refined report scoring so template, project-local, docs/example, and plugin-manifest findings no longer inflate grades like active runtime exposure.

## Validation

- `npm run typecheck`
- `npm test`
- `npm run build`
- live rescans of:
  - `everything-claude-code`
  - `PMX-backend`
  - `basket-trader`

## Upgrade Notes

- The GitHub Action bundle under `dist/` must be committed before tagging a release.
- The release workflow verifies that the pushed tag matches `package.json`, reruns the full gate, rebuilds `dist/`, and refuses to publish if generated action artifacts are out of sync.
- Recommended version bump for this train: `1.4.0`.
