import { describe, expect, it } from "vitest";
import { skillRules } from "../../src/rules/skills.js";
import type { ConfigFile } from "../../src/types.js";

function makeSkill(
  content: string,
  path = "skills/self-improver.md"
): ConfigFile {
  return {
    path,
    type: "skill-md",
    content,
  };
}

function runRules(files: ReadonlyArray<ConfigFile>) {
  return files.flatMap((file) =>
    skillRules.flatMap((rule) => rule.check(file, files))
  );
}

describe("skillRules", () => {
  it("does not flag a skill with observation, feedback, version, and rollback metadata", () => {
    const findings = runRules([
      makeSkill(`---
name: self-improver
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---

# Self Improver
`),
    ]);

    expect(findings).toHaveLength(0);
  });

  it("flags skills missing observation and feedback hooks", () => {
    const findings = runRules([
      makeSkill(`---
name: self-improver
version: 2.0.0
metadata:
  rollback_strategy: revert-to-last-stable
---

# Self Improver
`),
    ]);

    expect(findings.some((finding) => finding.id.includes("missing-telemetry"))).toBe(true);
    expect(findings.some((finding) => finding.description.includes("observation hooks"))).toBe(true);
    expect(findings.some((finding) => finding.description.includes("feedback hooks"))).toBe(true);
  });

  it("flags skills missing version or rollback metadata", () => {
    const findings = runRules([
      makeSkill(`---
name: self-improver
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
---

# Self Improver
`),
    ]);

    expect(findings.some((finding) => finding.id.includes("missing-governance"))).toBe(true);
    expect(findings.some((finding) => finding.description.includes("version metadata"))).toBe(true);
    expect(findings.some((finding) => finding.description.includes("rollback metadata"))).toBe(true);
  });

  it("accepts body sections for observation, feedback, and rollback markers", () => {
    const findings = runRules([
      makeSkill(`---
name: self-improver
version: 2.1.0
metadata:
  rollback_strategy: revert-to-last-stable
---

## Observation Hooks
- persist run metrics

## Feedback
- capture explicit user ratings

## Rollback
- revert to previous version if score regresses
`),
    ]);

    expect(findings).toHaveLength(0);
  });

  it("ignores skill-side history json files", () => {
    const files = [
      makeSkill(`---
name: self-improver
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---
`),
      {
        path: "skills/self-improver.history.json",
        type: "skill-md",
        content: JSON.stringify([{ success: true, feedbackScore: 5 }]),
      } satisfies ConfigFile,
    ];

    const findings = runRules(files);
    expect(findings).toHaveLength(0);
  });

  it.each([
    [
      "metadata.observation_hooks",
      "  observation_hooks:\n    - scripts/observe.sh",
      "",
    ],
    [
      "metadata.observe_hook",
      "  observe_hook: scripts/observe.sh",
      "",
    ],
    [
      "body observation heading",
      "",
      "## Observation\n- persist telemetry",
    ],
  ])("accepts %s as observation instrumentation", (_label, metadataMarker, bodyMarker) => {
    const findings = runRules([
      makeSkill(`---
name: self-improver
version: 2.0.0
metadata:
${metadataMarker ? `${metadataMarker}\n` : ""}  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---

${bodyMarker}
`),
    ]);

    expect(findings.some((finding) => finding.id.includes("missing-telemetry"))).toBe(false);
  });

  it.each([
    [
      "metadata.feedback_hooks",
      "  feedback_hooks:\n    - scripts/feedback.sh",
      "",
    ],
    [
      "metadata.feedback_hook",
      "  feedback_hook: scripts/feedback.sh",
      "",
    ],
    [
      "body feedback heading",
      "",
      "## Feedback\n- capture user scores",
    ],
  ])("accepts %s as feedback instrumentation", (_label, metadataMarker, bodyMarker) => {
    const findings = runRules([
      makeSkill(`---
name: self-improver
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
${metadataMarker ? `${metadataMarker}\n` : ""}  rollback_strategy: revert-to-last-stable
---

${bodyMarker}
`),
    ]);

    expect(findings.some((finding) => finding.id.includes("missing-telemetry"))).toBe(false);
  });

  it.each([
    ["frontmatter version", "version: 2.0.0", ""],
    ["metadata version", "", "  version: 2.0.0"],
  ])("accepts %s for version metadata", (_label, frontmatterVersion, metadataVersion) => {
    const findings = runRules([
      makeSkill(`---
name: self-improver
${frontmatterVersion}
metadata:
${metadataVersion ? `${metadataVersion}\n` : ""}  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---
`),
    ]);

    expect(findings.some((finding) => finding.id.includes("missing-governance"))).toBe(false);
  });

  it.each([
    ["rollback_strategy", "rollback_strategy: revert-to-last-stable"],
    ["rollback_metadata", "rollback_metadata:\n  previous_version: 1.9.0"],
    ["body rollback heading", ""],
  ])("accepts %s for rollback coverage", (_label, rollbackBlock) => {
    const findings = runRules([
      makeSkill(`---
name: self-improver
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
${rollbackBlock ? `  ${rollbackBlock.replace(/\n/g, "\n  ")}` : ""}
---

${rollbackBlock ? "" : "## Rollback\n- revert to 1.9.0"}
`),
    ]);

    expect(findings.some((finding) => finding.id.includes("missing-governance"))).toBe(false);
  });

  it.each([
    ["missing observation", `---
name: self-improver
version: 2.0.0
metadata:
  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---
`, "observation hooks"],
    ["missing feedback", `---
name: self-improver
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
  rollback_strategy: revert-to-last-stable
---
`, "feedback hooks"],
    ["missing both", `---
name: self-improver
version: 2.0.0
metadata:
  rollback_strategy: revert-to-last-stable
---
`, "observation hooks and feedback hooks"],
    ["missing version", `---
name: self-improver
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---
`, "version metadata"],
  ])("reports %s precisely", (_label, content, expectedEvidence) => {
    const findings = runRules([makeSkill(content)]);
    expect(findings.some((finding) => finding.evidence?.includes(expectedEvidence))).toBe(true);
  });

  it.each([
    ["frontmatter name", `---
name: custom-skill
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
---
`, "custom-skill"],
    ["path stem fallback", `---
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
---
`, "self-improver"],
    ["governance title", `---
name: self-improver
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
---
`, "Skill is missing version metadata and rollback metadata"],
    ["telemetry title", `---
name: self-improver
version: 2.0.0
metadata:
  rollback_strategy: revert-to-last-stable
---
`, "Skill is missing observation hooks and feedback hooks"],
  ])("formats %s correctly", (_label, content, expectedText) => {
    const findings = runRules([makeSkill(content)]);
    expect(findings.some((finding) => finding.title.includes(expectedText) || finding.description.includes(expectedText))).toBe(true);
  });
});
