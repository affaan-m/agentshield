import { describe, expect, it } from "vitest";
import { analyzeSkillHealth } from "../../src/skills/health.js";
import type { ConfigFile } from "../../src/types.js";

function makeFile(
  path: string,
  content: string,
  type: ConfigFile["type"] = "skill-md"
): ConfigFile {
  return { path, content, type };
}

describe("analyzeSkillHealth", () => {
  it("returns undefined when no skills are present", () => {
    const result = analyzeSkillHealth([
      makeFile("settings.json", "{}", "settings-json"),
    ]);

    expect(result).toBeUndefined();
  });

  it("computes skill health from matching execution history", () => {
    const result = analyzeSkillHealth([
      makeFile(
        "skills/self-improver.md",
        `---
name: self-improver
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---
`
      ),
      makeFile(
        "skills/self-improver.history.json",
        JSON.stringify([
          { success: true, feedbackScore: 5 },
          { status: "completed", rating: 4 },
          { status: "failed", rating: 2 },
        ])
      ),
    ]);

    expect(result?.totalSkills).toBe(1);
    expect(result?.observedSkills).toBe(1);
    expect(result?.averageScore).toBe(68);
    expect(result?.skills[0].status).toBe("at-risk");
    expect(result?.skills[0].observedRuns).toBe(3);
    expect(result?.skills[0].historyFiles).toContain("skills/self-improver.history.json");
  });

  it("ignores unrelated history files from other skills", () => {
    const result = analyzeSkillHealth([
      makeFile(
        "skills/self-improver.md",
        `---
name: self-improver
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---
`
      ),
      makeFile(
        "skills/other-skill.history.json",
        JSON.stringify([{ success: false, feedbackScore: 1 }])
      ),
    ]);

    expect(result?.skills[0].observedRuns).toBe(0);
    expect(result?.skills[0].status).toBe("unobserved");
  });

  it.each([
    ["success boolean", JSON.stringify([{ success: true }]), 1],
    ["succeeded boolean", JSON.stringify([{ succeeded: true }]), 1],
    ["passed boolean", JSON.stringify([{ passed: true }]), 1],
    ["completed status", JSON.stringify([{ status: "completed" }]), 1],
    ["failed status", JSON.stringify([{ status: "failed" }]), 0],
  ])("understands %s history records", (_label, historyContent, expectedSuccessPct) => {
    const result = analyzeSkillHealth([
      makeFile(
        "skills/self-improver.md",
        `---
name: self-improver
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---
`
      ),
      makeFile("skills/self-improver.history.json", historyContent),
    ]);

    expect(result?.skills[0].successRate).toBe(expectedSuccessPct);
  });

  it.each([
    ["rating 1-5", JSON.stringify([{ success: true, rating: 4 }]), 4],
    ["score 0-100", JSON.stringify([{ success: true, score: 80 }]), 4],
    ["boolean feedback", JSON.stringify([{ success: true, feedback: true }]), 5],
    ["nested feedback rating", JSON.stringify([{ success: true, userFeedback: { rating: 3 } }]), 3],
    ["nested positive flag", JSON.stringify([{ success: true, userFeedback: { positive: false } }]), 1],
  ])("normalizes %s feedback", (_label, historyContent, expectedFeedback) => {
    const result = analyzeSkillHealth([
      makeFile(
        "skills/self-improver.md",
        `---
name: self-improver
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---
`
      ),
      makeFile("skills/self-improver.feedback.json", historyContent),
    ]);

    expect(result?.skills[0].averageFeedback).toBe(expectedFeedback);
  });

  it("reads runs from wrapped history arrays", () => {
    const result = analyzeSkillHealth([
      makeFile(
        "skills/self-improver.md",
        `---
name: self-improver
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---
`
      ),
      makeFile(
        "skills/self-improver.metrics.json",
        JSON.stringify({
          runs: [
            { success: true, rating: 5 },
            { success: false, rating: 2 },
          ],
        })
      ),
    ]);

    expect(result?.skills[0].observedRuns).toBe(2);
    expect(result?.skills[0].averageFeedback).toBe(3.5);
  });

  it.each([
    ["history", { history: [{ success: true }] }],
    ["executions", { executions: [{ success: true }] }],
    ["observations", { observations: [{ success: true }] }],
    ["events", { events: [{ success: true }] }],
    ["entries", { entries: [{ success: true }] }],
  ])("reads wrapped %s arrays", (_label, payload) => {
    const result = analyzeSkillHealth([
      makeFile(
        "skills/self-improver.md",
        `---
name: self-improver
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---
`
      ),
      makeFile("skills/self-improver.history.json", JSON.stringify(payload)),
    ]);

    expect(result?.skills[0].observedRuns).toBe(1);
  });

  it.each([
    ["healthy", [{ success: true, rating: 5 }], "healthy"],
    ["watch", [{ success: true, rating: 1 }], "watch"],
    ["at-risk", [{ success: false, rating: 1 }], "at-risk"],
    ["unobserved", [{ note: "ignored" }], "unobserved"],
  ])("assigns %s status correctly", (_label, records, expectedStatus) => {
    const result = analyzeSkillHealth([
      makeFile(
        "skills/self-improver.md",
        `---
name: self-improver
version: 2.0.0
metadata:
  observation_hooks:
    - scripts/observe.sh
  feedback_hooks:
    - scripts/feedback.sh
  rollback_strategy: revert-to-last-stable
---
`
      ),
      makeFile("skills/self-improver.feedback.json", JSON.stringify(records)),
    ]);

    expect(result?.skills[0].status).toBe(expectedStatus);
  });
});
