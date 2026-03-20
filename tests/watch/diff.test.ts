import { describe, it, expect } from "vitest";
import {
  fingerprintFinding,
  createBaseline,
  diffBaseline,
} from "../../src/watch/diff.js";
import type { Finding, SecurityScore } from "../../src/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "test-rule",
    severity: "medium",
    category: "permissions",
    title: "Test finding",
    description: "A test finding",
    file: "settings.json",
    evidence: "some evidence",
    ...overrides,
  };
}

function makeScore(overrides: Partial<SecurityScore> = {}): SecurityScore {
  return {
    grade: "B",
    numericScore: 80,
    breakdown: {
      secrets: 0,
      permissions: 1,
      hooks: 0,
      mcp: 0,
      agents: 0,
    },
    ...overrides,
  };
}

describe("fingerprintFinding", () => {
  it("generates a stable fingerprint from id, file, and evidence", () => {
    const finding = makeFinding({
      id: "SEC-001",
      file: "settings.json",
      evidence: "allow: Bash(*)",
    });
    const fp = fingerprintFinding(finding);
    expect(fp).toBe("SEC-001::settings.json::allow: Bash(*)");
  });

  it("handles missing evidence", () => {
    const finding = makeFinding({
      id: "SEC-002",
      file: "mcp.json",
      evidence: undefined,
    });
    const fp = fingerprintFinding(finding);
    expect(fp).toBe("SEC-002::mcp.json::");
  });

  it("produces different fingerprints for different findings", () => {
    const f1 = makeFinding({ id: "A", file: "a.json", evidence: "x" });
    const f2 = makeFinding({ id: "B", file: "b.json", evidence: "y" });
    expect(fingerprintFinding(f1)).not.toBe(fingerprintFinding(f2));
  });

  it("produces same fingerprint regardless of other fields", () => {
    const f1 = makeFinding({ id: "A", file: "a.json", evidence: "x", severity: "critical" });
    const f2 = makeFinding({ id: "A", file: "a.json", evidence: "x", severity: "low" });
    expect(fingerprintFinding(f1)).toBe(fingerprintFinding(f2));
  });
});

describe("createBaseline", () => {
  it("creates a baseline with timestamp and finding IDs", () => {
    const findings = [
      makeFinding({ id: "R1", file: "a.json", evidence: "ev1" }),
      makeFinding({ id: "R2", file: "b.json", evidence: "ev2" }),
    ];
    const score = makeScore({ numericScore: 75 });

    const baseline = createBaseline(findings, score);

    expect(baseline.findings).toEqual(findings);
    expect(baseline.score).toEqual(score);
    expect(baseline.findingIds.size).toBe(2);
    expect(baseline.findingIds.has("R1::a.json::ev1")).toBe(true);
    expect(baseline.findingIds.has("R2::b.json::ev2")).toBe(true);
    expect(baseline.timestamp).toBeTruthy();
  });

  it("handles empty findings", () => {
    const baseline = createBaseline([], makeScore());
    expect(baseline.findings).toEqual([]);
    expect(baseline.findingIds.size).toBe(0);
  });
});

describe("diffBaseline", () => {
  it("detects new findings", () => {
    const baseline = createBaseline(
      [makeFinding({ id: "R1", file: "a.json", evidence: "ev1" })],
      makeScore({ numericScore: 90 })
    );

    const currentFindings = [
      makeFinding({ id: "R1", file: "a.json", evidence: "ev1" }),
      makeFinding({ id: "R2", file: "b.json", evidence: "ev2", severity: "high" }),
    ];
    const currentScore = makeScore({ numericScore: 75 });

    const drift = diffBaseline(baseline, currentFindings, currentScore);

    expect(drift.newFindings).toHaveLength(1);
    expect(drift.newFindings[0].id).toBe("R2");
    expect(drift.resolvedFindings).toHaveLength(0);
    expect(drift.isRegression).toBe(true);
    expect(drift.scoreDelta).toBe(-15);
  });

  it("detects resolved findings", () => {
    const baseline = createBaseline(
      [
        makeFinding({ id: "R1", file: "a.json", evidence: "ev1" }),
        makeFinding({ id: "R2", file: "b.json", evidence: "ev2" }),
      ],
      makeScore({ numericScore: 70 })
    );

    const currentFindings = [
      makeFinding({ id: "R1", file: "a.json", evidence: "ev1" }),
    ];
    const currentScore = makeScore({ numericScore: 85 });

    const drift = diffBaseline(baseline, currentFindings, currentScore);

    expect(drift.newFindings).toHaveLength(0);
    expect(drift.resolvedFindings).toHaveLength(1);
    expect(drift.resolvedFindings[0].id).toBe("R2");
    expect(drift.isRegression).toBe(false);
    expect(drift.scoreDelta).toBe(15);
  });

  it("detects critical findings flag", () => {
    const baseline = createBaseline([], makeScore({ numericScore: 100 }));
    const currentFindings = [
      makeFinding({ id: "R1", file: "a.json", evidence: "ev", severity: "critical" }),
    ];
    const currentScore = makeScore({ numericScore: 75 });

    const drift = diffBaseline(baseline, currentFindings, currentScore);

    expect(drift.hasCritical).toBe(true);
    expect(drift.isRegression).toBe(true);
  });

  it("reports no regression when no changes", () => {
    const findings = [makeFinding({ id: "R1", file: "a.json", evidence: "ev1" })];
    const score = makeScore({ numericScore: 80 });
    const baseline = createBaseline(findings, score);

    const drift = diffBaseline(baseline, findings, score);

    expect(drift.newFindings).toHaveLength(0);
    expect(drift.resolvedFindings).toHaveLength(0);
    expect(drift.isRegression).toBe(false);
    expect(drift.scoreDelta).toBe(0);
    expect(drift.hasCritical).toBe(false);
  });

  it("reports regression on score drop even without new findings", () => {
    const findings = [makeFinding({ id: "R1", file: "a.json", evidence: "ev1" })];
    const baseline = createBaseline(findings, makeScore({ numericScore: 80 }));

    // Same findings but lower score (e.g., due to scoring weight changes)
    const drift = diffBaseline(baseline, findings, makeScore({ numericScore: 70 }));

    expect(drift.isRegression).toBe(true);
    expect(drift.scoreDelta).toBe(-10);
  });

  it("handles simultaneous new and resolved findings", () => {
    const baseline = createBaseline(
      [
        makeFinding({ id: "R1", file: "a.json", evidence: "ev1" }),
        makeFinding({ id: "R2", file: "b.json", evidence: "ev2" }),
      ],
      makeScore({ numericScore: 70 })
    );

    const currentFindings = [
      makeFinding({ id: "R1", file: "a.json", evidence: "ev1" }),
      makeFinding({ id: "R3", file: "c.json", evidence: "ev3" }),
    ];
    const currentScore = makeScore({ numericScore: 72 });

    const drift = diffBaseline(baseline, currentFindings, currentScore);

    expect(drift.newFindings).toHaveLength(1);
    expect(drift.newFindings[0].id).toBe("R3");
    expect(drift.resolvedFindings).toHaveLength(1);
    expect(drift.resolvedFindings[0].id).toBe("R2");
    expect(drift.scoreDelta).toBe(2);
    expect(drift.isRegression).toBe(true); // new findings = regression
  });
});
