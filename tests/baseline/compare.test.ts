import { describe, it, expect, afterEach } from "vitest";
import { writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  fingerprintFinding,
  saveBaseline,
  loadBaseline,
  compareBaseline,
  evaluateGate,
  renderComparison,
  renderGateResult,
} from "../../src/baseline/compare.js";
import type { Finding, SecurityScore } from "../../src/types.js";
import type { SerializedBaseline } from "../../src/baseline/types.js";

const FIXTURES_DIR = join(process.cwd(), "tests", "baseline", "__fixtures__");

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
    breakdown: { secrets: 0, permissions: 1, hooks: 0, mcp: 0, agents: 0 },
    ...overrides,
  };
}

function makeBaseline(overrides: Partial<SerializedBaseline> = {}): SerializedBaseline {
  return {
    version: 1,
    timestamp: "2026-03-20T10:00:00.000Z",
    score: makeScore({ numericScore: 80 }),
    findings: [
      {
        id: "R1",
        severity: "medium",
        category: "permissions",
        title: "Finding 1",
        file: "a.json",
        evidence: "ev1",
        fingerprint: "R1::a.json::ev1",
      },
    ],
    ...overrides,
  };
}

function setup(): void {
  if (existsSync(FIXTURES_DIR)) {
    rmSync(FIXTURES_DIR, { recursive: true, force: true });
  }
  mkdirSync(FIXTURES_DIR, { recursive: true });
}

function cleanup(): void {
  if (existsSync(FIXTURES_DIR)) {
    rmSync(FIXTURES_DIR, { recursive: true, force: true });
  }
}

afterEach(cleanup);

describe("fingerprintFinding", () => {
  it("generates stable fingerprint", () => {
    const f = makeFinding({ id: "X", file: "y.json", evidence: "z" });
    expect(fingerprintFinding(f)).toBe("X::y.json::z");
  });

  it("handles missing evidence", () => {
    const f = makeFinding({ id: "X", file: "y.json", evidence: undefined });
    expect(fingerprintFinding(f)).toBe("X::y.json::");
  });
});

describe("saveBaseline / loadBaseline", () => {
  it("round-trips correctly", () => {
    setup();
    const path = join(FIXTURES_DIR, "baseline.json");
    const findings = [makeFinding({ id: "R1", file: "a.json", evidence: "ev1" })];
    const score = makeScore({ numericScore: 85 });

    saveBaseline(findings, score, path);
    const loaded = loadBaseline(path);

    expect(loaded).not.toBeNull();
    expect(loaded!.version).toBe(1);
    expect(loaded!.score.numericScore).toBe(85);
    expect(loaded!.findings).toHaveLength(1);
    expect(loaded!.findings[0].fingerprint).toBe("R1::a.json::ev1");
  });

  it("creates parent directories", () => {
    setup();
    const path = join(FIXTURES_DIR, "deep", "nested", "baseline.json");
    saveBaseline([], makeScore(), path);
    expect(existsSync(path)).toBe(true);
  });

  it("returns null for non-existent file", () => {
    expect(loadBaseline("/tmp/nonexistent-baseline-test-12345.json")).toBeNull();
  });

  it("returns null for invalid JSON", () => {
    setup();
    const path = join(FIXTURES_DIR, "bad.json");
    writeFileSync(path, "not json{{");
    expect(loadBaseline(path)).toBeNull();
  });

  it("returns null for wrong version", () => {
    setup();
    const path = join(FIXTURES_DIR, "v2.json");
    writeFileSync(path, JSON.stringify({ version: 2, findings: [] }));
    expect(loadBaseline(path)).toBeNull();
  });
});

describe("compareBaseline", () => {
  it("detects new findings", () => {
    const baseline = makeBaseline();
    const currentFindings = [
      makeFinding({ id: "R1", file: "a.json", evidence: "ev1" }),
      makeFinding({ id: "R2", file: "b.json", evidence: "ev2", severity: "high" }),
    ];
    const currentScore = makeScore({ numericScore: 70 });

    const result = compareBaseline(baseline, currentFindings, currentScore);

    expect(result.newFindings).toHaveLength(1);
    expect(result.newFindings[0].id).toBe("R2");
    expect(result.resolvedFindings).toHaveLength(0);
    expect(result.isRegression).toBe(true);
    expect(result.scoreDelta).toBe(-10);
    expect(result.newHighCount).toBe(1);
  });

  it("detects resolved findings", () => {
    const baseline = makeBaseline({
      findings: [
        { id: "R1", severity: "medium", category: "permissions", title: "F1", file: "a.json", evidence: "ev1", fingerprint: "R1::a.json::ev1" },
        { id: "R2", severity: "high", category: "hooks", title: "F2", file: "b.json", evidence: "ev2", fingerprint: "R2::b.json::ev2" },
      ],
    });
    const currentFindings = [makeFinding({ id: "R1", file: "a.json", evidence: "ev1" })];
    const currentScore = makeScore({ numericScore: 90 });

    const result = compareBaseline(baseline, currentFindings, currentScore);

    expect(result.resolvedFindings).toHaveLength(1);
    expect(result.resolvedFindings[0].id).toBe("R2");
    expect(result.isRegression).toBe(false);
  });

  it("reports no changes", () => {
    const baseline = makeBaseline();
    const currentFindings = [makeFinding({ id: "R1", file: "a.json", evidence: "ev1" })];
    const currentScore = makeScore({ numericScore: 80 });

    const result = compareBaseline(baseline, currentFindings, currentScore);

    expect(result.newFindings).toHaveLength(0);
    expect(result.resolvedFindings).toHaveLength(0);
    expect(result.isRegression).toBe(false);
    expect(result.unchangedCount).toBe(1);
  });

  it("detects critical regressions", () => {
    const baseline = makeBaseline();
    const currentFindings = [
      makeFinding({ id: "R1", file: "a.json", evidence: "ev1" }),
      makeFinding({ id: "CRIT", file: "x.json", evidence: "e", severity: "critical" }),
    ];
    const currentScore = makeScore({ numericScore: 50 });

    const result = compareBaseline(baseline, currentFindings, currentScore);

    expect(result.newCriticalCount).toBe(1);
    expect(result.isRegression).toBe(true);
  });
});

describe("evaluateGate", () => {
  it("passes when no regressions", () => {
    const comparison = {
      timestamp: "now",
      baselineTimestamp: "then",
      newFindings: [],
      resolvedFindings: [],
      unchangedCount: 1,
      scoreDelta: 0,
      baselineScore: 80,
      currentScore: 80,
      isRegression: false,
      newCriticalCount: 0,
      newHighCount: 0,
    };

    const result = evaluateGate(comparison);
    expect(result.passed).toBe(true);
    expect(result.reasons).toHaveLength(0);
  });

  it("fails on new critical findings", () => {
    const comparison = {
      timestamp: "now",
      baselineTimestamp: "then",
      newFindings: [makeFinding({ severity: "critical" })],
      resolvedFindings: [],
      unchangedCount: 0,
      scoreDelta: -25,
      baselineScore: 100,
      currentScore: 75,
      isRegression: true,
      newCriticalCount: 1,
      newHighCount: 0,
    };

    const result = evaluateGate(comparison);
    expect(result.passed).toBe(false);
    expect(result.reasons.some((r) => r.includes("critical"))).toBe(true);
  });

  it("fails on new high findings", () => {
    const comparison = {
      timestamp: "now",
      baselineTimestamp: "then",
      newFindings: [makeFinding({ severity: "high" })],
      resolvedFindings: [],
      unchangedCount: 0,
      scoreDelta: -15,
      baselineScore: 100,
      currentScore: 85,
      isRegression: true,
      newCriticalCount: 0,
      newHighCount: 1,
    };

    const result = evaluateGate(comparison);
    expect(result.passed).toBe(false);
    expect(result.reasons.some((r) => r.includes("high"))).toBe(true);
  });

  it("fails on score drop exceeding threshold", () => {
    const comparison = {
      timestamp: "now",
      baselineTimestamp: "then",
      newFindings: [],
      resolvedFindings: [],
      unchangedCount: 1,
      scoreDelta: -10,
      baselineScore: 80,
      currentScore: 70,
      isRegression: true,
      newCriticalCount: 0,
      newHighCount: 0,
    };

    const result = evaluateGate(comparison, {
      maxNewFindings: 0,
      maxScoreDrop: 5,
      failOnNewCritical: true,
      failOnNewHigh: true,
    });
    expect(result.passed).toBe(false);
    expect(result.reasons.some((r) => r.includes("Score dropped"))).toBe(true);
  });

  it("respects custom gate config", () => {
    const comparison = {
      timestamp: "now",
      baselineTimestamp: "then",
      newFindings: [makeFinding({ severity: "high" })],
      resolvedFindings: [],
      unchangedCount: 0,
      scoreDelta: -3,
      baselineScore: 80,
      currentScore: 77,
      isRegression: true,
      newCriticalCount: 0,
      newHighCount: 1,
    };

    // Allow high findings
    const result = evaluateGate(comparison, {
      maxNewFindings: 5,
      maxScoreDrop: 10,
      failOnNewCritical: true,
      failOnNewHigh: false,
    });
    expect(result.passed).toBe(true);
  });
});

describe("renderComparison", () => {
  it("renders comparison with new findings", () => {
    const comparison = {
      timestamp: "now",
      baselineTimestamp: "2026-03-19T10:00:00Z",
      newFindings: [makeFinding({ severity: "high", title: "New issue" })],
      resolvedFindings: [],
      unchangedCount: 1,
      scoreDelta: -10,
      baselineScore: 90,
      currentScore: 80,
      isRegression: true,
      newCriticalCount: 0,
      newHighCount: 1,
    };

    const output = renderComparison(comparison);
    expect(output).toContain("Baseline Comparison");
    expect(output).toContain("90 → 80");
    expect(output).toContain("REGRESSED");
    expect(output).toContain("NEW FINDINGS (1)");
    expect(output).toContain("New issue");
  });

  it("renders resolved findings", () => {
    const comparison = {
      timestamp: "now",
      baselineTimestamp: "2026-03-19T10:00:00Z",
      newFindings: [],
      resolvedFindings: [
        { id: "R1", severity: "medium" as const, category: "permissions", title: "Fixed", file: "a.json", fingerprint: "R1::a.json::" },
      ],
      unchangedCount: 0,
      scoreDelta: 10,
      baselineScore: 70,
      currentScore: 80,
      isRegression: false,
      newCriticalCount: 0,
      newHighCount: 0,
    };

    const output = renderComparison(comparison);
    expect(output).toContain("IMPROVED");
    expect(output).toContain("RESOLVED FINDINGS (1)");
  });
});

describe("renderGateResult", () => {
  it("renders passed gate", () => {
    const output = renderGateResult({
      passed: true,
      reasons: [],
      comparison: {} as any,
    });
    expect(output).toContain("PASSED");
  });

  it("renders failed gate with reasons", () => {
    const output = renderGateResult({
      passed: false,
      reasons: ["1 new critical finding(s)", "Score dropped by 15"],
      comparison: {} as any,
    });
    expect(output).toContain("FAILED");
    expect(output).toContain("critical");
    expect(output).toContain("Score dropped");
  });
});
