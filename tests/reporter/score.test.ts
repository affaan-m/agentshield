import { describe, it, expect } from "vitest";
import { calculateScore } from "../../src/reporter/score.js";
import type { Finding, ScanTarget } from "../../src/types.js";
import type { ScanResult } from "../../src/scanner/index.js";

function makeScanResult(findings: Finding[]): ScanResult {
  const target: ScanTarget = {
    path: "/test",
    files: [{ path: "test.json", type: "settings-json", content: "{}" }],
  };
  return { target, findings };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "test-finding",
    severity: "medium",
    category: "permissions",
    title: "Test finding",
    description: "Test description",
    file: "test.json",
    ...overrides,
  };
}

describe("calculateScore", () => {
  it("returns Grade A for no findings", () => {
    const result = makeScanResult([]);
    const report = calculateScore(result);
    expect(report.score.grade).toBe("A");
    expect(report.score.numericScore).toBe(100);
  });

  it("deducts 25 points per critical finding", () => {
    const result = makeScanResult([
      makeFinding({ id: "c1", severity: "critical" }),
    ]);
    const report = calculateScore(result);
    expect(report.score.numericScore).toBe(75);
    expect(report.score.grade).toBe("B");
  });

  it("deducts 15 points per high finding", () => {
    const result = makeScanResult([
      makeFinding({ id: "h1", severity: "high" }),
    ]);
    const report = calculateScore(result);
    expect(report.score.numericScore).toBe(85);
    expect(report.score.grade).toBe("B");
  });

  it("deducts 5 points per medium finding", () => {
    const result = makeScanResult([
      makeFinding({ id: "m1", severity: "medium" }),
      makeFinding({ id: "m2", severity: "medium" }),
    ]);
    const report = calculateScore(result);
    expect(report.score.numericScore).toBe(90);
  });

  it("floors score at 0", () => {
    const result = makeScanResult([
      makeFinding({ id: "c1", severity: "critical" }),
      makeFinding({ id: "c2", severity: "critical" }),
      makeFinding({ id: "c3", severity: "critical" }),
      makeFinding({ id: "c4", severity: "critical" }),
      makeFinding({ id: "c5", severity: "critical" }),
    ]);
    const report = calculateScore(result);
    expect(report.score.numericScore).toBe(0);
    expect(report.score.grade).toBe("F");
  });

  it("does not deduct for info findings", () => {
    const result = makeScanResult([
      makeFinding({ id: "i1", severity: "info" }),
      makeFinding({ id: "i2", severity: "info" }),
    ]);
    const report = calculateScore(result);
    expect(report.score.numericScore).toBe(100);
  });

  it("correctly counts findings by severity in summary", () => {
    const result = makeScanResult([
      makeFinding({ id: "c1", severity: "critical" }),
      makeFinding({ id: "h1", severity: "high" }),
      makeFinding({ id: "h2", severity: "high" }),
      makeFinding({ id: "m1", severity: "medium" }),
      makeFinding({ id: "l1", severity: "low" }),
      makeFinding({ id: "i1", severity: "info" }),
    ]);
    const report = calculateScore(result);
    expect(report.summary.critical).toBe(1);
    expect(report.summary.high).toBe(2);
    expect(report.summary.medium).toBe(1);
    expect(report.summary.low).toBe(1);
    expect(report.summary.info).toBe(1);
    expect(report.summary.totalFindings).toBe(6);
  });

  it("counts auto-fixable findings", () => {
    const result = makeScanResult([
      makeFinding({ id: "f1", fix: { description: "fix", before: "a", after: "b", auto: true } }),
      makeFinding({ id: "f2", fix: { description: "fix", before: "a", after: "b", auto: false } }),
      makeFinding({ id: "f3" }),
    ]);
    const report = calculateScore(result);
    expect(report.summary.autoFixable).toBe(1);
  });

  it("maps categories to score breakdown correctly", () => {
    const result = makeScanResult([
      makeFinding({ id: "s1", severity: "critical", category: "secrets" }),
      makeFinding({ id: "m1", severity: "high", category: "mcp" }),
      makeFinding({ id: "a1", severity: "medium", category: "agents" }),
    ]);
    const report = calculateScore(result);
    expect(report.score.breakdown.secrets).toBe(75); // 100 - 25
    expect(report.score.breakdown.mcp).toBe(85); // 100 - 15
    expect(report.score.breakdown.agents).toBe(95); // 100 - 5
    expect(report.score.breakdown.permissions).toBe(100); // untouched
    expect(report.score.breakdown.hooks).toBe(100); // untouched
  });

  it("grades correctly at boundaries", () => {
    // A: >= 90
    expect(calculateScore(makeScanResult([
      makeFinding({ id: "m1", severity: "medium" }),
      makeFinding({ id: "m2", severity: "medium" }),
    ])).score.grade).toBe("A");

    // B: 75-89
    expect(calculateScore(makeScanResult([
      makeFinding({ id: "c1", severity: "critical" }),
    ])).score.grade).toBe("B");

    // C: 60-74
    expect(calculateScore(makeScanResult([
      makeFinding({ id: "c1", severity: "critical" }),
      makeFinding({ id: "h1", severity: "high" }),
    ])).score.grade).toBe("C");

    // D: 40-59
    expect(calculateScore(makeScanResult([
      makeFinding({ id: "c1", severity: "critical" }),
      makeFinding({ id: "c2", severity: "critical" }),
    ])).score.grade).toBe("D");

    // F: < 40
    expect(calculateScore(makeScanResult([
      makeFinding({ id: "c1", severity: "critical" }),
      makeFinding({ id: "c2", severity: "critical" }),
      makeFinding({ id: "c3", severity: "critical" }),
    ])).score.grade).toBe("F");
  });
});
