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

  it("deducts 25 from category per critical finding", () => {
    const result = makeScanResult([
      makeFinding({ id: "c1", severity: "critical" }),
    ]);
    const report = calculateScore(result);
    // permissions category: 100 - 25 = 75, rest at 100
    expect(report.score.breakdown.permissions).toBe(75);
    // overall: (75 + 100 + 100 + 100 + 100) / 5 = 95
    expect(report.score.numericScore).toBe(95);
    expect(report.score.grade).toBe("A");
  });

  it("deducts 15 from category per high finding", () => {
    const result = makeScanResult([
      makeFinding({ id: "h1", severity: "high" }),
    ]);
    const report = calculateScore(result);
    // permissions: 100 - 15 = 85, rest at 100
    expect(report.score.breakdown.permissions).toBe(85);
    // overall: (85 + 100 + 100 + 100 + 100) / 5 = 97
    expect(report.score.numericScore).toBe(97);
    expect(report.score.grade).toBe("A");
  });

  it("deducts 5 from category per medium finding", () => {
    const result = makeScanResult([
      makeFinding({ id: "m1", severity: "medium" }),
      makeFinding({ id: "m2", severity: "medium" }),
    ]);
    const report = calculateScore(result);
    // permissions: 100 - 10 = 90, rest at 100
    expect(report.score.breakdown.permissions).toBe(90);
    // overall: (90 + 100 + 100 + 100 + 100) / 5 = 98
    expect(report.score.numericScore).toBe(98);
  });

  it("floors category score at 0", () => {
    const result = makeScanResult([
      makeFinding({ id: "c1", severity: "critical" }),
      makeFinding({ id: "c2", severity: "critical" }),
      makeFinding({ id: "c3", severity: "critical" }),
      makeFinding({ id: "c4", severity: "critical" }),
      makeFinding({ id: "c5", severity: "critical" }),
    ]);
    const report = calculateScore(result);
    // permissions: max(0, 100 - 125) = 0
    expect(report.score.breakdown.permissions).toBe(0);
    // overall: (100 + 0 + 100 + 100 + 100) / 5 = 80
    expect(report.score.numericScore).toBe(80);
    expect(report.score.grade).toBe("B");
  });

  it("floors overall score at 0 when all categories are 0", () => {
    const findings: Finding[] = [];
    const categories = ["secrets", "permissions", "hooks", "mcp", "agents"] as const;
    let idx = 0;
    for (const cat of categories) {
      for (let i = 0; i < 5; i++) {
        findings.push(makeFinding({ id: `f${idx++}`, severity: "critical", category: cat }));
      }
    }
    const result = makeScanResult(findings);
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

  it("computes overall score as average of category scores", () => {
    const result = makeScanResult([
      makeFinding({ id: "s1", severity: "critical", category: "secrets" }),
      makeFinding({ id: "m1", severity: "high", category: "mcp" }),
      makeFinding({ id: "a1", severity: "medium", category: "agents" }),
    ]);
    const report = calculateScore(result);
    // secrets=75, mcp=85, agents=95, permissions=100, hooks=100
    // avg = (75+85+95+100+100)/5 = 455/5 = 91
    expect(report.score.numericScore).toBe(91);
    expect(report.score.grade).toBe("A");
  });

  it("grades correctly at boundaries", () => {
    // A: >= 90 — 2 medium in one category
    expect(calculateScore(makeScanResult([
      makeFinding({ id: "m1", severity: "medium" }),
      makeFinding({ id: "m2", severity: "medium" }),
    ])).score.grade).toBe("A");

    // B: 75-89 — 1 critical each in 3 categories
    expect(calculateScore(makeScanResult([
      makeFinding({ id: "c1", severity: "critical", category: "secrets" }),
      makeFinding({ id: "c2", severity: "critical", category: "permissions" }),
      makeFinding({ id: "c3", severity: "critical", category: "hooks" }),
    ])).score.grade).toBe("B"); // avg = (75+75+75+100+100)/5 = 85

    // C: 60-74 — 2 critical each in 3 categories
    expect(calculateScore(makeScanResult([
      makeFinding({ id: "c1", severity: "critical", category: "secrets" }),
      makeFinding({ id: "c2", severity: "critical", category: "secrets" }),
      makeFinding({ id: "c3", severity: "critical", category: "permissions" }),
      makeFinding({ id: "c4", severity: "critical", category: "permissions" }),
      makeFinding({ id: "c5", severity: "critical", category: "hooks" }),
      makeFinding({ id: "c6", severity: "critical", category: "hooks" }),
    ])).score.grade).toBe("C"); // avg = (50+50+50+100+100)/5 = 70

    // D: 40-59 — 2 critical in each of 5 categories
    expect(calculateScore(makeScanResult([
      makeFinding({ id: "c1", severity: "critical", category: "secrets" }),
      makeFinding({ id: "c2", severity: "critical", category: "secrets" }),
      makeFinding({ id: "c3", severity: "critical", category: "permissions" }),
      makeFinding({ id: "c4", severity: "critical", category: "permissions" }),
      makeFinding({ id: "c5", severity: "critical", category: "hooks" }),
      makeFinding({ id: "c6", severity: "critical", category: "hooks" }),
      makeFinding({ id: "c7", severity: "critical", category: "mcp" }),
      makeFinding({ id: "c8", severity: "critical", category: "mcp" }),
      makeFinding({ id: "c9", severity: "critical", category: "agents" }),
      makeFinding({ id: "c10", severity: "critical", category: "agents" }),
    ])).score.grade).toBe("D"); // avg = (50+50+50+50+50)/5 = 50

    // F: < 40 — 3 critical in each of 5 categories
    expect(calculateScore(makeScanResult([
      makeFinding({ id: "c1", severity: "critical", category: "secrets" }),
      makeFinding({ id: "c2", severity: "critical", category: "secrets" }),
      makeFinding({ id: "c3", severity: "critical", category: "secrets" }),
      makeFinding({ id: "c4", severity: "critical", category: "permissions" }),
      makeFinding({ id: "c5", severity: "critical", category: "permissions" }),
      makeFinding({ id: "c6", severity: "critical", category: "permissions" }),
      makeFinding({ id: "c7", severity: "critical", category: "hooks" }),
      makeFinding({ id: "c8", severity: "critical", category: "hooks" }),
      makeFinding({ id: "c9", severity: "critical", category: "hooks" }),
      makeFinding({ id: "c10", severity: "critical", category: "mcp" }),
      makeFinding({ id: "c11", severity: "critical", category: "mcp" }),
      makeFinding({ id: "c12", severity: "critical", category: "mcp" }),
      makeFinding({ id: "c13", severity: "critical", category: "agents" }),
      makeFinding({ id: "c14", severity: "critical", category: "agents" }),
      makeFinding({ id: "c15", severity: "critical", category: "agents" }),
    ])).score.grade).toBe("F"); // avg = (25+25+25+25+25)/5 = 25
  });
});
