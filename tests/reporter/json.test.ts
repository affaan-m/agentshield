import { describe, it, expect } from "vitest";
import { renderJsonReport, renderMarkdownReport } from "../../src/reporter/json.js";
import type { SecurityReport } from "../../src/types.js";

function makeReport(overrides: Partial<SecurityReport> = {}): SecurityReport {
  return {
    timestamp: "2026-02-11T00:00:00.000Z",
    targetPath: "/tmp/test",
    findings: [],
    score: {
      grade: "B",
      numericScore: 80,
      breakdown: { secrets: 100, permissions: 80, hooks: 70, mcp: 90, agents: 60 },
    },
    summary: {
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      filesScanned: 5,
      autoFixable: 0,
    },
    ...overrides,
  };
}

describe("renderJsonReport", () => {
  it("returns valid JSON", () => {
    const output = renderJsonReport(makeReport());
    const parsed = JSON.parse(output);
    expect(parsed.targetPath).toBe("/tmp/test");
  });

  it("includes all report fields", () => {
    const output = renderJsonReport(makeReport());
    const parsed = JSON.parse(output);
    expect(parsed).toHaveProperty("timestamp");
    expect(parsed).toHaveProperty("targetPath");
    expect(parsed).toHaveProperty("findings");
    expect(parsed).toHaveProperty("score");
    expect(parsed).toHaveProperty("summary");
  });

  it("preserves findings in output", () => {
    const report = makeReport({
      findings: [
        {
          id: "TEST-001",
          severity: "high",
          category: "secrets",
          title: "Test finding",
          description: "A test",
          file: "test.md",
        },
      ],
      summary: {
        totalFindings: 1,
        critical: 0,
        high: 1,
        medium: 0,
        low: 0,
        info: 0,
        filesScanned: 1,
        autoFixable: 0,
      },
    });
    const parsed = JSON.parse(renderJsonReport(report));
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].title).toBe("Test finding");
  });
});

describe("renderMarkdownReport", () => {
  it("starts with markdown heading", () => {
    const output = renderMarkdownReport(makeReport());
    expect(output).toContain("# AgentShield Security Report");
  });

  it("includes grade and score", () => {
    const output = renderMarkdownReport(makeReport());
    expect(output).toContain("**Grade:** B (80/100)");
  });

  it("includes summary table", () => {
    const output = renderMarkdownReport(makeReport());
    expect(output).toContain("## Summary");
    expect(output).toContain("| Files scanned | 5 |");
  });

  it("includes score breakdown table", () => {
    const output = renderMarkdownReport(makeReport());
    expect(output).toContain("## Score Breakdown");
    expect(output).toContain("| Secrets | 100/100 |");
    expect(output).toContain("| Hooks | 70/100 |");
  });

  it("shows no issues message when empty", () => {
    const output = renderMarkdownReport(makeReport());
    expect(output).toContain("No Issues Found");
  });

  it("renders findings with severity emoji", () => {
    const report = makeReport({
      findings: [
        {
          id: "SEC-001",
          severity: "critical",
          category: "secrets",
          title: "Hardcoded key",
          description: "Found a key",
          file: "CLAUDE.md",
          line: 10,
          evidence: "sk-***",
          fix: { description: "Use env var", before: "sk-xxx", after: "${KEY}", auto: true },
        },
      ],
      summary: {
        totalFindings: 1,
        critical: 1,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        filesScanned: 1,
        autoFixable: 1,
      },
    });
    const output = renderMarkdownReport(report);
    expect(output).toContain("Hardcoded key");
    expect(output).toContain("**Severity:** critical");
    expect(output).toContain("**Evidence:** `sk-***`");
    expect(output).toContain("**Auto-fixable:** Yes");
    expect(output).toContain("`CLAUDE.md:10`");
  });
});
