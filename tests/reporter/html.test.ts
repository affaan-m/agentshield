import { describe, it, expect } from "vitest";
import { renderHtmlReport } from "../../src/reporter/html.js";
import type { SecurityReport } from "../../src/types.js";

function makeReport(overrides: Partial<SecurityReport> = {}): SecurityReport {
  return {
    timestamp: "2026-02-11T00:00:00.000Z",
    targetPath: "/tmp/test",
    findings: [],
    score: {
      grade: "A",
      numericScore: 95,
      breakdown: { secrets: 100, permissions: 90, hooks: 100, mcp: 85, agents: 100 },
    },
    summary: {
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      filesScanned: 4,
      autoFixable: 0,
    },
    ...overrides,
  };
}

describe("renderHtmlReport", () => {
  it("returns valid HTML document", () => {
    const html = renderHtmlReport(makeReport());
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("<html");
    expect(html).toContain("</html>");
  });

  it("includes the report title", () => {
    const html = renderHtmlReport(makeReport());
    expect(html).toContain("AgentShield Security Report");
  });

  it("includes the grade in the title tag", () => {
    const html = renderHtmlReport(makeReport());
    expect(html).toContain("<title>AgentShield Security Report — Grade A</title>");
  });

  it("includes inline styles", () => {
    const html = renderHtmlReport(makeReport());
    expect(html).toContain("<style>");
    expect(html).toContain("</style>");
  });

  it("shows numeric score", () => {
    const html = renderHtmlReport(makeReport());
    expect(html).toContain("95</strong>/100");
  });

  it("renders score breakdown bars", () => {
    const html = renderHtmlReport(makeReport());
    expect(html).toContain("Secrets");
    expect(html).toContain("Permissions");
    expect(html).toContain("Hooks");
    expect(html).toContain("MCP Servers");
    expect(html).toContain("Agents");
  });

  it("shows no-findings message when empty", () => {
    const html = renderHtmlReport(makeReport());
    expect(html).toContain("No security issues found");
  });

  it("renders findings with severity badges", () => {
    const report = makeReport({
      findings: [
        {
          id: "SEC-001",
          severity: "critical",
          category: "secrets",
          title: "Leaked API key",
          description: "Found exposed key",
          file: "CLAUDE.md",
          line: 5,
          evidence: "sk-ant-***",
          fix: {
            description: "Use env var",
            before: "sk-ant-xxx",
            after: "${KEY}",
            auto: true,
          },
        },
        {
          id: "MCP-001",
          severity: "high",
          category: "mcp",
          title: "Risky MCP server",
          description: "Shell runner detected",
          file: "mcp.json",
        },
      ],
      summary: {
        totalFindings: 2,
        critical: 1,
        high: 1,
        medium: 0,
        low: 0,
        info: 0,
        filesScanned: 3,
        autoFixable: 1,
      },
    });
    const html = renderHtmlReport(report);
    expect(html).toContain("Leaked API key");
    expect(html).toContain("CRITICAL");
    expect(html).toContain("Risky MCP server");
    expect(html).toContain("HIGH");
    expect(html).toContain("auto-fixable");
    expect(html).toContain("CLAUDE.md:5");
  });

  it("escapes HTML entities in user content", () => {
    const report = makeReport({
      targetPath: "/path/<script>alert(1)</script>",
    });
    const html = renderHtmlReport(report);
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("renders distribution chart SVG when findings exist", () => {
    const report = makeReport({
      summary: {
        totalFindings: 3,
        critical: 1,
        high: 1,
        medium: 1,
        low: 0,
        info: 0,
        filesScanned: 2,
        autoFixable: 0,
      },
    });
    const html = renderHtmlReport(report);
    expect(html).toContain("<svg");
    expect(html).toContain("legend");
  });

  it("renders grade badge for each grade level", () => {
    for (const grade of ["A", "B", "C", "D", "F"] as const) {
      const html = renderHtmlReport(makeReport({
        score: {
          grade,
          numericScore: grade === "A" ? 95 : grade === "F" ? 20 : 60,
          breakdown: { secrets: 100, permissions: 100, hooks: 100, mcp: 100, agents: 100 },
        },
      }));
      expect(html).toContain(`<span class="grade-letter">${grade}</span>`);
    }
  });

  it("includes responsive media queries", () => {
    const html = renderHtmlReport(makeReport());
    expect(html).toContain("@media");
    expect(html).toContain("max-width: 640px");
  });

  it("includes footer", () => {
    const html = renderHtmlReport(makeReport());
    expect(html).toContain("Security auditor for AI agent configurations");
  });
});
