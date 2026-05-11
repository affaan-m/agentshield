import { describe, expect, it } from "vitest";
import { renderSarifReport } from "../../src/reporter/sarif.js";
import type { SecurityReport } from "../../src/types.js";

function makeReport(overrides: Partial<SecurityReport> = {}): SecurityReport {
  return {
    timestamp: "2026-05-11T20:00:00.000Z",
    targetPath: "/tmp/repo",
    findings: [],
    score: {
      grade: "B",
      numericScore: 84,
      breakdown: { secrets: 100, permissions: 80, hooks: 80, mcp: 80, agents: 80 },
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

describe("renderSarifReport", () => {
  it("renders a SARIF 2.1.0 document", () => {
    const sarif = JSON.parse(renderSarifReport(makeReport()));

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("AgentShield");
  });

  it("maps findings to rules and results", () => {
    const sarif = JSON.parse(renderSarifReport(makeReport({
      findings: [
        {
          id: "secrets-hardcoded-1",
          severity: "critical",
          category: "secrets",
          title: "Hardcoded API key",
          description: "Found a hardcoded API key.",
          file: "CLAUDE.md",
          line: 7,
          runtimeConfidence: "active-runtime",
          evidence: "sk-***",
          fix: {
            description: "Move the key into an environment variable.",
            before: "sk-xxx",
            after: "${API_KEY}",
            auto: false,
          },
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
        autoFixable: 0,
      },
    })));

    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.rules[0]).toMatchObject({
      id: "secrets-hardcoded-1",
      properties: {
        category: "secrets",
        severity: "critical",
        "security-severity": "9.5",
        precision: "very-high",
      },
    });
    expect(sarif.runs[0].results[0]).toMatchObject({
      ruleId: "secrets-hardcoded-1",
      ruleIndex: 0,
      level: "error",
      message: { text: "Found a hardcoded API key." },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: "CLAUDE.md" },
            region: { startLine: 7 },
          },
        },
      ],
    });
  });

  it("deduplicates rules while preserving multiple results", () => {
    const sarif = JSON.parse(renderSarifReport(makeReport({
      findings: [
        {
          id: "mcp-url-transport",
          severity: "high",
          category: "mcp",
          title: "Remote MCP transport",
          description: "Remote MCP server configured.",
          file: "mcp.json",
        },
        {
          id: "mcp-url-transport",
          severity: "high",
          category: "mcp",
          title: "Remote MCP transport",
          description: "Remote MCP server configured.",
          file: ".claude/mcp.json",
        },
      ],
      summary: {
        totalFindings: 2,
        critical: 0,
        high: 2,
        medium: 0,
        low: 0,
        info: 0,
        filesScanned: 2,
        autoFixable: 0,
      },
    })));

    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].results).toHaveLength(2);
    expect(sarif.runs[0].results[1].ruleIndex).toBe(0);
  });

  it("normalizes Windows path separators in artifact URIs", () => {
    const sarif = JSON.parse(renderSarifReport(makeReport({
      findings: [
        {
          id: "hooks-shell",
          severity: "medium",
          category: "hooks",
          title: "Hook finding",
          description: "A hook finding.",
          file: ".claude\\hooks\\scan.ps1",
        },
      ],
      summary: {
        totalFindings: 1,
        critical: 0,
        high: 0,
        medium: 1,
        low: 0,
        info: 0,
        filesScanned: 1,
        autoFixable: 0,
      },
    })));

    expect(
      sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri
    ).toBe(".claude/hooks/scan.ps1");
  });
});
