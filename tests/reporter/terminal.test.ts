import { describe, it, expect } from "vitest";
import { renderTerminalReport } from "../../src/reporter/terminal.js";
import type { SecurityReport } from "../../src/types.js";

function makeReport(overrides: Partial<SecurityReport> = {}): SecurityReport {
  return {
    timestamp: "2026-02-11T00:00:00.000Z",
    targetPath: "/tmp/test",
    findings: [],
    score: {
      grade: "A",
      numericScore: 100,
      breakdown: { secrets: 100, permissions: 100, hooks: 100, mcp: 100, agents: 100 },
    },
    summary: {
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      filesScanned: 3,
      autoFixable: 0,
    },
    ...overrides,
  };
}

describe("renderTerminalReport", () => {
  it("returns a string with report header", () => {
    const output = renderTerminalReport(makeReport());
    expect(output).toContain("AgentShield Security Report");
  });

  it("includes the target path", () => {
    const output = renderTerminalReport(makeReport({ targetPath: "/home/user/.claude" }));
    expect(output).toContain("/home/user/.claude");
  });

  it("includes grade and score", () => {
    const output = renderTerminalReport(makeReport());
    expect(output).toContain("Grade");
    expect(output).toContain("100");
  });

  it("shows score breakdown categories", () => {
    const output = renderTerminalReport(makeReport());
    expect(output).toContain("Secrets");
    expect(output).toContain("Permissions");
    expect(output).toContain("Hooks");
    expect(output).toContain("MCP Servers");
    expect(output).toContain("Agents");
  });

  it("shows no issues message when findings are empty", () => {
    const output = renderTerminalReport(makeReport());
    expect(output).toContain("No security issues found");
  });

  it("renders findings grouped by severity", () => {
    const report = makeReport({
      findings: [
        {
          id: "SEC-001",
          severity: "critical",
          category: "secrets",
          title: "Hardcoded API key",
          description: "Found a hardcoded secret",
          file: "CLAUDE.md",
          line: 5,
          evidence: "sk-ant-***",
        },
        {
          id: "HOOK-001",
          severity: "medium",
          category: "hooks",
          title: "Unvalidated hook",
          description: "Hook does not validate input",
          file: "settings.json",
        },
      ],
      summary: {
        totalFindings: 2,
        critical: 1,
        high: 0,
        medium: 1,
        low: 0,
        info: 0,
        filesScanned: 2,
        autoFixable: 0,
      },
    });
    const output = renderTerminalReport(report);
    expect(output).toContain("Hardcoded API key");
    expect(output).toContain("Unvalidated hook");
    expect(output).toContain("CRITICAL");
    expect(output).toContain("MEDIUM");
  });

  it("shows evidence when present", () => {
    const report = makeReport({
      findings: [
        {
          id: "SEC-001",
          severity: "high",
          category: "secrets",
          title: "Leaked token",
          description: "Token found",
          file: "test.md",
          evidence: "ghp_abc***",
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
    const output = renderTerminalReport(report);
    expect(output).toContain("ghp_abc***");
  });

  it("shows fix suggestion and auto-fixable count", () => {
    const report = makeReport({
      findings: [
        {
          id: "SEC-001",
          severity: "critical",
          category: "secrets",
          title: "Hardcoded secret",
          description: "Remove it",
          file: "CLAUDE.md",
          fix: {
            description: "Use environment variable",
            before: "sk-ant-xxx",
            after: "${ANTHROPIC_API_KEY}",
            auto: true,
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
        autoFixable: 1,
      },
    });
    const output = renderTerminalReport(report);
    expect(output).toContain("Use environment variable");
    expect(output).toContain("auto-fixable");
    expect(output).toContain("--fix");
  });

  it("includes footer", () => {
    const output = renderTerminalReport(makeReport());
    expect(output).toContain("AgentShield");
  });
});
