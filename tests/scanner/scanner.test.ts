import { describe, it, expect } from "vitest";
import { scan } from "../../src/scanner/index.js";
import { resolve } from "node:path";

const VULNERABLE_PATH = resolve(import.meta.dirname, "../../examples/vulnerable");

describe("scanner", () => {
  describe("scan()", () => {
    it("discovers files in the vulnerable example", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.target.files.length).toBeGreaterThan(0);
    });

    it("identifies correct file types", () => {
      const result = scan(VULNERABLE_PATH);
      const types = result.target.files.map((f) => f.type);
      expect(types).toContain("claude-md");
      expect(types).toContain("settings-json");
      expect(types).toContain("mcp-json");
      expect(types).toContain("agent-md");
    });

    it("finds critical findings in vulnerable config", () => {
      const result = scan(VULNERABLE_PATH);
      const criticals = result.findings.filter((f) => f.severity === "critical");
      expect(criticals.length).toBeGreaterThan(0);
    });

    it("returns findings sorted by severity", () => {
      const result = scan(VULNERABLE_PATH);
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      for (let i = 1; i < result.findings.length; i++) {
        const prev = severityOrder[result.findings[i - 1].severity];
        const curr = severityOrder[result.findings[i].severity];
        expect(curr).toBeGreaterThanOrEqual(prev);
      }
    });

    it("detects hardcoded secrets in CLAUDE.md", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.title.includes("Anthropic API key"))).toBe(true);
      expect(result.findings.some((f) => f.title.includes("OpenAI API key"))).toBe(true);
    });

    it("detects overly permissive Bash(*) in allow list", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.evidence === "Bash(*)")).toBe(true);
    });

    it("detects command injection in hooks", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.category === "injection")).toBe(true);
    });

    it("detects risky MCP servers", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.title.includes("shell-runner"))).toBe(true);
    });

    it("detects agent with Bash access", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.title.includes("Bash access"))).toBe(true);
    });
  });
});
