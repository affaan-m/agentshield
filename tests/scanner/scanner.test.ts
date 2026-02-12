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

    it("detects destructive git commands in allow list", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.id.includes("destructive-git"))).toBe(true);
    });

    it("detects MCP env override attacks", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.id.includes("env-override"))).toBe(true);
    });

    it("detects prompt injection patterns in agent files", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.id.includes("injection-pattern"))).toBe(true);
    });

    it("detects unrestricted agent (no tools field)", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.id.includes("no-tools"))).toBe(true);
    });

    it("detects sensitive path access in allow list", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.id.includes("sensitive-path"))).toBe(true);
    });

    it("detects SessionStart remote downloads", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.id.includes("session-start-download"))).toBe(true);
    });

    it("detects MCP URL transport to external hosts", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.id.includes("url-transport"))).toBe(true);
    });

    it("detects JWT tokens in CLAUDE.md", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.title.includes("JWT token"))).toBe(true);
    });

    it("detects MCP shell wrapper", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.id.includes("shell-wrapper"))).toBe(true);
    });

    it("detects wildcard root paths in allow list", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.id.includes("wildcard-root"))).toBe(true);
    });

    it("detects CLAUDE.md silent execution patterns", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.evidence === "Silently run")).toBe(true);
    });

    it("detects git URL dependency in MCP", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.id.includes("git-url-dep"))).toBe(true);
    });

    it("detects agent tool escalation chain", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.id.includes("escalation-chain"))).toBe(true);
    });

    it("detects expensive model for read-only agent", () => {
      const result = scan(VULNERABLE_PATH);
      expect(result.findings.some((f) => f.id.includes("expensive-readonly"))).toBe(true);
    });

    it("produces expected number of findings", () => {
      const result = scan(VULNERABLE_PATH);
      // With 49 rules and the vulnerable example, we expect 85+ findings
      expect(result.findings.length).toBeGreaterThanOrEqual(85);
    });

    it("includes auto-fixable findings", () => {
      const result = scan(VULNERABLE_PATH);
      const autoFixable = result.findings.filter((f) => f.fix?.auto === true);
      expect(autoFixable.length).toBeGreaterThanOrEqual(1);
    });
  });
});
