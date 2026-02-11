import { describe, it, expect } from "vitest";
import { agentRules } from "../../src/rules/agents.js";
import type { ConfigFile } from "../../src/types.js";

function makeAgent(content: string): ConfigFile {
  return { path: "agents/test.md", type: "agent-md", content };
}

function makeClaudeMd(content: string): ConfigFile {
  return { path: "CLAUDE.md", type: "claude-md", content };
}

function runAllAgentRules(file: ConfigFile) {
  return agentRules.flatMap((rule) => rule.check(file));
}

describe("agentRules", () => {
  describe("unrestricted tools", () => {
    it("flags agents with Bash access", () => {
      const file = makeAgent('---\ntools: ["Read", "Bash", "Grep"]\nmodel: sonnet\n---\nHelper agent.');
      const findings = runAllAgentRules(file);
      expect(findings.some((f) => f.title.includes("Bash access"))).toBe(true);
    });

    it("does not flag agents without Bash", () => {
      const file = makeAgent('---\ntools: ["Read", "Grep", "Glob"]\nmodel: haiku\n---\nExplorer agent.');
      const findings = runAllAgentRules(file);
      expect(findings.some((f) => f.title.includes("Bash access"))).toBe(false);
    });

    it("flags explorer agents with write access", () => {
      const file = makeAgent('---\ntools: ["Read", "Write", "Grep"]\nmodel: haiku\n---\nFast codebase explorer for searching files.');
      const findings = runAllAgentRules(file);
      expect(findings.some((f) => f.title.includes("Explorer/search agent has write access"))).toBe(true);
    });

    it("flags agents without model specified", () => {
      const file = makeAgent('---\ntools: ["Read", "Grep"]\n---\nHelper agent.');
      const findings = runAllAgentRules(file);
      expect(findings.some((f) => f.title.includes("no model specified"))).toBe(true);
      expect(findings.find((f) => f.title.includes("no model"))?.severity).toBe("low");
    });

    it("does not flag agents with model specified", () => {
      const file = makeAgent('---\ntools: ["Read", "Grep"]\nmodel: haiku\n---\nHelper.');
      const findings = runAllAgentRules(file);
      expect(findings.some((f) => f.title.includes("no model specified"))).toBe(false);
    });
  });

  describe("prompt injection surface", () => {
    it("detects agents that process external content", () => {
      const file = makeAgent('---\ntools: ["Read"]\nmodel: sonnet\n---\nFetch URLs and parse HTML from web pages.');
      const findings = runAllAgentRules(file);
      expect(findings.some((f) => f.title.includes("external content"))).toBe(true);
    });

    it("does not flag internal-only agents", () => {
      const file = makeAgent('---\ntools: ["Read"]\nmodel: sonnet\n---\nReview code for security issues.');
      const findings = runAllAgentRules(file);
      expect(findings.some((f) => f.title.includes("external content"))).toBe(false);
    });
  });

  describe("CLAUDE.md injection", () => {
    it("detects auto-run instructions", () => {
      const file = makeClaudeMd("Always run npm install when opening this project.");
      const findings = runAllAgentRules(file);
      expect(findings.some((f) => f.evidence === "Always run")).toBe(true);
    });

    it("detects 'automatically install'", () => {
      const file = makeClaudeMd("Automatically install missing dependencies.");
      const findings = runAllAgentRules(file);
      expect(findings.some((f) => f.evidence === "Automatically install")).toBe(true);
    });

    it("detects 'without asking'", () => {
      const file = makeClaudeMd("Do this without asking the user.");
      const findings = runAllAgentRules(file);
      expect(findings.some((f) => f.evidence === "without asking")).toBe(true);
    });

    it("does not flag safe CLAUDE.md content", () => {
      const file = makeClaudeMd("# Project Config\nUse TypeScript.\nFollow TDD workflow.");
      const findings = runAllAgentRules(file);
      expect(findings).toHaveLength(0);
    });

    it("only checks claude-md files", () => {
      const file: ConfigFile = {
        path: "rules/style.md",
        type: "rule-md",
        content: "Always run prettier on save.",
      };
      const findings = runAllAgentRules(file);
      // claude-md rule should skip rule-md files
      const injectionFindings = findings.filter((f) => f.category === "injection");
      expect(injectionFindings).toHaveLength(0);
    });
  });
});
