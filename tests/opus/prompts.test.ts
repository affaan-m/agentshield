import { describe, it, expect } from "vitest";
import {
  buildConfigContext,
  buildAuditorContext,
  ATTACKER_SYSTEM_PROMPT,
  DEFENDER_SYSTEM_PROMPT,
  AUDITOR_SYSTEM_PROMPT,
} from "../../src/opus/prompts.js";

describe("opus prompts", () => {
  describe("system prompts", () => {
    it("attacker prompt mentions red team perspective", () => {
      expect(ATTACKER_SYSTEM_PROMPT).toContain("red team");
    });

    it("defender prompt mentions hardening", () => {
      expect(DEFENDER_SYSTEM_PROMPT).toContain("hardening");
    });

    it("auditor prompt mentions final assessment", () => {
      expect(AUDITOR_SYSTEM_PROMPT).toContain("final assessment");
    });

    it("attacker prompt covers key attack vectors", () => {
      expect(ATTACKER_SYSTEM_PROMPT).toContain("Prompt injection");
      expect(ATTACKER_SYSTEM_PROMPT).toContain("Command injection");
      expect(ATTACKER_SYSTEM_PROMPT).toContain("Data exfiltration");
      expect(ATTACKER_SYSTEM_PROMPT).toContain("Supply chain");
    });
  });

  describe("buildConfigContext", () => {
    it("formats files as markdown code blocks", () => {
      const files = [
        { path: "CLAUDE.md", content: "# Instructions" },
        { path: "settings.json", content: '{"permissions":{}}' },
      ];
      const result = buildConfigContext(files);
      expect(result).toContain("### File: CLAUDE.md");
      expect(result).toContain("# Instructions");
      expect(result).toContain("### File: settings.json");
      expect(result).toContain('{"permissions":{}}');
    });

    it("wraps content in code fences", () => {
      const files = [{ path: "test.md", content: "hello" }];
      const result = buildConfigContext(files);
      expect(result).toContain("```\nhello\n```");
    });

    it("handles empty file list", () => {
      const result = buildConfigContext([]);
      expect(result).toContain("## AI Agent Configuration Files");
    });
  });

  describe("buildAuditorContext", () => {
    it("combines config, attacker, and defender analysis", () => {
      const result = buildAuditorContext(
        "CONFIG_CONTEXT",
        "ATTACKER_FINDINGS",
        "DEFENDER_RECS"
      );
      expect(result).toContain("CONFIG_CONTEXT");
      expect(result).toContain("ATTACKER_FINDINGS");
      expect(result).toContain("DEFENDER_RECS");
    });

    it("includes section headers for each perspective", () => {
      const result = buildAuditorContext("config", "attack", "defend");
      expect(result).toContain("Red Team Analysis");
      expect(result).toContain("Blue Team Analysis");
    });
  });
});
