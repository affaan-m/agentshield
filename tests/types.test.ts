import { describe, it, expect } from "vitest";
import { SettingsSchema, McpConfigSchema, SEVERITY_ORDER } from "../src/types.js";

describe("types", () => {
  describe("SEVERITY_ORDER", () => {
    it("critical has lowest order value", () => {
      expect(SEVERITY_ORDER.critical).toBe(0);
    });

    it("info has highest order value", () => {
      expect(SEVERITY_ORDER.info).toBe(4);
    });

    it("has correct ordering", () => {
      expect(SEVERITY_ORDER.critical).toBeLessThan(SEVERITY_ORDER.high);
      expect(SEVERITY_ORDER.high).toBeLessThan(SEVERITY_ORDER.medium);
      expect(SEVERITY_ORDER.medium).toBeLessThan(SEVERITY_ORDER.low);
      expect(SEVERITY_ORDER.low).toBeLessThan(SEVERITY_ORDER.info);
    });
  });

  describe("SettingsSchema", () => {
    it("validates a valid settings config", () => {
      const result = SettingsSchema.safeParse({
        hooks: {
          PreToolUse: [{ matcher: "Bash", hook: "echo hi" }],
        },
        permissions: {
          allow: ["Read", "Write"],
          deny: ["Bash(*)"],
        },
      });
      expect(result.success).toBe(true);
    });

    it("validates minimal config", () => {
      const result = SettingsSchema.safeParse({});
      expect(result.success).toBe(true);
    });

    it("rejects invalid hook format", () => {
      const result = SettingsSchema.safeParse({
        hooks: {
          PreToolUse: [{ wrong: "field" }],
        },
      });
      expect(result.success).toBe(false);
    });
  });

  describe("McpConfigSchema", () => {
    it("validates a valid MCP config", () => {
      const result = McpConfigSchema.safeParse({
        mcpServers: {
          github: {
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-github"],
            env: { GITHUB_TOKEN: "token" },
          },
        },
      });
      expect(result.success).toBe(true);
    });

    it("validates minimal MCP config", () => {
      const result = McpConfigSchema.safeParse({
        mcpServers: {
          test: { command: "test-server" },
        },
      });
      expect(result.success).toBe(true);
    });

    it("rejects missing command", () => {
      const result = McpConfigSchema.safeParse({
        mcpServers: {
          test: { args: ["--flag"] },
        },
      });
      expect(result.success).toBe(false);
    });
  });
});
