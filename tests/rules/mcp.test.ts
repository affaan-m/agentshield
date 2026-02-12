import { describe, it, expect } from "vitest";
import { mcpRules } from "../../src/rules/mcp.js";
import type { ConfigFile } from "../../src/types.js";

function makeMcpConfig(servers: Record<string, unknown>): ConfigFile {
  return {
    path: "mcp.json",
    type: "mcp-json",
    content: JSON.stringify({ mcpServers: servers }),
  };
}

function runAllMcpRules(file: ConfigFile) {
  return mcpRules.flatMap((rule) => rule.check(file));
}

describe("mcpRules", () => {
  describe("risky MCP servers", () => {
    it("flags filesystem MCP as high risk", () => {
      const file = makeMcpConfig({ filesystem: { command: "node", description: "fs" } });
      const findings = runAllMcpRules(file);
      expect(findings.some((f) => f.title.includes("filesystem") && f.severity === "high")).toBe(true);
    });

    it("flags shell MCP as critical risk", () => {
      const file = makeMcpConfig({ "shell-runner": { command: "node" } });
      const findings = runAllMcpRules(file);
      expect(findings.some((f) => f.severity === "critical" && f.title.includes("shell"))).toBe(true);
    });

    it("flags database MCP as high risk", () => {
      const file = makeMcpConfig({ "postgres-db": { command: "node" } });
      const findings = runAllMcpRules(file);
      expect(findings.some((f) => f.title.includes("postgres-db"))).toBe(true);
    });

    it("flags browser MCP as high risk", () => {
      const file = makeMcpConfig({ "puppeteer": { command: "node" } });
      const findings = runAllMcpRules(file);
      expect(findings.some((f) => f.title.includes("puppeteer"))).toBe(true);
    });

    it("does not flag safe MCP servers", () => {
      const file = makeMcpConfig({
        memory: { command: "node", description: "Memory server" },
        github: { command: "node", description: "GitHub" },
      });
      const findings = runAllMcpRules(file);
      const riskyFindings = findings.filter((f) => f.id.startsWith("mcp-risky"));
      expect(riskyFindings).toHaveLength(0);
    });
  });

  describe("hardcoded env secrets", () => {
    it("detects hardcoded tokens in MCP env", () => {
      const file = makeMcpConfig({
        myserver: {
          command: "node",
          env: { API_AUTH_TOKEN: "hardcoded-secret-value-here" },
        },
      });
      const findings = runAllMcpRules(file);
      expect(findings.some((f) => f.id.includes("hardcoded-env") && f.severity === "critical")).toBe(true);
    });

    it("skips env var references", () => {
      const file = makeMcpConfig({
        myserver: {
          command: "node",
          env: { API_AUTH_TOKEN: "${MY_TOKEN}" },
        },
      });
      const findings = runAllMcpRules(file);
      const hardcodedFindings = findings.filter((f) => f.id.includes("hardcoded-env"));
      expect(hardcodedFindings).toHaveLength(0);
    });

    it("skips non-secret env vars", () => {
      const file = makeMcpConfig({
        myserver: {
          command: "node",
          env: { NODE_ENV: "production", LOG_LEVEL: "debug" },
        },
      });
      const findings = runAllMcpRules(file);
      const hardcodedFindings = findings.filter((f) => f.id.includes("hardcoded-env"));
      expect(hardcodedFindings).toHaveLength(0);
    });
  });

  describe("npx supply chain", () => {
    it("flags npx -y auto-install", () => {
      const file = makeMcpConfig({
        myserver: { command: "npx", args: ["-y", "@example/server"] },
      });
      const findings = runAllMcpRules(file);
      expect(findings.some((f) => f.id.includes("npx-y"))).toBe(true);
    });

    it("does not flag npx without -y", () => {
      const file = makeMcpConfig({
        myserver: { command: "npx", args: ["@example/server"] },
      });
      const findings = runAllMcpRules(file);
      const npxFindings = findings.filter((f) => f.id.includes("npx-y"));
      expect(npxFindings).toHaveLength(0);
    });

    it("does not flag non-npx commands", () => {
      const file = makeMcpConfig({
        myserver: { command: "node", args: ["server.js"] },
      });
      const findings = runAllMcpRules(file);
      const npxFindings = findings.filter((f) => f.id.includes("npx-y"));
      expect(npxFindings).toHaveLength(0);
    });
  });

  describe("missing descriptions", () => {
    it("flags servers without descriptions", () => {
      const file = makeMcpConfig({ myserver: { command: "node" } });
      const findings = runAllMcpRules(file);
      expect(findings.some((f) => f.severity === "info" && f.title.includes("no description"))).toBe(true);
    });

    it("does not flag servers with descriptions", () => {
      const file = makeMcpConfig({ myserver: { command: "node", description: "My server" } });
      const findings = runAllMcpRules(file);
      const descFindings = findings.filter((f) => f.id.includes("no-desc"));
      expect(descFindings).toHaveLength(0);
    });
  });

  describe("unrestricted root path", () => {
    it("flags filesystem server with / path", () => {
      const file = makeMcpConfig({
        filesystem: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/"] },
      });
      const findings = runAllMcpRules(file);
      expect(findings.some((f) => f.id.includes("root-path") && f.severity === "high")).toBe(true);
    });

    it("flags server with ~ home directory path", () => {
      const file = makeMcpConfig({
        myfs: { command: "node", args: ["server.js", "~"] },
      });
      const findings = runAllMcpRules(file);
      expect(findings.some((f) => f.id.includes("root-path"))).toBe(true);
    });

    it("flags server with C:\\ Windows root path", () => {
      const file = makeMcpConfig({
        myfs: { command: "node", args: ["server.js", "C:\\"] },
      });
      const findings = runAllMcpRules(file);
      expect(findings.some((f) => f.id.includes("root-path"))).toBe(true);
    });

    it("does not flag restricted paths", () => {
      const file = makeMcpConfig({
        filesystem: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "./src"] },
      });
      const findings = runAllMcpRules(file);
      const rootFindings = findings.filter((f) => f.id.includes("root-path"));
      expect(rootFindings).toHaveLength(0);
    });

    it("provides fix suggestion", () => {
      const file = makeMcpConfig({
        filesystem: { command: "npx", args: ["-y", "server", "/"] },
      });
      const findings = runAllMcpRules(file);
      const rootFinding = findings.find((f) => f.id.includes("root-path"));
      expect(rootFinding?.fix).toBeDefined();
      expect(rootFinding?.fix?.after).toContain("./src");
    });
  });

  describe("no version pin", () => {
    it("flags npx with unversioned scoped package", () => {
      const file = makeMcpConfig({
        myserver: { command: "npx", args: ["-y", "@example/server"] },
      });
      const findings = runAllMcpRules(file);
      expect(findings.some((f) => f.id.includes("no-version") && f.severity === "medium")).toBe(true);
    });

    it("does not flag versioned scoped package", () => {
      const file = makeMcpConfig({
        myserver: { command: "npx", args: ["-y", "@example/server@1.2.3"] },
      });
      const findings = runAllMcpRules(file);
      const versionFindings = findings.filter((f) => f.id.includes("no-version"));
      expect(versionFindings).toHaveLength(0);
    });

    it("does not flag non-npx commands", () => {
      const file = makeMcpConfig({
        myserver: { command: "node", args: ["@example/server"] },
      });
      const findings = runAllMcpRules(file);
      const versionFindings = findings.filter((f) => f.id.includes("no-version"));
      expect(versionFindings).toHaveLength(0);
    });

    it("skips packages without scope/slash", () => {
      const file = makeMcpConfig({
        myserver: { command: "npx", args: ["-y", "simple-package"] },
      });
      const findings = runAllMcpRules(file);
      const versionFindings = findings.filter((f) => f.id.includes("no-version"));
      expect(versionFindings).toHaveLength(0);
    });
  });

  describe("excessive server count", () => {
    it("flags more than 10 servers", () => {
      const servers: Record<string, unknown> = {};
      for (let i = 0; i < 12; i++) {
        servers[`server-${i}`] = { command: "node", description: `Server ${i}` };
      }
      const file = makeMcpConfig(servers);
      const findings = runAllMcpRules(file);
      expect(findings.some((f) => f.id === "mcp-excessive-servers" && f.severity === "low")).toBe(true);
      expect(findings.some((f) => f.title.includes("12"))).toBe(true);
    });

    it("does not flag 10 or fewer servers", () => {
      const servers: Record<string, unknown> = {};
      for (let i = 0; i < 10; i++) {
        servers[`server-${i}`] = { command: "node", description: `Server ${i}` };
      }
      const file = makeMcpConfig(servers);
      const findings = runAllMcpRules(file);
      const countFindings = findings.filter((f) => f.id === "mcp-excessive-servers");
      expect(countFindings).toHaveLength(0);
    });

    it("does not flag empty config", () => {
      const file = makeMcpConfig({});
      const findings = runAllMcpRules(file);
      const countFindings = findings.filter((f) => f.id === "mcp-excessive-servers");
      expect(countFindings).toHaveLength(0);
    });
  });
});
