import { describe, it, expect } from "vitest";
import { extractPackages } from "../../src/supply-chain/extract.js";
import type { ConfigFile } from "../../src/types.js";

function makeMcpConfig(servers: Record<string, { command: string; args?: string[] }>): ConfigFile {
  return {
    path: "mcp.json",
    type: "mcp-json",
    content: JSON.stringify({ mcpServers: servers }),
  };
}

describe("extractPackages", () => {
  it("extracts packages from npx commands", () => {
    const file = makeMcpConfig({
      github: { command: "npx", args: ["@modelcontextprotocol/server-github"] },
    });
    const packages = extractPackages([file]);

    expect(packages).toHaveLength(1);
    expect(packages[0].name).toBe("@modelcontextprotocol/server-github");
    expect(packages[0].source).toBe("npx");
    expect(packages[0].serverName).toBe("github");
  });

  it("extracts versioned packages from npx", () => {
    const file = makeMcpConfig({
      fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@1.2.3"] },
    });
    const packages = extractPackages([file]);

    expect(packages).toHaveLength(1);
    expect(packages[0].name).toBe("@modelcontextprotocol/server-filesystem");
    expect(packages[0].version).toBe("1.2.3");
  });

  it("skips flags in npx args", () => {
    const file = makeMcpConfig({
      test: { command: "npx", args: ["-y", "--no-install", "some-mcp-server"] },
    });
    const packages = extractPackages([file]);

    expect(packages).toHaveLength(1);
    expect(packages[0].name).toBe("some-mcp-server");
  });

  it("extracts packages from direct commands", () => {
    const file = makeMcpConfig({
      git: { command: "mcp-server-git", args: ["--repo", "."] },
    });
    const packages = extractPackages([file]);

    expect(packages).toHaveLength(1);
    expect(packages[0].name).toBe("mcp-server-git");
    expect(packages[0].source).toBe("command");
  });

  it("extracts git URLs from args", () => {
    const file = makeMcpConfig({
      custom: {
        command: "npx",
        args: ["https://github.com/org/mcp-custom-server#v1.0.0"],
      },
    });
    const packages = extractPackages([file]);

    expect(packages.some((p) => p.source === "git")).toBe(true);
    const gitPkg = packages.find((p) => p.source === "git")!;
    expect(gitPkg.gitRef).toBe("v1.0.0");
  });

  it("skips git URLs when extracting npx package specs", () => {
    const file = makeMcpConfig({
      custom: {
        command: "npx",
        args: ["https://github.com/org/mcp-custom-server#v1.0.0"],
      },
    });
    const packages = extractPackages([file]);

    expect(packages).toHaveLength(1);
    expect(packages[0].source).toBe("git");
  });

  it("detects unpinned git URLs", () => {
    const file = makeMcpConfig({
      custom: {
        command: "npx",
        args: ["https://github.com/org/mcp-server"],
      },
    });
    const packages = extractPackages([file]);

    const gitPkg = packages.find((p) => p.source === "git");
    expect(gitPkg).toBeDefined();
    expect(gitPkg!.gitRef).toBeUndefined();
  });

  it("deduplicates packages", () => {
    const file1 = makeMcpConfig({
      s1: { command: "npx", args: ["@modelcontextprotocol/server-github"] },
    });
    const file2 = makeMcpConfig({
      s2: { command: "npx", args: ["@modelcontextprotocol/server-github"] },
    });
    const packages = extractPackages([file1, file2]);

    expect(packages).toHaveLength(1);
  });

  it("keeps git packages with different refs as separate entries", () => {
    const file = makeMcpConfig({
      unpinned: { command: "npx", args: ["https://github.com/org/mcp-server"] },
      pinned: {
        command: "npx",
        args: ["https://github.com/org/mcp-server#0123456789abcdef0123456789abcdef01234567"],
      },
    });
    const packages = extractPackages([file]);

    const gitPackages = packages.filter((pkg) => pkg.source === "git");
    expect(gitPackages).toHaveLength(2);
    expect(gitPackages.map((pkg) => pkg.gitRef)).toEqual([
      undefined,
      "0123456789abcdef0123456789abcdef01234567",
    ]);
  });

  it("handles multiple servers in one config", () => {
    const file = makeMcpConfig({
      github: { command: "npx", args: ["@modelcontextprotocol/server-github"] },
      fs: { command: "npx", args: ["@modelcontextprotocol/server-filesystem"] },
      git: { command: "mcp-server-git", args: [] },
    });
    const packages = extractPackages([file]);

    expect(packages.length).toBeGreaterThanOrEqual(3);
  });

  it("handles invalid JSON gracefully", () => {
    const file: ConfigFile = {
      path: "mcp.json",
      type: "mcp-json",
      content: "not valid json{{",
    };
    const packages = extractPackages([file]);

    expect(packages).toEqual([]);
  });

  it("skips non-MCP config files", () => {
    const file: ConfigFile = {
      path: "CLAUDE.md",
      type: "claude-md",
      content: "# My config\nnpx @malicious/package",
    };
    const packages = extractPackages([file]);

    expect(packages).toEqual([]);
  });

  it("extracts node_modules paths from node commands", () => {
    const file = makeMcpConfig({
      custom: {
        command: "node",
        args: ["node_modules/@scope/my-mcp-server/dist/index.js"],
      },
    });
    const packages = extractPackages([file]);

    expect(packages.some((p) => p.name === "@scope/my-mcp-server")).toBe(true);
  });
});
