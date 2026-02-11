import { describe, it, expect } from "vitest";
import {
  TOOL_REGISTRY,
  createSafeWhitelist,
  createGuardedWhitelist,
  createCustomWhitelist,
  validateToolCall,
  scopeToolCall,
  executeToolCall,
  getToolsByRiskLevel,
} from "../../src/miniclaw/tools.js";
import type { ToolCallRequest, ToolWhitelist } from "../../src/miniclaw/types.js";

// ─── TOOL_REGISTRY ────────────────────────────────────────

describe("TOOL_REGISTRY", () => {
  it("contains exactly 9 tools", () => {
    expect(TOOL_REGISTRY).toHaveLength(9);
  });

  it("contains all safe tools: read, search, list", () => {
    const safeNames = TOOL_REGISTRY.filter((t) => t.riskLevel === "safe").map((t) => t.name);
    expect(safeNames).toEqual(expect.arrayContaining(["read", "search", "list"]));
    expect(safeNames).toHaveLength(3);
  });

  it("contains all guarded tools: write, edit, glob", () => {
    const guardedNames = TOOL_REGISTRY.filter((t) => t.riskLevel === "guarded").map((t) => t.name);
    expect(guardedNames).toEqual(expect.arrayContaining(["write", "edit", "glob"]));
    expect(guardedNames).toHaveLength(3);
  });

  it("contains all restricted tools: bash, network, external_api", () => {
    const restrictedNames = TOOL_REGISTRY.filter((t) => t.riskLevel === "restricted").map((t) => t.name);
    expect(restrictedNames).toEqual(expect.arrayContaining(["bash", "network", "external_api"]));
    expect(restrictedNames).toHaveLength(3);
  });

  it("every tool has name, description, and riskLevel", () => {
    for (const tool of TOOL_REGISTRY) {
      expect(tool.name).toBeTruthy();
      expect(tool.description).toBeTruthy();
      expect(["safe", "guarded", "restricted"]).toContain(tool.riskLevel);
    }
  });
});

// ─── createSafeWhitelist ──────────────────────────────────

describe("createSafeWhitelist", () => {
  it("returns a whitelist with exactly 3 tools", () => {
    const whitelist = createSafeWhitelist();
    expect(whitelist.tools).toHaveLength(3);
  });

  it("all tools have riskLevel 'safe'", () => {
    const whitelist = createSafeWhitelist();
    for (const tool of whitelist.tools) {
      expect(tool.riskLevel).toBe("safe");
    }
  });

  it("includes read, search, and list", () => {
    const whitelist = createSafeWhitelist();
    const names = whitelist.tools.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(["read", "search", "list"]));
  });
});

// ─── createGuardedWhitelist ───────────────────────────────

describe("createGuardedWhitelist", () => {
  it("returns a whitelist with exactly 6 tools (safe + guarded)", () => {
    const whitelist = createGuardedWhitelist();
    expect(whitelist.tools).toHaveLength(6);
  });

  it("does not include any restricted tools", () => {
    const whitelist = createGuardedWhitelist();
    const restrictedTools = whitelist.tools.filter((t) => t.riskLevel === "restricted");
    expect(restrictedTools).toHaveLength(0);
  });

  it("includes all safe and guarded tool names", () => {
    const whitelist = createGuardedWhitelist();
    const names = whitelist.tools.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(["read", "search", "list", "write", "edit", "glob"]));
  });
});

// ─── createCustomWhitelist ────────────────────────────────

describe("createCustomWhitelist", () => {
  it("includes recognized tools in the whitelist", () => {
    const { whitelist } = createCustomWhitelist(["read", "write"]);
    const names = whitelist.tools.map((t) => t.name);
    expect(names).toEqual(["read", "write"]);
  });

  it("returns unrecognized tool names separately", () => {
    const { unrecognized } = createCustomWhitelist(["read", "fake_tool"]);
    expect(unrecognized).toEqual(["fake_tool"]);
  });

  it("returns empty whitelist and empty unrecognized for empty input", () => {
    const { whitelist, unrecognized } = createCustomWhitelist([]);
    expect(whitelist.tools).toHaveLength(0);
    expect(unrecognized).toHaveLength(0);
  });

  it("handles a mix of valid and invalid tool names", () => {
    const { whitelist, unrecognized } = createCustomWhitelist([
      "read", "nope", "bash", "also_nope",
    ]);
    expect(whitelist.tools.map((t) => t.name)).toEqual(["read", "bash"]);
    expect(unrecognized).toEqual(["nope", "also_nope"]);
  });
});

// ─── validateToolCall ─────────────────────────────────────

describe("validateToolCall", () => {
  const safeWhitelist = createSafeWhitelist();
  const guardedWhitelist = createGuardedWhitelist();

  it("allows a tool that is in the whitelist", () => {
    const call: ToolCallRequest = { tool: "read", args: { path: "test.ts" } };
    const result = validateToolCall(call, safeWhitelist);
    expect(result.allowed).toBe(true);
    expect(result.tool).toBe("read");
  });

  it("denies a tool in the registry but not in the whitelist (mentions risk level)", () => {
    const call: ToolCallRequest = { tool: "write", args: {} };
    const result = validateToolCall(call, safeWhitelist);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("guarded");
    expect(result.reason).toContain("not in the session whitelist");
  });

  it("denies an unknown tool not in the registry", () => {
    const call: ToolCallRequest = { tool: "hack_system", args: {} };
    const result = validateToolCall(call, safeWhitelist);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("not in the tool registry");
  });

  it("safe whitelist allows read but denies write and bash", () => {
    expect(validateToolCall({ tool: "read", args: {} }, safeWhitelist).allowed).toBe(true);
    expect(validateToolCall({ tool: "write", args: {} }, safeWhitelist).allowed).toBe(false);
    expect(validateToolCall({ tool: "bash", args: {} }, safeWhitelist).allowed).toBe(false);
  });

  it("guarded whitelist allows read and write but denies bash", () => {
    expect(validateToolCall({ tool: "read", args: {} }, guardedWhitelist).allowed).toBe(true);
    expect(validateToolCall({ tool: "write", args: {} }, guardedWhitelist).allowed).toBe(true);
    expect(validateToolCall({ tool: "bash", args: {} }, guardedWhitelist).allowed).toBe(false);
  });
});

// ─── scopeToolCall ────────────────────────────────────────

describe("scopeToolCall", () => {
  const sandbox = "/tmp/miniclaw-sandboxes/session-123";

  it("rewrites path arguments to sandbox scope", () => {
    const call: ToolCallRequest = { tool: "read", args: { path: "src/index.ts" } };
    const scoped = scopeToolCall(call, sandbox);
    expect(scoped.args["path"]).toBe(`${sandbox}/src/index.ts`);
  });

  it("strips leading slash from absolute paths", () => {
    const call: ToolCallRequest = { tool: "read", args: { path: "/etc/passwd" } };
    const scoped = scopeToolCall(call, sandbox);
    expect(scoped.args["path"]).toBe(`${sandbox}/etc/passwd`);
  });

  it("removes ../ sequences from path arguments", () => {
    const call: ToolCallRequest = { tool: "read", args: { path: "../../etc/passwd" } };
    const scoped = scopeToolCall(call, sandbox);
    expect(scoped.args["path"]).toBe(`${sandbox}/etc/passwd`);
  });

  it("passes non-path arguments through unchanged", () => {
    const call: ToolCallRequest = { tool: "search", args: { pattern: "TODO", maxResults: 10 } };
    const scoped = scopeToolCall(call, sandbox);
    expect(scoped.args["pattern"]).toBe("TODO");
    expect(scoped.args["maxResults"]).toBe(10);
  });

  it("recognizes various path argument key names", () => {
    const pathKeys = ["path", "file", "filePath", "file_path", "directory", "dir", "target"];
    for (const key of pathKeys) {
      const call: ToolCallRequest = { tool: "read", args: { [key]: "foo.ts" } };
      const scoped = scopeToolCall(call, sandbox);
      expect(scoped.args[key]).toBe(`${sandbox}/foo.ts`);
    }
  });

  it("preserves the tool name in the scoped call", () => {
    const call: ToolCallRequest = { tool: "write", args: { path: "out.ts" } };
    const scoped = scopeToolCall(call, sandbox);
    expect(scoped.tool).toBe("write");
  });
});

// ─── executeToolCall ──────────────────────────────────────

describe("executeToolCall", () => {
  const sandbox = "/tmp/miniclaw-sandboxes/session-abc";
  const sessionId = "session-abc";

  it("read tool without path argument returns error message", async () => {
    const call: ToolCallRequest = { tool: "read", args: {} };
    const { result } = await executeToolCall(call, sandbox, sessionId);
    expect(result).toContain("'path' argument is required");
  });

  it("write tool without required args returns error message", async () => {
    const call: ToolCallRequest = { tool: "write", args: {} };
    const { result } = await executeToolCall(call, sandbox, sessionId);
    expect(result).toContain("'path' and 'content' arguments are required");
  });

  it("write tool with blocked extension produces sandbox_violation event", async () => {
    const call: ToolCallRequest = {
      tool: "write",
      args: { path: `${sandbox}/malicious.exe`, content: "bad stuff" },
    };
    const { result, events } = await executeToolCall(call, sandbox, sessionId);
    expect(result).toContain("Error");
    expect(events.some((e) => e.type === "sandbox_violation")).toBe(true);
  });

  it("search tool without pattern returns error message", async () => {
    const call: ToolCallRequest = { tool: "search", args: {} };
    const { result } = await executeToolCall(call, sandbox, sessionId);
    expect(result).toContain("'pattern' argument is required");
  });

  it("list tool uses sandbox path as default directory", async () => {
    const call: ToolCallRequest = { tool: "list", args: {} };
    const { result } = await executeToolCall(call, sandbox, sessionId);
    expect(result).toContain(sandbox);
  });

  it("unknown tool executor produces tool_denied event", async () => {
    const call: ToolCallRequest = { tool: "bash", args: {} };
    const { result, events } = await executeToolCall(call, sandbox, sessionId);
    expect(result).toContain("No executor for tool");
    expect(events.some((e) => e.type === "tool_denied")).toBe(true);
  });
});

// ─── getToolsByRiskLevel ──────────────────────────────────

describe("getToolsByRiskLevel", () => {
  it("returns safe, guarded, and restricted groups", () => {
    const groups = getToolsByRiskLevel();
    expect(groups).toHaveProperty("safe");
    expect(groups).toHaveProperty("guarded");
    expect(groups).toHaveProperty("restricted");
  });

  it("safe group contains read, search, list", () => {
    const groups = getToolsByRiskLevel();
    const names = groups.safe.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(["read", "search", "list"]));
    expect(names).toHaveLength(3);
  });

  it("guarded group contains write, edit, glob", () => {
    const groups = getToolsByRiskLevel();
    const names = groups.guarded.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(["write", "edit", "glob"]));
    expect(names).toHaveLength(3);
  });

  it("restricted group contains bash, network, external_api", () => {
    const groups = getToolsByRiskLevel();
    const names = groups.restricted.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(["bash", "network", "external_api"]));
    expect(names).toHaveLength(3);
  });
});
