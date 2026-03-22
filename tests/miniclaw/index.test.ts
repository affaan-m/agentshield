import { describe, it, expect, afterEach, vi } from "vitest";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  startMiniClaw,
  createMiniClawSession,
  sanitizePrompt,
  filterResponse,
  routePrompt,
  createSandbox,
  destroySandbox,
  validatePath,
  TOOL_REGISTRY,
  createSafeWhitelist,
  validateToolCall,
  createMiniClawServer,
} from "../../src/miniclaw/index.js";

const TEST_ROOT = join(tmpdir(), "miniclaw-index-test");

afterEach(async () => {
  await rm(TEST_ROOT, { recursive: true, force: true });
  vi.restoreAllMocks();
  vi.resetModules();
});

describe("startMiniClaw", () => {
  it("is exported as a function", () => {
    expect(typeof startMiniClaw).toBe("function");
  });

  it("builds default config through the safe whitelist", async () => {
    const startServerMock = vi.fn(() => ({
      server: {} as never,
      stop: vi.fn(),
    }));
    const createSafeWhitelistMock = vi.fn(() => ({ tools: [] }));

    vi.doMock("../../src/miniclaw/server.js", async () => {
      const actual = await vi.importActual<typeof import("../../src/miniclaw/server.js")>(
        "../../src/miniclaw/server.js"
      );
      return {
        ...actual,
        startServer: startServerMock,
      };
    });

    vi.doMock("../../src/miniclaw/tools.js", async () => {
      const actual = await vi.importActual<typeof import("../../src/miniclaw/tools.js")>(
        "../../src/miniclaw/tools.js"
      );
      return {
        ...actual,
        createSafeWhitelist: createSafeWhitelistMock,
      };
    });

    const types = await import("../../src/miniclaw/types.js");
    const module = await import("../../src/miniclaw/index.js");
    const result = module.startMiniClaw();

    expect(createSafeWhitelistMock).toHaveBeenCalledTimes(1);
    expect(startServerMock).toHaveBeenCalledWith({
      sandbox: types.DEFAULT_SANDBOX_CONFIG,
      server: types.DEFAULT_SERVER_CONFIG,
      tools: { tools: [] },
    });
    expect(result).toBe(startServerMock.mock.results[0]?.value);
  });

  it("passes explicit config through without regenerating a whitelist", async () => {
    const startServerMock = vi.fn(() => ({
      server: {} as never,
      stop: vi.fn(),
    }));
    const createSafeWhitelistMock = vi.fn(() => ({ tools: [] }));

    vi.doMock("../../src/miniclaw/server.js", async () => {
      const actual = await vi.importActual<typeof import("../../src/miniclaw/server.js")>(
        "../../src/miniclaw/server.js"
      );
      return {
        ...actual,
        startServer: startServerMock,
      };
    });

    vi.doMock("../../src/miniclaw/tools.js", async () => {
      const actual = await vi.importActual<typeof import("../../src/miniclaw/tools.js")>(
        "../../src/miniclaw/tools.js"
      );
      return {
        ...actual,
        createSafeWhitelist: createSafeWhitelistMock,
      };
    });

    const types = await import("../../src/miniclaw/types.js");
    const module = await import("../../src/miniclaw/index.js");
    const config = {
      sandbox: {
        ...types.DEFAULT_SANDBOX_CONFIG,
        rootPath: TEST_ROOT,
      },
      server: {
        ...types.DEFAULT_SERVER_CONFIG,
        port: 4321,
      },
      tools: {
        tools: [],
      },
    };

    module.startMiniClaw(config);

    expect(createSafeWhitelistMock).not.toHaveBeenCalled();
    expect(startServerMock).toHaveBeenCalledWith(config);
  });
});

describe("createMiniClawSession", () => {
  it("creates a session with a sandbox directory", async () => {
    const session = await createMiniClawSession({
      sandbox: { rootPath: TEST_ROOT },
    });

    expect(session.sandboxPath).toContain(TEST_ROOT);
  });

  it("returns an object with id, createdAt, sandboxPath, and allowedTools", async () => {
    const session = await createMiniClawSession({
      sandbox: { rootPath: TEST_ROOT },
    });

    expect(session).toHaveProperty("id");
    expect(session).toHaveProperty("createdAt");
    expect(session).toHaveProperty("sandboxPath");
    expect(session).toHaveProperty("allowedTools");
  });

  it("generates a unique session id", async () => {
    const session1 = await createMiniClawSession({
      sandbox: { rootPath: TEST_ROOT },
    });
    const session2 = await createMiniClawSession({
      sandbox: { rootPath: TEST_ROOT },
    });

    expect(session1.id).not.toBe(session2.id);
  });

  it("sets createdAt to a valid ISO 8601 timestamp", async () => {
    const session = await createMiniClawSession({
      sandbox: { rootPath: TEST_ROOT },
    });

    expect(() => new Date(session.createdAt).toISOString()).not.toThrow();
  });
});

describe("re-exported router functions", () => {
  it("sanitizePrompt is exported as a function", () => {
    expect(typeof sanitizePrompt).toBe("function");
  });

  it("filterResponse is exported as a function", () => {
    expect(typeof filterResponse).toBe("function");
  });

  it("routePrompt is exported as a function", () => {
    expect(typeof routePrompt).toBe("function");
  });
});

describe("re-exported sandbox functions", () => {
  it("createSandbox is exported as a function", () => {
    expect(typeof createSandbox).toBe("function");
  });

  it("destroySandbox is exported as a function", () => {
    expect(typeof destroySandbox).toBe("function");
  });

  it("validatePath is exported as a function", () => {
    expect(typeof validatePath).toBe("function");
  });
});

describe("re-exported tool functions", () => {
  it("TOOL_REGISTRY is exported and defined", () => {
    expect(TOOL_REGISTRY).toBeDefined();
  });

  it("createSafeWhitelist is exported as a function", () => {
    expect(typeof createSafeWhitelist).toBe("function");
  });

  it("validateToolCall is exported as a function", () => {
    expect(typeof validateToolCall).toBe("function");
  });
});

describe("re-exported server functions", () => {
  it("createMiniClawServer is exported as a function", () => {
    expect(typeof createMiniClawServer).toBe("function");
  });
});
