import { describe, it, expect, afterEach } from "vitest";
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
});

describe("startMiniClaw", () => {
  it("is exported as a function", () => {
    expect(typeof startMiniClaw).toBe("function");
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
