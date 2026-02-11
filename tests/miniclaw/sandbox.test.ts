import { describe, it, expect, afterEach } from "vitest";
import { mkdir, writeFile, rm, stat, realpath } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import {
  validatePath,
  validateExtension,
  checkFileSize,
  createSandbox,
  destroySandbox,
  createSecurityEvent,
} from "../../src/miniclaw/sandbox.js";

// ─── Helpers ──────────────────────────────────────────────

/**
 * Creates a unique temp directory under /tmp for test isolation.
 * Returns the realpath-resolved path so that symlinks (e.g. macOS /tmp -> /private/tmp)
 * do not cause false negatives in validatePath's symlink-escape check.
 */
async function makeTempDir(): Promise<string> {
  const dir = join("/tmp", `miniclaw-test-${randomUUID()}`);
  await mkdir(dir, { recursive: true });
  return realpath(dir);
}

/** Quietly removes a directory tree. Never throws. */
async function cleanDir(dir: string): Promise<void> {
  try {
    await rm(dir, { recursive: true, force: true });
  } catch {
    // best-effort cleanup
  }
}

// ─── validatePath ─────────────────────────────────────────

describe("validatePath", () => {
  let sandbox: string;

  afterEach(async () => {
    if (sandbox) await cleanDir(sandbox);
  });

  it("accepts a valid relative path within the sandbox", async () => {
    sandbox = await makeTempDir();
    const result = await validatePath(sandbox, "src/index.ts");
    expect(result.valid).toBe(true);
    expect(result.resolvedPath).toBe(join(sandbox, "src/index.ts"));
  });

  it("blocks path traversal with ../", async () => {
    sandbox = await makeTempDir();
    const result = await validatePath(sandbox, "../../../etc/passwd");
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Path traversal detected");
  });

  it("blocks absolute paths outside the sandbox", async () => {
    sandbox = await makeTempDir();
    const result = await validatePath(sandbox, "/etc/passwd");
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Path traversal detected");
  });

  it("accepts the sandbox root itself", async () => {
    sandbox = await makeTempDir();
    const result = await validatePath(sandbox, ".");
    expect(result.valid).toBe(true);
  });

  it("accepts non-existent paths within the sandbox (new files)", async () => {
    sandbox = await makeTempDir();
    const result = await validatePath(sandbox, "does/not/exist.ts");
    expect(result.valid).toBe(true);
    expect(result.reason).toContain("new file");
  });

  it("accepts a path to an existing file within the sandbox", async () => {
    sandbox = await makeTempDir();
    const filePath = join(sandbox, "real-file.txt");
    await writeFile(filePath, "hello");
    const result = await validatePath(sandbox, "real-file.txt");
    expect(result.valid).toBe(true);
    expect(result.resolvedPath).toBe(filePath);
  });
});

// ─── validateExtension ───────────────────────────────────

describe("validateExtension", () => {
  const allowed = [".ts", ".js", ".json", ".md", ".txt"];

  it("allows a .ts extension", () => {
    const result = validateExtension("app.ts", allowed);
    expect(result.valid).toBe(true);
  });

  it("allows a .json extension", () => {
    const result = validateExtension("config.json", allowed);
    expect(result.valid).toBe(true);
  });

  it("blocks a .sh extension", () => {
    const result = validateExtension("deploy.sh", [".ts", ".js"]);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain(".sh");
  });

  it("blocks a .exe extension", () => {
    const result = validateExtension("malware.exe", allowed);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain(".exe");
  });

  it("blocks files without extensions", () => {
    const result = validateExtension("Makefile", allowed);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("without extensions");
  });

  it("is case-insensitive for extension matching", () => {
    // extname returns ".TS" for "app.TS", toLowerCase normalizes it
    const result = validateExtension("app.TS", allowed);
    expect(result.valid).toBe(true);
  });
});

// ─── checkFileSize ────────────────────────────────────────

describe("checkFileSize", () => {
  let tempDir: string;

  afterEach(async () => {
    if (tempDir) await cleanDir(tempDir);
  });

  it("returns valid for a file within the size limit", async () => {
    tempDir = await makeTempDir();
    const filePath = join(tempDir, "small.txt");
    await writeFile(filePath, "hello"); // 5 bytes
    const result = await checkFileSize(filePath, 1024);
    expect(result.valid).toBe(true);
    expect(result.size).toBe(5);
  });

  it("returns invalid for a file exceeding the size limit", async () => {
    tempDir = await makeTempDir();
    const filePath = join(tempDir, "big.txt");
    const content = "x".repeat(2000);
    await writeFile(filePath, content);
    const result = await checkFileSize(filePath, 100);
    expect(result.valid).toBe(false);
    expect(result.size).toBe(2000);
    expect(result.reason).toContain("exceeds maximum");
  });

  it("returns valid with size 0 for a non-existent file", async () => {
    const result = await checkFileSize("/tmp/definitely-does-not-exist-" + randomUUID(), 1024);
    expect(result.valid).toBe(true);
    expect(result.size).toBe(0);
    expect(result.reason).toContain("does not exist");
  });
});

// ─── createSandbox ────────────────────────────────────────

describe("createSandbox", () => {
  const createdPaths: string[] = [];

  afterEach(async () => {
    for (const p of createdPaths) {
      await cleanDir(p);
    }
    createdPaths.length = 0;
  });

  it("creates a directory that exists on disk", async () => {
    const rootPath = join("/tmp", `miniclaw-root-${randomUUID()}`);
    createdPaths.push(rootPath);
    const session = await createSandbox({ rootPath, maxFileSize: 1024, allowedExtensions: [], networkPolicy: "none", maxDuration: 5000 });
    createdPaths.push(session.sandboxPath);

    const stats = await stat(session.sandboxPath);
    expect(stats.isDirectory()).toBe(true);
  });

  it("returns a session with a UUID id", async () => {
    const rootPath = join("/tmp", `miniclaw-root-${randomUUID()}`);
    createdPaths.push(rootPath);
    const session = await createSandbox({ rootPath, maxFileSize: 1024, allowedExtensions: [], networkPolicy: "none", maxDuration: 5000 });
    createdPaths.push(session.sandboxPath);

    // UUID v4 format: 8-4-4-4-12 hex chars
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    expect(session.id).toMatch(uuidRegex);
  });

  it("returns a session with sandboxPath under rootPath", async () => {
    const rootPath = join("/tmp", `miniclaw-root-${randomUUID()}`);
    createdPaths.push(rootPath);
    const session = await createSandbox({ rootPath, maxFileSize: 1024, allowedExtensions: [], networkPolicy: "none", maxDuration: 5000 });
    createdPaths.push(session.sandboxPath);

    expect(session.sandboxPath.startsWith(rootPath + "/")).toBe(true);
  });

  it("uses DEFAULT_SANDBOX_CONFIG when no config is provided", async () => {
    const session = await createSandbox();
    createdPaths.push(session.sandboxPath);
    // The default root is /tmp/miniclaw-sandboxes
    createdPaths.push("/tmp/miniclaw-sandboxes");

    expect(session.sandboxPath.startsWith("/tmp/miniclaw-sandboxes/")).toBe(true);
    // Default maxDuration is 300_000
    expect(session.maxDuration).toBe(300_000);
  });

  it("respects a custom maxDuration parameter", async () => {
    const rootPath = join("/tmp", `miniclaw-root-${randomUUID()}`);
    createdPaths.push(rootPath);
    const session = await createSandbox(
      { rootPath, maxFileSize: 1024, allowedExtensions: [], networkPolicy: "none", maxDuration: 5000 },
      [],
      60_000,
    );
    createdPaths.push(session.sandboxPath);

    expect(session.maxDuration).toBe(60_000);
  });
});

// ─── destroySandbox ───────────────────────────────────────

describe("destroySandbox", () => {
  let rootPath: string;

  afterEach(async () => {
    if (rootPath) await cleanDir(rootPath);
  });

  it("successfully destroys a valid sandbox directory", async () => {
    rootPath = await makeTempDir();
    const sandboxPath = join(rootPath, "session-abc");
    await mkdir(sandboxPath);
    await writeFile(join(sandboxPath, "file.txt"), "data");

    const result = await destroySandbox(sandboxPath, rootPath);
    expect(result.success).toBe(true);

    // Verify the directory no longer exists
    await expect(stat(sandboxPath)).rejects.toThrow();
  });

  it("refuses to delete a path outside the root", async () => {
    rootPath = await makeTempDir();
    const result = await destroySandbox("/etc", rootPath);
    expect(result.success).toBe(false);
    expect(result.reason).toContain("not under root");
  });

  it("refuses to delete the root directory itself", async () => {
    rootPath = await makeTempDir();
    const result = await destroySandbox(rootPath, rootPath);
    expect(result.success).toBe(false);
    // The root itself fails the startsWith(root + "/") check
    expect(result.reason).toContain("not under root");
  });

  it("refuses to delete a nested subdirectory (must be direct child)", async () => {
    rootPath = await makeTempDir();
    const deep = join(rootPath, "session-1", "nested", "deep");
    await mkdir(deep, { recursive: true });

    const result = await destroySandbox(deep, rootPath);
    expect(result.success).toBe(false);
    expect(result.reason).toContain("direct child");
  });
});

// ─── createSecurityEvent ──────────────────────────────────

describe("createSecurityEvent", () => {
  it("creates an event with the correct type", () => {
    const event = createSecurityEvent("path_traversal_blocked", "Tried to escape sandbox", "sess-123");
    expect(event.type).toBe("path_traversal_blocked");
  });

  it("creates an event with an ISO 8601 timestamp", () => {
    const before = new Date().toISOString();
    const event = createSecurityEvent("tool_denied", "Bash not allowed", "sess-456");
    const after = new Date().toISOString();

    // Verify it parses as a valid date and falls within the test window
    const eventTime = new Date(event.timestamp).getTime();
    expect(eventTime).toBeGreaterThanOrEqual(new Date(before).getTime());
    expect(eventTime).toBeLessThanOrEqual(new Date(after).getTime());
  });

  it("creates an event with the correct sessionId", () => {
    const event = createSecurityEvent("sandbox_violation", "Write outside sandbox", "sess-789");
    expect(event.sessionId).toBe("sess-789");
  });

  it("creates an event with the correct details", () => {
    const event = createSecurityEvent("prompt_injection_detected", "Ignore previous instructions", "sess-abc");
    expect(event.details).toBe("Ignore previous instructions");
  });
});
