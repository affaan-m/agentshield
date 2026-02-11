import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, writeFileSync, mkdtempSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runInit, renderInitSummary } from "../../src/init/index.js";

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "agentshield-init-"));
}

describe("runInit", () => {
  it("creates .claude directory with config files", () => {
    const dir = createTempDir();
    const result = runInit(dir);

    expect(result.directory).toBe(join(dir, ".claude"));
    expect(existsSync(join(dir, ".claude"))).toBe(true);
    expect(existsSync(join(dir, ".claude", "settings.json"))).toBe(true);
    expect(existsSync(join(dir, ".claude", "CLAUDE.md"))).toBe(true);
    expect(existsSync(join(dir, ".claude", "mcp.json"))).toBe(true);
  });

  it("creates valid settings.json with permissions", () => {
    const dir = createTempDir();
    runInit(dir);

    const settings = JSON.parse(
      readFileSync(join(dir, ".claude", "settings.json"), "utf-8")
    );
    expect(settings.permissions).toBeDefined();
    expect(settings.permissions.allow).toBeInstanceOf(Array);
    expect(settings.permissions.deny).toBeInstanceOf(Array);
  });

  it("creates settings with scoped Bash permissions (no Bash(*))", () => {
    const dir = createTempDir();
    runInit(dir);

    const settings = JSON.parse(
      readFileSync(join(dir, ".claude", "settings.json"), "utf-8")
    );
    const allow = settings.permissions.allow as string[];
    expect(allow.some((p: string) => p === "Bash(*)")).toBe(false);
    expect(allow.some((p: string) => p.startsWith("Bash(git"))).toBe(true);
  });

  it("creates settings with deny list for dangerous commands", () => {
    const dir = createTempDir();
    runInit(dir);

    const settings = JSON.parse(
      readFileSync(join(dir, ".claude", "settings.json"), "utf-8")
    );
    const deny = settings.permissions.deny as string[];
    expect(deny.some((p: string) => p.includes("rm -rf"))).toBe(true);
    expect(deny.some((p: string) => p.includes("sudo"))).toBe(true);
  });

  it("creates settings with hooks", () => {
    const dir = createTempDir();
    runInit(dir);

    const settings = JSON.parse(
      readFileSync(join(dir, ".claude", "settings.json"), "utf-8")
    );
    expect(settings.hooks).toBeDefined();
    expect(settings.hooks.PreToolUse).toBeInstanceOf(Array);
    expect(settings.hooks.PostToolUse).toBeInstanceOf(Array);
  });

  it("creates CLAUDE.md with security guidelines", () => {
    const dir = createTempDir();
    runInit(dir);

    const content = readFileSync(join(dir, ".claude", "CLAUDE.md"), "utf-8");
    expect(content).toContain("Security Guidelines");
    expect(content).toContain("NEVER hardcode API keys");
  });

  it("creates mcp.json with empty servers", () => {
    const dir = createTempDir();
    runInit(dir);

    const config = JSON.parse(
      readFileSync(join(dir, ".claude", "mcp.json"), "utf-8")
    );
    expect(config.mcpServers).toEqual({});
  });

  it("skips existing files without overwriting", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, ".claude"));
    writeFileSync(join(dir, ".claude", "settings.json"), '{"custom": true}');

    const result = runInit(dir);

    // settings.json should be skipped
    const skipped = result.files.filter((f) => f.status === "skipped");
    expect(skipped.length).toBeGreaterThanOrEqual(1);

    // Original content preserved
    const content = readFileSync(join(dir, ".claude", "settings.json"), "utf-8");
    expect(content).toBe('{"custom": true}');
  });

  it("creates only missing files when some already exist", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, ".claude"));
    writeFileSync(join(dir, ".claude", "settings.json"), "{}");

    const result = runInit(dir);

    const created = result.files.filter((f) => f.status === "created");
    const skipped = result.files.filter((f) => f.status === "skipped");
    expect(created.length).toBe(2); // CLAUDE.md + mcp.json
    expect(skipped.length).toBe(1); // settings.json
  });

  it("reports all 3 files in result", () => {
    const dir = createTempDir();
    const result = runInit(dir);
    expect(result.files).toHaveLength(3);
  });
});

describe("renderInitSummary", () => {
  it("shows directory path", () => {
    const output = renderInitSummary({
      directory: "/home/user/.claude",
      files: [{ path: "/home/user/.claude/settings.json", status: "created" }],
    });
    expect(output).toContain("/home/user/.claude");
  });

  it("shows created files with + prefix", () => {
    const output = renderInitSummary({
      directory: "/tmp/.claude",
      files: [
        { path: "/tmp/.claude/settings.json", status: "created" },
        { path: "/tmp/.claude/CLAUDE.md", status: "created" },
      ],
    });
    expect(output).toContain("Created:");
    expect(output).toContain("+ /tmp/.claude/settings.json");
    expect(output).toContain("+ /tmp/.claude/CLAUDE.md");
  });

  it("shows skipped files with ~ prefix and reason", () => {
    const output = renderInitSummary({
      directory: "/tmp/.claude",
      files: [
        {
          path: "/tmp/.claude/settings.json",
          status: "skipped",
          reason: "File already exists",
        },
      ],
    });
    expect(output).toContain("Skipped");
    expect(output).toContain("~ /tmp/.claude/settings.json");
    expect(output).toContain("File already exists");
  });

  it("shows next steps when files were created", () => {
    const output = renderInitSummary({
      directory: "/tmp/.claude",
      files: [{ path: "/tmp/.claude/settings.json", status: "created" }],
    });
    expect(output).toContain("Next steps");
    expect(output).toContain("agentshield scan");
  });

  it("does not show next steps when all files skipped", () => {
    const output = renderInitSummary({
      directory: "/tmp/.claude",
      files: [
        { path: "/tmp/.claude/settings.json", status: "skipped", reason: "exists" },
      ],
    });
    expect(output).not.toContain("Next steps");
  });
});
