import { describe, it, expect } from "vitest";
import { discoverConfigFiles } from "../../src/scanner/discovery.js";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "agentshield-test-"));
}

describe("discoverConfigFiles", () => {
  it("discovers CLAUDE.md at root", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "CLAUDE.md"), "# Instructions");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "claude-md")).toBe(true);
    expect(result.files.some((f) => f.content === "# Instructions")).toBe(true);
  });

  it("discovers .claude/CLAUDE.md", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, ".claude"));
    writeFileSync(join(dir, ".claude", "CLAUDE.md"), "# Project rules");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "claude-md")).toBe(true);
  });

  it("discovers settings.json", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "settings.json"), '{"permissions":{}}');

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "settings-json")).toBe(true);
  });

  it("discovers mcp.json", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "mcp.json"), '{"mcpServers":{}}');

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "mcp-json")).toBe(true);
  });

  it("discovers agent files in agents/ subdirectory", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "agents"));
    writeFileSync(join(dir, "agents", "helper.md"), "Agent prompt");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "agent-md")).toBe(true);
  });

  it("discovers .claude/agents/ subdirectory", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, ".claude"));
    mkdirSync(join(dir, ".claude", "agents"));
    writeFileSync(join(dir, ".claude", "agents", "coder.md"), "Coder agent");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "agent-md")).toBe(true);
  });

  it("discovers hook scripts", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "hooks"));
    writeFileSync(join(dir, "hooks", "pre-commit.sh"), "#!/bin/bash\necho hello");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "hook-script")).toBe(true);
  });

  it("discovers .claude.json as mcp config", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".claude.json"), '{"mcpServers":{}}');

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "mcp-json")).toBe(true);
  });

  it("returns empty files for empty directory", () => {
    const dir = createTempDir();
    const result = discoverConfigFiles(dir);
    expect(result.files).toHaveLength(0);
    expect(result.path).toBe(dir);
  });

  it("discovers skill files in skills/ subdirectory", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "skills"));
    writeFileSync(join(dir, "skills", "tdd.md"), "TDD workflow");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "skill-md")).toBe(true);
  });

  it("discovers command files in commands/ subdirectory", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "commands"));
    writeFileSync(join(dir, "commands", "deploy.md"), "Deploy command");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "skill-md")).toBe(true);
  });
});
