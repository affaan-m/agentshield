import { describe, it, expect, afterEach } from "vitest";
import { installRuntime, uninstallRuntime } from "../../src/runtime/install.js";
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";

const FIXTURES_DIR = join(process.cwd(), "tests", "runtime", "__install_fixtures__");

function setupFixtures(): void {
  if (existsSync(FIXTURES_DIR)) {
    rmSync(FIXTURES_DIR, { recursive: true, force: true });
  }
  mkdirSync(join(FIXTURES_DIR, ".claude"), { recursive: true });
}

function cleanupFixtures(): void {
  if (existsSync(FIXTURES_DIR)) {
    rmSync(FIXTURES_DIR, { recursive: true, force: true });
  }
}

describe("installRuntime", () => {
  afterEach(() => cleanupFixtures());

  it("creates .agentshield directory and policy file", () => {
    setupFixtures();
    const result = installRuntime(FIXTURES_DIR);

    expect(result.policyCreated).toBe(true);
    expect(existsSync(result.policyPath)).toBe(true);

    const policy = JSON.parse(readFileSync(result.policyPath, "utf-8"));
    expect(policy.version).toBe(1);
  });

  it("installs PreToolUse hook into settings.json", () => {
    setupFixtures();
    // Create initial settings
    writeFileSync(
      join(FIXTURES_DIR, ".claude", "settings.json"),
      JSON.stringify({ permissions: { allow: ["Read"] } })
    );

    const result = installRuntime(FIXTURES_DIR);

    expect(result.hookInstalled).toBe(true);

    const settings = JSON.parse(readFileSync(result.settingsPath, "utf-8"));
    expect(settings.hooks.PreToolUse).toBeDefined();
    expect(settings.hooks.PreToolUse.length).toBeGreaterThan(0);
    expect(settings.hooks.PreToolUse[0].hook).toContain("runtime-policy");
  });

  it("preserves existing settings", () => {
    setupFixtures();
    writeFileSync(
      join(FIXTURES_DIR, ".claude", "settings.json"),
      JSON.stringify({
        permissions: { allow: ["Read"], deny: ["Bash"] },
        hooks: {
          PostToolUse: [{ matcher: "", hook: "echo done" }],
        },
      })
    );

    installRuntime(FIXTURES_DIR);

    const settings = JSON.parse(
      readFileSync(join(FIXTURES_DIR, ".claude", "settings.json"), "utf-8")
    );
    expect(settings.permissions.allow).toContain("Read");
    expect(settings.permissions.deny).toContain("Bash");
    expect(settings.hooks.PostToolUse).toHaveLength(1);
    expect(settings.hooks.PreToolUse).toHaveLength(1);
  });

  it("does not duplicate hook on re-install", () => {
    setupFixtures();
    installRuntime(FIXTURES_DIR);
    const result = installRuntime(FIXTURES_DIR);

    expect(result.hookInstalled).toBe(false);
    expect(result.message).toContain("already installed");
  });

  it("does not overwrite existing policy", () => {
    setupFixtures();
    const policyDir = join(FIXTURES_DIR, ".agentshield");
    mkdirSync(policyDir, { recursive: true });
    writeFileSync(
      join(policyDir, "runtime-policy.json"),
      JSON.stringify({ version: 1, deny: [{ tool: "custom" }] })
    );

    const result = installRuntime(FIXTURES_DIR);

    expect(result.policyCreated).toBe(false);
    const policy = JSON.parse(
      readFileSync(join(policyDir, "runtime-policy.json"), "utf-8")
    );
    expect(policy.deny[0].tool).toBe("custom");
  });

  it("creates settings.json if it does not exist", () => {
    setupFixtures();
    const result = installRuntime(FIXTURES_DIR);

    expect(result.hookInstalled).toBe(true);
    expect(existsSync(result.settingsPath)).toBe(true);
  });
});

describe("uninstallRuntime", () => {
  afterEach(() => cleanupFixtures());

  it("removes the AgentShield hook", () => {
    setupFixtures();
    installRuntime(FIXTURES_DIR);
    const result = uninstallRuntime(FIXTURES_DIR);

    expect(result.removed).toBe(true);
    expect(result.message).toContain("removed");

    const settings = JSON.parse(
      readFileSync(join(FIXTURES_DIR, ".claude", "settings.json"), "utf-8")
    );
    expect(settings.hooks.PreToolUse).toHaveLength(0);
  });

  it("preserves other hooks", () => {
    setupFixtures();
    writeFileSync(
      join(FIXTURES_DIR, ".claude", "settings.json"),
      JSON.stringify({
        hooks: {
          PreToolUse: [
            { matcher: "", hook: "echo custom" },
          ],
        },
      })
    );
    installRuntime(FIXTURES_DIR);
    uninstallRuntime(FIXTURES_DIR);

    const settings = JSON.parse(
      readFileSync(join(FIXTURES_DIR, ".claude", "settings.json"), "utf-8")
    );
    expect(settings.hooks.PreToolUse).toHaveLength(1);
    expect(settings.hooks.PreToolUse[0].hook).toBe("echo custom");
  });

  it("reports not found when no hook installed", () => {
    setupFixtures();
    writeFileSync(
      join(FIXTURES_DIR, ".claude", "settings.json"),
      JSON.stringify({ hooks: { PreToolUse: [] } })
    );

    const result = uninstallRuntime(FIXTURES_DIR);
    expect(result.removed).toBe(false);
    expect(result.message).toContain("not found");
  });

  it("handles missing settings.json", () => {
    setupFixtures();
    const result = uninstallRuntime(join(FIXTURES_DIR, "nonexistent"));
    expect(result.removed).toBe(false);
    expect(result.message).toContain("No settings.json");
  });
});
