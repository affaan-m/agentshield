import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { installRuntime, repairRuntime } from "../../src/runtime/install.js";
import { getRuntimeStatus } from "../../src/runtime/status.js";

const FIXTURES_DIR = join(process.cwd(), "tests", "runtime", "__repair_fixtures__");

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

describe("repairRuntime", () => {
  afterEach(() => cleanupFixtures());

  it("backs up invalid settings and recreates a ready runtime install", () => {
    setupFixtures();
    const settingsPath = join(FIXTURES_DIR, ".claude", "settings.json");
    writeFileSync(settingsPath, "{ invalid json");

    const result = repairRuntime(FIXTURES_DIR);
    const status = getRuntimeStatus(FIXTURES_DIR);

    expect(result.settingsBackupPath?.endsWith("settings.json.agentshield.bak")).toBe(true);
    expect(existsSync(result.settingsBackupPath ?? "")).toBe(true);
    expect(readFileSync(result.settingsBackupPath ?? "", "utf-8")).toBe("{ invalid json");
    expect(status.health).toBe("ready");
    expect(status.hookInstalled).toBe(true);
    expect(status.policyValid).toBe(true);
  });

  it("backs up invalid policy and restores a valid default policy", () => {
    setupFixtures();
    const installResult = installRuntime(FIXTURES_DIR);
    writeFileSync(installResult.policyPath, "{ invalid json");

    const result = repairRuntime(FIXTURES_DIR);
    const status = getRuntimeStatus(FIXTURES_DIR);
    const repairedPolicy = JSON.parse(readFileSync(installResult.policyPath, "utf-8"));

    expect(result.policyBackupPath?.endsWith("runtime-policy.json.agentshield.bak")).toBe(true);
    expect(existsSync(result.policyBackupPath ?? "")).toBe(true);
    expect(readFileSync(result.policyBackupPath ?? "", "utf-8")).toBe("{ invalid json");
    expect(repairedPolicy.version).toBe(1);
    expect(Array.isArray(repairedPolicy.deny)).toBe(true);
    expect(status.health).toBe("ready");
    expect(status.hookInstalled).toBe(true);
  });
});
