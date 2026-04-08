import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { installRuntime, uninstallRuntime } from "../../src/runtime/install.js";
import { getRuntimeStatus } from "../../src/runtime/status.js";

const FIXTURES_DIR = join(process.cwd(), "tests", "runtime", "__status_fixtures__");

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

describe("getRuntimeStatus", () => {
  afterEach(() => cleanupFixtures());

  it("reports ready when runtime hook and policy are installed", () => {
    setupFixtures();
    const installResult = installRuntime(FIXTURES_DIR);

    const status = getRuntimeStatus(FIXTURES_DIR);

    expect(status.health).toBe("ready");
    expect(status.checkExitCode).toBe(0);
    expect(status.settingsPath).toBe(installResult.settingsPath);
    expect(status.settingsExists).toBe(true);
    expect(status.settingsValid).toBe(true);
    expect(status.hookInstalled).toBe(true);
    expect(status.hookCount).toBe(1);
    expect(status.policyPath).toBe(installResult.policyPath);
    expect(status.policyExists).toBe(true);
    expect(status.policyValid).toBe(true);
    expect(status.logPath.endsWith(".agentshield/runtime.ndjson")).toBe(true);
  });

  it("reports not_installed when no runtime hook is present", () => {
    setupFixtures();

    const status = getRuntimeStatus(FIXTURES_DIR);

    expect(status.health).toBe("not_installed");
    expect(status.checkExitCode).toBe(1);
    expect(status.hookInstalled).toBe(false);
    expect(status.hookCount).toBe(0);
    expect(status.settingsExists).toBe(false);
  });

  it("reports missing_policy when the hook is installed but policy file is missing", () => {
    setupFixtures();
    const installResult = installRuntime(FIXTURES_DIR);
    unlinkSync(installResult.policyPath);

    const status = getRuntimeStatus(FIXTURES_DIR);

    expect(status.health).toBe("missing_policy");
    expect(status.checkExitCode).toBe(1);
    expect(status.hookInstalled).toBe(true);
    expect(status.policyExists).toBe(false);
    expect(status.policyValid).toBe(false);
  });

  it("reports invalid_policy when the runtime policy cannot be parsed", () => {
    setupFixtures();
    const installResult = installRuntime(FIXTURES_DIR);
    writeFileSync(installResult.policyPath, "{ invalid json");

    const status = getRuntimeStatus(FIXTURES_DIR);

    expect(status.health).toBe("invalid_policy");
    expect(status.checkExitCode).toBe(2);
    expect(status.policyExists).toBe(true);
    expect(status.policyValid).toBe(false);
    expect(status.message).toContain("policy");
  });

  it("reports invalid_settings when settings.json exists but cannot be parsed", () => {
    setupFixtures();
    writeFileSync(join(FIXTURES_DIR, ".claude", "settings.json"), "{ invalid json");

    const status = getRuntimeStatus(FIXTURES_DIR);

    expect(status.health).toBe("invalid_settings");
    expect(status.checkExitCode).toBe(2);
    expect(status.settingsExists).toBe(true);
    expect(status.settingsValid).toBe(false);
    expect(status.hookInstalled).toBe(false);
  });

  it("returns to not_installed after runtime uninstall", () => {
    setupFixtures();
    installRuntime(FIXTURES_DIR);
    uninstallRuntime(FIXTURES_DIR);

    const status = getRuntimeStatus(FIXTURES_DIR);

    expect(status.health).toBe("not_installed");
    expect(status.checkExitCode).toBe(1);
    expect(status.hookInstalled).toBe(false);
    expect(status.hookCount).toBe(0);
  });

  it("uses the configured log path from a valid runtime policy", () => {
    setupFixtures();
    const installResult = installRuntime(FIXTURES_DIR);
    const policy = JSON.parse(readFileSync(installResult.policyPath, "utf-8"));
    policy.log.path = ".agentshield/custom/runtime.log";
    writeFileSync(installResult.policyPath, JSON.stringify(policy, null, 2));

    const status = getRuntimeStatus(FIXTURES_DIR);

    expect(status.health).toBe("ready");
    expect(status.logPath.endsWith(".agentshield/custom/runtime.log")).toBe(true);
  });
});
