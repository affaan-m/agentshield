import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { resolveSettingsPath, RUNTIME_HOOK_MARKER } from "./install.js";
import { RuntimePolicySchema } from "./types.js";
import type { RuntimeStatusHealth, RuntimeStatusResult } from "./types.js";

function defaultLogPath(targetPath: string): string {
  return resolve(targetPath, ".agentshield", "runtime.ndjson");
}

function runtimePolicyPath(targetPath: string): string {
  return join(targetPath, ".agentshield", "runtime-policy.json");
}

export function getRuntimeStatus(targetPath: string): RuntimeStatusResult {
  const settingsPath = resolveSettingsPath(targetPath);
  const settingsExists = existsSync(settingsPath);
  const policyPath = runtimePolicyPath(targetPath);
  const policyExists = existsSync(policyPath);

  let settingsValid = false;
  let hookCount = 0;

  if (settingsExists) {
    try {
      const settings = JSON.parse(readFileSync(settingsPath, "utf-8")) as {
        hooks?: { PreToolUse?: Array<{ hook?: unknown }> };
      };
      const preToolUse = settings.hooks?.PreToolUse;
      settingsValid = true;
      if (Array.isArray(preToolUse)) {
        hookCount = preToolUse.filter(
          (entry) => typeof entry.hook === "string" && entry.hook.includes(RUNTIME_HOOK_MARKER)
        ).length;
      }
    } catch {
      settingsValid = false;
    }
  }

  let policyValid = false;
  let logPath = defaultLogPath(targetPath);

  if (policyExists) {
    try {
      const parsed = JSON.parse(readFileSync(policyPath, "utf-8"));
      const result = RuntimePolicySchema.safeParse(parsed);
      if (result.success) {
        policyValid = true;
        const configuredLogPath = result.data.log?.path ?? ".agentshield/runtime.ndjson";
        logPath = resolve(targetPath, configuredLogPath);
      }
    } catch {
      policyValid = false;
    }
  }

  const logExists = existsSync(logPath);
  const hookInstalled = hookCount > 0;

  let health: RuntimeStatusHealth;
  let checkExitCode: number;
  let message: string;

  if (settingsExists && !settingsValid) {
    health = "invalid_settings";
    checkExitCode = 2;
    message = "settings.json exists but could not be parsed.";
  } else if (!hookInstalled) {
    health = "not_installed";
    checkExitCode = 1;
    message = "AgentShield runtime hook is not installed.";
  } else if (!policyExists) {
    health = "missing_policy";
    checkExitCode = 1;
    message = "Runtime hook is installed, but runtime-policy.json is missing.";
  } else if (!policyValid) {
    health = "invalid_policy";
    checkExitCode = 2;
    message = "Runtime hook is installed, but runtime-policy.json is invalid.";
  } else {
    health = "ready";
    checkExitCode = 0;
    message = "AgentShield runtime monitor is installed and ready.";
  }

  return {
    settingsPath,
    settingsExists,
    settingsValid,
    hookInstalled,
    hookCount,
    policyPath,
    policyExists,
    policyValid,
    logPath,
    logExists,
    health,
    checkExitCode,
    message,
  };
}
