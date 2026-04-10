import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from "node:fs";
import { join, dirname } from "node:path";
import { RuntimePolicySchema } from "./types.js";
import type { InstallResult, RuntimeRepairResult } from "./types.js";
import { generateDefaultPolicy } from "./policy.js";
import { getRuntimeStatus } from "./status.js";

export const RUNTIME_HOOK_MARKER = "agentshield/runtime-policy";

const HOOK_COMMAND = "node -e \"const fs=require('fs'),p=require('path');const s=Date.now();const t=process.env.TOOL_NAME||'unknown';const i=process.env.TOOL_INPUT||'';const pp=p.resolve('.agentshield/runtime-policy.json');if(!fs.existsSync(pp)){process.exit(0)}const pol=JSON.parse(fs.readFileSync(pp,'utf-8'));for(const r of pol.deny||[]){if(r.tool==='*'||r.tool===t||t.startsWith(r.tool.replace('*',''))){if(!r.pattern||new RegExp(r.pattern,'i').test(i)){const lp=p.resolve((pol.log||{}).path||'.agentshield/runtime.ndjson');const d=p.dirname(lp);if(!fs.existsSync(d))fs.mkdirSync(d,{recursive:true});fs.appendFileSync(lp,JSON.stringify({timestamp:new Date().toISOString(),tool:t,decision:'block',reason:r.reason,durationMs:Date.now()-s})+'\\n');process.stderr.write('AgentShield: BLOCKED '+t+' — '+(r.reason||'denied by policy')+'\\n');process.exit(2)}}}const lp2=p.resolve((pol.log||{}).path||'.agentshield/runtime.ndjson');const d2=p.dirname(lp2);if(!fs.existsSync(d2))fs.mkdirSync(d2,{recursive:true});fs.appendFileSync(lp2,JSON.stringify({timestamp:new Date().toISOString(),tool:t,decision:'allow',durationMs:Date.now()-s})+'\\n');process.exit(0)\"";

const HOOK_ENTRY = {
  matcher: "",
  hook: HOOK_COMMAND,
};

type ParsedSettings = {
  readonly exists: boolean;
  readonly valid: boolean;
  readonly value: Record<string, unknown>;
};

function parseJsonObject(raw: string): Record<string, unknown> | null {
  const parsed = JSON.parse(raw);
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    return null;
  }

  return parsed as Record<string, unknown>;
}

function readSettingsFile(settingsPath: string): ParsedSettings {
  if (!existsSync(settingsPath)) {
    return { exists: false, valid: true, value: {} };
  }

  try {
    const parsed = parseJsonObject(readFileSync(settingsPath, "utf-8"));
    if (!parsed) {
      return { exists: true, valid: false, value: {} };
    }

    return { exists: true, valid: true, value: parsed };
  } catch {
    return { exists: true, valid: false, value: {} };
  }
}

function runtimePolicyPath(targetPath: string): string {
  return join(targetPath, ".agentshield", "runtime-policy.json");
}

function hasValidRuntimePolicy(policyPath: string): boolean {
  if (!existsSync(policyPath)) {
    return false;
  }

  try {
    const parsed = JSON.parse(readFileSync(policyPath, "utf-8"));
    return RuntimePolicySchema.safeParse(parsed).success;
  } catch {
    return false;
  }
}

function repairHint(): string {
  return "Run `agentshield runtime repair` to back up invalid files and restore a healthy runtime monitor.";
}

function nextBackupPath(filePath: string): string {
  const basePath = `${filePath}.agentshield.bak`;
  if (!existsSync(basePath)) {
    return basePath;
  }

  let index = 1;
  while (existsSync(`${basePath}.${index}`)) {
    index += 1;
  }

  return `${basePath}.${index}`;
}

function backupFile(filePath: string): string {
  const backupPath = nextBackupPath(filePath);
  renameSync(filePath, backupPath);
  return backupPath;
}

function installRuntimeAtPath(targetPath: string, settingsPath: string): InstallResult {
  const policyPath = runtimePolicyPath(targetPath);
  const policyDir = dirname(policyPath);

  if (!existsSync(policyDir)) {
    mkdirSync(policyDir, { recursive: true });
  }

  let policyCreated = false;
  if (!existsSync(policyPath)) {
    writeFileSync(policyPath, generateDefaultPolicy());
    policyCreated = true;
  }

  const settingsState = readSettingsFile(settingsPath);
  if (!settingsState.valid) {
    return {
      hookInstalled: false,
      policyCreated,
      settingsPath,
      policyPath,
      message: `settings.json exists but could not be parsed. ${repairHint()}`,
    };
  }

  const settings = settingsState.value;
  const hooks = (settings.hooks ?? {}) as Record<string, unknown[]>;
  const preToolUse = (hooks.PreToolUse ?? []) as Array<{ matcher?: string; hook?: string }>;

  const alreadyInstalled = preToolUse.some(
    (h) => typeof h.hook === "string" && h.hook.includes(RUNTIME_HOOK_MARKER)
  );

  if (alreadyInstalled) {
    return {
      hookInstalled: false,
      policyCreated,
      settingsPath,
      policyPath,
      message: "AgentShield runtime hook is already installed.",
    };
  }

  const updatedPreToolUse = [...preToolUse, HOOK_ENTRY];
  const updatedHooks = { ...hooks, PreToolUse: updatedPreToolUse };
  const updatedSettings = { ...settings, hooks: updatedHooks };

  const dir = dirname(settingsPath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(settingsPath, JSON.stringify(updatedSettings, null, 2));

  return {
    hookInstalled: true,
    policyCreated,
    settingsPath,
    policyPath,
    message: "AgentShield runtime hook installed successfully.",
  };
}

/**
 * Install the AgentShield runtime hook into settings.json
 * and create a default policy file.
 */
export function installRuntime(targetPath: string): InstallResult {
  const settingsPath = resolveSettingsPath(targetPath);
  const policyPath = runtimePolicyPath(targetPath);
  const settingsState = readSettingsFile(settingsPath);

  if (settingsState.exists && !settingsState.valid) {
    return {
      hookInstalled: false,
      policyCreated: false,
      settingsPath,
      policyPath,
      message: `settings.json exists but could not be parsed. ${repairHint()}`,
    };
  }

  if (existsSync(policyPath) && !hasValidRuntimePolicy(policyPath)) {
    return {
      hookInstalled: false,
      policyCreated: false,
      settingsPath,
      policyPath,
      message: `runtime-policy.json exists but is invalid. ${repairHint()}`,
    };
  }

  return installRuntimeAtPath(targetPath, settingsPath);
}

/**
 * Repair the AgentShield runtime monitor by backing up unreadable config
 * files and recreating a healthy install in place.
 */
export function repairRuntime(targetPath: string): RuntimeRepairResult {
  const settingsPath = resolveSettingsPath(targetPath);
  const policyPath = runtimePolicyPath(targetPath);

  let settingsBackupPath: string | undefined;
  let policyBackupPath: string | undefined;

  const settingsState = readSettingsFile(settingsPath);
  if (settingsState.exists && !settingsState.valid) {
    const dir = dirname(settingsPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    settingsBackupPath = backupFile(settingsPath);
  }

  if (existsSync(policyPath) && !hasValidRuntimePolicy(policyPath)) {
    const policyDir = dirname(policyPath);
    if (!existsSync(policyDir)) {
      mkdirSync(policyDir, { recursive: true });
    }
    policyBackupPath = backupFile(policyPath);
  }

  const installResult = installRuntimeAtPath(targetPath, settingsPath);
  const status = getRuntimeStatus(targetPath);
  const changed = Boolean(
    settingsBackupPath || policyBackupPath || installResult.hookInstalled || installResult.policyCreated
  );
  const repaired = status.health === "ready";

  return {
    repaired,
    changed,
    hookInstalled: installResult.hookInstalled,
    policyCreated: installResult.policyCreated,
    settingsPath: installResult.settingsPath,
    policyPath: installResult.policyPath,
    settingsBackupPath,
    policyBackupPath,
    message: repaired
      ? changed
        ? "AgentShield runtime monitor repaired successfully."
        : "AgentShield runtime monitor is already healthy."
      : `AgentShield runtime monitor is still not ready. ${status.message}`,
  };
}

/**
 * Uninstall the AgentShield runtime hook from settings.json.
 */
export function uninstallRuntime(targetPath: string): {
  readonly removed: boolean;
  readonly message: string;
} {
  const settingsPath = resolveSettingsPath(targetPath);

  if (!existsSync(settingsPath)) {
    return { removed: false, message: "No settings.json found." };
  }

  const settingsState = readSettingsFile(settingsPath);
  if (!settingsState.valid) {
    return { removed: false, message: `Failed to parse settings.json. ${repairHint()}` };
  }

  const settings = settingsState.value;
  const hooks = settings.hooks as Record<string, unknown[]> | undefined;
  if (!hooks?.PreToolUse) {
    return { removed: false, message: "No PreToolUse hooks found." };
  }

  const preToolUse = hooks.PreToolUse as Array<{ hook?: string }>;
  const filtered = preToolUse.filter(
    (h) => !(typeof h.hook === "string" && h.hook.includes(RUNTIME_HOOK_MARKER))
  );

  if (filtered.length === preToolUse.length) {
    return { removed: false, message: "AgentShield runtime hook not found." };
  }

  const updatedHooks = { ...hooks, PreToolUse: filtered };
  const updatedSettings = { ...settings, hooks: updatedHooks };
  writeFileSync(settingsPath, JSON.stringify(updatedSettings, null, 2));

  return { removed: true, message: "AgentShield runtime hook removed." };
}

export function resolveSettingsPath(targetPath: string): string {
  // Check .claude/settings.json first
  const claudeSettings = join(targetPath, ".claude", "settings.json");
  if (existsSync(claudeSettings)) return claudeSettings;

  // Check settings.json in target
  const directSettings = join(targetPath, "settings.json");
  if (existsSync(directSettings)) return directSettings;

  // Default to .claude/settings.json
  return claudeSettings;
}
