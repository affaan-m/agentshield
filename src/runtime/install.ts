import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import type { InstallResult } from "./types.js";
import { generateDefaultPolicy } from "./policy.js";

export const RUNTIME_HOOK_MARKER = "agentshield/runtime-policy";

const HOOK_COMMAND = "node -e \"const fs=require('fs'),p=require('path');const s=Date.now();const t=process.env.TOOL_NAME||'unknown';const i=process.env.TOOL_INPUT||'';const pp=p.resolve('.agentshield/runtime-policy.json');if(!fs.existsSync(pp)){process.exit(0)}const pol=JSON.parse(fs.readFileSync(pp,'utf-8'));for(const r of pol.deny||[]){if(r.tool==='*'||r.tool===t||t.startsWith(r.tool.replace('*',''))){if(!r.pattern||new RegExp(r.pattern,'i').test(i)){const lp=p.resolve((pol.log||{}).path||'.agentshield/runtime.ndjson');const d=p.dirname(lp);if(!fs.existsSync(d))fs.mkdirSync(d,{recursive:true});fs.appendFileSync(lp,JSON.stringify({timestamp:new Date().toISOString(),tool:t,decision:'block',reason:r.reason,durationMs:Date.now()-s})+'\\n');process.stderr.write('AgentShield: BLOCKED '+t+' — '+(r.reason||'denied by policy')+'\\n');process.exit(2)}}}const lp2=p.resolve((pol.log||{}).path||'.agentshield/runtime.ndjson');const d2=p.dirname(lp2);if(!fs.existsSync(d2))fs.mkdirSync(d2,{recursive:true});fs.appendFileSync(lp2,JSON.stringify({timestamp:new Date().toISOString(),tool:t,decision:'allow',durationMs:Date.now()-s})+'\\n');process.exit(0)\"";

const HOOK_ENTRY = {
  matcher: "",
  hook: HOOK_COMMAND,
};

/**
 * Install the AgentShield runtime hook into settings.json
 * and create a default policy file.
 */
export function installRuntime(targetPath: string): InstallResult {
  const settingsPath = resolveSettingsPath(targetPath);
  const policyDir = join(targetPath, ".agentshield");
  const policyPath = join(policyDir, "runtime-policy.json");

  // Create .agentshield directory
  if (!existsSync(policyDir)) {
    mkdirSync(policyDir, { recursive: true });
  }

  // Create default policy if not exists
  let policyCreated = false;
  if (!existsSync(policyPath)) {
    writeFileSync(policyPath, generateDefaultPolicy());
    policyCreated = true;
  }

  // Read or create settings.json
  let settings: Record<string, unknown> = {};
  if (existsSync(settingsPath)) {
    try {
      settings = JSON.parse(readFileSync(settingsPath, "utf-8"));
    } catch {
      settings = {};
    }
  }

  // Add PreToolUse hook
  const hooks = (settings.hooks ?? {}) as Record<string, unknown[]>;
  const preToolUse = (hooks.PreToolUse ?? []) as Array<{ matcher?: string; hook?: string }>;

  // Check if already installed
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

  try {
    const settings = JSON.parse(readFileSync(settingsPath, "utf-8"));
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
  } catch {
    return { removed: false, message: "Failed to parse settings.json." };
  }
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
