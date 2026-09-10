import type { Rule } from "../types.js";
import { secretRules } from "./secrets.js";
import { permissionRules } from "./permissions.js";
import { hookRules } from "./hooks.js";
import { mcpRules } from "./mcp.js";
import { cveMcpRules } from "./mcp-cve.js";
import { toolPoisoningRules } from "./mcp-tool-poisoning.js";
import { packageManagerRules } from "./package-manager.js";
import { agentRules } from "./agents.js";
import { skillRules } from "./skills.js";
import { promptDefenseRules } from "./prompt-defense.js";
import { codexRules } from "./codex.js";
import { hermesRules } from "./hermes.js";
import { claudeCodeRules } from "./claude-code.js";

/**
 * Returns all built-in security rules.
 * Each rule knows how to check a specific config file type.
 * claudeCodeRules covers the September 2026 Claude Code surface (settings
 * keys, hooks schema, skill and subagent frontmatter) and is appended last.
 */
export function getBuiltinRules(): ReadonlyArray<Rule> {
  return [
    ...secretRules,
    ...permissionRules,
    ...hookRules,
    ...mcpRules,
    ...cveMcpRules,
    ...toolPoisoningRules,
    ...packageManagerRules,
    ...skillRules,
    ...agentRules,
    ...promptDefenseRules,
    ...codexRules,
    ...hermesRules,
    ...claudeCodeRules,
  ];
}
