import type { Rule } from "../types.js";
import { secretRules } from "./secrets.js";
import { permissionRules } from "./permissions.js";
import { hookRules } from "./hooks.js";
import { mcpRules } from "./mcp.js";
import { agentRules } from "./agents.js";

/**
 * Returns all built-in security rules.
 * Each rule knows how to check a specific config file type.
 */
export function getBuiltinRules(): ReadonlyArray<Rule> {
  return [
    ...secretRules,
    ...permissionRules,
    ...hookRules,
    ...mcpRules,
    ...agentRules,
  ];
}
