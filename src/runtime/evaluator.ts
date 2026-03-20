import type { RuntimePolicy, ToolCall, EvalResult, RuntimeLogEntry } from "./types.js";
import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Evaluate a tool call against the runtime policy.
 * Returns allow/block decision with reason.
 */
export function evaluateToolCall(
  toolCall: ToolCall,
  policy: RuntimePolicy
): EvalResult {
  // Check deny rules
  for (const rule of policy.deny) {
    if (!matchesTool(toolCall.tool, rule.tool)) {
      continue;
    }

    // If no pattern, block all calls to this tool
    if (!rule.pattern) {
      return {
        decision: "block",
        tool: toolCall.tool,
        reason: rule.reason ?? `Tool "${toolCall.tool}" is denied by policy`,
        matchedRule: `deny:${rule.tool}`,
        timestamp: toolCall.timestamp,
      };
    }

    // Check if input matches the pattern
    if (matchesPattern(toolCall.input, rule.pattern)) {
      return {
        decision: "block",
        tool: toolCall.tool,
        reason: rule.reason ?? `Input matches denied pattern "${rule.pattern}"`,
        matchedRule: `deny:${rule.tool}:${rule.pattern}`,
        timestamp: toolCall.timestamp,
      };
    }
  }

  return {
    decision: "allow",
    tool: toolCall.tool,
    timestamp: toolCall.timestamp,
  };
}

/**
 * Check if a tool name matches a deny rule's tool pattern.
 * Supports exact match and glob-style wildcards (*).
 */
function matchesTool(toolName: string, rulePattern: string): boolean {
  if (rulePattern === "*") return true;
  if (rulePattern === toolName) return true;

  // Simple glob: "Bash*" matches "Bash", "BashExec", etc.
  if (rulePattern.endsWith("*")) {
    return toolName.startsWith(rulePattern.slice(0, -1));
  }

  return false;
}

/**
 * Check if tool input matches a deny pattern.
 * Uses case-insensitive regex matching.
 */
function matchesPattern(input: string, pattern: string): boolean {
  try {
    const regex = new RegExp(pattern, "i");
    return regex.test(input);
  } catch {
    // Invalid regex, fall back to substring match
    return input.toLowerCase().includes(pattern.toLowerCase());
  }
}

/**
 * Log a tool call evaluation result to an NDJSON file.
 */
export function logEvalResult(
  result: EvalResult,
  durationMs: number,
  logPath: string
): void {
  try {
    const dir = dirname(logPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    const entry: RuntimeLogEntry = {
      timestamp: result.timestamp,
      tool: result.tool,
      decision: result.decision,
      reason: result.reason,
      durationMs,
    };

    appendFileSync(logPath, JSON.stringify(entry) + "\n");
  } catch {
    // Logging failure should not block tool execution
  }
}
