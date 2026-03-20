import { readFileSync, existsSync } from "node:fs";
import { OrgPolicySchema } from "./types.js";
import type { OrgPolicy, PolicyViolation, PolicyEvaluation } from "./types.js";
import type { Finding, SecurityScore, ConfigFile, Severity } from "../types.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

/**
 * Load and validate an organization policy file.
 */
export function loadPolicy(policyPath: string): OrgPolicy | null {
  if (!existsSync(policyPath)) return null;

  try {
    const raw = readFileSync(policyPath, "utf-8");
    const parsed = JSON.parse(raw);
    return OrgPolicySchema.parse(parsed);
  } catch {
    return null;
  }
}

/**
 * Evaluate scan results against an organization policy.
 */
export function evaluatePolicy(
  policy: OrgPolicy,
  findings: ReadonlyArray<Finding>,
  score: SecurityScore,
  files: ReadonlyArray<ConfigFile>
): PolicyEvaluation {
  const violations: PolicyViolation[] = [];

  // 1. Check min score
  if (score.numericScore < policy.min_score) {
    violations.push({
      rule: "min_score",
      severity: "high",
      description: `Security score ${score.numericScore} is below the required minimum of ${policy.min_score}.`,
      expected: `Score >= ${policy.min_score}`,
      actual: `Score = ${score.numericScore}`,
    });
  }

  // 2. Check max severity
  const maxSeverityIndex = SEVERITY_ORDER[policy.max_severity];
  const exceedingFindings = findings.filter(
    (f) => SEVERITY_ORDER[f.severity] < maxSeverityIndex
  );
  if (exceedingFindings.length > 0) {
    violations.push({
      rule: "max_severity",
      severity: "high",
      description: `${exceedingFindings.length} finding(s) exceed the maximum allowed severity of "${policy.max_severity}".`,
      expected: `No findings above ${policy.max_severity}`,
      actual: `${exceedingFindings.length} finding(s) above threshold`,
    });
  }

  // 3. Check required deny list
  const denyList = extractDenyList(files);
  for (const required of policy.required_deny_list) {
    if (!denyList.some((d) => matchesDenyPattern(d, required))) {
      violations.push({
        rule: "required_deny_list",
        severity: "medium",
        description: `Required deny pattern "${required}" not found in permissions.deny list.`,
        expected: `"${required}" in deny list`,
        actual: "Missing from deny list",
      });
    }
  }

  // 4. Check banned MCP servers
  const mcpServers = extractMcpServerNames(files);
  for (const banned of policy.banned_mcp_servers) {
    const found = mcpServers.filter((s) => matchesBanned(s, banned));
    for (const server of found) {
      violations.push({
        rule: "banned_mcp_servers",
        severity: "high",
        description: `MCP server "${server}" is banned by organization policy.`,
        expected: `"${banned}" not in MCP servers`,
        actual: `"${server}" is configured`,
      });
    }
  }

  // 5. Check banned tools
  const allowedTools = extractAllowList(files);
  for (const banned of policy.banned_tools) {
    const found = allowedTools.filter((t) => matchesDenyPattern(t, banned));
    for (const tool of found) {
      violations.push({
        rule: "banned_tools",
        severity: "high",
        description: `Tool "${tool}" is banned by organization policy but appears in the allow list.`,
        expected: `"${banned}" not in allow list`,
        actual: `"${tool}" is allowed`,
      });
    }
  }

  // 6. Check required hooks
  const configuredHooks = extractHookPatterns(files);
  for (const required of policy.required_hooks) {
    const found = configuredHooks.some(
      (h) =>
        h.event === required.event &&
        h.command.includes(required.pattern)
    );
    if (!found) {
      violations.push({
        rule: "required_hooks",
        severity: "medium",
        description: required.description ??
          `Required ${required.event} hook with pattern "${required.pattern}" not found.`,
        expected: `${required.event} hook containing "${required.pattern}"`,
        actual: "Not configured",
      });
    }
  }

  return {
    policyName: policy.name ?? "Organization Policy",
    passed: violations.length === 0,
    violations,
    score: score.numericScore,
    minScore: policy.min_score,
  };
}

/**
 * Extract permissions.deny entries from settings files.
 */
function extractDenyList(files: ReadonlyArray<ConfigFile>): ReadonlyArray<string> {
  const denyItems: string[] = [];

  for (const file of files) {
    if (file.type !== "settings-json") continue;

    try {
      const config = JSON.parse(file.content);
      const deny = config?.permissions?.deny;
      if (Array.isArray(deny)) {
        denyItems.push(...deny.filter((d: unknown) => typeof d === "string"));
      }
    } catch {
      // Skip invalid JSON
    }
  }

  return denyItems;
}

/**
 * Extract permissions.allow entries from settings files.
 */
function extractAllowList(files: ReadonlyArray<ConfigFile>): ReadonlyArray<string> {
  const allowItems: string[] = [];

  for (const file of files) {
    if (file.type !== "settings-json") continue;

    try {
      const config = JSON.parse(file.content);
      const allow = config?.permissions?.allow;
      if (Array.isArray(allow)) {
        allowItems.push(...allow.filter((a: unknown) => typeof a === "string"));
      }
    } catch {
      // Skip invalid JSON
    }
  }

  return allowItems;
}

/**
 * Extract MCP server names from config files.
 */
function extractMcpServerNames(files: ReadonlyArray<ConfigFile>): ReadonlyArray<string> {
  const names: string[] = [];

  for (const file of files) {
    if (file.type !== "mcp-json" && file.type !== "settings-json") continue;

    try {
      const config = JSON.parse(file.content);
      const servers = config?.mcpServers;
      if (servers && typeof servers === "object") {
        names.push(...Object.keys(servers));
      }
    } catch {
      // Skip invalid JSON
    }
  }

  return names;
}

/**
 * Extract hook configurations from settings files.
 */
function extractHookPatterns(
  files: ReadonlyArray<ConfigFile>
): ReadonlyArray<{ readonly event: string; readonly command: string }> {
  const hooks: { event: string; command: string }[] = [];

  for (const file of files) {
    if (file.type !== "settings-json") continue;

    try {
      const config = JSON.parse(file.content);
      const hookGroups = config?.hooks;
      if (!hookGroups || typeof hookGroups !== "object") continue;

      for (const [event, entries] of Object.entries(hookGroups)) {
        if (!Array.isArray(entries)) continue;
        for (const entry of entries) {
          const hook = (entry as { hook?: string }).hook;
          if (typeof hook === "string") {
            hooks.push({ event, command: hook });
          }
        }
      }
    } catch {
      // Skip invalid JSON
    }
  }

  return hooks;
}

function matchesDenyPattern(actual: string, pattern: string): boolean {
  if (actual === pattern) return true;
  if (actual.toLowerCase() === pattern.toLowerCase()) return true;
  return actual.startsWith(pattern);
}

function matchesBanned(serverName: string, banned: string): boolean {
  if (serverName === banned) return true;
  if (serverName.toLowerCase() === banned.toLowerCase()) return true;
  // Glob-style: "shell*" matches "shell-server"
  if (banned.endsWith("*") && serverName.startsWith(banned.slice(0, -1))) {
    return true;
  }
  return false;
}

/**
 * Render policy evaluation results.
 */
export function renderPolicyEvaluation(evaluation: PolicyEvaluation): string {
  const lines: string[] = [];
  const divider = "─".repeat(60);

  lines.push("");
  lines.push(`  ${divider}`);
  lines.push(`  Organization Policy: ${evaluation.policyName}`);
  lines.push(`  ${divider}`);
  lines.push("");

  if (evaluation.passed) {
    lines.push("  Status: COMPLIANT");
  } else {
    lines.push("  Status: NON-COMPLIANT");
    lines.push(`  Violations: ${evaluation.violations.length}`);
  }

  lines.push(`  Score: ${evaluation.score} (minimum: ${evaluation.minScore})`);
  lines.push("");

  if (evaluation.violations.length > 0) {
    lines.push("  POLICY VIOLATIONS:");
    for (const v of evaluation.violations) {
      lines.push(`    [${v.severity.toUpperCase().padEnd(8)}] ${v.rule}: ${v.description}`);
      lines.push(`               Expected: ${v.expected}`);
      lines.push(`               Actual:   ${v.actual}`);
    }
    lines.push("");
  }

  lines.push(`  ${divider}`);
  lines.push("");

  return lines.join("\n");
}

/**
 * Generate an example policy file.
 */
export function generateExamplePolicy(): string {
  const example: OrgPolicy = {
    version: 1,
    name: "Acme Corp Security Policy",
    description: "Organization-wide Claude Code security requirements",
    required_deny_list: ["Bash(rm -rf", "Bash(curl.*|.*sh"],
    banned_mcp_servers: ["shell", "terminal"],
    min_score: 75,
    max_severity: "high",
    required_hooks: [
      {
        event: "PreToolUse",
        pattern: "agentshield",
        description: "AgentShield runtime monitor must be installed",
      },
    ],
    banned_tools: ["Bash(*)"],
  };

  return JSON.stringify(example, null, 2);
}
