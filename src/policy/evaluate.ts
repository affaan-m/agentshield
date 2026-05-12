import { readFileSync, existsSync } from "node:fs";
import { OrgPolicySchema } from "./types.js";
import { generatePolicyPack } from "./presets.js";
import type {
  AppliedPolicyException,
  OrgPolicy,
  PolicyExceptionAuditEntry,
  PolicyExceptionLifecycleStatus,
  PolicyExceptionSummary,
  PolicyException,
  PolicyPack,
  PolicyViolation,
  PolicyEvaluation,
} from "./types.js";
import type { Finding, SecurityScore, ConfigFile, Severity } from "../types.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};
const EXPIRING_SOON_DAYS = 7;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

export type LoadPolicyResult =
  | { readonly success: true; readonly policy: OrgPolicy }
  | { readonly success: false; readonly error: string };

export interface EvaluatePolicyOptions {
  readonly now?: Date;
}

/**
 * Load and validate an organization policy file.
 */
export function loadPolicy(policyPath: string): LoadPolicyResult {
  if (!existsSync(policyPath)) {
    return { success: false, error: `Policy file not found: ${policyPath}` };
  }

  try {
    const raw = readFileSync(policyPath, "utf-8");
    const parsed = JSON.parse(raw);
    return { success: true, policy: OrgPolicySchema.parse(parsed) };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, error: message };
  }
}

/**
 * Evaluate scan results against an organization policy.
 */
export function evaluatePolicy(
  policy: OrgPolicy,
  findings: ReadonlyArray<Finding>,
  score: SecurityScore,
  files: ReadonlyArray<ConfigFile>,
  options: EvaluatePolicyOptions = {}
): PolicyEvaluation {
  const violations: PolicyViolation[] = [];
  const now = options.now ?? new Date();

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

  const exceptionResult = applyPolicyExceptions(
    violations,
    policy.exceptions ?? [],
    now
  );
  const expiredExceptionViolations = buildExpiredExceptionViolations(
    policy.exceptions ?? [],
    now
  );
  const finalViolations = [
    ...exceptionResult.violations,
    ...expiredExceptionViolations,
  ];

  return {
    policyName: policy.name ?? "Organization Policy",
    policyPack: policy.policy_pack,
    owners: policy.owners ?? [],
    passed: finalViolations.length === 0,
    violations: finalViolations,
    exceptionsApplied: exceptionResult.applied,
    exceptionSummary: buildExceptionSummary(policy.exceptions ?? [], now),
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

/**
 * Check whether an actual deny-list entry satisfies a required pattern.
 * Matching succeeds on exact equality, case-insensitive equality, or when
 * the actual entry starts with the required pattern. For example, a pattern
 * of "Bash(rm" matches "Bash(rm -rf /)", but the reverse does not.
 * Equality checks are case-insensitive; prefix matching keeps the current
 * case-sensitive behavior.
 */
function matchesDenyPattern(actual: string, pattern: string): boolean {
  if (actual === pattern) return true;
  if (actual.toLowerCase() === pattern.toLowerCase()) return true;
  return actual.startsWith(pattern);
}

/**
 * Check whether a configured MCP server matches a banned server pattern.
 */
function matchesBanned(serverName: string, banned: string): boolean {
  if (serverName === banned) return true;
  if (serverName.toLowerCase() === banned.toLowerCase()) return true;
  // Glob-style: "shell*" matches "shell-server"
  if (banned.endsWith("*") && serverName.startsWith(banned.slice(0, -1))) {
    return true;
  }
  return false;
}

function applyPolicyExceptions(
  violations: ReadonlyArray<PolicyViolation>,
  exceptions: ReadonlyArray<PolicyException>,
  now: Date
): {
  readonly violations: ReadonlyArray<PolicyViolation>;
  readonly applied: ReadonlyArray<AppliedPolicyException>;
} {
  const applied: AppliedPolicyException[] = [];
  const remaining: PolicyViolation[] = [];
  const activeExceptions = exceptions.filter((exception) =>
    isExceptionActive(exception, now)
  );

  for (const violation of violations) {
    const exception = activeExceptions.find((candidate) =>
      exceptionMatchesViolation(candidate, violation)
    );

    if (!exception) {
      remaining.push(violation);
      continue;
    }

    applied.push({
      id: exception.id,
      rule: exception.rule,
      owner: exception.owner,
      reason: exception.reason,
      expiresAt: exception.expires_at,
      violation: violation.description,
    });
  }

  return { violations: remaining, applied };
}

function buildExpiredExceptionViolations(
  exceptions: ReadonlyArray<PolicyException>,
  now: Date
): ReadonlyArray<PolicyViolation> {
  return exceptions
    .filter((exception) => !isExceptionActive(exception, now))
    .map((exception) => ({
      rule: "expired_exception",
      severity: "high" as const,
      description: `Policy exception "${exception.id}" for rule "${exception.rule}" has expired.`,
      expected: "Exception must have a future expires_at timestamp or be removed",
      actual: `Expired at ${exception.expires_at}`,
    }));
}

function isExceptionActive(exception: PolicyException, now: Date): boolean {
  const expiresAt = new Date(exception.expires_at);
  if (Number.isNaN(expiresAt.getTime())) return false;
  return expiresAt.getTime() >= now.getTime();
}

function buildExceptionSummary(
  exceptions: ReadonlyArray<PolicyException>,
  now: Date
): PolicyExceptionSummary {
  const entries = exceptions
    .map((exception) => buildExceptionAuditEntry(exception, now))
    .sort(compareExceptionAuditEntries);

  return {
    total: entries.length,
    active: entries.filter((entry) =>
      entry.status === "active" || entry.status === "expiring_soon"
    ).length,
    expiringSoon: entries.filter((entry) => entry.status === "expiring_soon").length,
    expired: entries.filter((entry) => entry.status === "expired").length,
    entries,
  };
}

function buildExceptionAuditEntry(
  exception: PolicyException,
  now: Date
): PolicyExceptionAuditEntry {
  const expiresAt = new Date(exception.expires_at);
  const daysUntilExpiry = Number.isNaN(expiresAt.getTime())
    ? Number.NEGATIVE_INFINITY
    : Math.ceil((expiresAt.getTime() - now.getTime()) / MS_PER_DAY);
  const status = statusForExceptionDays(daysUntilExpiry);

  return {
    id: exception.id,
    rule: exception.rule,
    owner: exception.owner,
    reason: exception.reason,
    expiresAt: exception.expires_at,
    status,
    daysUntilExpiry,
    ...(exception.scope ? { scope: exception.scope } : {}),
    ...(exception.ticket ? { ticket: exception.ticket } : {}),
  };
}

function statusForExceptionDays(daysUntilExpiry: number): PolicyExceptionLifecycleStatus {
  if (daysUntilExpiry < 0) return "expired";
  if (daysUntilExpiry <= EXPIRING_SOON_DAYS) return "expiring_soon";
  return "active";
}

function compareExceptionAuditEntries(
  a: PolicyExceptionAuditEntry,
  b: PolicyExceptionAuditEntry
): number {
  const statusRank: Record<PolicyExceptionLifecycleStatus, number> = {
    expiring_soon: 0,
    active: 1,
    expired: 2,
  };
  const statusDelta = statusRank[a.status] - statusRank[b.status];
  if (statusDelta !== 0) return statusDelta;
  const dayDelta = a.daysUntilExpiry - b.daysUntilExpiry;
  if (dayDelta !== 0) return dayDelta;
  return a.id.localeCompare(b.id);
}

function exceptionMatchesViolation(
  exception: PolicyException,
  violation: PolicyViolation
): boolean {
  if (exception.rule !== violation.rule) return false;
  if (exception.severity && exception.severity !== violation.severity) {
    return false;
  }

  if (!exception.scope) return true;

  const scope = exception.scope.toLowerCase();
  const haystack = [
    violation.description,
    violation.expected,
    violation.actual,
  ].join("\n").toLowerCase();

  return haystack.includes(scope);
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

  if (evaluation.policyPack) {
    lines.push(`  Policy Pack: ${evaluation.policyPack}`);
  }
  if (evaluation.owners && evaluation.owners.length > 0) {
    lines.push(`  Owners: ${evaluation.owners.join(", ")}`);
  }
  lines.push("");

  if (evaluation.passed) {
    const hasExceptions = (evaluation.exceptionsApplied?.length ?? 0) > 0;
    lines.push(`  Status: ${hasExceptions ? "COMPLIANT (WITH EXCEPTIONS)" : "COMPLIANT"}`);
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

  if (evaluation.exceptionsApplied && evaluation.exceptionsApplied.length > 0) {
    lines.push("  EXCEPTIONS APPLIED:");
    for (const exception of evaluation.exceptionsApplied) {
      lines.push(`    ${exception.id} (${exception.rule}) owner=${exception.owner} expires=${exception.expiresAt}`);
      lines.push(`               Reason: ${exception.reason}`);
    }
    lines.push("");
  }

  if (evaluation.exceptionSummary && evaluation.exceptionSummary.total > 0) {
    const summary = evaluation.exceptionSummary;
    lines.push("  EXCEPTION AUDIT:");
    lines.push(
      `    total=${summary.total} active=${summary.active} expiring_soon=${summary.expiringSoon} expired=${summary.expired}`
    );
    for (const exception of summary.entries) {
      const details = [
        `status=${exception.status}`,
        `owner=${exception.owner}`,
        `expires=${exception.expiresAt}`,
        `days=${formatExceptionDays(exception.daysUntilExpiry)}`,
        ...(exception.scope ? [`scope=${exception.scope}`] : []),
        ...(exception.ticket ? [`ticket=${exception.ticket}`] : []),
      ];
      lines.push(`    ${exception.id} (${exception.rule}) ${details.join(" ")}`);
    }
    lines.push("");
  }

  lines.push(`  ${divider}`);
  lines.push("");

  return lines.join("\n");
}

function formatExceptionDays(daysUntilExpiry: number): string {
  return Number.isFinite(daysUntilExpiry) ? String(daysUntilExpiry) : "invalid";
}

/**
 * Generate an example policy file.
 */
export function generateExamplePolicy(
  pack: PolicyPack = "enterprise",
  options: {
    readonly name?: string;
    readonly owners?: ReadonlyArray<string>;
  } = {}
): string {
  const policy = generatePolicyPack(pack, {
    name: options.name ?? "Acme Corp Security Policy",
    owners: options.owners ?? ["security-platform@acme.example"],
  });
  const example: OrgPolicy = {
    ...policy,
    exceptions: [
      {
        id: "AS-EX-001",
        rule: "required_hooks",
        owner: "security-platform@acme.example",
        reason: "Legacy repository migration window",
        expires_at: "2026-06-30T23:59:59.000Z",
        scope: "agentshield",
        ticket: "SEC-1234",
      },
    ],
  };

  return JSON.stringify(example, null, 2);
}
