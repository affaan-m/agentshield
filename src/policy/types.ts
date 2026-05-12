import { z } from "zod";
import type { Severity } from "../types.js";

type Primitive = string | number | boolean | bigint | symbol | null | undefined;

type DeepReadonly<T> =
  T extends Primitive | ((...args: never[]) => unknown)
    ? T
    : T extends readonly (infer U)[]
      ? ReadonlyArray<DeepReadonly<U>>
      : T extends object
        ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
        : T;

// ─── Organization Policy Schema ─────────────────────────────

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);

export const PolicyPackSchema = z.enum([
  "oss",
  "team",
  "enterprise",
  "regulated",
  "high-risk-hooks-mcp",
  "ci-enforcement",
]);

export const PolicyExceptionSchema = z.object({
  id: z.string().min(1),
  rule: z.string().min(1),
  owner: z.string().min(1),
  reason: z.string().min(1),
  expires_at: z.string().datetime(),
  scope: z.string().optional(),
  severity: SeveritySchema.optional(),
  ticket: z.string().optional(),
});

export const OrgPolicySchema = z.object({
  version: z.literal(1),
  name: z.string().optional(),
  description: z.string().optional(),
  policy_pack: PolicyPackSchema.default("team"),
  owners: z.array(z.string()).default([]),
  exceptions: z.array(PolicyExceptionSchema).default([]),

  /** Items that MUST appear in the permissions.deny list */
  required_deny_list: z.array(z.string()).default([]),

  /** MCP servers that are banned from use */
  banned_mcp_servers: z.array(z.string()).default([]),

  /** Minimum acceptable security score (0-100) */
  min_score: z.number().int().min(0).max(100).default(60),

  /** Maximum allowed severity for any single finding */
  max_severity: SeveritySchema.default("critical"),

  /** Hook patterns that must be present in settings */
  required_hooks: z.array(
    z.object({
      event: z.enum(["PreToolUse", "PostToolUse", "SessionStart", "Stop"]),
      pattern: z.string(),
      description: z.string().optional(),
    })
  ).default([]),

  /** Tools that must NOT appear in the allow list */
  banned_tools: z.array(z.string()).default([]),
});

export type PolicyPack = DeepReadonly<z.infer<typeof PolicyPackSchema>>;
export type PolicyException = DeepReadonly<z.infer<typeof PolicyExceptionSchema>>;
export type OrgPolicy = DeepReadonly<z.infer<typeof OrgPolicySchema>>;

// ─── Policy Violation ───────────────────────────────────────

export interface PolicyViolation {
  readonly rule: string;
  readonly severity: Severity;
  readonly description: string;
  readonly expected: string;
  readonly actual: string;
}

// ─── Policy Evaluation Result ───────────────────────────────

export interface PolicyEvaluation {
  readonly policyName: string;
  readonly policyPack?: PolicyPack;
  readonly owners?: ReadonlyArray<string>;
  readonly passed: boolean;
  readonly violations: ReadonlyArray<PolicyViolation>;
  readonly exceptionsApplied?: ReadonlyArray<AppliedPolicyException>;
  readonly score: number;
  readonly minScore: number;
}

export interface AppliedPolicyException {
  readonly id: string;
  readonly rule: string;
  readonly owner: string;
  readonly reason: string;
  readonly expiresAt: string;
  readonly violation: string;
}
