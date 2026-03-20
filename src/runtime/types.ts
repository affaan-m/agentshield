import { z } from "zod";

// ─── Runtime Policy Configuration ───────────────────────────

export const RuntimePolicySchema = z.object({
  version: z.literal(1),
  deny: z.array(
    z.object({
      tool: z.string(),
      pattern: z.string().optional(),
      reason: z.string().optional(),
    })
  ).default([]),
  rateLimit: z.object({
    maxPerMinute: z.number().int().min(1).default(60),
    tools: z.array(z.string()).default([]),
  }).optional(),
  log: z.object({
    enabled: z.boolean().default(true),
    path: z.string().default(".agentshield/runtime.ndjson"),
  }).optional(),
});

export type RuntimePolicy = z.infer<typeof RuntimePolicySchema>;

// ─── Tool Call Representation ───────────────────────────────

export interface ToolCall {
  readonly tool: string;
  readonly input: string;
  readonly timestamp: string;
}

// ─── Evaluation Result ──────────────────────────────────────

export type EvalDecision = "allow" | "block";

export interface EvalResult {
  readonly decision: EvalDecision;
  readonly tool: string;
  readonly reason?: string;
  readonly matchedRule?: string;
  readonly timestamp: string;
}

// ─── Log Entry ──────────────────────────────────────────────

export interface RuntimeLogEntry {
  readonly timestamp: string;
  readonly tool: string;
  readonly decision: EvalDecision;
  readonly reason?: string;
  readonly durationMs: number;
}

// ─── Install Result ─────────────────────────────────────────

export interface InstallResult {
  readonly hookInstalled: boolean;
  readonly policyCreated: boolean;
  readonly settingsPath: string;
  readonly policyPath: string;
  readonly message: string;
}
