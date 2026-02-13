import { z } from "zod";

// ─── Severity Levels ───────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

// ─── Vulnerability Finding ─────────────────────────────────

export interface Finding {
  readonly id: string;
  readonly severity: Severity;
  readonly category: FindingCategory;
  readonly title: string;
  readonly description: string;
  readonly file: string;
  readonly line?: number;
  readonly evidence?: string;
  readonly fix?: Fix;
}

export type FindingCategory =
  | "secrets"
  | "permissions"
  | "hooks"
  | "mcp"
  | "agents"
  | "injection"
  | "exposure"
  | "exfiltration"
  | "misconfiguration";

// ─── Fix Suggestion ────────────────────────────────────────

export interface Fix {
  readonly description: string;
  readonly before: string;
  readonly after: string;
  readonly auto: boolean; // Can be applied automatically
}

// ─── Scan Target ───────────────────────────────────────────

export interface ScanTarget {
  readonly path: string;
  readonly files: ReadonlyArray<ConfigFile>;
}

export interface ConfigFile {
  readonly path: string;
  readonly type: ConfigFileType;
  readonly content: string;
}

export type ConfigFileType =
  | "claude-md"
  | "settings-json"
  | "mcp-json"
  | "agent-md"
  | "skill-md"
  | "hook-script"
  | "rule-md"
  | "context-md"
  | "unknown";

// ─── Scanner Rule ──────────────────────────────────────────

export interface Rule {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly severity: Severity;
  readonly category: FindingCategory;
  readonly check: (file: ConfigFile) => ReadonlyArray<Finding>;
}

// ─── Security Report ───────────────────────────────────────

export interface SecurityReport {
  readonly timestamp: string;
  readonly targetPath: string;
  readonly findings: ReadonlyArray<Finding>;
  readonly score: SecurityScore;
  readonly summary: ReportSummary;
}

export interface SecurityScore {
  readonly grade: Grade;
  readonly numericScore: number; // 0-100
  readonly breakdown: ScoreBreakdown;
}

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface ScoreBreakdown {
  readonly secrets: number;
  readonly permissions: number;
  readonly hooks: number;
  readonly mcp: number;
  readonly agents: number;
}

export interface ReportSummary {
  readonly totalFindings: number;
  readonly critical: number;
  readonly high: number;
  readonly medium: number;
  readonly low: number;
  readonly info: number;
  readonly filesScanned: number;
  readonly autoFixable: number;
}

// ─── Opus Analysis ─────────────────────────────────────────

export interface OpusAnalysis {
  readonly attacker: OpusPerspective;
  readonly defender: OpusPerspective;
  readonly auditor: OpusAudit;
}

export interface OpusPerspective {
  readonly role: "attacker" | "defender";
  readonly findings: ReadonlyArray<string>;
  readonly reasoning: string;
}

export interface OpusAudit {
  readonly overallAssessment: string;
  readonly riskLevel: Severity;
  readonly recommendations: ReadonlyArray<string>;
  readonly score: number;
}

// ─── CLI Options ───────────────────────────────────────────

export interface ScanOptions {
  readonly path: string;
  readonly format: "terminal" | "json" | "markdown" | "html";
  readonly fix: boolean;
  readonly opus: boolean;
  readonly verbose: boolean;
}

// ─── Zod Schemas for Config Validation ─────────────────────

export const SettingsSchema = z.object({
  hooks: z
    .object({
      PreToolUse: z.array(z.object({ matcher: z.string(), hook: z.string() })).optional(),
      PostToolUse: z.array(z.object({ matcher: z.string(), hook: z.string() })).optional(),
      SessionStart: z.array(z.object({ hook: z.string() })).optional(),
      Stop: z.array(z.object({ hook: z.string() })).optional(),
    })
    .optional(),
  permissions: z
    .object({
      allow: z.array(z.string()).optional(),
      deny: z.array(z.string()).optional(),
    })
    .optional(),
});

export const McpConfigSchema = z.object({
  mcpServers: z.record(
    z.string(),
    z.object({
      command: z.string(),
      args: z.array(z.string()).optional(),
      env: z.record(z.string(), z.string()).optional(),
      description: z.string().optional(),
    })
  ),
});

export type SettingsConfig = z.infer<typeof SettingsSchema>;
export type McpConfig = z.infer<typeof McpConfigSchema>;
