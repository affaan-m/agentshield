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

// ─── Structured Tool Use Types (Opus Pipeline) ────────────

export type AttackImpact =
  | "rce"
  | "data_exfiltration"
  | "privilege_escalation"
  | "persistence"
  | "lateral_movement"
  | "denial_of_service";

export type AttackDifficulty = "trivial" | "easy" | "moderate" | "hard" | "expert";

export interface AttackVector {
  readonly attack_name: string;
  readonly attack_chain: ReadonlyArray<string>;
  readonly entry_point: string;
  readonly impact: AttackImpact;
  readonly difficulty: AttackDifficulty;
  readonly cvss_estimate: number;
  readonly evidence: string;
  readonly prerequisites?: string;
}

export type DefenseFixType =
  | "add_hook"
  | "restrict_permission"
  | "remove_secret"
  | "add_validation"
  | "restrict_mcp"
  | "add_monitoring"
  | "other";

export type DefensePriority = "critical" | "high" | "medium" | "low";
export type DefenseEffort = "trivial" | "easy" | "moderate" | "significant";

export interface DefenseGap {
  readonly gap_name: string;
  readonly current_state: string;
  readonly recommended_fix: string;
  readonly fix_type: DefenseFixType;
  readonly priority: DefensePriority;
  readonly effort: DefenseEffort;
  readonly auto_fixable: boolean;
}

export interface GoodPractice {
  readonly practice_name: string;
  readonly description: string;
  readonly effectiveness: "strong" | "moderate" | "weak";
}

export interface AuditTopRisk {
  readonly risk: string;
  readonly severity: string;
  readonly action: string;
}

export interface AuditActionStep {
  readonly step: number;
  readonly action: string;
  readonly priority: string;
  readonly effort: string;
}

export interface FinalAssessment {
  readonly risk_level: "critical" | "high" | "medium" | "low";
  readonly score: number;
  readonly executive_summary: string;
  readonly top_risks: ReadonlyArray<AuditTopRisk>;
  readonly strengths?: ReadonlyArray<string>;
  readonly action_plan: ReadonlyArray<AuditActionStep>;
}

// ─── Structured Opus Results ──────────────────────────────

export interface StructuredAttackerResult {
  readonly attacks: ReadonlyArray<AttackVector>;
  readonly reasoning: string;
}

export interface StructuredDefenderResult {
  readonly gaps: ReadonlyArray<DefenseGap>;
  readonly goodPractices: ReadonlyArray<GoodPractice>;
  readonly reasoning: string;
}

export interface StructuredAuditorResult {
  readonly assessment: FinalAssessment;
  readonly reasoning: string;
}

// ─── Injection Test Results ────────────────────────────────

export interface InjectionTestResult {
  readonly payload: string;
  readonly category: string;
  readonly blocked: boolean;
  readonly details: string;
}

export interface InjectionSuiteResult {
  readonly totalPayloads: number;
  readonly blocked: number;
  readonly bypassed: number;
  readonly results: ReadonlyArray<InjectionTestResult>;
}

// ─── Sandbox Execution Results ────────────────────────────

export interface SandboxBehavior {
  readonly hookId: string;
  readonly hookCommand: string;
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly networkAttempts: ReadonlyArray<string>;
  readonly fileAccesses: ReadonlyArray<string>;
  readonly suspiciousBehaviors: ReadonlyArray<string>;
}

export interface SandboxResult {
  readonly hooksExecuted: number;
  readonly behaviors: ReadonlyArray<SandboxBehavior>;
  readonly riskFindings: ReadonlyArray<Finding>;
}

// ─── Taint Analysis Results ───────────────────────────────

export interface TaintFlow {
  readonly source: TaintNode;
  readonly sink: TaintNode;
  readonly path: ReadonlyArray<string>;
  readonly severity: Severity;
  readonly description: string;
}

export interface TaintNode {
  readonly file: string;
  readonly line?: number;
  readonly label: string;
  readonly type: "source" | "sink" | "transform";
}

export interface TaintResult {
  readonly flows: ReadonlyArray<TaintFlow>;
  readonly sources: ReadonlyArray<TaintNode>;
  readonly sinks: ReadonlyArray<TaintNode>;
}

// ─── Corpus Validation Results ────────────────────────────

export interface CorpusValidationResult {
  readonly totalAttacks: number;
  readonly detected: number;
  readonly missed: number;
  readonly detectionRate: number;
  readonly results: ReadonlyArray<{
    readonly attackId: string;
    readonly attackName: string;
    readonly detected: boolean;
    readonly ruleId?: string;
  }>;
}

// ─── Scan Log Entry ───────────────────────────────────────

export interface ScanLogEntry {
  readonly timestamp: string;
  readonly level: "info" | "warn" | "error" | "debug";
  readonly phase: string;
  readonly message: string;
  readonly data?: Record<string, unknown>;
}

// ─── Deep Scan Result ─────────────────────────────────────

export interface DeepScanResult {
  readonly staticAnalysis: {
    readonly findings: ReadonlyArray<Finding>;
    readonly score: SecurityScore;
  };
  readonly taintAnalysis: TaintResult | null;
  readonly injectionTests: InjectionSuiteResult | null;
  readonly sandboxResults: SandboxResult | null;
  readonly opusAnalysis: OpusAnalysis | null;
  readonly corpusValidation: CorpusValidationResult | null;
}

// ─── CLI Options ───────────────────────────────────────────

export interface ScanOptions {
  readonly path: string;
  readonly format: "terminal" | "json" | "markdown" | "html";
  readonly fix: boolean;
  readonly opus: boolean;
  readonly injection: boolean;
  readonly sandbox: boolean;
  readonly deep: boolean;
  readonly taint: boolean;
  readonly corpus: boolean;
  readonly log?: string;
  readonly logFormat: "ndjson" | "json";
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
