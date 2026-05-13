import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fingerprintFinding } from "../fingerprint.js";
import type { Finding, SecurityReport, Severity } from "../types.js";

export interface RemediationPlanOptions {
  readonly generatedAt?: string;
}

export interface RemediationPlanWriteOptions extends RemediationPlanOptions {
  readonly outputPath: string;
  readonly report: SecurityReport;
}

export interface RemediationPlanResult {
  readonly outputPath: string;
  readonly plan: RemediationPlan;
}

export interface RemediationPlan {
  readonly schemaVersion: 1;
  readonly generatedAt: string;
  readonly targetPath: string;
  readonly score: {
    readonly grade: string;
    readonly numericScore: number;
  };
  readonly summary: RemediationPlanSummary;
  readonly workflow: RemediationWorkflow;
  readonly findings: ReadonlyArray<RemediationPlanFinding>;
}

export interface RemediationPlanSummary {
  readonly totalFindings: number;
  readonly autoFixable: number;
  readonly manualReview: number;
  readonly bySeverity: Record<Severity, number>;
}

export interface RemediationPlanFinding {
  readonly fingerprint: string;
  readonly id: string;
  readonly severity: Severity;
  readonly category: string;
  readonly title: string;
  readonly description: string;
  readonly file: string;
  readonly line?: number;
  readonly runtimeConfidence?: string;
  readonly hasEvidence: boolean;
  readonly action: "auto-fix" | "manual-review";
  readonly recommendedCommand: string;
  readonly fix?: {
    readonly description: string;
    readonly auto: boolean;
  };
}

export interface RemediationWorkflow {
  readonly phases: ReadonlyArray<RemediationWorkflowPhase>;
}

export interface RemediationWorkflowPhase {
  readonly id: "auto-fix" | "manual-review" | "verify";
  readonly title: string;
  readonly description: string;
  readonly command: string;
  readonly findingCount: number;
  readonly findingFingerprints: ReadonlyArray<string>;
  readonly blocking: boolean;
}

const ZERO_BY_SEVERITY: Record<Severity, number> = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function buildRemediationPlan(
  report: SecurityReport,
  options: RemediationPlanOptions = {}
): RemediationPlan {
  const findings = [...report.findings]
    .sort(compareFindings)
    .map((finding) => toPlanFinding(finding));

  return {
    schemaVersion: 1,
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    targetPath: report.targetPath,
    score: {
      grade: report.score.grade,
      numericScore: report.score.numericScore,
    },
    summary: {
      totalFindings: findings.length,
      autoFixable: findings.filter((finding) => finding.action === "auto-fix").length,
      manualReview: findings.filter((finding) => finding.action === "manual-review").length,
      bySeverity: countBySeverity(report.findings),
    },
    workflow: buildWorkflow(findings),
    findings,
  };
}

export function writeRemediationPlan(
  options: RemediationPlanWriteOptions
): RemediationPlanResult {
  const outputPath = resolve(options.outputPath);
  const plan = buildRemediationPlan(options.report, {
    generatedAt: options.generatedAt,
  });

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(plan, null, 2)}\n`, "utf-8");

  return {
    outputPath,
    plan,
  };
}

function toPlanFinding(finding: Finding): RemediationPlanFinding {
  const autoFixable = finding.fix?.auto === true;
  return {
    fingerprint: fingerprintFinding(finding),
    id: finding.id,
    severity: finding.severity,
    category: finding.category,
    title: finding.title,
    description: finding.description,
    file: finding.file,
    line: finding.line,
    runtimeConfidence: finding.runtimeConfidence,
    hasEvidence: Boolean(finding.evidence),
    action: autoFixable ? "auto-fix" : "manual-review",
    recommendedCommand: autoFixable
      ? "agentshield scan --fix"
      : "Review finding and apply the remediation in source control.",
    fix: finding.fix
      ? {
          description: finding.fix.description,
          auto: finding.fix.auto,
        }
      : undefined,
  };
}

function countBySeverity(findings: ReadonlyArray<Finding>): Record<Severity, number> {
  const counts = { ...ZERO_BY_SEVERITY };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

function buildWorkflow(
  findings: ReadonlyArray<RemediationPlanFinding>
): RemediationWorkflow {
  const autoFixable = findings.filter((finding) => finding.action === "auto-fix");
  const manualReview = findings.filter((finding) => finding.action === "manual-review");
  const phases: RemediationWorkflowPhase[] = [];

  if (autoFixable.length > 0) {
    phases.push({
      id: "auto-fix",
      title: "Apply safe auto-fixes",
      description:
        "Run the fix engine first for findings explicitly marked auto-fixable, then review the diff before committing.",
      command: "agentshield scan --fix",
      findingCount: autoFixable.length,
      findingFingerprints: autoFixable.map((finding) => finding.fingerprint),
      blocking: false,
    });
  }

  if (manualReview.length > 0) {
    phases.push({
      id: "manual-review",
      title: "Resolve manual findings",
      description:
        "Apply the finding-specific remediation notes in source control for items that require maintainer judgment.",
      command: "Review finding-specific remediation notes in source control.",
      findingCount: manualReview.length,
      findingFingerprints: manualReview.map((finding) => finding.fingerprint),
      blocking: true,
    });
  }

  if (findings.length > 0) {
    phases.push({
      id: "verify",
      title: "Verify clean scan",
      description:
        "Re-run AgentShield after remediation and gate on the updated result before merging or publishing.",
      command: "agentshield scan --gate",
      findingCount: findings.length,
      findingFingerprints: findings.map((finding) => finding.fingerprint),
      blocking: true,
    });
  }

  return { phases };
}

function compareFindings(left: Finding, right: Finding): number {
  return (
    SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity] ||
    left.file.localeCompare(right.file) ||
    left.id.localeCompare(right.id) ||
    (left.evidence ?? "").localeCompare(right.evidence ?? "")
  );
}
