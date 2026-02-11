import type { Finding, Grade, ReportSummary, SecurityReport, SecurityScore, ScoreBreakdown } from "../types.js";
import type { ScanResult } from "../scanner/index.js";

/**
 * Calculate security score from findings.
 * Score starts at 100 and deducts based on severity.
 */
export function calculateScore(result: ScanResult): SecurityReport {
  const { findings, target } = result;
  const summary = summarizeFindings(findings, target.files.length);
  const score = computeScore(findings);

  return {
    timestamp: new Date().toISOString(),
    targetPath: target.path,
    findings,
    score,
    summary,
  };
}

function summarizeFindings(
  findings: ReadonlyArray<Finding>,
  filesScanned: number
): ReportSummary {
  const autoFixable = findings.filter((f) => f.fix?.auto).length;

  return {
    totalFindings: findings.length,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
    filesScanned,
    autoFixable,
  };
}

function computeScore(findings: ReadonlyArray<Finding>): SecurityScore {
  // Deductions per severity
  const deductions: Record<string, number> = {
    critical: 25,
    high: 15,
    medium: 5,
    low: 2,
    info: 0,
  };

  let totalDeduction = 0;
  const categoryDeductions: Record<string, number> = {
    secrets: 0,
    permissions: 0,
    hooks: 0,
    mcp: 0,
    agents: 0,
  };

  for (const finding of findings) {
    const deduction = deductions[finding.severity] ?? 0;
    totalDeduction += deduction;

    // Map finding category to score category
    const scoreCategory = mapToScoreCategory(finding.category);
    categoryDeductions[scoreCategory] =
      (categoryDeductions[scoreCategory] ?? 0) + deduction;
  }

  const numericScore = Math.max(0, 100 - totalDeduction);
  const grade = scoreToGrade(numericScore);

  // Normalize category scores to 0-100
  const maxCategoryScore = 100;
  const breakdown: ScoreBreakdown = {
    secrets: Math.max(0, maxCategoryScore - categoryDeductions.secrets),
    permissions: Math.max(0, maxCategoryScore - categoryDeductions.permissions),
    hooks: Math.max(0, maxCategoryScore - categoryDeductions.hooks),
    mcp: Math.max(0, maxCategoryScore - categoryDeductions.mcp),
    agents: Math.max(0, maxCategoryScore - categoryDeductions.agents),
  };

  return { grade, numericScore, breakdown };
}

function mapToScoreCategory(category: string): string {
  const mapping: Record<string, string> = {
    secrets: "secrets",
    permissions: "permissions",
    hooks: "hooks",
    injection: "hooks",
    mcp: "mcp",
    agents: "agents",
    exposure: "hooks",
    misconfiguration: "permissions",
  };
  return mapping[category] ?? "permissions";
}

function scoreToGrade(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}
