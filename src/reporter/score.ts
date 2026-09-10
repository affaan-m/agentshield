import type { Finding, Grade, ReportSummary, SecurityReport, SecurityScore, ScoreBreakdown } from "../types.js";
import type { ScanResult } from "../scanner/index.js";
import { detectDefenses } from "./defenses.js";

const SCORE_DEDUCTIONS: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 2,
  info: 0,
};

const TEMPLATE_EXAMPLE_CATEGORY_CAP = 10;

/**
 * Titles the permission rules use for guard patterns they surface at info
 * severity. These describe protective config and must never cost points.
 */
export const GUARD_PATTERN_TITLE_PREFIXES: ReadonlyArray<string> = [
  "Guard pattern:",
  "Deny/ask rule blocking",
  "Prohibition of",
  "Mention of",
  "Example config:",
];

/**
 * True when a finding is informational or a recognized guard pattern.
 * Such findings are listed in reports but contribute zero deduction.
 */
export function isNonPenalizingFinding(finding: Finding): boolean {
  if (finding.severity === "info") return true;
  // Guard-pattern findings are emitted at info severity. Any other severity
  // on a guard title is a rule bug, and the finding is still scored so the
  // bug stays visible instead of silently masking a real deduction.
  return false;
}

/** True when the title marks a guard pattern the permission rules credit. */
export function isGuardPatternFinding(finding: Finding): boolean {
  return GUARD_PATTERN_TITLE_PREFIXES.some((prefix) => finding.title.startsWith(prefix));
}

/**
 * Deduction a single finding contributes before category capping. This is
 * the one place severity turns into points, so the zero-deduction guarantee
 * for info and guard-pattern findings lives here and is unit tested.
 */
export function deductionFor(finding: Finding): number {
  if (isNonPenalizingFinding(finding)) return 0;
  const deduction = (SCORE_DEDUCTIONS[finding.severity] ?? 0) * confidenceWeight(finding);
  return deduction > 0 ? deduction : 0;
}

/**
 * Calculate security score from findings.
 * Score starts at 100 and deducts based on severity.
 */
export function calculateScore(result: ScanResult): SecurityReport {
  const { findings, target, skillHealth, harnessAdapters } = result;
  const defenses = detectDefenses(target.files);
  const summary = summarizeFindings(findings, target.files.length, defenses.length);
  const score = computeScore(findings);

  return {
    timestamp: new Date().toISOString(),
    targetPath: target.path,
    findings,
    score,
    summary,
    defenses,
    harnessAdapters,
    skillHealth,
  };
}

function summarizeFindings(
  findings: ReadonlyArray<Finding>,
  filesScanned: number,
  defenses: number
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
    defenses,
  };
}

function computeScore(findings: ReadonlyArray<Finding>): SecurityScore {
  const categoryDeductions: Record<string, number> = {
    secrets: 0,
    permissions: 0,
    hooks: 0,
    mcp: 0,
    agents: 0,
  };
  const templateInventoryDeductions = new Map<string, number>();

  for (const finding of findings) {
    const scoreCategory = mapToScoreCategory(finding.category);
    const deduction = deductionFor(finding);
    if (deduction === 0) continue;

    if (isTemplateInventoryFinding(finding)) {
      const templateKey = `${scoreCategory}:${finding.file}`;
      templateInventoryDeductions.set(
        templateKey,
        (templateInventoryDeductions.get(templateKey) ?? 0) + deduction
      );
      continue;
    }

    categoryDeductions[scoreCategory] =
      (categoryDeductions[scoreCategory] ?? 0) + deduction;
  }

  for (const [templateKey, deduction] of templateInventoryDeductions) {
    const [scoreCategory] = templateKey.split(":", 1);
    categoryDeductions[scoreCategory] =
      (categoryDeductions[scoreCategory] ?? 0) +
      Math.min(deduction, TEMPLATE_EXAMPLE_CATEGORY_CAP);
  }

  // Compute per-category scores (each 0-100)
  const maxCategoryScore = 100;
  const breakdown: ScoreBreakdown = {
    secrets: roundedCategoryScore(maxCategoryScore, categoryDeductions.secrets),
    permissions: roundedCategoryScore(maxCategoryScore, categoryDeductions.permissions),
    hooks: roundedCategoryScore(maxCategoryScore, categoryDeductions.hooks),
    mcp: roundedCategoryScore(maxCategoryScore, categoryDeductions.mcp),
    agents: roundedCategoryScore(maxCategoryScore, categoryDeductions.agents),
  };

  // Overall score = average of category scores
  const categoryScores = Object.values(breakdown);
  const numericScore = Math.round(
    categoryScores.reduce((sum, s) => sum + s, 0) / categoryScores.length
  );
  const grade = scoreToGrade(numericScore);

  return { grade, numericScore, breakdown };
}

function isTemplateInventoryFinding(finding: Finding): boolean {
  return finding.runtimeConfidence === "template-example" && finding.category !== "secrets";
}

function confidenceWeight(finding: Finding): number {
  if (
    (finding.runtimeConfidence === "template-example" ||
      finding.runtimeConfidence === "docs-example") &&
    finding.category !== "secrets"
  ) {
    return 0.25;
  }

  if (finding.runtimeConfidence === "project-local-optional" && finding.category !== "secrets") {
    return 0.75;
  }

  if (finding.runtimeConfidence === "plugin-manifest" && finding.category !== "secrets") {
    return 0.5;
  }

  if (finding.runtimeConfidence === "plugin-cache" && finding.category !== "secrets") {
    return 0.5;
  }

  return 1;
}

function roundedCategoryScore(maxCategoryScore: number, deduction: number): number {
  return Math.max(0, Math.round(maxCategoryScore - deduction));
}

function mapToScoreCategory(category: string): string {
  // Every FindingCategory must map to one of the 5 score categories.
  // Keep in sync with FindingCategory type in types.ts.
  const mapping: Record<string, string> = {
    secrets: "secrets",
    permissions: "permissions",
    hooks: "hooks",
    mcp: "mcp",
    skills: "agents",
    agents: "agents",
    injection: "agents",    // prompt injection → agents category
    exposure: "hooks",      // data exposure via hooks/exfiltration
    misconfiguration: "permissions",  // config issues → permissions
  };
  return mapping[category] ?? "agents";
}

function scoreToGrade(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}
