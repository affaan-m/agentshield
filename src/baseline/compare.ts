import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import { mkdirSync } from "node:fs";
import type { Finding, SecurityScore } from "../types.js";
import type {
  SerializedBaseline,
  SerializedFinding,
  BaselineComparison,
  GateConfig,
  GateResult,
} from "./types.js";
import { DEFAULT_GATE_CONFIG } from "./types.js";

/**
 * Create a fingerprint for a finding (stable across scans).
 */
export function fingerprintFinding(finding: Finding): string {
  return `${finding.id}::${finding.file}::${finding.evidence ?? ""}`;
}

/**
 * Save current scan results as a baseline file.
 */
export function saveBaseline(
  findings: ReadonlyArray<Finding>,
  score: SecurityScore,
  outputPath: string
): void {
  const serialized: SerializedBaseline = {
    version: 1,
    timestamp: new Date().toISOString(),
    score,
    findings: findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      category: f.category,
      title: f.title,
      file: f.file,
      evidence: f.evidence,
      fingerprint: fingerprintFinding(f),
    })),
  };

  const dir = dirname(outputPath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  writeFileSync(outputPath, JSON.stringify(serialized, null, 2));
}

/**
 * Load a baseline from a JSON file.
 */
export function loadBaseline(baselinePath: string): SerializedBaseline | null {
  if (!existsSync(baselinePath)) return null;

  try {
    const raw = readFileSync(baselinePath, "utf-8");
    const parsed = JSON.parse(raw);

    if (parsed.version !== 1 || !Array.isArray(parsed.findings)) {
      return null;
    }

    return parsed as SerializedBaseline;
  } catch {
    return null;
  }
}

/**
 * Compare current scan results against a stored baseline.
 */
export function compareBaseline(
  baseline: SerializedBaseline,
  currentFindings: ReadonlyArray<Finding>,
  currentScore: SecurityScore
): BaselineComparison {
  const baselineFingerprints = new Set(
    baseline.findings.map((f) => f.fingerprint)
  );
  const currentFingerprints = new Set(
    currentFindings.map(fingerprintFinding)
  );

  const newFindings = currentFindings.filter(
    (f) => !baselineFingerprints.has(fingerprintFinding(f))
  );

  const resolvedFindings = baseline.findings.filter(
    (f) => !currentFingerprints.has(f.fingerprint)
  );

  const unchangedCount =
    currentFindings.length - newFindings.length;

  const scoreDelta =
    currentScore.numericScore - baseline.score.numericScore;

  const newCriticalCount = newFindings.filter(
    (f) => f.severity === "critical"
  ).length;
  const newHighCount = newFindings.filter(
    (f) => f.severity === "high"
  ).length;

  const isRegression =
    newFindings.length > 0 || scoreDelta < 0;

  return {
    timestamp: new Date().toISOString(),
    baselineTimestamp: baseline.timestamp,
    newFindings,
    resolvedFindings,
    unchangedCount,
    scoreDelta,
    baselineScore: baseline.score.numericScore,
    currentScore: currentScore.numericScore,
    isRegression,
    newCriticalCount,
    newHighCount,
  };
}

/**
 * Evaluate a baseline comparison against gate configuration.
 * Returns pass/fail and reasons.
 */
export function evaluateGate(
  comparison: BaselineComparison,
  config: GateConfig = DEFAULT_GATE_CONFIG
): GateResult {
  const reasons: string[] = [];

  if (config.failOnNewCritical && comparison.newCriticalCount > 0) {
    reasons.push(
      `${comparison.newCriticalCount} new critical finding(s) introduced`
    );
  }

  if (config.failOnNewHigh && comparison.newHighCount > 0) {
    reasons.push(
      `${comparison.newHighCount} new high finding(s) introduced`
    );
  }

  if (comparison.newFindings.length > config.maxNewFindings) {
    reasons.push(
      `${comparison.newFindings.length} new finding(s) exceed threshold of ${config.maxNewFindings}`
    );
  }

  if (comparison.scoreDelta < -config.maxScoreDrop) {
    reasons.push(
      `Score dropped by ${Math.abs(comparison.scoreDelta)} points (max allowed: ${config.maxScoreDrop})`
    );
  }

  return {
    passed: reasons.length === 0,
    reasons,
    comparison,
  };
}

/**
 * Render a baseline comparison for the terminal.
 */
export function renderComparison(comparison: BaselineComparison): string {
  const lines: string[] = [];
  const divider = "─".repeat(60);

  lines.push("");
  lines.push(`  ${divider}`);
  lines.push("  Baseline Comparison Report");
  lines.push(`  ${divider}`);
  lines.push("");

  const direction = comparison.scoreDelta > 0 ? "+" : "";
  const label = comparison.scoreDelta > 0
    ? "IMPROVED"
    : comparison.scoreDelta < 0
      ? "REGRESSED"
      : "UNCHANGED";

  lines.push(
    `  Score: ${comparison.baselineScore} → ${comparison.currentScore} (${direction}${comparison.scoreDelta}) [${label}]`
  );
  lines.push(
    `  Baseline from: ${comparison.baselineTimestamp}`
  );
  lines.push("");

  if (comparison.newFindings.length > 0) {
    lines.push(`  NEW FINDINGS (${comparison.newFindings.length}):`);
    for (const f of comparison.newFindings) {
      lines.push(`    [${f.severity.toUpperCase().padEnd(8)}] ${f.title}`);
      lines.push(`               ${f.file}`);
    }
    lines.push("");
  }

  if (comparison.resolvedFindings.length > 0) {
    lines.push(`  RESOLVED FINDINGS (${comparison.resolvedFindings.length}):`);
    for (const f of comparison.resolvedFindings) {
      lines.push(`    [RESOLVED] ${f.title}`);
    }
    lines.push("");
  }

  lines.push(`  Unchanged: ${comparison.unchangedCount} finding(s)`);
  lines.push(`  ${divider}`);
  lines.push("");

  return lines.join("\n");
}

/**
 * Render gate result for terminal output.
 */
export function renderGateResult(result: GateResult): string {
  const lines: string[] = [];

  if (result.passed) {
    lines.push("  Gate: PASSED — No regressions detected.");
  } else {
    lines.push("  Gate: FAILED — Security regressions detected:");
    for (const reason of result.reasons) {
      lines.push(`    - ${reason}`);
    }
  }

  lines.push("");
  return lines.join("\n");
}
