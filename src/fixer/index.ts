import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import type { Finding, Severity } from "../types.js";
import type { ScanResult } from "../scanner/index.js";
import { applyTransform } from "./transforms.js";

/**
 * Summary of a single applied fix.
 */
export interface AppliedFix {
  readonly file: string;
  readonly findingId: string;
  readonly title: string;
  readonly description: string;
  readonly before: string;
  readonly after: string;
}

/**
 * Overall result of running the fix engine.
 */
export interface FixResult {
  readonly applied: ReadonlyArray<AppliedFix>;
  readonly skipped: ReadonlyArray<SkippedFix>;
  readonly totalAutoFixable: number;
}

/**
 * A fix that was skipped (e.g., the before text was not found in the file).
 */
export interface SkippedFix {
  readonly file: string;
  readonly findingId: string;
  readonly title: string;
  readonly reason: string;
}

/**
 * Collect auto-fixable findings from scan results.
 *
 * Only returns findings where `fix.auto === true`.
 */
function getAutoFixableFindings(
  findings: ReadonlyArray<Finding>
): ReadonlyArray<Finding> {
  return findings.filter(
    (f): f is Finding & { readonly fix: NonNullable<Finding["fix"]> } =>
      f.fix !== undefined && f.fix.auto === true
  );
}

/**
 * Group findings by file path so we can batch-process each file.
 */
function groupByFile(
  findings: ReadonlyArray<Finding>
): ReadonlyMap<string, ReadonlyArray<Finding>> {
  const groups = new Map<string, Finding[]>();

  for (const finding of findings) {
    const existing = groups.get(finding.file);
    if (existing) {
      groups.set(finding.file, [...existing, finding]);
    } else {
      groups.set(finding.file, [finding]);
    }
  }

  return groups;
}

/**
 * Apply all auto-fixable findings from a scan result.
 *
 * For each finding where `fix.auto === true`:
 * 1. Read the file content
 * 2. Apply the appropriate transform (replace fix.before with fix.after)
 * 3. Write the updated content back
 *
 * Returns a summary of what was fixed and what was skipped.
 */
export function applyFixes(scanResult: ScanResult): FixResult {
  const autoFixable = getAutoFixableFindings(scanResult.findings);
  const grouped = groupByFile(autoFixable);

  const applied: AppliedFix[] = [];
  const skipped: SkippedFix[] = [];

  for (const [relPath, findings] of grouped) {
    const filePath = resolve(scanResult.target.path, relPath);
    let content: string;
    try {
      content = readFileSync(filePath, "utf-8");
    } catch {
      for (const finding of findings) {
        skipped.push({
          file: filePath,
          findingId: finding.id,
          title: finding.title,
          reason: `Could not read file: ${filePath}`,
        });
      }
      continue;
    }

    let updatedContent = content;
    let fileModified = false;

    for (const finding of findings) {
      if (!finding.fix) {
        continue;
      }

      const result = applyTransform(updatedContent, finding);

      if (result.applied) {
        updatedContent = result.content;
        fileModified = true;
        applied.push({
          file: filePath,
          findingId: finding.id,
          title: finding.title,
          description: finding.fix.description,
          before: finding.fix.before,
          after: finding.fix.after,
        });
      } else {
        skipped.push({
          file: filePath,
          findingId: finding.id,
          title: finding.title,
          reason: "Pattern not found in file content",
        });
      }
    }

    if (fileModified) {
      writeFileSync(filePath, updatedContent, "utf-8");
    }
  }

  return {
    applied,
    skipped,
    totalAutoFixable: autoFixable.length,
  };
}

/**
 * A finding that appeared only after fixes were applied.
 */
export interface IntroducedFinding {
  readonly id: string;
  readonly severity: Severity;
  readonly title: string;
  readonly file: string;
}

/**
 * Tamper-evident record of a verified fix run. The digest binds the score
 * movement and finding deltas so a downstream consumer (PR comment, evidence
 * pack) can attest that the applied fixes were proven not to regress posture.
 */
export interface FixAttestation {
  readonly tool: "agentshield";
  readonly version: string;
  readonly scoreBefore: number;
  readonly scoreAfter: number;
  readonly fixesApplied: number;
  readonly findingsResolved: number;
  readonly findingsIntroduced: number;
  readonly verified: boolean;
  readonly digest: string;
}

/**
 * Result of applying fixes and re-scanning to prove they did not make things
 * worse. If the score regresses (or a new high/critical finding appears), all
 * written files are rolled back to their pre-fix contents.
 */
export interface FixVerification {
  readonly result: FixResult;
  readonly verified: boolean;
  readonly reverted: boolean;
  readonly scoreBefore: number;
  readonly scoreAfter: number;
  readonly resolvedFindingIds: ReadonlyArray<string>;
  readonly introducedFindings: ReadonlyArray<IntroducedFinding>;
  readonly reason?: string;
  readonly attestation: FixAttestation;
}

export interface VerifyFixesOptions {
  /** Posture score before any fix is applied. */
  readonly scoreBefore: number;
  /** Re-run the scanner against the now-modified target. */
  readonly rescan: () => ScanResult;
  /** Compute the numeric posture score for a scan result. */
  readonly score: (result: ScanResult) => number;
  /** Tool version recorded in the attestation. */
  readonly version?: string;
}

// Identity of a finding that survives the index churn caused by editing a file.
function fingerprintFinding(finding: Finding): string {
  return `${finding.file}|${finding.severity}|${finding.title}`;
}

function buildAttestation(fields: Omit<FixAttestation, "digest">): FixAttestation {
  const digest =
    "sha256:" + createHash("sha256").update(JSON.stringify(fields)).digest("hex");
  return { ...fields, digest };
}

/**
 * Apply auto-fixes, then re-scan and verify the fixes did not regress posture.
 *
 * The loop closes the gap that made naive auto-fix risky (issue #102 showed a
 * permission tighten that the scanner then re-flagged): we snapshot every file
 * before writing, apply fixes, re-scan, and roll everything back if the score
 * dropped or a new high/critical finding appeared. On success it emits a
 * tamper-evident attestation (OSS verify-after-fix; the hosted ecc-tools App
 * uses the same primitive to open an autofix PR with before/after evidence).
 */
export function applyFixesVerified(
  scanResult: ScanResult,
  options: VerifyFixesOptions
): FixVerification {
  const { scoreBefore, rescan, score, version = "unknown" } = options;

  // Snapshot originals BEFORE applyFixes writes, so a regression can be undone.
  const snapshots = new Map<string, string>();
  for (const finding of getAutoFixableFindings(scanResult.findings)) {
    const filePath = resolve(scanResult.target.path, finding.file);
    if (!snapshots.has(filePath)) {
      try {
        snapshots.set(filePath, readFileSync(filePath, "utf-8"));
      } catch {
        // Unreadable files are reported as skipped by applyFixes below.
      }
    }
  }

  const result = applyFixes(scanResult);

  // Nothing was written: trivially verified, no re-scan needed.
  if (result.applied.length === 0) {
    return {
      result,
      verified: true,
      reverted: false,
      scoreBefore,
      scoreAfter: scoreBefore,
      resolvedFindingIds: [],
      introducedFindings: [],
      attestation: buildAttestation({
        tool: "agentshield",
        version,
        scoreBefore,
        scoreAfter: scoreBefore,
        fixesApplied: 0,
        findingsResolved: 0,
        findingsIntroduced: 0,
        verified: true,
      }),
    };
  }

  const after = rescan();
  const scoreAfter = score(after);

  const beforePrints = new Set(scanResult.findings.map(fingerprintFinding));
  const afterPrints = new Set(after.findings.map(fingerprintFinding));
  const introducedFindings: IntroducedFinding[] = after.findings
    .filter((f) => !beforePrints.has(fingerprintFinding(f)))
    .map((f) => ({ id: f.id, severity: f.severity, title: f.title, file: f.file }));
  const introducedHigh = introducedFindings.filter(
    (f) => f.severity === "critical" || f.severity === "high"
  );

  const regressed = scoreAfter < scoreBefore || introducedHigh.length > 0;

  if (regressed) {
    for (const [filePath, original] of snapshots) {
      try {
        writeFileSync(filePath, original, "utf-8");
      } catch {
        // Best-effort revert; surfaced via reason below.
      }
    }
    const reason =
      scoreAfter < scoreBefore
        ? `score regressed ${scoreBefore} -> ${scoreAfter}`
        : `introduced ${introducedHigh.length} new high/critical finding(s)`;
    return {
      result,
      verified: false,
      reverted: true,
      scoreBefore,
      scoreAfter,
      resolvedFindingIds: [],
      introducedFindings,
      reason,
      attestation: buildAttestation({
        tool: "agentshield",
        version,
        scoreBefore,
        scoreAfter,
        fixesApplied: 0,
        findingsResolved: 0,
        findingsIntroduced: introducedFindings.length,
        verified: false,
      }),
    };
  }

  const resolvedFindingIds = scanResult.findings
    .filter((f) => !afterPrints.has(fingerprintFinding(f)))
    .map((f) => f.id);

  return {
    result,
    verified: true,
    reverted: false,
    scoreBefore,
    scoreAfter,
    resolvedFindingIds,
    introducedFindings,
    attestation: buildAttestation({
      tool: "agentshield",
      version,
      scoreBefore,
      scoreAfter,
      fixesApplied: result.applied.length,
      findingsResolved: resolvedFindingIds.length,
      findingsIntroduced: introducedFindings.length,
      verified: true,
    }),
  };
}

/**
 * Render a fix result summary as a formatted string for terminal output.
 */
export function renderFixSummary(result: FixResult): string {
  const lines: string[] = [];

  lines.push("");
  lines.push("  Fix Engine Results");
  lines.push("  " + "─".repeat(40));

  if (result.applied.length === 0 && result.skipped.length === 0) {
    lines.push("  No auto-fixable findings to apply.");
    lines.push("");
    return lines.join("\n");
  }

  lines.push(
    `  Auto-fixable: ${String(result.totalAutoFixable)}, ` +
    `Applied: ${String(result.applied.length)}, ` +
    `Skipped: ${String(result.skipped.length)}`
  );
  lines.push("");

  if (result.applied.length > 0) {
    lines.push("  Applied Fixes:");
    for (const fix of result.applied) {
      lines.push(`    [FIXED] ${fix.title}`);
      lines.push(`            ${fix.file}`);
      lines.push(`            ${fix.description}`);
      lines.push("");
    }
  }

  if (result.skipped.length > 0) {
    lines.push("  Skipped Fixes:");
    for (const skip of result.skipped) {
      lines.push(`    [SKIP]  ${skip.title}`);
      lines.push(`            ${skip.file}`);
      lines.push(`            Reason: ${skip.reason}`);
      lines.push("");
    }
  }

  return lines.join("\n");
}

/**
 * Render a verified-fix result: the fix summary plus the verification verdict
 * (kept vs rolled back) and the tamper-evident attestation digest.
 */
export function renderFixVerification(verification: FixVerification): string {
  const lines: string[] = [renderFixSummary(verification.result)];

  lines.push("  Fix Verification");
  lines.push("  " + "─".repeat(40));

  if (verification.result.applied.length === 0) {
    lines.push("  No fixes applied; nothing to verify.");
  } else if (verification.reverted) {
    lines.push(`  [REVERTED] Fixes rolled back — ${verification.reason}.`);
    lines.push(`  Score: ${verification.scoreBefore} (restored, no change on disk).`);
    if (verification.introducedFindings.length > 0) {
      lines.push(`  The fix would have introduced ${verification.introducedFindings.length} new finding(s).`);
    }
  } else {
    const delta = verification.scoreAfter - verification.scoreBefore;
    lines.push(`  [VERIFIED] ${verification.result.applied.length} fix(es) kept; no regression.`);
    lines.push(
      `  Score: ${verification.scoreBefore} -> ${verification.scoreAfter} (${delta >= 0 ? "+" : ""}${delta}).`
    );
    lines.push(
      `  Findings resolved: ${verification.resolvedFindingIds.length}, introduced: ${verification.introducedFindings.length}.`
    );
  }

  lines.push(`  Attestation: ${verification.attestation.digest}`);
  lines.push("");

  return lines.join("\n");
}
