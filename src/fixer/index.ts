import { readFileSync, writeFileSync } from "node:fs";
import type { Finding } from "../types.js";
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

  for (const [filePath, findings] of grouped) {
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
