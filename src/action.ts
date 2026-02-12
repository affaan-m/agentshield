/**
 * GitHub Action entry point for AgentShield.
 *
 * Reads inputs from environment variables (INPUT_*), runs the scanner,
 * and outputs results as GitHub Action annotations, outputs, and job summary.
 * Does not depend on @actions/core — uses native GitHub Actions workflow commands.
 */

import { resolve } from "node:path";
import { existsSync } from "node:fs";
import { appendFileSync } from "node:fs";
import { scan } from "./scanner/index.js";
import { calculateScore } from "./reporter/score.js";
import { renderMarkdownReport } from "./reporter/json.js";
import type { Finding, Severity } from "./types.js";

// ─── GitHub Actions Helpers ──────────────────────────────────

function getInput(name: string, fallback: string): string {
  // GitHub Actions preserves hyphens in INPUT_ env vars (only spaces → underscores)
  const envKey = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
  return process.env[envKey]?.trim() ?? fallback;
}

function setOutput(name: string, value: string): void {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    appendFileSync(outputFile, `${name}=${value}\n`);
  } else {
    // Fallback for older runners
    console.log(`::set-output name=${name}::${value}`);
  }
}

function writeJobSummary(markdown: string): void {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) {
    appendFileSync(summaryFile, markdown);
  }
}

function annotateWarning(file: string, line: number | undefined, message: string): void {
  const lineParam = line ? `,line=${line}` : "";
  console.log(`::warning file=${file}${lineParam}::${escapeAnnotation(message)}`);
}

function annotateError(file: string, line: number | undefined, message: string): void {
  const lineParam = line ? `,line=${line}` : "";
  console.log(`::error file=${file}${lineParam}::${escapeAnnotation(message)}`);
}

function escapeAnnotation(message: string): string {
  return message
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
}

// ─── Severity Filtering ─────────────────────────────────────

const SEVERITY_ORDER: ReadonlyArray<Severity> = ["critical", "high", "medium", "low", "info"];

function severityIndex(severity: string): number {
  const idx = SEVERITY_ORDER.indexOf(severity as Severity);
  return idx === -1 ? SEVERITY_ORDER.length : idx;
}

function isAtOrAboveSeverity(finding: Finding, minSeverity: string): boolean {
  return severityIndex(finding.severity) <= severityIndex(minSeverity);
}

// ─── Annotation Logic ───────────────────────────────────────

function emitAnnotations(findings: ReadonlyArray<Finding>): void {
  for (const finding of findings) {
    const message = `[${finding.severity.toUpperCase()}] ${finding.title}: ${finding.description}`;

    if (finding.severity === "critical" || finding.severity === "high") {
      annotateError(finding.file, finding.line, message);
    } else {
      annotateWarning(finding.file, finding.line, message);
    }
  }
}

// ─── Main ────────────────────────────────────────────────────

async function run(): Promise<void> {
  const inputPath = getInput("path", ".");
  const minSeverity = getInput("min-severity", "medium");
  const failOnFindings = getInput("fail-on-findings", "true") === "true";
  const format = getInput("format", "terminal");

  // Resolve and validate path
  const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd();
  const targetPath = resolve(workspace, inputPath);

  if (!existsSync(targetPath)) {
    console.log(`::error::AgentShield: Path does not exist: ${targetPath}`);
    process.exitCode = 1;
    return;
  }

  console.log(`AgentShield: Scanning ${targetPath}`);
  console.log(`  min-severity: ${minSeverity}`);
  console.log(`  fail-on-findings: ${failOnFindings}`);
  console.log(`  format: ${format}`);
  console.log("");

  // Run scan
  const result = scan(targetPath);

  // Filter findings by severity
  const filteredResult = {
    ...result,
    findings: result.findings.filter((f) => isAtOrAboveSeverity(f, minSeverity)),
  };

  // Calculate score
  const report = calculateScore(filteredResult);

  // Emit GitHub annotations for each finding
  emitAnnotations(filteredResult.findings);

  // Set action outputs
  setOutput("score", String(report.score.numericScore));
  setOutput("grade", report.score.grade);
  setOutput("total-findings", String(report.summary.totalFindings));
  setOutput("critical-count", String(report.summary.critical));

  // Write job summary as markdown
  const markdownSummary = renderMarkdownReport(report);
  writeJobSummary(markdownSummary);

  // Console output for the log
  console.log(`Score: ${report.score.numericScore}/100 (Grade: ${report.score.grade})`);
  console.log(`Findings: ${report.summary.totalFindings} total`);
  console.log(`  Critical: ${report.summary.critical}`);
  console.log(`  High: ${report.summary.high}`);
  console.log(`  Medium: ${report.summary.medium}`);
  console.log(`  Low: ${report.summary.low}`);
  console.log(`  Info: ${report.summary.info}`);

  // Fail if requested and findings exist
  if (failOnFindings && filteredResult.findings.length > 0) {
    console.log("");
    console.log(
      `::error::AgentShield found ${filteredResult.findings.length} finding(s) at or above ${minSeverity} severity. Failing the action.`
    );
    process.exitCode = 1;
  }
}

run().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.log(`::error::AgentShield action failed: ${escapeAnnotation(message)}`);
  process.exitCode = 1;
});
