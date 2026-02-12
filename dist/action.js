import {
  calculateScore,
  renderMarkdownReport,
  scan
} from "./chunk-UJVY7OA5.js";

// src/action.ts
import { resolve } from "path";
import { existsSync } from "fs";
import { appendFileSync } from "fs";
function getInput(name, fallback) {
  const envKey = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
  return process.env[envKey]?.trim() ?? fallback;
}
function setOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    appendFileSync(outputFile, `${name}=${value}
`);
  } else {
    console.log(`::set-output name=${name}::${value}`);
  }
}
function writeJobSummary(markdown) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) {
    appendFileSync(summaryFile, markdown);
  }
}
function annotateWarning(file, line, message) {
  const lineParam = line ? `,line=${line}` : "";
  console.log(`::warning file=${file}${lineParam}::${escapeAnnotation(message)}`);
}
function annotateError(file, line, message) {
  const lineParam = line ? `,line=${line}` : "";
  console.log(`::error file=${file}${lineParam}::${escapeAnnotation(message)}`);
}
function escapeAnnotation(message) {
  return message.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
var SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
function severityIndex(severity) {
  const idx = SEVERITY_ORDER.indexOf(severity);
  return idx === -1 ? SEVERITY_ORDER.length : idx;
}
function isAtOrAboveSeverity(finding, minSeverity) {
  return severityIndex(finding.severity) <= severityIndex(minSeverity);
}
function emitAnnotations(findings) {
  for (const finding of findings) {
    const message = `[${finding.severity.toUpperCase()}] ${finding.title}: ${finding.description}`;
    if (finding.severity === "critical" || finding.severity === "high") {
      annotateError(finding.file, finding.line, message);
    } else {
      annotateWarning(finding.file, finding.line, message);
    }
  }
}
async function run() {
  const inputPath = getInput("path", ".");
  const minSeverity = getInput("min-severity", "medium");
  const failOnFindings = getInput("fail-on-findings", "true") === "true";
  const format = getInput("format", "terminal");
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
  const result = scan(targetPath);
  const filteredResult = {
    ...result,
    findings: result.findings.filter((f) => isAtOrAboveSeverity(f, minSeverity))
  };
  const report = calculateScore(filteredResult);
  emitAnnotations(filteredResult.findings);
  setOutput("score", String(report.score.numericScore));
  setOutput("grade", report.score.grade);
  setOutput("total-findings", String(report.summary.totalFindings));
  setOutput("critical-count", String(report.summary.critical));
  const markdownSummary = renderMarkdownReport(report);
  writeJobSummary(markdownSummary);
  console.log(`Score: ${report.score.numericScore}/100 (Grade: ${report.score.grade})`);
  console.log(`Findings: ${report.summary.totalFindings} total`);
  console.log(`  Critical: ${report.summary.critical}`);
  console.log(`  High: ${report.summary.high}`);
  console.log(`  Medium: ${report.summary.medium}`);
  console.log(`  Low: ${report.summary.low}`);
  console.log(`  Info: ${report.summary.info}`);
  if (failOnFindings && filteredResult.findings.length > 0) {
    console.log("");
    console.log(
      `::error::AgentShield found ${filteredResult.findings.length} finding(s) at or above ${minSeverity} severity. Failing the action.`
    );
    process.exitCode = 1;
  }
}
run().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.log(`::error::AgentShield action failed: ${escapeAnnotation(message)}`);
  process.exitCode = 1;
});
