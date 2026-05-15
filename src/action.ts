/**
 * GitHub Action entry point for AgentShield.
 *
 * Reads inputs from environment variables (INPUT_*), runs the scanner,
 * and outputs results as GitHub Action annotations, outputs, and job summary.
 * Does not depend on @actions/core — uses native GitHub Actions workflow commands.
 */

import { resolve } from "node:path";
import { dirname } from "node:path";
import { existsSync } from "node:fs";
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { scan } from "./scanner/index.js";
import { calculateScore } from "./reporter/score.js";
import { renderMarkdownReport } from "./reporter/json.js";
import { renderSarifReport } from "./reporter/sarif.js";
import { verifyEvidencePack, writeEvidencePack } from "./evidence-pack/index.js";
import {
  renderPolicyJobSummary,
  statusForPolicyEvaluation,
} from "./action-policy.js";
import {
  renderBaselineJobSummary,
  renderMissingBaselineJobSummary,
  statusForBaselineGate,
} from "./action-baseline.js";
import {
  renderSupplyChainJobSummary,
  shouldFailForSupplyChain,
  statusForSupplyChainReport,
} from "./action-supply-chain.js";
import type { PolicyEvaluation } from "./policy/index.js";
import type { BaselineComparison } from "./baseline/index.js";
import type { SupplyChainReport } from "./supply-chain/index.js";
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

function emptySupplyChainReport(): SupplyChainReport {
  return {
    packages: [],
    totalPackages: 0,
    riskyPackages: 0,
    criticalCount: 0,
    highCount: 0,
    provenance: {
      npmPackages: 0,
      gitPackages: 0,
      pinnedPackages: 0,
      unpinnedPackages: 0,
      knownGoodPackages: 0,
      registryMetadataPackages: 0,
    },
  };
}

// ─── Main ────────────────────────────────────────────────────

async function run(): Promise<void> {
  const inputPath = getInput("path", ".");
  const minSeverity = getInput("min-severity", "medium");
  const failOnFindings = getInput("fail-on-findings", "true") === "true";
  const format = getInput("format", "terminal");
  const baselinePath = getInput("baseline", "");
  const saveBaselinePath = getInput("save-baseline", "");
  const sarifOutput = getInput("sarif-output", "agentshield-results.sarif");
  const policyPath = getInput("policy", "");
  const failOnPolicy = getInput("fail-on-policy", "true") === "true";
  const supplyChainRequested = getInput("supply-chain", "true") === "true";
  const supplyChainOnline = getInput("supply-chain-online", "false") === "true";
  const failOnSupplyChainInput = getInput("fail-on-supply-chain", "");
  const failOnSupplyChain = failOnSupplyChainInput
    ? failOnSupplyChainInput === "true"
    : failOnFindings;
  const evidencePackPath = getInput("evidence-pack", "");
  const verifyEvidencePackOutput = getInput("verify-evidence-pack", "true") === "true";

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
  if (policyPath) {
    console.log(`  policy: ${policyPath}`);
    console.log(`  fail-on-policy: ${failOnPolicy}`);
  }
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
  setOutput("baseline-status", "not-run");
  setOutput("new-findings", "0");
  setOutput("resolved-findings", "0");
  setOutput("unchanged-findings", "0");
  setOutput("score-delta", "0");
  setOutput("policy-status", "not-run");
  setOutput("policy-violations", "0");
  setOutput("supply-chain-status", "not-run");
  setOutput("supply-chain-risky-packages", "0");
  setOutput("supply-chain-critical-count", "0");
  setOutput("supply-chain-high-count", "0");
  setOutput("evidence-pack-status", "not-run");
  setOutput("evidence-pack-digest", "");

  let policyEvaluation: PolicyEvaluation | null = null;
  let shouldFailOnPolicy = false;
  let baselineComparison: BaselineComparison | null = null;
  let shouldFailOnBaseline = false;
  let supplyChainReport: SupplyChainReport = emptySupplyChainReport();
  let shouldFailOnSupplyChain = false;

  if (policyPath) {
    const { loadPolicy, evaluatePolicy, renderPolicyEvaluation } = await import(
      "./policy/index.js"
    );
    const resolvedPolicyPath = resolve(workspace, policyPath);
    const policyResult = loadPolicy(resolvedPolicyPath);

    if (!policyResult.success) {
      setOutput("policy-status", "error");
      console.log(
        `::error::AgentShield policy load failed: ${escapeAnnotation(policyResult.error)}`
      );
      writeJobSummary([
        "",
        "",
        "## AgentShield Organization Policy",
        "",
        "- Status: error",
        `- Error: ${policyResult.error}`,
        "",
      ].join("\n"));
      if (failOnPolicy) {
        shouldFailOnPolicy = true;
      }
    } else {
      policyEvaluation = evaluatePolicy(
        policyResult.policy,
        filteredResult.findings,
        report.score,
        result.target.files
      );
      const policyStatus = statusForPolicyEvaluation(policyEvaluation);
      setOutput("policy-status", policyStatus);
      setOutput("policy-violations", String(policyEvaluation.violations.length));
      writeJobSummary(renderPolicyJobSummary(policyEvaluation));
      console.log(renderPolicyEvaluation(policyEvaluation));

      if (!policyEvaluation.passed) {
        for (const violation of policyEvaluation.violations) {
          const message = escapeAnnotation(violation.description);
          console.log(
            `::error::AgentShield policy violation ${violation.rule}: ${message}`
          );
        }
        if (failOnPolicy) {
          shouldFailOnPolicy = true;
        }
      }
    }
  }

  if (format === "sarif") {
    const sarifPath = resolve(workspace, sarifOutput);
    mkdirSync(dirname(sarifPath), { recursive: true });
    writeFileSync(
      sarifPath,
      renderSarifReport(report, {
        policyEvaluation: policyEvaluation ?? undefined,
        policyUri: policyPath || undefined,
      })
    );
    setOutput("sarif-path", sarifPath);
    console.log(`SARIF written to: ${sarifPath}`);
  }

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

  if (supplyChainRequested || supplyChainOnline || evidencePackPath) {
    try {
      const { extractPackages, renderSupplyChainReport, verifyPackages } = await import(
        "./supply-chain/index.js"
      );
      const packages = extractPackages(result.target.files);
      supplyChainReport = await verifyPackages(packages, {
        online: supplyChainOnline,
      });
      const supplyChainStatus = statusForSupplyChainReport(supplyChainReport);

      setOutput("supply-chain-status", supplyChainStatus);
      setOutput("supply-chain-risky-packages", String(supplyChainReport.riskyPackages));
      setOutput("supply-chain-critical-count", String(supplyChainReport.criticalCount));
      setOutput("supply-chain-high-count", String(supplyChainReport.highCount));
      writeJobSummary(renderSupplyChainJobSummary(supplyChainReport, {
        online: supplyChainOnline,
        failOnSupplyChain,
      }));

      if (supplyChainRequested || supplyChainOnline) {
        console.log(renderSupplyChainReport(supplyChainReport));
      } else {
        console.log(
          `Supply-chain verification: ${supplyChainStatus.toUpperCase()} ` +
          `(${supplyChainReport.riskyPackages}/${supplyChainReport.totalPackages} risky packages)`
        );
      }

      if (
        (supplyChainRequested || supplyChainOnline) &&
        shouldFailForSupplyChain(supplyChainReport, { failOnSupplyChain })
      ) {
        const reason = [
          `${supplyChainReport.criticalCount} critical`,
          `${supplyChainReport.highCount} high`,
        ].join(", ");
        console.log(`::error::AgentShield supply-chain gate FAILED: ${reason} package risk(s)`);
        shouldFailOnSupplyChain = true;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setOutput("supply-chain-status", "error");
      console.log(`::error::AgentShield supply-chain verification failed: ${escapeAnnotation(message)}`);
      process.exitCode = 1;
      return;
    }
  }

  // Save baseline if requested
  if (saveBaselinePath) {
    const { saveBaseline } = await import("./baseline/index.js");
    const savePath = resolve(workspace, saveBaselinePath);
    saveBaseline(filteredResult.findings, report.score, savePath);
    setOutput("baseline-path", savePath);
    console.log(`Baseline saved to: ${savePath}`);
  }

  // Compare against baseline if provided
  if (baselinePath) {
    const { loadBaseline, compareBaseline, evaluateGate } = await import("./baseline/index.js");
    const baseline = loadBaseline(resolve(workspace, baselinePath));

    if (baseline) {
      const comparison = compareBaseline(baseline, filteredResult.findings, report.score);
      baselineComparison = comparison;

      setOutput("new-findings", String(comparison.newFindings.length));
      setOutput("resolved-findings", String(comparison.resolvedFindings.length));
      setOutput("unchanged-findings", String(comparison.unchangedCount));
      setOutput("score-delta", String(comparison.scoreDelta));

      // Emit annotations only for NEW findings (regression-only mode)
      if (comparison.newFindings.length > 0) {
        console.log("");
        console.log(`Baseline comparison: ${comparison.newFindings.length} new, ${comparison.resolvedFindings.length} resolved`);
        emitAnnotations(comparison.newFindings);
      }

      const gateResult = evaluateGate(comparison);
      setOutput("baseline-status", statusForBaselineGate(gateResult));
      writeJobSummary(renderBaselineJobSummary(comparison, gateResult));
      if (!gateResult.passed) {
        console.log("");
        console.log(`::error::AgentShield gate FAILED: ${gateResult.reasons.join("; ")}`);
        shouldFailOnBaseline = true;
      } else {
        console.log("Baseline gate: PASSED");
      }
    } else {
      setOutput("baseline-status", "missing");
      writeJobSummary(renderMissingBaselineJobSummary(baselinePath));
      console.log(`::warning::Could not load baseline from ${baselinePath}. Skipping comparison.`);
    }
  }

  if (evidencePackPath) {
    try {
      const packPath = resolve(workspace, evidencePackPath);
      const pack = writeEvidencePack({
        outputDir: packPath,
        report,
        policyEvaluation: policyEvaluation ?? undefined,
        policyPath: policyPath || undefined,
        baselineComparison: baselineComparison ?? undefined,
        baselinePath: baselinePath || undefined,
        supplyChainReport,
      });
      setOutput("evidence-pack-path", pack.outputDir);
      console.log(`Evidence pack written to: ${pack.outputDir}`);

      if (verifyEvidencePackOutput) {
        const verification = verifyEvidencePack(pack.outputDir);
        setOutput("evidence-pack-status", verification.ok ? "passed" : "failed");
        setOutput("evidence-pack-digest", verification.bundleDigest ?? "");
        if (!verification.ok) {
          console.log(`::error::AgentShield evidence pack verification failed: ${escapeAnnotation(verification.errors.join("; "))}`);
          process.exitCode = 1;
          return;
        }
        console.log(`Evidence pack verification: PASSED (${verification.bundleDigest})`);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setOutput("evidence-pack-status", "error");
      console.log(`::error::AgentShield evidence pack failed: ${escapeAnnotation(message)}`);
      process.exitCode = 1;
      return;
    }
  }

  if (shouldFailOnPolicy) {
    process.exitCode = 1;
    return;
  }

  if (shouldFailOnBaseline) {
    process.exitCode = 1;
    return;
  }

  if (shouldFailOnSupplyChain) {
    process.exitCode = 1;
    return;
  }

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
