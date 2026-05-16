#!/usr/bin/env node

import { Command } from "commander";
import { resolve } from "node:path";
import { dirname, join } from "node:path";
import { existsSync, writeFileSync, appendFileSync, mkdirSync } from "node:fs";
import { scan } from "./scanner/index.js";
import { calculateScore } from "./reporter/score.js";
import { renderTerminalReport } from "./reporter/terminal.js";
import { renderJsonReport, renderMarkdownReport } from "./reporter/json.js";
import { renderHtmlReport } from "./reporter/html.js";
import { renderSarifReport } from "./reporter/sarif.js";
import {
  inspectEvidencePack,
  inspectEvidencePackFleet,
  verifyEvidencePack,
  writeEvidencePack,
} from "./evidence-pack/index.js";
import { runOpusPipeline, renderOpusAnalysis } from "./opus/index.js";
import { applyFixes, renderFixSummary } from "./fixer/index.js";
import { runInit, renderInitSummary } from "./init/index.js";
import { startMiniClaw } from "./miniclaw/index.js";
import { startWatcher } from "./watch/index.js";
import type { AlertMode } from "./watch/types.js";
import { getRuntimeStatus, installRuntime, repairRuntime, uninstallRuntime } from "./runtime/index.js";
import type { BaselineComparison } from "./baseline/index.js";
import type { SupplyChainReport } from "./supply-chain/index.js";
import type {
  InjectionSuiteResult,
  SandboxResult,
  SandboxBehavior,
  Finding,
  TaintResult,
  CorpusValidationResult,
  ScanLogEntry,
  DeepScanResult,
} from "./types.js";
import type { PolicyEvaluation } from "./policy/index.js";

function writeStdout(line = ""): void {
  process.stdout.write(`${line}\n`);
}

// ─── Dynamic Module Loaders ───────────────────────────────────
// These modules are being built in parallel by other agents.
// Dynamic imports with try/catch ensure the build doesn't break
// if a module isn't ready yet.

async function runInjectionTests(
  targetPath: string
): Promise<InjectionSuiteResult | null> {
  try {
    const { runInjectionSuite } = await import("./injection/index.js");
    return await runInjectionSuite(targetPath);
  } catch (e) {
    console.error(
      "  Injection module not available:",
      (e as Error).message
    );
    return null;
  }
}

async function runSandboxAnalysis(
  targetPath: string
): Promise<SandboxResult | null> {
  try {
    const { executeAllHooks, analyzeAllExecutions } = await import("./sandbox/index.js");
    const { discoverConfigFiles } = await import("./scanner/index.js");

    const target = discoverConfigFiles(targetPath);
    const settingsFile = target.files.find((f) => f.type === "settings-json");
    if (!settingsFile) return null;

    const executions = await executeAllHooks(settingsFile.content);
    const analyses = analyzeAllExecutions(executions);

    const behaviors: SandboxBehavior[] = executions.map((exec: { hookCommand: string; exitCode: number | null; stdout: string; stderr: string; observations: ReadonlyArray<{ type: string; detail: string }> }, i: number) => ({
      hookId: `hook-${i}`,
      hookCommand: exec.hookCommand,
      exitCode: exec.exitCode ?? -1,
      stdout: exec.stdout,
      stderr: exec.stderr,
      networkAttempts: exec.observations
        .filter((o) => o.type === "network_request")
        .map((o) => o.detail),
      fileAccesses: exec.observations
        .filter((o) => o.type === "file_read" || o.type === "file_write")
        .map((o) => o.detail),
      suspiciousBehaviors: exec.observations
        .filter((o) => o.type === "suspicious_output" || o.type === "process_spawn")
        .map((o) => o.detail),
    }));

    const riskFindings: Finding[] = [];
    for (const analysis of analyses) {
      for (const finding of analysis.findings) {
        riskFindings.push({
          id: finding.id,
          severity: finding.severity,
          category: "misconfiguration",
          title: finding.title,
          description: finding.description,
          file: "settings.json",
          evidence: finding.evidence,
        });
      }
    }

    return { hooksExecuted: executions.length, behaviors, riskFindings };
  } catch (e) {
    console.error(
      "  Sandbox module not available:",
      (e as Error).message
    );
    return null;
  }
}

async function runTaintAnalysis(
  targetPath: string
): Promise<TaintResult | null> {
  try {
    const { analyzeTaint } = await import("./taint/index.js");
    const { discoverConfigFiles } = await import("./scanner/index.js");

    const target = discoverConfigFiles(targetPath);
    const files = target.files.map((f) => ({ path: f.path, content: f.content }));

    return analyzeTaint(files);
  } catch (e) {
    console.error(
      "  Taint analysis module not available:",
      (e as Error).message
    );
    return null;
  }
}

async function runCorpusValidation(
  _targetPath: string
): Promise<CorpusValidationResult | null> {
  try {
    const { validateCorpus, defaultRuleScanFn } = await import("./corpus/index.js");
    const { getBuiltinRules } = await import("./rules/index.js");

    const rules = getBuiltinRules();
    const validation = validateCorpus(defaultRuleScanFn, rules);

    const totalAttacks = validation.totalConfigs;
    const detected = validation.passed;
    const missed = validation.failed;

    return {
      totalAttacks,
      detected,
      missed,
      detectionRate: totalAttacks > 0 ? detected / totalAttacks : 0,
      readyForRegressionGate: validation.readyForRegressionGate,
      categoryBreakdown: validation.categoryBreakdown,
      accuracyRecommendations: validation.accuracyRecommendations,
      results: validation.results.map((r: { configId: string; configName: string; passed: boolean; missingRules: ReadonlyArray<string> }) => ({
        attackId: r.configId,
        attackName: r.configName,
        detected: r.passed,
        ruleId: r.missingRules.length === 0 ? r.configId : undefined,
      })),
    };
  } catch (e) {
    console.error(
      "  Corpus module not available:",
      (e as Error).message
    );
    return null;
  }
}

// ─── Scan Logger ──────────────────────────────────────────────

function createScanLogger(
  logPath: string | undefined,
  logFormat: "ndjson" | "json"
): {
  readonly log: (entry: Omit<ScanLogEntry, "timestamp">) => void;
  readonly flush: () => void;
} {
  const entries: ScanLogEntry[] = [];

  return {
    log(entry: Omit<ScanLogEntry, "timestamp">) {
      const fullEntry: ScanLogEntry = {
        ...entry,
        timestamp: new Date().toISOString(),
      };
      entries.push(fullEntry);

      if (logPath && logFormat === "ndjson") {
        appendFileSync(logPath, JSON.stringify(fullEntry) + "\n");
      }
    },
    flush() {
      if (logPath && logFormat === "json") {
        writeFileSync(logPath, JSON.stringify(entries, null, 2));
      }
    },
  };
}

// ─── CLI Setup ────────────────────────────────────────────────

const program = new Command();
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

program
  .name("agentshield")
  .description("Security auditor for AI agent configurations")
  .version("1.4.0");

function emitReportOutput(output: string, outputPath: string | undefined): void {
  if (!outputPath) {
    console.log(output);
    return;
  }

  const resolvedOutput = resolve(outputPath);
  mkdirSync(dirname(resolvedOutput), { recursive: true });
  writeFileSync(resolvedOutput, output);
  console.log(`Report written to: ${resolvedOutput}`);
}

function collectOption(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function severityIndex(severity: string): number {
  return SEVERITY_ORDER.indexOf(severity as typeof SEVERITY_ORDER[number]);
}

function filterFindingsByMinSeverity<T extends { severity: string }>(
  findings: ReadonlyArray<T>,
  minSeverity: string
): T[] {
  const minIndex = severityIndex(minSeverity);
  return findings.filter((finding) => severityIndex(finding.severity) <= minIndex);
}

function validateMinSeverity(minSeverity: string): boolean {
  return severityIndex(minSeverity) >= 0;
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

program
  .command("scan")
  .description("Scan a Claude Code configuration directory for security issues")
  .option("-p, --path <path>", "Path to scan (default: ~/.claude or current dir)")
  .option("-f, --format <format>", "Output format: terminal, json, markdown, html, sarif", "terminal")
  .option("-o, --output <path>", "Write the primary report output to a file")
  .option("--fix", "Auto-apply safe fixes", false)
  .option("--opus", "Enable Opus 4.6 multi-agent deep analysis", false)
  .option("--stream", "Stream Opus analysis in real-time", false)
  .option("--injection", "Run active prompt injection testing against the config", false)
  .option("--sandbox", "Execute hooks in sandbox and observe behavior", false)
  .option("--taint", "Run taint analysis (data flow tracking)", false)
  .option("--deep", "Run ALL analysis (injection + sandbox + taint + opus)", false)
  .option("--log <path>", "Write structured scan log to file")
  .option("--log-format <format>", "Log format: ndjson (default) or json", "ndjson")
  .option("--corpus", "Run scanner validation against built-in attack corpus", false)
  .option("--corpus-gate", "Run built-in attack corpus and fail if scanner accuracy regresses", false)
  .option("--baseline <path>", "Compare against a baseline file and report regressions")
  .option("--save-baseline <path>", "Save current scan results as a baseline file")
  .option("--gate", "Fail if new critical/high findings or score drops (use with --baseline)", false)
  .option("--supply-chain", "Verify MCP npm packages against known-bad list and typosquatting", false)
  .option("--supply-chain-online", "Also query npm registry for metadata (requires network)", false)
  .option("--policy <path>", "Validate against an organization policy file")
  .option("--evidence-pack <dir>", "Write a portable evidence bundle for audits and security reviews")
  .option("--remediation-plan <path>", "Write a stable-fingerprint JSON remediation plan")
  .option("--no-evidence-redact", "Disable evidence-pack redaction of local paths, usernames, emails, and token-shaped strings")
  .option("--min-severity <severity>", "Minimum severity to report: critical, high, medium, low, info", "info")
  .option("-v, --verbose", "Show detailed output", false)
  .action(async (options) => {
    const targetPath = resolveTargetPath(options.path);

    if (!existsSync(targetPath)) {
      console.error(`Error: Path does not exist: ${targetPath}`);
      process.exit(1);
    }

    // Initialize scan logger
    const logger = createScanLogger(options.log, options.logFormat);
    logger.log({ level: "info", phase: "init", message: `Scanning ${targetPath}` });

    // Resolve --deep flag: enables all analysis modes
    const enableInjection = options.deep || options.injection;
    const enableSandbox = options.deep || options.sandbox;
    const enableTaint = options.deep || options.taint;
    const enableOpus = options.deep || options.opus;

    // ── Phase 1: Static rule-based scan ──────────────────────
    logger.log({ level: "info", phase: "static", message: "Running static analysis" });
    const result = scan(targetPath);

    // Filter by severity
    const filteredResult = {
      ...result,
      findings: filterFindingsByMinSeverity(result.findings, options.minSeverity),
    };

    // Generate report
    const report = calculateScore(filteredResult);
    logger.log({
      level: "info",
      phase: "static",
      message: `Static analysis complete: ${report.summary.totalFindings} findings`,
      data: { grade: report.score.grade, score: report.score.numericScore },
    });

    let policyEvaluation: PolicyEvaluation | null = null;
    let policyExitCode = 0;
    let baselineComparison: BaselineComparison | null = null;
    let supplyChainReport: SupplyChainReport | null = null;
    const machineReportToStdout =
      !options.output && (options.format === "json" || options.format === "sarif");
    const writePolicyOutput = (message: string): void => {
      if (machineReportToStdout) {
        console.error(message);
      } else {
        console.log(message);
      }
    };
    const writeAuxiliaryOutput = writePolicyOutput;

    // ── Phase 1c: Organization policy validation ──────────
    if (options.policy) {
      logger.log({ level: "info", phase: "policy", message: "Validating against organization policy" });
      try {
        const { loadPolicy: loadOrgPolicy, evaluatePolicy, renderPolicyEvaluation } =
          await import("./policy/index.js");
        const policyResult = loadOrgPolicy(resolve(options.policy));
        if (!policyResult.success) {
          console.error(`\n  Error: ${policyResult.error}\n`);
          logger.log({
            level: "error",
            phase: "policy",
            message: `Failed to load policy: ${policyResult.error}`,
          });
          process.exit(4);
        }

        policyEvaluation = evaluatePolicy(
          policyResult.policy,
          filteredResult.findings,
          report.score,
          result.target.files
        );
        writePolicyOutput(renderPolicyEvaluation(policyEvaluation));
        logger.log({
          level: policyEvaluation.passed ? "info" : "warn",
          phase: "policy",
          message: `Policy "${policyEvaluation.policyName}": ${policyEvaluation.passed ? "COMPLIANT" : `NON-COMPLIANT (${policyEvaluation.violations.length} violations)`}`,
        });
        if (!policyEvaluation.passed) {
          policyExitCode = 4;
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`  Policy evaluation failed: ${message}`);
        logger.log({ level: "error", phase: "policy", message: `Failed: ${message}` });
        process.exit(4);
      }
    }

    // Output static scan
    let renderedReport: string;
    switch (options.format) {
      case "json":
        renderedReport = renderJsonReport(report);
        break;
      case "markdown":
        renderedReport = renderMarkdownReport(report);
        break;
      case "html":
        renderedReport = renderHtmlReport(report);
        break;
      case "sarif":
        renderedReport = renderSarifReport(report, {
          policyEvaluation: policyEvaluation ?? undefined,
          policyUri: options.policy,
        });
        break;
      default:
        renderedReport = renderTerminalReport(report);
    }
    emitReportOutput(renderedReport, options.output);

    if (options.remediationPlan) {
      try {
        const { writeRemediationPlan } = await import("./remediation/index.js");
        const remediationPlan = writeRemediationPlan({
          outputPath: options.remediationPlan,
          report,
        });
        writeAuxiliaryOutput(`\n  Remediation plan written to: ${remediationPlan.outputPath}\n`);
        logger.log({
          level: "info",
          phase: "remediation",
          message: `Remediation plan written to ${remediationPlan.outputPath}`,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        writeAuxiliaryOutput(`\n  Error: Failed to write remediation plan: ${message}\n`);
        logger.log({ level: "error", phase: "remediation", message: `Failed: ${message}` });
        process.exit(1);
      }
    }

    // ── Phase 1b: Baseline save/compare ───────────────────
    if (options.saveBaseline) {
      const { saveBaseline } = await import("./baseline/index.js");
      saveBaseline(filteredResult.findings, report.score, options.saveBaseline);
      writeAuxiliaryOutput(`\n  Baseline saved to: ${options.saveBaseline}\n`);
      logger.log({ level: "info", phase: "baseline", message: `Baseline saved to ${options.saveBaseline}` });
    }

    if (options.baseline) {
      const { loadBaseline, compareBaseline, evaluateGate, renderComparison, renderGateResult } =
        await import("./baseline/index.js");
      const baseline = loadBaseline(options.baseline);
      if (!baseline) {
        console.error(`\n  Error: Could not load baseline from ${options.baseline}\n`);
      } else {
        baselineComparison = compareBaseline(baseline, filteredResult.findings, report.score);
        writeAuxiliaryOutput(renderComparison(baselineComparison));
        logger.log({
          level: baselineComparison.isRegression ? "warn" : "info",
          phase: "baseline",
          message: `Baseline comparison: ${baselineComparison.newFindings.length} new, ${baselineComparison.resolvedFindings.length} resolved, score delta ${baselineComparison.scoreDelta}`,
        });

        if (options.gate) {
          const gateResult = evaluateGate(baselineComparison);
          writeAuxiliaryOutput(renderGateResult(gateResult));
          if (!gateResult.passed) {
            logger.log({ level: "error", phase: "gate", message: `Gate FAILED: ${gateResult.reasons.join("; ")}` });
            process.exit(3);
          }
        }
      }
    }

    // ── Phase 1d: Supply-chain evidence ───────────────────
    if (options.supplyChain || options.supplyChainOnline || options.evidencePack) {
      logger.log({ level: "info", phase: "supply-chain", message: "Running supply chain verification" });
      try {
        const { extractPackages, verifyPackages, renderSupplyChainReport } =
          await import("./supply-chain/index.js");
        const packages = extractPackages(result.target.files);
        supplyChainReport = await verifyPackages(packages, {
          online: options.supplyChainOnline,
        });
        if ((options.supplyChain || options.supplyChainOnline) && options.format === "terminal") {
          // Preserve machine-readable stdout for json/markdown/html scans.
          console.log(renderSupplyChainReport(supplyChainReport));
        }
        logger.log({
          level: supplyChainReport.criticalCount > 0 ? "error" : supplyChainReport.highCount > 0 ? "warn" : "info",
          phase: "supply-chain",
          message: `Supply chain: ${supplyChainReport.riskyPackages}/${supplyChainReport.totalPackages} risky packages`,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`  Supply chain verification failed: ${message}`);
        logger.log({ level: "error", phase: "supply-chain", message: `Failed: ${message}` });
        process.exit(5);
      }
    }

    if (options.evidencePack) {
      try {
        const pack = writeEvidencePack({
          outputDir: options.evidencePack,
          report,
          policyEvaluation: policyEvaluation ?? undefined,
          policyPath: options.policy,
          baselineComparison: baselineComparison ?? undefined,
          baselinePath: options.baseline,
          supplyChainReport: supplyChainReport ?? emptySupplyChainReport(),
          redact: options.evidenceRedact,
        });
        writeAuxiliaryOutput(`\n  Evidence pack written to: ${pack.outputDir}\n`);
        logger.log({ level: "info", phase: "evidence-pack", message: `Evidence pack written to ${pack.outputDir}` });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        writeAuxiliaryOutput(`\n  Error: Failed to write evidence pack: ${message}\n`);
        logger.log({ level: "error", phase: "evidence-pack", message: `Failed to write evidence pack: ${message}` });
        process.exit(1);
      }
    }

    if (policyExitCode > 0) {
      process.exit(policyExitCode);
    }

    // ── Phase 2: Auto-fix (if enabled) ──────────────────────
    if (options.fix) {
      logger.log({ level: "info", phase: "fix", message: "Applying auto-fixes" });
      const fixResult = applyFixes(filteredResult);
      console.log(renderFixSummary(fixResult));
    }

    // ── Phase 3: Taint analysis ─────────────────────────────
    let taintResult: TaintResult | null = null;
    if (enableTaint) {
      logger.log({ level: "info", phase: "taint", message: "Running taint analysis" });
      taintResult = await runTaintAnalysis(targetPath);
      if (taintResult) {
        const { renderTaintResults } = await import("./reporter/terminal.js");
        console.log(renderTaintResults(taintResult));
        logger.log({
          level: "info",
          phase: "taint",
          message: `Taint analysis complete: ${taintResult.flows.length} flows found`,
        });
      }
    }

    // ── Phase 4: Active injection testing ───────────────────
    let injectionResult: InjectionSuiteResult | null = null;
    if (enableInjection) {
      logger.log({ level: "info", phase: "injection", message: "Running injection tests" });
      injectionResult = await runInjectionTests(targetPath);
      if (injectionResult) {
        const { renderInjectionResults } = await import("./reporter/terminal.js");
        console.log(renderInjectionResults(injectionResult));
        logger.log({
          level: injectionResult.bypassed > 0 ? "warn" : "info",
          phase: "injection",
          message: `Injection tests: ${injectionResult.blocked}/${injectionResult.totalPayloads} blocked`,
        });
      }
    }

    // ── Phase 5: Sandbox hook execution ─────────────────────
    let sandboxResult: SandboxResult | null = null;
    if (enableSandbox) {
      logger.log({ level: "info", phase: "sandbox", message: "Running sandbox hook execution" });
      sandboxResult = await runSandboxAnalysis(targetPath);
      if (sandboxResult) {
        const { renderSandboxResults } = await import("./reporter/terminal.js");
        console.log(renderSandboxResults(sandboxResult));
        logger.log({
          level: sandboxResult.riskFindings.length > 0 ? "warn" : "info",
          phase: "sandbox",
          message: `Sandbox: ${sandboxResult.hooksExecuted} hooks executed, ${sandboxResult.riskFindings.length} risks`,
        });
      }
    }

    // ── Phase 6: Opus multi-agent analysis (if enabled) ─────
    if (enableOpus) {
      if (!process.env.ANTHROPIC_API_KEY) {
        console.error(
          "\nError: ANTHROPIC_API_KEY environment variable required for --opus mode.\n" +
            "Set it with: export ANTHROPIC_API_KEY=your-key-here\n"
        );
        if (!options.deep) {
          process.exit(1);
        }
      } else {
        logger.log({ level: "info", phase: "opus", message: "Running Opus pipeline" });
        try {
          const opusAnalysis = await runOpusPipeline(result, {
            verbose: options.verbose,
            stream: options.stream || options.format === "terminal",
          });

          console.log(renderOpusAnalysis(opusAnalysis));
          logger.log({
            level: "info",
            phase: "opus",
            message: "Opus analysis complete",
            data: { riskLevel: opusAnalysis.auditor.riskLevel },
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          console.error(`\nOpus analysis failed: ${message}`);
          console.error("The static scan results above are still valid.\n");
          logger.log({ level: "error", phase: "opus", message: `Opus failed: ${message}` });
        }
      }
    }

    // ── Phase 7: Corpus validation ──────────────────────────
    let corpusResult: CorpusValidationResult | null = null;
    if (options.corpus || options.corpusGate) {
      logger.log({ level: "info", phase: "corpus", message: "Running corpus validation" });
      corpusResult = await runCorpusValidation(targetPath);
      if (corpusResult) {
        const { renderCorpusResults } = await import("./reporter/terminal.js");
        console.log(renderCorpusResults(corpusResult));
        logger.log({
          level: "info",
          phase: "corpus",
          message: `Corpus: ${corpusResult.detected}/${corpusResult.totalAttacks} detected (${(corpusResult.detectionRate * 100).toFixed(1)}%)`,
        });

        if (options.corpusGate && !corpusResult.readyForRegressionGate) {
          const missedAttacks = corpusResult.results
            .filter((result) => !result.detected)
            .map((result) => result.attackId)
            .join(", ");
          const reason = missedAttacks
            ? `Missed corpus attacks: ${missedAttacks}`
            : "Corpus validation did not meet the regression gate.";
          logger.log({ level: "error", phase: "corpus", message: `Gate FAILED: ${reason}` });
          console.error(`\n  Error: Corpus regression gate failed. ${reason}\n`);
          process.exit(6);
        }
      }
    }

    // ── Deep scan summary (if --deep) ───────────────────────
    if (options.deep) {
      const { renderDeepScanSummary } = await import("./reporter/terminal.js");
      const deepResult: DeepScanResult = {
        staticAnalysis: {
          findings: filteredResult.findings,
          score: report.score,
        },
        taintAnalysis: taintResult,
        injectionTests: injectionResult,
        sandboxResults: sandboxResult,
        opusAnalysis: null,
        corpusValidation: corpusResult,
      };
      console.log(renderDeepScanSummary(deepResult));
    }

    // ── Flush log ───────────────────────────────────────────
    logger.log({ level: "info", phase: "done", message: "Scan complete" });
    logger.flush();

    if (options.log) {
      console.log(`\n  Scan log written to: ${options.log}\n`);
    }

    // Exit with non-zero if critical findings
    if (report.summary.critical > 0) {
      process.exit(2);
    }
  });

program
  .command("init")
  .description("Generate a secure baseline Claude Code configuration")
  .option("-p, --path <path>", "Target directory (default: current directory)")
  .action((options) => {
    const initResult = runInit(options.path);
    console.log(renderInitSummary(initResult));
  });

// ─── Evidence Pack Commands ──────────────────────────────

const evidencePack = program
  .command("evidence-pack")
  .description("Inspect and verify AgentShield evidence-pack bundles");

evidencePack
  .command("inspect")
  .description("Inspect verified evidence-pack contents for downstream consumers")
  .argument("<dir>", "Evidence-pack directory")
  .option("--json", "Emit machine-readable inspection results", false)
  .action((dir, options) => {
    const result = inspectEvidencePack(dir);
    if (options.json) {
      writeStdout(JSON.stringify(result, null, 2));
    } else {
      writeStdout();
      writeStdout("AgentShield Evidence Pack Inspection");
      writeStdout(`Directory:   ${result.outputDir}`);
      writeStdout(`Status:      ${result.ok ? "passed" : "failed"}`);
      writeStdout(`Digest:      ${result.bundleDigest ?? "not available"}`);
      writeStdout(`Generated:   ${result.generatedAt ?? "unknown"}`);
      writeStdout(`Target:      ${result.targetPath ?? "unknown"}`);
      writeStdout(`Artifacts:   ${result.verifiedArtifactCount}/${result.artifactCount} verified`);
      if (result.report) {
        writeStdout(
          `Score:       ${result.report.score.numericScore}/100 (${result.report.score.grade}); ${result.report.findings.total} findings`
        );
        writeStdout(
          `Findings:    critical ${result.report.findings.critical}, high ${result.report.findings.high}, medium ${result.report.findings.medium}, low ${result.report.findings.low}, info ${result.report.findings.info}`
        );
      }
      writeStdout(`Policy:      ${result.policy.status}`);
      writeStdout(`Baseline:    ${result.baseline.status}`);
      if (result.supplyChain) {
        writeStdout(
          `Supply:      ${result.supplyChain.riskyPackages}/${result.supplyChain.totalPackages} risky packages`
        );
      }
      if (result.ciContext) {
        writeStdout(
          `CI:          ${result.ciContext.provider}${result.ciContext.repository ? ` ${result.ciContext.repository}` : ""}`
        );
      }
      if (result.remediation) {
        writeStdout(
          `Remediate:   ${result.remediation.autoFixable} auto-fixable, ${result.remediation.manualReview} manual-review`
        );
      }
      if (result.errors.length > 0) {
        writeStdout();
        writeStdout("Errors:");
        for (const error of result.errors) {
          writeStdout(`- ${error}`);
        }
      }
      writeStdout();
    }

    if (!result.ok) {
      process.exit(6);
    }
  });

evidencePack
  .command("fleet")
  .description("Inspect multiple evidence packs and summarize fleet routing")
  .argument("<dirs...>", "Evidence-pack directories")
  .option("--json", "Emit machine-readable fleet inspection results", false)
  .action((dirs: ReadonlyArray<string>, options) => {
    const result = inspectEvidencePackFleet(dirs);
    if (options.json) {
      writeStdout(JSON.stringify(result, null, 2));
    } else {
      writeStdout();
      writeStdout("AgentShield Evidence Pack Fleet");
      writeStdout(
        `Packs:       ${result.summary.totalPacks} total, ${result.summary.verifiedPacks} verified, ${result.summary.invalidPacks} invalid`
      );
      writeStdout(`Status:      ${result.ok ? "verified" : "invalid evidence"}`);
      writeStdout(`Attention:   ${result.requiresAttention ? "required" : "none"}`);
      writeStdout(
        `Findings:    critical ${result.summary.critical}, high ${result.summary.high}, medium ${result.summary.medium}, low ${result.summary.low}, info ${result.summary.info}`
      );
      writeStdout(
        `Policy:      ${result.summary.policyFailures} failed; Baseline: ${result.summary.baselineRegressions} regressed; Supply: ${result.summary.riskyPackages} risky packages`
      );
      writeStdout(
        `Remediate:   ${result.summary.autoFixable} auto-fixable, ${result.summary.manualReview} manual-review`
      );
      writeStdout();
      writeStdout("Routes:");
      for (const route of result.routes) {
        writeStdout(
          `- ${route.route} ${route.repository ?? route.targetPath ?? route.outputDir}: ${route.reason}`
        );
      }
      if (result.reviewItems.length > 0) {
        writeStdout();
        writeStdout("Review items:");
        for (const item of result.reviewItems) {
          writeStdout(
            `- ${item.severity} ${item.route} ${item.repository ?? item.targetPath ?? item.outputDir}: ${item.recommendation}`
          );
        }
      }
      writeStdout();
    }

    if (!result.ok) {
      process.exit(6);
    }
  });

evidencePack
  .command("verify")
  .description("Verify evidence-pack artifact digests and bundle digest")
  .argument("<dir>", "Evidence-pack directory")
  .option("--json", "Emit machine-readable verification results", false)
  .action((dir, options) => {
    const result = verifyEvidencePack(dir);
    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log("");
      console.log("AgentShield Evidence Pack Verification");
      console.log(`Directory: ${result.outputDir}`);
      console.log(`Status:    ${result.ok ? "passed" : "failed"}`);
      console.log(`Digest:    ${result.bundleDigest ?? "not available"}`);
      console.log("");
      for (const artifact of result.artifacts) {
        console.log(`- ${artifact.ok ? "OK" : "FAIL"} ${artifact.file}`);
      }
      if (result.errors.length > 0) {
        console.log("");
        console.log("Errors:");
        for (const error of result.errors) {
          console.log(`- ${error}`);
        }
      }
      console.log("");
    }

    if (!result.ok) {
      process.exit(6);
    }
  });

// ─── Baseline Commands ───────────────────────────────────

const baseline = program
  .command("baseline")
  .description("Create and inspect AgentShield drift baselines");

baseline
  .command("write")
  .description("Scan a target and write the current findings as a baseline")
  .option("-p, --path <path>", "Path to scan (default: ~/.claude or current dir)")
  .requiredOption("-o, --output <path>", "Path to write the baseline JSON file")
  .option("--min-severity <severity>", "Minimum severity to include: critical, high, medium, low, info", "info")
  .option("--json", "Emit machine-readable baseline metadata", false)
  .action(async (options) => {
    if (!validateMinSeverity(options.minSeverity)) {
      console.error(`Error: --min-severity must be one of: ${SEVERITY_ORDER.join(", ")}`);
      process.exit(1);
    }

    const targetPath = resolveTargetPath(options.path);
    if (!existsSync(targetPath)) {
      console.error(`Error: Path does not exist: ${targetPath}`);
      process.exit(1);
    }

    const { saveBaseline } = await import("./baseline/index.js");
    const result = scan(targetPath);
    const filteredResult = {
      ...result,
      findings: filterFindingsByMinSeverity(result.findings, options.minSeverity),
    };
    const report = calculateScore(filteredResult);
    const outputPath = resolve(options.output);

    saveBaseline(filteredResult.findings, report.score, outputPath);

    const metadata = {
      baselinePath: outputPath,
      targetPath,
      score: report.score.numericScore,
      grade: report.score.grade,
      findings: filteredResult.findings.length,
      minSeverity: options.minSeverity,
    };

    if (options.json) {
      console.log(JSON.stringify(metadata, null, 2));
      return;
    }

    console.log("\n  Baseline written\n");
    console.log(`  Target:   ${metadata.targetPath}`);
    console.log(`  Output:   ${metadata.baselinePath}`);
    console.log(`  Score:    ${metadata.score} (${metadata.grade})`);
    console.log(`  Findings: ${metadata.findings}`);
    console.log(`  Filter:   ${metadata.minSeverity}+\n`);
  });

// ─── Watch Command ───────────────────────────────────────

program
  .command("watch")
  .description("Continuously monitor config directories for security regressions")
  .option("-p, --path <path>", "Path to watch (default: ~/.claude or current dir)")
  .option("--debounce <ms>", "Debounce interval in milliseconds", "500")
  .option("--alert <mode>", "Alert mode: terminal, webhook, both", "terminal")
  .option("--webhook <url>", "Webhook URL for alerts")
  .option("--min-severity <severity>", "Minimum severity to track: critical, high, medium, low, info", "info")
  .option("--block", "Exit non-zero if critical findings detected (for CI integration)", false)
  .action((options) => {
    const targetPath = resolveTargetPath(options.path);

    if (!existsSync(targetPath)) {
      console.error(`Error: Path does not exist: ${targetPath}`);
      process.exit(1);
    }

    const debounceMs = parseInt(options.debounce, 10);
    if (isNaN(debounceMs) || debounceMs < 100) {
      console.error("Error: Debounce must be at least 100ms.");
      process.exit(1);
    }

    const alertMode = options.alert as AlertMode;
    if (!["terminal", "webhook", "both"].includes(alertMode)) {
      console.error("Error: Alert mode must be: terminal, webhook, or both.");
      process.exit(1);
    }

    if ((alertMode === "webhook" || alertMode === "both") && !options.webhook) {
      console.error("Error: --webhook URL required when alert mode is 'webhook' or 'both'.");
      process.exit(1);
    }

    const validSeverities = ["critical", "high", "medium", "low", "info"];
    if (!validSeverities.includes(options.minSeverity)) {
      console.error(`Error: --min-severity must be one of: ${validSeverities.join(", ")}`);
      process.exit(1);
    }

    console.log(`\n  AgentShield Watch Mode\n`);
    console.log(`  Watching:       ${targetPath}`);
    console.log(`  Debounce:       ${debounceMs}ms`);
    console.log(`  Alert mode:     ${alertMode}`);
    console.log(`  Min severity:   ${options.minSeverity}`);
    if (options.webhook) {
      console.log(`  Webhook:        ${options.webhook}`);
    }
    console.log(`\n  Performing initial scan to establish baseline...`);

    const homeClaude = resolve(
      process.env.HOME ?? process.env.USERPROFILE ?? ".",
      ".claude"
    );

    const watchPaths = [targetPath];
    if (existsSync(homeClaude) && homeClaude !== targetPath) {
      watchPaths.push(homeClaude);
      console.log(`  Also watching:  ${homeClaude}`);
    }

    const { stop, getState } = startWatcher({
      paths: watchPaths,
      debounceMs,
      alertMode,
      webhookUrl: options.webhook,
      minSeverity: options.minSeverity,
      blockOnCritical: options.block,
    });

    const state = getState();
    if (state.baseline) {
      console.log(`  Baseline score: ${state.baseline.score.numericScore} (${state.baseline.score.grade})`);
      console.log(`  Findings:       ${state.baseline.findings.length}`);
    }

    console.log(`\n  Watching for changes... (Press Ctrl+C to stop)\n`);

    const handleSignal = (): void => {
      console.log("\n  Stopping watch...\n");
      stop();
      process.exit(0);
    };

    process.on("SIGINT", handleSignal);
    process.on("SIGTERM", handleSignal);

    // If --block and initial scan has critical findings, exit immediately
    if (options.block && state.baseline) {
      const hasCritical = state.baseline.findings.some(
        (f) => f.severity === "critical"
      );
      if (hasCritical) {
        console.error("  BLOCKED: Critical findings detected in initial scan.");
        stop();
        process.exit(2);
      }
    }
  });

// ─── Runtime Commands ────────────────────────────────────

const runtime = program
  .command("runtime")
  .description("Runtime monitoring — PreToolUse hook for policy enforcement");

runtime
  .command("install")
  .description("Install the AgentShield PreToolUse hook into settings.json")
  .option("-p, --path <path>", "Target directory (default: current directory)", ".")
  .action((options) => {
    const result = installRuntime(resolve(options.path));

    console.log(`\n  AgentShield Runtime Monitor\n`);
    console.log(`  ${result.message}`);
    if (result.hookInstalled) {
      console.log(`  Settings: ${result.settingsPath}`);
    }
    if (result.policyCreated) {
      console.log(`  Policy:   ${result.policyPath}`);
      console.log(`\n  Edit the policy file to configure deny rules.`);
    }
    console.log();
  });

runtime
  .command("uninstall")
  .description("Remove the AgentShield PreToolUse hook from settings.json")
  .option("-p, --path <path>", "Target directory (default: current directory)", ".")
  .action((options) => {
    const result = uninstallRuntime(resolve(options.path));

    console.log(`\n  AgentShield Runtime Monitor\n`);
    console.log(`  ${result.message}\n`);
  });

runtime
  .command("status")
  .description("Inspect runtime hook, policy, and logging readiness")
  .option("-p, --path <path>", "Target directory (default: current directory)", ".")
  .option("--json", "Output status as JSON", false)
  .option("--check", "Exit non-zero when runtime monitor is not ready", false)
  .action((options) => {
    const result = getRuntimeStatus(resolve(options.path));

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(`\n  AgentShield Runtime Monitor\n`);
      console.log(`  Health:         ${result.health}`);
      console.log(`  Settings:       ${result.settingsPath}`);
      console.log(`  Settings file:  ${result.settingsExists ? "present" : "missing"}`);
      console.log(`  Settings valid: ${result.settingsValid ? "yes" : "no"}`);
      console.log(`  Hook installed: ${result.hookInstalled ? "yes" : "no"} (${result.hookCount})`);
      console.log(`  Policy:         ${result.policyPath}`);
      console.log(`  Policy file:    ${result.policyExists ? "present" : "missing"}`);
      console.log(`  Policy valid:   ${result.policyValid ? "yes" : "no"}`);
      console.log(`  Log path:       ${result.logPath}`);
      console.log(`  Log file:       ${result.logExists ? "present" : "missing"}`);
      console.log(`\n  ${result.message}\n`);
    }

    if (options.check) {
      process.exit(result.checkExitCode);
    }
  });

runtime
  .command("repair")
  .description("Back up invalid runtime files and restore a healthy monitor install")
  .option("-p, --path <path>", "Target directory (default: current directory)", ".")
  .action((options) => {
    const result = repairRuntime(resolve(options.path));
    const status = getRuntimeStatus(resolve(options.path));

    console.log(`\n  AgentShield Runtime Monitor\n`);
    console.log(`  ${result.message}`);
    if (result.settingsBackupPath) {
      console.log(`  Settings backup: ${result.settingsBackupPath}`);
    }
    if (result.policyBackupPath) {
      console.log(`  Policy backup:   ${result.policyBackupPath}`);
    }
    console.log(`  Health:          ${status.health}`);
    console.log(`  Settings:        ${result.settingsPath}`);
    console.log(`  Policy:          ${result.policyPath}\n`);

    if (!result.repaired) {
      process.exit(1);
    }
  });

// ─── Policy Commands ─────────────────────────────────────

const policyCmd = program
  .command("policy")
  .description("Organization-wide security policy management");

policyCmd
  .command("init")
  .description("Generate an example organization policy file")
  .option("-o, --output <path>", "Output path", ".agentshield/policy.json")
  .option("--pack <pack>", "Policy pack preset: oss, team, enterprise, regulated, high-risk-hooks-mcp, ci-enforcement", "enterprise")
  .option("--owner <owner>", "Policy owner identifier; repeat for multiple owners", collectOption, [])
  .option("--name <name>", "Policy display name")
  .action(async (options) => {
    const { generateExamplePolicy, listPolicyPacks, PolicyPackSchema } = await import("./policy/index.js");
    const outputPath = resolve(options.output);
    const packResult = PolicyPackSchema.safeParse(options.pack);

    if (existsSync(outputPath)) {
      console.error(`\n  Error: Policy file already exists at ${outputPath}\n`);
      process.exit(1);
    }

    if (!packResult.success) {
      const packs = listPolicyPacks()
        .map((pack) => pack.id)
        .join(", ");
      console.error(`\n  Error: Unknown policy pack "${options.pack}". Valid packs: ${packs}\n`);
      process.exit(1);
    }

    const dir = resolve(outputPath, "..");
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    writeFileSync(outputPath, generateExamplePolicy(packResult.data, {
      name: options.name,
      owners: options.owner,
    }));
    console.log(`\n  Example policy written to: ${outputPath}`);
    console.log(`  Policy pack: ${packResult.data}`);
    console.log(`  Edit the file to match your organization's requirements.`);
    console.log(`  Then run: agentshield scan --policy ${options.output}\n`);
  });

policyCmd
  .command("export")
  .description("Export policy pack JSON files with a checksum manifest")
  .option("-o, --output-dir <path>", "Output directory", ".agentshield/policies")
  .option("--pack <pack>", "Policy pack to export; repeat for multiple packs", collectOption, [])
  .option("--owner <owner>", "Policy owner identifier; repeat for multiple owners", collectOption, [])
  .option("--name-prefix <prefix>", "Prefix generated policy names")
  .option("--json", "Emit the export manifest as JSON", false)
  .action(async (options) => {
    const {
      exportPolicyPacks,
      listPolicyPacks,
      PolicyPackSchema,
    } = await import("./policy/index.js");
    const requestedPacks = options.pack as string[];
    const validPackIds = listPolicyPacks().map((pack) => pack.id);
    const packs = requestedPacks.length > 0
      ? requestedPacks.map((pack) => {
        const result = PolicyPackSchema.safeParse(pack);
        if (!result.success) {
          console.error(`\n  Error: Unknown policy pack "${pack}". Valid packs: ${validPackIds.join(", ")}\n`);
          process.exit(1);
        }
        return result.data;
      })
      : undefined;
    const outputDir = resolve(options.outputDir);
    const manifest = exportPolicyPacks({
      outputDir,
      packs,
      owners: options.owner,
      namePrefix: options.namePrefix,
    });

    if (options.json) {
      writeStdout(JSON.stringify(manifest, null, 2));
      return;
    }

    console.log(`\n  Policy bundle written to: ${outputDir}`);
    console.log(`  Manifest:       ${join(outputDir, "manifest.json")}`);
    console.log(`  Policies:       ${manifest.packs.length}`);
    for (const pack of manifest.packs) {
      console.log(`  - ${pack.id}: ${pack.file} (${pack.sha256})`);
    }
    if (manifest.packs[0]) {
      console.log(`  Then run: agentshield scan --policy ${join(options.outputDir, manifest.packs[0].file)}\n`);
    } else {
      console.log("");
    }
  });

// ─── MiniClaw Commands ───────────────────────────────────

const miniclaw = program
  .command("miniclaw")
  .description("MiniClaw — minimal secure sandboxed AI agent runtime");

miniclaw
  .command("start")
  .description("Start the MiniClaw server")
  .option("-p, --port <port>", "Port to listen on", "3847")
  .option("-H, --hostname <hostname>", "Hostname to bind to", "localhost")
  .option("--network <policy>", "Network policy: none, localhost, allowlist", "none")
  .option("--rate-limit <limit>", "Max requests per minute per IP", "10")
  .option("--sandbox-root <path>", "Root path for sandbox directories", "/tmp/miniclaw-sandboxes")
  .option("--max-duration <ms>", "Max session duration in milliseconds", "300000")
  .action((options) => {
    const port = parseInt(options.port, 10);
    const rateLimit = parseInt(options.rateLimit, 10);
    const maxDuration = parseInt(options.maxDuration, 10);

    if (isNaN(port) || port < 0 || port > 65535) {
      console.error("Error: Invalid port number. Must be between 0 and 65535.");
      process.exit(1);
    }

    if (isNaN(rateLimit) || rateLimit < 1) {
      console.error("Error: Invalid rate limit. Must be a positive integer.");
      process.exit(1);
    }

    const networkPolicy = options.network as "none" | "localhost" | "allowlist";
    if (!["none", "localhost", "allowlist"].includes(networkPolicy)) {
      console.error("Error: Invalid network policy. Must be: none, localhost, or allowlist.");
      process.exit(1);
    }

    console.log(`\n  MiniClaw — Secure Agent Runtime\n`);
    console.log(`  Starting server...`);
    console.log(`  Port:           ${port}`);
    console.log(`  Hostname:       ${options.hostname}`);
    console.log(`  Network policy: ${networkPolicy}`);
    console.log(`  Rate limit:     ${rateLimit} req/min`);
    console.log(`  Sandbox root:   ${options.sandboxRoot}`);
    console.log(`  Max duration:   ${maxDuration}ms\n`);

    const { server } = startMiniClaw({
      server: {
        port,
        hostname: options.hostname,
        corsOrigins: [
          `http://${options.hostname}:${port}`,
          "http://localhost:3000",
        ],
        rateLimit,
        maxRequestSize: 10_240,
      },
      sandbox: {
        rootPath: options.sandboxRoot,
        maxFileSize: 10_485_760,
        allowedExtensions: [
          ".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".txt",
          ".css", ".html", ".yaml", ".yml", ".toml", ".xml",
          ".csv", ".svg", ".env.example",
        ],
        networkPolicy,
        maxDuration,
      },
    });

    server.on("listening", () => {
      const address = server.address();
      const boundPort =
        address && typeof address === "object" && "port" in address
          ? address.port
          : port;
      console.log(`  Listening on http://${options.hostname}:${boundPort}`);
      console.log(`  Health check: http://${options.hostname}:${boundPort}/api/health`);
      console.log(`\n  Press Ctrl+C to stop.\n`);
    });

    server.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE") {
        console.error(`\n  Error: Port ${port} is already in use.`);
        console.error(`  Try a different port: agentshield miniclaw start --port 4000\n`);
      } else {
        console.error(`\n  Server error: ${err.message}\n`);
      }
      process.exit(1);
    });
  });

program.parse();

function resolveTargetPath(pathArg?: string): string {
  if (pathArg) {
    return resolve(pathArg);
  }

  // Try current directory's .claude/
  const localClaude = resolve(process.cwd(), ".claude");
  if (existsSync(localClaude)) {
    return localClaude;
  }

  // Try home directory's ~/.claude/
  const homeClaude = resolve(
    process.env.HOME ?? process.env.USERPROFILE ?? ".",
    ".claude"
  );
  if (existsSync(homeClaude)) {
    return homeClaude;
  }

  // Fall back to current directory
  return process.cwd();
}
