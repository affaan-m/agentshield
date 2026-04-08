#!/usr/bin/env node

import { Command } from "commander";
import { resolve } from "node:path";
import { existsSync, writeFileSync, appendFileSync, mkdirSync } from "node:fs";
import { scan } from "./scanner/index.js";
import { calculateScore } from "./reporter/score.js";
import { renderTerminalReport } from "./reporter/terminal.js";
import { renderJsonReport, renderMarkdownReport } from "./reporter/json.js";
import { renderHtmlReport } from "./reporter/html.js";
import { runOpusPipeline, renderOpusAnalysis } from "./opus/index.js";
import { applyFixes, renderFixSummary } from "./fixer/index.js";
import { runInit, renderInitSummary } from "./init/index.js";
import { startMiniClaw } from "./miniclaw/index.js";
import { startWatcher } from "./watch/index.js";
import type { AlertMode } from "./watch/types.js";
import { getRuntimeStatus, installRuntime, uninstallRuntime } from "./runtime/index.js";
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

program
  .name("agentshield")
  .description("Security auditor for AI agent configurations")
  .version("1.4.0");

program
  .command("scan")
  .description("Scan a Claude Code configuration directory for security issues")
  .option("-p, --path <path>", "Path to scan (default: ~/.claude or current dir)")
  .option("-f, --format <format>", "Output format: terminal, json, markdown, html", "terminal")
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
  .option("--baseline <path>", "Compare against a baseline file and report regressions")
  .option("--save-baseline <path>", "Save current scan results as a baseline file")
  .option("--gate", "Fail if new critical/high findings or score drops (use with --baseline)", false)
  .option("--supply-chain", "Verify MCP npm packages against known-bad list and typosquatting", false)
  .option("--supply-chain-online", "Also query npm registry for metadata (requires network)", false)
  .option("--policy <path>", "Validate against an organization policy file")
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
    const severityOrder = ["critical", "high", "medium", "low", "info"];
    const minIndex = severityOrder.indexOf(options.minSeverity);
    const filteredResult = {
      ...result,
      findings: result.findings.filter(
        (f) => severityOrder.indexOf(f.severity) <= minIndex
      ),
    };

    // Generate report
    const report = calculateScore(filteredResult);
    logger.log({
      level: "info",
      phase: "static",
      message: `Static analysis complete: ${report.summary.totalFindings} findings`,
      data: { grade: report.score.grade, score: report.score.numericScore },
    });

    // Output static scan
    switch (options.format) {
      case "json":
        console.log(renderJsonReport(report));
        break;
      case "markdown":
        console.log(renderMarkdownReport(report));
        break;
      case "html":
        console.log(renderHtmlReport(report));
        break;
      default:
        console.log(renderTerminalReport(report));
    }

    // ── Phase 1b: Baseline save/compare ───────────────────
    if (options.saveBaseline) {
      const { saveBaseline } = await import("./baseline/index.js");
      saveBaseline(filteredResult.findings, report.score, options.saveBaseline);
      console.log(`\n  Baseline saved to: ${options.saveBaseline}\n`);
      logger.log({ level: "info", phase: "baseline", message: `Baseline saved to ${options.saveBaseline}` });
    }

    if (options.baseline) {
      const { loadBaseline, compareBaseline, evaluateGate, renderComparison, renderGateResult } =
        await import("./baseline/index.js");
      const baseline = loadBaseline(options.baseline);
      if (!baseline) {
        console.error(`\n  Error: Could not load baseline from ${options.baseline}\n`);
      } else {
        const comparison = compareBaseline(baseline, filteredResult.findings, report.score);
        console.log(renderComparison(comparison));
        logger.log({
          level: comparison.isRegression ? "warn" : "info",
          phase: "baseline",
          message: `Baseline comparison: ${comparison.newFindings.length} new, ${comparison.resolvedFindings.length} resolved, score delta ${comparison.scoreDelta}`,
        });

        if (options.gate) {
          const gateResult = evaluateGate(comparison);
          console.log(renderGateResult(gateResult));
          if (!gateResult.passed) {
            logger.log({ level: "error", phase: "gate", message: `Gate FAILED: ${gateResult.reasons.join("; ")}` });
            process.exit(3);
          }
        }
      }
    }

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

        const evaluation = evaluatePolicy(
          policyResult.policy,
          filteredResult.findings,
          report.score,
          result.target.files
        );
        console.log(renderPolicyEvaluation(evaluation));
        logger.log({
          level: evaluation.passed ? "info" : "warn",
          phase: "policy",
          message: `Policy "${evaluation.policyName}": ${evaluation.passed ? "COMPLIANT" : `NON-COMPLIANT (${evaluation.violations.length} violations)`}`,
        });
        if (!evaluation.passed) {
          process.exit(4);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`  Policy evaluation failed: ${message}`);
        logger.log({ level: "error", phase: "policy", message: `Failed: ${message}` });
        process.exit(4);
      }
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
    if (options.corpus) {
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
      }
    }

    // ── Phase 8: Supply chain verification ─────────────────
    if (options.supplyChain || options.supplyChainOnline) {
      logger.log({ level: "info", phase: "supply-chain", message: "Running supply chain verification" });
      try {
        const { extractPackages, verifyPackages, renderSupplyChainReport } =
          await import("./supply-chain/index.js");
        const packages = extractPackages(result.target.files);
        const scReport = await verifyPackages(packages, {
          online: options.supplyChainOnline,
        });
        if (options.format === "terminal") {
          // Preserve machine-readable stdout for json/markdown/html scans.
          console.log(renderSupplyChainReport(scReport));
        }
        logger.log({
          level: scReport.criticalCount > 0 ? "error" : scReport.highCount > 0 ? "warn" : "info",
          phase: "supply-chain",
          message: `Supply chain: ${scReport.riskyPackages}/${scReport.totalPackages} risky packages`,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`  Supply chain verification failed: ${message}`);
        logger.log({ level: "error", phase: "supply-chain", message: `Failed: ${message}` });
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

// ─── Policy Commands ─────────────────────────────────────

const policyCmd = program
  .command("policy")
  .description("Organization-wide security policy management");

policyCmd
  .command("init")
  .description("Generate an example organization policy file")
  .option("-o, --output <path>", "Output path", ".agentshield/policy.json")
  .action(async (options) => {
    const { generateExamplePolicy } = await import("./policy/index.js");
    const outputPath = resolve(options.output);

    if (existsSync(outputPath)) {
      console.error(`\n  Error: Policy file already exists at ${outputPath}\n`);
      process.exit(1);
    }

    const dir = resolve(outputPath, "..");
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    writeFileSync(outputPath, generateExamplePolicy());
    console.log(`\n  Example policy written to: ${outputPath}`);
    console.log(`  Edit the file to match your organization's requirements.`);
    console.log(`  Then run: agentshield scan --policy ${options.output}\n`);
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
