import chalk from "chalk";
import type {
  Finding,
  SecurityReport,
  Severity,
  InjectionSuiteResult,
  SandboxResult,
  TaintResult,
  CorpusValidationResult,
  DeepScanResult,
} from "../types.js";

/**
 * Render a security report to the terminal with colors and formatting.
 */
export function renderTerminalReport(report: SecurityReport): string {
  const lines: string[] = [];

  // Header
  lines.push("");
  lines.push(chalk.bold.cyan("  AgentShield Security Report"));
  lines.push(chalk.dim(`  ${report.timestamp}`));
  lines.push(chalk.dim(`  Target: ${report.targetPath}`));
  lines.push("");

  // Grade banner
  lines.push(renderGrade(report.score.grade, report.score.numericScore));
  lines.push("");

  // Score breakdown
  lines.push(chalk.bold("  Score Breakdown"));
  lines.push(renderBar("Secrets", report.score.breakdown.secrets));
  lines.push(renderBar("Permissions", report.score.breakdown.permissions));
  lines.push(renderBar("Hooks", report.score.breakdown.hooks));
  lines.push(renderBar("MCP Servers", report.score.breakdown.mcp));
  lines.push(renderBar("Agents", report.score.breakdown.agents));
  lines.push("");

  // Summary
  const s = report.summary;
  lines.push(chalk.bold("  Summary"));
  lines.push(`  Files scanned: ${s.filesScanned}`);
  lines.push(
    `  Findings: ${s.totalFindings} total — ` +
      `${chalk.red(`${s.critical} critical`)}, ` +
      `${chalk.yellow(`${s.high} high`)}, ` +
      `${chalk.blue(`${s.medium} medium`)}, ` +
      `${chalk.dim(`${s.low} low, ${s.info} info`)}`
  );
  if (s.autoFixable > 0) {
    lines.push(chalk.green(`  Auto-fixable: ${s.autoFixable} (use --fix)`));
  }
  lines.push("");

  // Findings grouped by severity
  if (report.findings.length > 0) {
    lines.push(chalk.bold("  Findings"));
    lines.push("");

    const grouped = groupBySeverity(report.findings);

    for (const [severity, findings] of grouped) {
      if (findings.length === 0) continue;

      lines.push(`  ${severityIcon(severity)} ${chalk.bold(severity.toUpperCase())} (${findings.length})`);
      lines.push("");

      for (const finding of findings) {
        lines.push(renderFinding(finding));
      }
    }
  } else {
    lines.push(chalk.green.bold("  No security issues found!"));
    lines.push("");
  }

  // Footer
  lines.push(chalk.dim("  ─────────────────────────────────────────"));
  lines.push(chalk.dim("  AgentShield — Security auditor for AI agent configs"));
  lines.push("");

  return lines.join("\n");
}

// ─── Injection Test Results ───────────────────────────────────

/**
 * Render prompt injection test results as a terminal table.
 */
export function renderInjectionResults(
  result: InjectionSuiteResult
): string {
  const lines: string[] = [];
  const divider = "━".repeat(56);

  lines.push("");
  lines.push(chalk.red(`  ┏${divider}┓`));
  lines.push(chalk.red(`  ┃  ${"Prompt Injection Testing".padEnd(divider.length - 2)}┃`));
  lines.push(chalk.red(`  ┃  ${"Active payload testing against config defenses".padEnd(divider.length - 2)}┃`));
  lines.push(chalk.red(`  ┗${divider}┛`));
  lines.push("");

  // Summary bar
  const blockRate = result.totalPayloads > 0
    ? Math.round((result.blocked / result.totalPayloads) * 100)
    : 0;
  const blockColor = blockRate >= 90 ? chalk.green : blockRate >= 70 ? chalk.yellow : chalk.red;

  lines.push(chalk.bold("  Injection Test Summary"));
  lines.push(`  Total payloads: ${result.totalPayloads}`);
  lines.push(`  Blocked:        ${blockColor(`${result.blocked}`)}`);
  lines.push(`  Bypassed:       ${result.bypassed > 0 ? chalk.red.bold(`${result.bypassed}`) : chalk.green("0")}`);
  lines.push(`  Block rate:     ${blockColor(`${blockRate}%`)}`);
  lines.push("");

  // Results table
  if (result.results.length > 0) {
    lines.push(chalk.bold("  Payload Results"));
    lines.push("");

    // Header
    const statusCol = "Status".padEnd(9);
    const categoryCol = "Category".padEnd(20);
    const payloadCol = "Payload";
    lines.push(chalk.dim(`    ${statusCol} ${categoryCol} ${payloadCol}`));
    lines.push(chalk.dim(`    ${"─".repeat(9)} ${"─".repeat(20)} ${"─".repeat(30)}`));

    for (const test of result.results) {
      const status = test.blocked
        ? chalk.green("BLOCKED")
        : chalk.red.bold("BYPASS ");
      const category = test.category.padEnd(20);
      const payload = test.payload.length > 40
        ? test.payload.substring(0, 37) + "..."
        : test.payload;

      lines.push(`    ${status}  ${chalk.dim(category)} ${payload}`);
    }

    lines.push("");
  }

  // Show bypassed details
  const bypassed = result.results.filter((r) => !r.blocked);
  if (bypassed.length > 0) {
    lines.push(chalk.red.bold("  Bypassed Payloads (require attention)"));
    lines.push("");
    for (const test of bypassed) {
      lines.push(chalk.red(`    ● ${test.payload}`));
      lines.push(chalk.dim(`      Category: ${test.category}`));
      lines.push(chalk.dim(`      Details: ${test.details}`));
      lines.push("");
    }
  }

  return lines.join("\n");
}

// ─── Sandbox Execution Results ────────────────────────────────

/**
 * Render sandbox hook execution results.
 */
export function renderSandboxResults(result: SandboxResult): string {
  const lines: string[] = [];
  const divider = "━".repeat(56);

  lines.push("");
  lines.push(chalk.magenta(`  ┏${divider}┓`));
  lines.push(chalk.magenta(`  ┃  ${"Sandbox Hook Execution".padEnd(divider.length - 2)}┃`));
  lines.push(chalk.magenta(`  ┃  ${"Behavioral analysis of hook commands".padEnd(divider.length - 2)}┃`));
  lines.push(chalk.magenta(`  ┗${divider}┛`));
  lines.push("");

  lines.push(chalk.bold("  Sandbox Summary"));
  lines.push(`  Hooks executed: ${result.hooksExecuted}`);
  lines.push(
    `  Risk findings:  ${result.riskFindings.length > 0 ? chalk.red(`${result.riskFindings.length}`) : chalk.green("0")}`
  );
  lines.push("");

  // Behavioral analysis for each hook
  if (result.behaviors.length > 0) {
    lines.push(chalk.bold("  Hook Behaviors"));
    lines.push("");

    for (const behavior of result.behaviors) {
      const exitIcon = behavior.exitCode === 0 ? chalk.green("✓") : chalk.red("✗");
      lines.push(`  ${exitIcon} ${chalk.bold(behavior.hookId)}`);
      lines.push(chalk.dim(`    Command: ${behavior.hookCommand}`));
      lines.push(chalk.dim(`    Exit code: ${behavior.exitCode}`));

      if (behavior.networkAttempts.length > 0) {
        lines.push(chalk.yellow(`    Network attempts: ${behavior.networkAttempts.length}`));
        for (const attempt of behavior.networkAttempts) {
          lines.push(chalk.yellow(`      → ${attempt}`));
        }
      }

      if (behavior.fileAccesses.length > 0) {
        lines.push(chalk.blue(`    File accesses: ${behavior.fileAccesses.length}`));
        for (const access of behavior.fileAccesses.slice(0, 5)) {
          lines.push(chalk.dim(`      → ${access}`));
        }
        if (behavior.fileAccesses.length > 5) {
          lines.push(chalk.dim(`      ... and ${behavior.fileAccesses.length - 5} more`));
        }
      }

      if (behavior.suspiciousBehaviors.length > 0) {
        lines.push(chalk.red.bold(`    Suspicious behaviors:`));
        for (const suspicious of behavior.suspiciousBehaviors) {
          lines.push(chalk.red(`      ● ${suspicious}`));
        }
      }

      lines.push("");
    }
  }

  // Risk findings
  if (result.riskFindings.length > 0) {
    lines.push(chalk.red.bold("  Sandbox Risk Findings"));
    lines.push("");
    for (const finding of result.riskFindings) {
      lines.push(renderFinding(finding));
    }
  }

  return lines.join("\n");
}

// ─── Taint Analysis Results ───────────────────────────────────

/**
 * Render taint flow analysis as source → sink visualization.
 */
export function renderTaintResults(result: TaintResult): string {
  const lines: string[] = [];
  const divider = "━".repeat(56);

  lines.push("");
  lines.push(chalk.yellow(`  ┏${divider}┓`));
  lines.push(chalk.yellow(`  ┃  ${"Taint Analysis — Data Flow Tracking".padEnd(divider.length - 2)}┃`));
  lines.push(chalk.yellow(`  ┃  ${"Tracking untrusted inputs to dangerous sinks".padEnd(divider.length - 2)}┃`));
  lines.push(chalk.yellow(`  ┗${divider}┛`));
  lines.push("");

  lines.push(chalk.bold("  Taint Summary"));
  lines.push(`  Sources (untrusted inputs): ${result.sources.length}`);
  lines.push(`  Sinks (dangerous outputs):  ${result.sinks.length}`);
  lines.push(
    `  Tainted flows:              ${result.flows.length > 0 ? chalk.red(`${result.flows.length}`) : chalk.green("0")}`
  );
  lines.push("");

  // Source listing
  if (result.sources.length > 0) {
    lines.push(chalk.bold("  Sources"));
    for (const source of result.sources) {
      const loc = source.line
        ? chalk.dim(`${source.file}:${source.line}`)
        : chalk.dim(source.file);
      lines.push(`    ${chalk.yellow("◆")} ${source.label} ${loc}`);
    }
    lines.push("");
  }

  // Sink listing
  if (result.sinks.length > 0) {
    lines.push(chalk.bold("  Sinks"));
    for (const sink of result.sinks) {
      const loc = sink.line
        ? chalk.dim(`${sink.file}:${sink.line}`)
        : chalk.dim(sink.file);
      lines.push(`    ${chalk.red("▼")} ${sink.label} ${loc}`);
    }
    lines.push("");
  }

  // Flow visualization
  if (result.flows.length > 0) {
    lines.push(chalk.bold("  Tainted Flows"));
    lines.push("");

    for (const flow of result.flows) {
      const icon = severityIcon(flow.severity);
      lines.push(`  ${icon} ${chalk.bold(flow.description)}`);
      lines.push("");

      // Source
      const sourceLoc = flow.source.line
        ? `${flow.source.file}:${flow.source.line}`
        : flow.source.file;
      lines.push(chalk.yellow(`    ◆ SOURCE: ${flow.source.label}`));
      lines.push(chalk.dim(`      ${sourceLoc}`));

      // Path steps
      for (const step of flow.path) {
        lines.push(chalk.dim(`      │`));
        lines.push(chalk.dim(`      ├─ ${step}`));
      }

      // Sink
      const sinkLoc = flow.sink.line
        ? `${flow.sink.file}:${flow.sink.line}`
        : flow.sink.file;
      lines.push(chalk.dim(`      │`));
      lines.push(chalk.red(`    ▼ SINK: ${flow.sink.label}`));
      lines.push(chalk.dim(`      ${sinkLoc}`));
      lines.push("");
    }
  }

  return lines.join("\n");
}

// ─── Corpus Validation Results ────────────────────────────────

/**
 * Render corpus validation results (scanner accuracy testing).
 */
export function renderCorpusResults(
  result: CorpusValidationResult
): string {
  const lines: string[] = [];
  const divider = "━".repeat(56);

  lines.push("");
  lines.push(chalk.cyan(`  ┏${divider}┓`));
  lines.push(chalk.cyan(`  ┃  ${"Corpus Validation — Scanner Accuracy".padEnd(divider.length - 2)}┃`));
  lines.push(chalk.cyan(`  ┃  ${"Testing scanner against known attack patterns".padEnd(divider.length - 2)}┃`));
  lines.push(chalk.cyan(`  ┗${divider}┛`));
  lines.push("");

  const rate = (result.detectionRate * 100).toFixed(1);
  const rateColor = result.detectionRate >= 0.95 ? chalk.green
    : result.detectionRate >= 0.80 ? chalk.yellow
    : chalk.red;

  lines.push(chalk.bold("  Corpus Summary"));
  lines.push(`  Total attacks:   ${result.totalAttacks}`);
  lines.push(`  Detected:        ${chalk.green(`${result.detected}`)}`);
  lines.push(`  Missed:          ${result.missed > 0 ? chalk.red(`${result.missed}`) : chalk.green("0")}`);
  lines.push(`  Detection rate:  ${rateColor(`${rate}%`)}`);
  lines.push("");

  // Detection rate bar
  lines.push(renderBar("Detection", Math.round(result.detectionRate * 100)));
  lines.push("");

  // Show missed attacks (these need attention)
  const missed = result.results.filter((r) => !r.detected);
  if (missed.length > 0) {
    lines.push(chalk.red.bold("  Missed Attacks (scanner gaps)"));
    lines.push("");
    for (const miss of missed) {
      lines.push(chalk.red(`    ● ${miss.attackName}`));
      lines.push(chalk.dim(`      ID: ${miss.attackId}`));
    }
    lines.push("");
  }

  return lines.join("\n");
}

// ─── Deep Scan Summary ────────────────────────────────────────

/**
 * Render a summary of all analysis phases for --deep mode.
 */
export function renderDeepScanSummary(result: DeepScanResult): string {
  const lines: string[] = [];
  const divider = "═".repeat(56);

  lines.push("");
  lines.push(chalk.bold.cyan(`  ╔${divider}╗`));
  lines.push(chalk.bold.cyan(`  ║  ${"Deep Scan Summary — All Analysis Layers".padEnd(divider.length - 2)}║`));
  lines.push(chalk.bold.cyan(`  ╚${divider}╝`));
  lines.push("");

  // Static analysis
  const grade = result.staticAnalysis.score.grade;
  const gradeColor = grade === "A" || grade === "B" ? chalk.green
    : grade === "C" ? chalk.yellow
    : chalk.red;
  lines.push(`  ${chalk.bold("1. Static Analysis")}     ${gradeColor(`Grade: ${grade} (${result.staticAnalysis.score.numericScore}/100)`)}`);
  lines.push(chalk.dim(`     ${result.staticAnalysis.findings.length} findings from 118 rules`));

  // Taint analysis
  if (result.taintAnalysis) {
    const flowCount = result.taintAnalysis.flows.length;
    const flowColor = flowCount > 0 ? chalk.red : chalk.green;
    lines.push(`  ${chalk.bold("2. Taint Analysis")}      ${flowColor(`${flowCount} tainted flows`)}`);
    lines.push(chalk.dim(`     ${result.taintAnalysis.sources.length} sources, ${result.taintAnalysis.sinks.length} sinks`));
  } else {
    lines.push(`  ${chalk.bold("2. Taint Analysis")}      ${chalk.dim("not available")}`);
  }

  // Injection testing
  if (result.injectionTests) {
    const blockRate = result.injectionTests.totalPayloads > 0
      ? Math.round((result.injectionTests.blocked / result.injectionTests.totalPayloads) * 100)
      : 0;
    const blockColor = blockRate >= 90 ? chalk.green : blockRate >= 70 ? chalk.yellow : chalk.red;
    lines.push(`  ${chalk.bold("3. Injection Testing")}   ${blockColor(`${blockRate}% blocked`)} (${result.injectionTests.blocked}/${result.injectionTests.totalPayloads})`);
    if (result.injectionTests.bypassed > 0) {
      lines.push(chalk.red(`     ${result.injectionTests.bypassed} payloads bypassed defenses`));
    }
  } else {
    lines.push(`  ${chalk.bold("3. Injection Testing")}   ${chalk.dim("not available")}`);
  }

  // Sandbox
  if (result.sandboxResults) {
    const riskCount = result.sandboxResults.riskFindings.length;
    const riskColor = riskCount > 0 ? chalk.red : chalk.green;
    lines.push(`  ${chalk.bold("4. Sandbox Execution")}   ${riskColor(`${riskCount} risks`)} from ${result.sandboxResults.hooksExecuted} hooks`);
  } else {
    lines.push(`  ${chalk.bold("4. Sandbox Execution")}   ${chalk.dim("not available")}`);
  }

  // Opus
  if (result.opusAnalysis) {
    const riskColor = result.opusAnalysis.auditor.riskLevel === "critical" ? chalk.red
      : result.opusAnalysis.auditor.riskLevel === "high" ? chalk.yellow
      : chalk.green;
    lines.push(`  ${chalk.bold("5. Opus Pipeline")}       ${riskColor(`Risk: ${result.opusAnalysis.auditor.riskLevel.toUpperCase()}`)} (${result.opusAnalysis.auditor.score}/100)`);
  } else {
    lines.push(`  ${chalk.bold("5. Opus Pipeline")}       ${chalk.dim("not available (set ANTHROPIC_API_KEY)")}`);
  }

  lines.push("");
  lines.push(chalk.dim("  ─────────────────────────────────────────"));
  lines.push(chalk.bold.cyan("  AgentShield Deep Scan Complete"));
  lines.push("");

  return lines.join("\n");
}

// ─── Internal Helpers ─────────────────────────────────────────

function renderGrade(grade: string, score: number): string {
  const gradeColors: Record<string, typeof chalk.green> = {
    A: chalk.green,
    B: chalk.green,
    C: chalk.yellow,
    D: chalk.red,
    F: chalk.red.bold,
  };

  const colorFn = gradeColors[grade] ?? chalk.white;
  const gradeDisplay = colorFn.bold(`  Grade: ${grade}`);
  const scoreDisplay = colorFn(` (${score}/100)`);

  return `${gradeDisplay}${scoreDisplay}`;
}

function renderBar(label: string, score: number): string {
  const width = 20;
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;

  let colorFn: typeof chalk.green;
  if (score >= 80) colorFn = chalk.green;
  else if (score >= 60) colorFn = chalk.yellow;
  else colorFn = chalk.red;

  const bar = colorFn("█".repeat(filled)) + chalk.dim("░".repeat(empty));
  const paddedLabel = label.padEnd(14);

  return `  ${paddedLabel} ${bar} ${score}`;
}

function severityIcon(severity: Severity): string {
  const icons: Record<Severity, string> = {
    critical: chalk.red("●"),
    high: chalk.yellow("●"),
    medium: chalk.blue("●"),
    low: chalk.dim("●"),
    info: chalk.dim("○"),
  };
  return icons[severity] ?? "○";
}

function renderFinding(finding: Finding): string {
  const lines: string[] = [];
  const icon = severityIcon(finding.severity);
  const location = finding.line
    ? chalk.dim(`${finding.file}:${finding.line}`)
    : chalk.dim(finding.file);

  lines.push(`    ${icon} ${finding.title}`);
  lines.push(`      ${location}`);
  lines.push(`      ${chalk.dim(finding.description)}`);

  if (finding.evidence) {
    lines.push(`      Evidence: ${chalk.yellow(finding.evidence)}`);
  }

  if (finding.fix) {
    lines.push(
      `      Fix: ${chalk.green(finding.fix.description)}` +
        (finding.fix.auto ? chalk.green(" [auto-fixable]") : "")
    );
  }

  lines.push("");
  return lines.join("\n");
}

function groupBySeverity(
  findings: ReadonlyArray<Finding>
): Array<[Severity, ReadonlyArray<Finding>]> {
  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
  return severities.map((s) => [s, findings.filter((f) => f.severity === s)]);
}
