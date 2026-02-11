import chalk from "chalk";
import type { Finding, SecurityReport, Severity } from "../types.js";

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
