import type { SecurityReport } from "../types.js";

/**
 * Render a security report as formatted JSON.
 */
export function renderJsonReport(report: SecurityReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Render a security report as markdown.
 */
export function renderMarkdownReport(report: SecurityReport): string {
  const lines: string[] = [];
  const s = report.summary;

  lines.push("# AgentShield Security Report");
  lines.push("");
  lines.push(`**Date:** ${report.timestamp}`);
  lines.push(`**Target:** ${report.targetPath}`);
  lines.push(`**Grade:** ${report.score.grade} (${report.score.numericScore}/100)`);
  lines.push("");

  // Summary table
  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("|--------|-------|");
  lines.push(`| Files scanned | ${s.filesScanned} |`);
  lines.push(`| Total findings | ${s.totalFindings} |`);
  lines.push(`| Critical | ${s.critical} |`);
  lines.push(`| High | ${s.high} |`);
  lines.push(`| Medium | ${s.medium} |`);
  lines.push(`| Low | ${s.low} |`);
  lines.push(`| Info | ${s.info} |`);
  lines.push(`| Auto-fixable | ${s.autoFixable} |`);
  lines.push("");

  // Score breakdown (dynamically generated from breakdown keys)
  const categoryLabels: Record<string, string> = {
    secrets: "Secrets",
    permissions: "Permissions",
    hooks: "Hooks",
    mcp: "MCP Servers",
    agents: "Agents",
  };

  lines.push("## Score Breakdown");
  lines.push("");
  lines.push("| Category | Score |");
  lines.push("|----------|-------|");
  for (const [key, score] of Object.entries(report.score.breakdown)) {
    const label = categoryLabels[key] ?? key;
    lines.push(`| ${label} | ${score}/100 |`);
  }
  lines.push("");

  // Findings
  if (report.findings.length > 0) {
    lines.push("## Findings");
    lines.push("");

    for (const finding of report.findings) {
      const emoji =
        finding.severity === "critical"
          ? "🔴"
          : finding.severity === "high"
          ? "🟡"
          : finding.severity === "medium"
          ? "🔵"
          : "⚪";

      lines.push(`### ${emoji} ${finding.title}`);
      lines.push("");
      lines.push(`- **Severity:** ${finding.severity}`);
      lines.push(`- **Category:** ${finding.category}`);
      lines.push(`- **File:** \`${finding.file}${finding.line ? `:${finding.line}` : ""}\``);
      lines.push(`- **Description:** ${finding.description}`);

      if (finding.evidence) {
        lines.push(`- **Evidence:** \`${finding.evidence}\``);
      }

      if (finding.fix) {
        lines.push(`- **Fix:** ${finding.fix.description}`);
        if (finding.fix.auto) {
          lines.push("- **Auto-fixable:** Yes");
        }
      }

      lines.push("");
    }
  } else {
    lines.push("## No Issues Found");
    lines.push("");
    lines.push("No security issues were detected in the scanned configuration.");
  }

  return lines.join("\n");
}
