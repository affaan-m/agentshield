#!/usr/bin/env node
import {
  calculateScore,
  renderJsonReport,
  renderMarkdownReport,
  scan
} from "./chunk-WUGVJZVL.js";
import {
  startMiniClaw
} from "./chunk-GH4JN4Y3.js";

// src/index.ts
import { Command } from "commander";
import { resolve as resolve3 } from "path";
import { existsSync as existsSync2 } from "fs";

// src/reporter/terminal.ts
import chalk from "chalk";
function renderTerminalReport(report) {
  const lines = [];
  lines.push("");
  lines.push(chalk.bold.cyan("  AgentShield Security Report"));
  lines.push(chalk.dim(`  ${report.timestamp}`));
  lines.push(chalk.dim(`  Target: ${report.targetPath}`));
  lines.push("");
  lines.push(renderGrade(report.score.grade, report.score.numericScore));
  lines.push("");
  lines.push(chalk.bold("  Score Breakdown"));
  lines.push(renderBar("Secrets", report.score.breakdown.secrets));
  lines.push(renderBar("Permissions", report.score.breakdown.permissions));
  lines.push(renderBar("Hooks", report.score.breakdown.hooks));
  lines.push(renderBar("MCP Servers", report.score.breakdown.mcp));
  lines.push(renderBar("Agents", report.score.breakdown.agents));
  lines.push("");
  const s = report.summary;
  lines.push(chalk.bold("  Summary"));
  lines.push(`  Files scanned: ${s.filesScanned}`);
  lines.push(
    `  Findings: ${s.totalFindings} total \u2014 ${chalk.red(`${s.critical} critical`)}, ${chalk.yellow(`${s.high} high`)}, ${chalk.blue(`${s.medium} medium`)}, ${chalk.dim(`${s.low} low, ${s.info} info`)}`
  );
  if (s.autoFixable > 0) {
    lines.push(chalk.green(`  Auto-fixable: ${s.autoFixable} (use --fix)`));
  }
  lines.push("");
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
  lines.push(chalk.dim("  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"));
  lines.push(chalk.dim("  AgentShield \u2014 Security auditor for AI agent configs"));
  lines.push("");
  return lines.join("\n");
}
function renderGrade(grade, score) {
  const gradeColors = {
    A: chalk.green,
    B: chalk.green,
    C: chalk.yellow,
    D: chalk.red,
    F: chalk.red.bold
  };
  const colorFn = gradeColors[grade] ?? chalk.white;
  const gradeDisplay = colorFn.bold(`  Grade: ${grade}`);
  const scoreDisplay = colorFn(` (${score}/100)`);
  return `${gradeDisplay}${scoreDisplay}`;
}
function renderBar(label, score) {
  const width = 20;
  const filled = Math.round(score / 100 * width);
  const empty = width - filled;
  let colorFn;
  if (score >= 80) colorFn = chalk.green;
  else if (score >= 60) colorFn = chalk.yellow;
  else colorFn = chalk.red;
  const bar = colorFn("\u2588".repeat(filled)) + chalk.dim("\u2591".repeat(empty));
  const paddedLabel = label.padEnd(14);
  return `  ${paddedLabel} ${bar} ${score}`;
}
function severityIcon(severity) {
  const icons = {
    critical: chalk.red("\u25CF"),
    high: chalk.yellow("\u25CF"),
    medium: chalk.blue("\u25CF"),
    low: chalk.dim("\u25CF"),
    info: chalk.dim("\u25CB")
  };
  return icons[severity] ?? "\u25CB";
}
function renderFinding(finding) {
  const lines = [];
  const icon = severityIcon(finding.severity);
  const location = finding.line ? chalk.dim(`${finding.file}:${finding.line}`) : chalk.dim(finding.file);
  lines.push(`    ${icon} ${finding.title}`);
  lines.push(`      ${location}`);
  lines.push(`      ${chalk.dim(finding.description)}`);
  if (finding.evidence) {
    lines.push(`      Evidence: ${chalk.yellow(finding.evidence)}`);
  }
  if (finding.fix) {
    lines.push(
      `      Fix: ${chalk.green(finding.fix.description)}` + (finding.fix.auto ? chalk.green(" [auto-fixable]") : "")
    );
  }
  lines.push("");
  return lines.join("\n");
}
function groupBySeverity(findings) {
  const severities = ["critical", "high", "medium", "low", "info"];
  return severities.map((s) => [s, findings.filter((f) => f.severity === s)]);
}

// src/reporter/html.ts
function renderHtmlReport(report) {
  const gradeMeta = gradeMetadata(report.score.grade);
  const findings = [...report.findings];
  const s = report.summary;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AgentShield Security Report \u2014 Grade ${report.score.grade}</title>
  <style>${inlineStyles()}</style>
</head>
<body>
  <div class="container">

    <!-- Header -->
    <header class="header">
      <div class="header-content">
        <div class="grade-badge" style="background-color: ${gradeMeta.color};">
          <span class="grade-letter">${report.score.grade}</span>
        </div>
        <div class="header-info">
          <h1 class="title">AgentShield Security Report</h1>
          <p class="subtitle">Score: <strong>${report.score.numericScore}</strong>/100</p>
          <p class="meta">Target: ${escapeHtml(report.targetPath)}</p>
          <p class="meta">Scanned: ${formatTimestamp(report.timestamp)}</p>
        </div>
      </div>
    </header>

    <!-- Summary Stats -->
    <section class="section">
      <h2 class="section-title">Summary</h2>
      <div class="stats-grid">
        ${renderStatCard("Files Scanned", String(s.filesScanned), "files")}
        ${renderStatCard("Total Findings", String(s.totalFindings), "findings")}
        ${renderStatCard("Auto-Fixable", String(s.autoFixable), "fixable")}
        ${renderStatCard("Critical", String(s.critical), "critical")}
        ${renderStatCard("High", String(s.high), "high")}
        ${renderStatCard("Medium", String(s.medium), "medium")}
        ${renderStatCard("Low", String(s.low), "low")}
        ${renderStatCard("Info", String(s.info), "info")}
      </div>
    </section>

    <!-- Score Breakdown -->
    <section class="section">
      <h2 class="section-title">Score Breakdown</h2>
      <div class="breakdown">
        ${renderScoreBar("Secrets", report.score.breakdown.secrets)}
        ${renderScoreBar("Permissions", report.score.breakdown.permissions)}
        ${renderScoreBar("Hooks", report.score.breakdown.hooks)}
        ${renderScoreBar("MCP Servers", report.score.breakdown.mcp)}
        ${renderScoreBar("Agents", report.score.breakdown.agents)}
      </div>
    </section>

    <!-- Severity Distribution -->
    <section class="section">
      <h2 class="section-title">Severity Distribution</h2>
      <div class="distribution">
        ${renderDistributionChart(s)}
      </div>
    </section>

    <!-- Findings -->
    <section class="section">
      <h2 class="section-title">Findings</h2>
      ${findings.length === 0 ? '<div class="no-findings"><p>No security issues found. Your configuration looks good!</p></div>' : renderFindingsGrouped(findings)}
    </section>

    <!-- Footer -->
    <footer class="footer">
      <p>Generated by <strong>AgentShield</strong> &mdash; Security auditor for AI agent configurations</p>
      <p class="footer-timestamp">${formatTimestamp(report.timestamp)}</p>
    </footer>

  </div>
</body>
</html>`;
}
function gradeMetadata(grade) {
  const map = {
    A: { color: "#2ea043", label: "Excellent" },
    B: { color: "#388bfd", label: "Good" },
    C: { color: "#d29922", label: "Fair" },
    D: { color: "#db6d28", label: "Poor" },
    F: { color: "#f85149", label: "Critical" }
  };
  return map[grade];
}
function severityColor(severity) {
  const colors = {
    critical: "#f85149",
    high: "#d29922",
    medium: "#388bfd",
    low: "#8b949e",
    info: "#6e7681"
  };
  return colors[severity];
}
function scoreBarColor(score) {
  if (score >= 80) return "#2ea043";
  if (score >= 60) return "#d29922";
  return "#f85149";
}
function renderScoreBar(label, score) {
  const color = scoreBarColor(score);
  const pct = Math.max(0, Math.min(100, score));
  return `
    <div class="bar-row">
      <span class="bar-label">${escapeHtml(label)}</span>
      <div class="bar-track">
        <div class="bar-fill" style="width: ${pct}%; background-color: ${color};"></div>
      </div>
      <span class="bar-value" style="color: ${color};">${score}/100</span>
    </div>`;
}
function renderStatCard(label, value, kind) {
  const kindColorMap = {
    files: "#8b949e",
    findings: "#e6edf3",
    fixable: "#2ea043",
    critical: "#f85149",
    high: "#d29922",
    medium: "#388bfd",
    low: "#8b949e",
    info: "#6e7681"
  };
  const color = kindColorMap[kind] ?? "#e6edf3";
  return `
    <div class="stat-card">
      <div class="stat-value" style="color: ${color};">${escapeHtml(value)}</div>
      <div class="stat-label">${escapeHtml(label)}</div>
    </div>`;
}
function renderDistributionChart(summary) {
  const segments = [
    { label: "Critical", count: summary.critical, color: "#f85149" },
    { label: "High", count: summary.high, color: "#d29922" },
    { label: "Medium", count: summary.medium, color: "#388bfd" },
    { label: "Low", count: summary.low, color: "#8b949e" },
    { label: "Info", count: summary.info, color: "#6e7681" }
  ];
  const total = segments.reduce((acc, seg) => acc + seg.count, 0);
  if (total === 0) {
    return '<p class="no-findings-text">No findings to display.</p>';
  }
  const barWidth = 600;
  const barHeight = 32;
  let xOffset = 0;
  const rects = segments.map((seg) => {
    const width = total > 0 ? seg.count / total * barWidth : 0;
    const rect = width > 0 ? `<rect x="${xOffset}" y="0" width="${width}" height="${barHeight}" fill="${seg.color}" rx="0" />` : "";
    xOffset += width;
    return rect;
  });
  const legend = segments.filter((seg) => seg.count > 0).map(
    (seg) => `<span class="legend-item"><span class="legend-dot" style="background-color: ${seg.color};"></span>${escapeHtml(seg.label)}: ${seg.count}</span>`
  ).join("");
  return `
    <svg class="dist-bar" viewBox="0 0 ${barWidth} ${barHeight}" preserveAspectRatio="none">
      <rect x="0" y="0" width="${barWidth}" height="${barHeight}" fill="#21262d" rx="6" />
      <clipPath id="bar-clip"><rect x="0" y="0" width="${barWidth}" height="${barHeight}" rx="6" /></clipPath>
      <g clip-path="url(#bar-clip)">${rects.join("")}</g>
    </svg>
    <div class="legend">${legend}</div>`;
}
function renderFindingsGrouped(findings) {
  const severities = ["critical", "high", "medium", "low", "info"];
  const grouped = severities.map(
    (sev) => [sev, findings.filter((f) => f.severity === sev)]
  );
  return grouped.filter(([, items]) => items.length > 0).map(([sev, items]) => {
    const color = severityColor(sev);
    const cards = items.map((f) => renderFindingCard(f)).join("");
    return `
        <div class="findings-group">
          <h3 class="group-header" style="color: ${color};">
            <span class="severity-dot" style="background-color: ${color};"></span>
            ${sev.toUpperCase()} (${items.length})
          </h3>
          ${cards}
        </div>`;
  }).join("");
}
function renderFindingCard(finding) {
  const color = severityColor(finding.severity);
  const location = finding.line ? `${escapeHtml(finding.file)}:${finding.line}` : escapeHtml(finding.file);
  const evidenceBlock = finding.evidence ? `<div class="finding-evidence"><strong>Evidence:</strong><pre><code>${escapeHtml(finding.evidence)}</code></pre></div>` : "";
  const fixBlock = finding.fix ? `<div class="finding-fix">
        <strong>Fix:</strong> ${escapeHtml(finding.fix.description)}
        ${finding.fix.auto ? '<span class="auto-fix-badge">auto-fixable</span>' : ""}
        ${finding.fix.before ? `<div class="fix-diff"><div class="diff-before"><strong>Before:</strong><pre><code>${escapeHtml(finding.fix.before)}</code></pre></div><div class="diff-after"><strong>After:</strong><pre><code>${escapeHtml(finding.fix.after)}</code></pre></div></div>` : ""}
      </div>` : "";
  return `
    <div class="finding-card">
      <div class="finding-header">
        <span class="severity-badge" style="background-color: ${color};">${finding.severity.toUpperCase()}</span>
        <span class="finding-title">${escapeHtml(finding.title)}</span>
      </div>
      <div class="finding-meta">
        <span class="finding-category">${escapeHtml(finding.category)}</span>
        <span class="finding-location">${location}</span>
      </div>
      <p class="finding-description">${escapeHtml(finding.description)}</p>
      ${evidenceBlock}
      ${fixBlock}
    </div>`;
}
function formatTimestamp(iso) {
  try {
    const date = new Date(iso);
    return date.toLocaleString("en-US", {
      weekday: "long",
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZoneName: "short"
    });
  } catch {
    return iso;
  }
}
function escapeHtml(text) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
function inlineStyles() {
  return `
    /* Reset & Base */
    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
      background-color: #0d1117;
      color: #e6edf3;
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
    }

    .container {
      max-width: 960px;
      margin: 0 auto;
      padding: 24px 16px;
    }

    /* Header */
    .header {
      background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 32px;
      margin-bottom: 24px;
    }

    .header-content {
      display: flex;
      align-items: center;
      gap: 32px;
      flex-wrap: wrap;
    }

    .grade-badge {
      width: 120px;
      height: 120px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      box-shadow: 0 0 40px rgba(0, 0, 0, 0.4);
    }

    .grade-letter {
      font-size: 64px;
      font-weight: 800;
      color: #ffffff;
      text-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    }

    .header-info {
      flex: 1;
      min-width: 200px;
    }

    .title {
      font-size: 28px;
      font-weight: 700;
      color: #e6edf3;
      margin-bottom: 4px;
    }

    .subtitle {
      font-size: 20px;
      color: #8b949e;
      margin-bottom: 8px;
    }

    .subtitle strong {
      color: #e6edf3;
      font-size: 24px;
    }

    .meta {
      font-size: 14px;
      color: #6e7681;
      margin-bottom: 2px;
    }

    /* Section */
    .section {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }

    .section-title {
      font-size: 20px;
      font-weight: 600;
      color: #e6edf3;
      margin-bottom: 16px;
      padding-bottom: 8px;
      border-bottom: 1px solid #21262d;
    }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
      gap: 12px;
    }

    .stat-card {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }

    .stat-value {
      font-size: 28px;
      font-weight: 700;
      line-height: 1.2;
    }

    .stat-label {
      font-size: 12px;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-top: 4px;
    }

    /* Score Breakdown Bars */
    .breakdown {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .bar-row {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .bar-label {
      width: 120px;
      font-size: 14px;
      color: #8b949e;
      text-align: right;
      flex-shrink: 0;
    }

    .bar-track {
      flex: 1;
      height: 20px;
      background: #21262d;
      border-radius: 10px;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      border-radius: 10px;
      transition: width 0.3s ease;
    }

    .bar-value {
      width: 70px;
      font-size: 14px;
      font-weight: 600;
      text-align: right;
      flex-shrink: 0;
    }

    /* Distribution */
    .distribution {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .dist-bar {
      width: 100%;
      height: 32px;
      border-radius: 6px;
    }

    .legend {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
    }

    .legend-item {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      color: #8b949e;
    }

    .legend-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
      flex-shrink: 0;
    }

    .no-findings-text {
      color: #8b949e;
      font-style: italic;
    }

    /* Findings */
    .findings-group {
      margin-bottom: 20px;
    }

    .group-header {
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .severity-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
      flex-shrink: 0;
    }

    .finding-card {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 12px;
    }

    .finding-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 8px;
      flex-wrap: wrap;
    }

    .severity-badge {
      font-size: 11px;
      font-weight: 700;
      color: #ffffff;
      padding: 2px 8px;
      border-radius: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      flex-shrink: 0;
    }

    .finding-title {
      font-size: 16px;
      font-weight: 600;
      color: #e6edf3;
    }

    .finding-meta {
      display: flex;
      gap: 16px;
      margin-bottom: 8px;
      flex-wrap: wrap;
    }

    .finding-category {
      font-size: 12px;
      color: #8b949e;
      background: #21262d;
      padding: 2px 8px;
      border-radius: 4px;
    }

    .finding-location {
      font-size: 12px;
      color: #6e7681;
      font-family: 'SF Mono', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
    }

    .finding-description {
      font-size: 14px;
      color: #8b949e;
      margin-bottom: 8px;
    }

    .finding-evidence {
      margin-top: 8px;
    }

    .finding-evidence strong,
    .finding-fix strong {
      font-size: 12px;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.3px;
    }

    .finding-evidence pre,
    .fix-diff pre {
      background: #161b22;
      border: 1px solid #21262d;
      border-radius: 6px;
      padding: 12px;
      margin-top: 4px;
      overflow-x: auto;
    }

    .finding-evidence code,
    .fix-diff code {
      font-family: 'SF Mono', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
      font-size: 13px;
      color: #e6edf3;
      white-space: pre-wrap;
      word-break: break-all;
    }

    .finding-fix {
      margin-top: 12px;
      font-size: 14px;
      color: #8b949e;
    }

    .auto-fix-badge {
      display: inline-block;
      font-size: 11px;
      font-weight: 600;
      color: #2ea043;
      background: rgba(46, 160, 67, 0.15);
      border: 1px solid rgba(46, 160, 67, 0.4);
      padding: 1px 6px;
      border-radius: 4px;
      margin-left: 8px;
    }

    .fix-diff {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      margin-top: 8px;
    }

    .diff-before strong {
      color: #f85149;
    }

    .diff-after strong {
      color: #2ea043;
    }

    .no-findings {
      background: rgba(46, 160, 67, 0.1);
      border: 1px solid rgba(46, 160, 67, 0.3);
      border-radius: 8px;
      padding: 24px;
      text-align: center;
      color: #2ea043;
      font-size: 16px;
    }

    /* Footer */
    .footer {
      text-align: center;
      padding: 24px;
      color: #6e7681;
      font-size: 13px;
      border-top: 1px solid #21262d;
      margin-top: 12px;
    }

    .footer strong {
      color: #8b949e;
    }

    .footer-timestamp {
      margin-top: 4px;
      font-size: 12px;
    }

    /* Responsive */
    @media (max-width: 640px) {
      .header-content {
        flex-direction: column;
        text-align: center;
      }

      .bar-label {
        width: 80px;
        font-size: 12px;
      }

      .bar-value {
        width: 60px;
        font-size: 12px;
      }

      .fix-diff {
        grid-template-columns: 1fr;
      }

      .stats-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }
  `;
}

// src/opus/pipeline.ts
import Anthropic from "@anthropic-ai/sdk";
import chalk2 from "chalk";

// src/opus/prompts.ts
var ATTACKER_SYSTEM_PROMPT = `You are a red team security researcher analyzing an AI agent's configuration for exploitable vulnerabilities. Your goal is to find every possible attack vector.

Think like an attacker who has:
1. Access to a repository that a developer will open with Claude Code
2. The ability to craft malicious CLAUDE.md files, hook scripts, or MCP server configs
3. Knowledge of how Claude Code processes hooks, permissions, skills, and agent definitions

For each vulnerability you find, explain:
- The attack vector (how would you exploit this?)
- The impact (what could an attacker achieve?)
- The difficulty (how hard is this to exploit?)

Focus on:
- Prompt injection via CLAUDE.md in cloned repos
- Command injection through hook variable interpolation
- Data exfiltration via hooks that phone home
- Permission escalation through overly broad allow rules
- Supply chain attacks via npx -y auto-installation
- MCP server misconfiguration enabling unauthorized access
- Agent definitions that process untrusted external content

Be thorough and adversarial. Find things that automated scanners would miss.`;
var DEFENDER_SYSTEM_PROMPT = `You are a security architect reviewing an AI agent's configuration to recommend hardening measures. Your goal is to identify weaknesses and propose concrete fixes.

For each issue you find, provide:
- The specific vulnerability or weakness
- A concrete fix (exact config change, not vague advice)
- The priority (critical, high, medium, low)
- Whether it can be automated or requires manual review

Focus on defense-in-depth:
- Are permissions following least privilege?
- Do hooks validate their inputs?
- Are MCP servers restricted to minimum necessary access?
- Is there monitoring/logging for suspicious agent behavior?
- Are secrets properly managed via environment variables?
- Do agents have appropriate tool restrictions for their role?

Also identify GOOD security practices already in place \u2014 acknowledge what the configuration does well.`;
var AUDITOR_SYSTEM_PROMPT = `You are a security auditor producing a final assessment of an AI agent's configuration. You will receive:
1. The raw configuration files
2. An attacker's analysis (red team findings)
3. A defender's analysis (hardening recommendations)

Your job is to:
1. Validate the attacker's findings \u2014 which are real threats vs theoretical?
2. Evaluate the defender's recommendations \u2014 which are practical vs overkill?
3. Produce a final risk assessment with:
   - Overall risk level (critical, high, medium, low)
   - Top 3 most important issues to fix immediately
   - Top 3 things the configuration does well
   - A numeric security score (0-100)
   - A prioritized action plan

Be balanced and practical. Not every theoretical vulnerability is worth fixing. Focus on real-world risk.`;
function buildConfigContext(files) {
  const sections = files.map(
    (f) => `### File: ${f.path}
\`\`\`
${f.content}
\`\`\``
  );
  return `## AI Agent Configuration Files

${sections.join("\n\n")}`;
}
function buildAuditorContext(configContext, attackerAnalysis, defenderAnalysis) {
  return `${configContext}

## Red Team Analysis (Attacker Perspective)

${attackerAnalysis}

## Blue Team Analysis (Defender Perspective)

${defenderAnalysis}`;
}

// src/opus/pipeline.ts
var MODEL = "claude-opus-4-6";
function renderPhaseBanner(phaseNumber, title, subtitle, colorFn) {
  const divider = "\u2501".repeat(56);
  process.stdout.write("\n");
  process.stdout.write(colorFn(`  \u250F${divider}\u2513
`));
  process.stdout.write(colorFn(`  \u2503  ${phaseNumber}: ${title.padEnd(divider.length - phaseNumber.length - 4)}\u2503
`));
  process.stdout.write(colorFn(`  \u2503  ${subtitle.padEnd(divider.length - 2)}\u2503
`));
  process.stdout.write(colorFn(`  \u2517${divider}\u251B
`));
  process.stdout.write("\n");
}
function renderPhaseComplete(label, tokenCount, colorFn) {
  process.stdout.write("\n");
  process.stdout.write(
    colorFn(`  \u2713 ${label} complete`) + chalk2.dim(` (${tokenCount} tokens)
`)
  );
}
var SPINNER_FRAMES = ["\u280B", "\u2819", "\u2839", "\u2838", "\u283C", "\u2834", "\u2826", "\u2827", "\u2807", "\u280F"];
function createSpinner(label, colorFn) {
  let frame = 0;
  let lastTokenCount = 0;
  const intervalId = setInterval(() => {
    frame = (frame + 1) % SPINNER_FRAMES.length;
    const spinner = colorFn(SPINNER_FRAMES[frame]);
    process.stdout.write(`\r  ${spinner} ${label} \u2014 ${chalk2.dim(`${lastTokenCount} tokens`)}`);
  }, 80);
  return {
    update(tokenCount) {
      lastTokenCount = tokenCount;
    },
    stop() {
      clearInterval(intervalId);
      process.stdout.write("\r" + " ".repeat(60) + "\r");
    }
  };
}
async function runOpusPipeline(scanResult, options) {
  const client = new Anthropic();
  const configContext = buildConfigContext(
    scanResult.target.files.map((f) => ({ path: f.path, content: f.content }))
  );
  let attackerRaw;
  let defenderRaw;
  if (options.stream) {
    renderPhaseBanner(
      "Phase 1a",
      "ATTACKER (Red Team)",
      "Adversarial analysis \u2014 finding attack vectors",
      chalk2.red
    );
    attackerRaw = await runPerspectiveStreaming(
      client,
      "attacker",
      configContext,
      options.verbose,
      chalk2.red
    );
    renderPhaseComplete("Attacker analysis", attackerRaw.length, chalk2.red);
    renderPhaseBanner(
      "Phase 1b",
      "DEFENDER (Blue Team)",
      "Defensive analysis \u2014 hardening recommendations",
      chalk2.blue
    );
    defenderRaw = await runPerspectiveStreaming(
      client,
      "defender",
      configContext,
      options.verbose,
      chalk2.blue
    );
    renderPhaseComplete("Defender analysis", defenderRaw.length, chalk2.blue);
  } else {
    const [aRaw, dRaw] = await Promise.all([
      runPerspectiveNonStreaming(client, "attacker", configContext),
      runPerspectiveNonStreaming(client, "defender", configContext)
    ]);
    attackerRaw = aRaw;
    defenderRaw = dRaw;
  }
  const auditorContext = buildAuditorContext(configContext, attackerRaw, defenderRaw);
  let auditorRaw;
  if (options.stream) {
    renderPhaseBanner(
      "Phase 2",
      "AUDITOR (Final Verdict)",
      "Synthesizing attacker + defender into final assessment",
      chalk2.cyan
    );
    auditorRaw = await runAuditorStreaming(
      client,
      auditorContext,
      options.verbose
    );
    renderPhaseComplete("Auditor synthesis", auditorRaw.length, chalk2.cyan);
    process.stdout.write("\n");
  } else {
    auditorRaw = await runAuditorNonStreaming(client, auditorContext);
  }
  const attacker = parseAttackerResponse(attackerRaw);
  const defender = parseDefenderResponse(defenderRaw);
  const auditor = parseAuditorResponse(auditorRaw);
  return { attacker, defender, auditor };
}
async function runPerspectiveStreaming(client, role, configContext, verbose, colorFn) {
  const systemPrompt = role === "attacker" ? ATTACKER_SYSTEM_PROMPT : DEFENDER_SYSTEM_PROMPT;
  const roleLabel = role === "attacker" ? "Attacker" : "Defender";
  let fullText = "";
  const stream = client.messages.stream({
    model: MODEL,
    max_tokens: 4096,
    system: systemPrompt,
    messages: [
      {
        role: "user",
        content: `Analyze the following AI agent configuration from your ${role} perspective.

${configContext}`
      }
    ]
  });
  if (verbose) {
    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        const text = event.delta.text;
        fullText += text;
        process.stdout.write(chalk2.dim(text));
      }
    }
  } else {
    const spinner = createSpinner(roleLabel, colorFn);
    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        fullText += event.delta.text;
        spinner.update(fullText.length);
      }
    }
    spinner.stop();
  }
  return fullText;
}
async function runPerspectiveNonStreaming(client, role, configContext) {
  const systemPrompt = role === "attacker" ? ATTACKER_SYSTEM_PROMPT : DEFENDER_SYSTEM_PROMPT;
  const response = await client.messages.create({
    model: MODEL,
    max_tokens: 4096,
    system: systemPrompt,
    messages: [
      {
        role: "user",
        content: `Analyze the following AI agent configuration from your ${role} perspective.

${configContext}`
      }
    ]
  });
  const textBlock = response.content.find((b) => b.type === "text");
  return textBlock?.type === "text" ? textBlock.text : "";
}
async function runAuditorStreaming(client, auditorContext, verbose) {
  let fullText = "";
  const stream = client.messages.stream({
    model: MODEL,
    max_tokens: 4096,
    system: AUDITOR_SYSTEM_PROMPT,
    messages: [
      {
        role: "user",
        content: `Produce your final security audit based on the following:

${auditorContext}`
      }
    ]
  });
  if (verbose) {
    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        const text = event.delta.text;
        fullText += text;
        process.stdout.write(chalk2.dim(text));
      }
    }
  } else {
    const spinner = createSpinner("Auditor", chalk2.cyan);
    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        fullText += event.delta.text;
        spinner.update(fullText.length);
      }
    }
    spinner.stop();
  }
  return fullText;
}
async function runAuditorNonStreaming(client, auditorContext) {
  const response = await client.messages.create({
    model: MODEL,
    max_tokens: 4096,
    system: AUDITOR_SYSTEM_PROMPT,
    messages: [
      {
        role: "user",
        content: `Produce your final security audit based on the following:

${auditorContext}`
      }
    ]
  });
  const textBlock = response.content.find((b) => b.type === "text");
  return textBlock?.type === "text" ? textBlock.text : "";
}
function parseBulletFindings(raw) {
  return raw.split("\n").filter((line) => {
    const bulletMatches = [...line.matchAll(/^[-*]\s+/g)];
    const numberedMatches = [...line.matchAll(/^\d+\.\s+/g)];
    return bulletMatches.length > 0 || numberedMatches.length > 0;
  }).map((line) => line.replace(/^[-*\d.]+\s+/, "").trim()).filter((line) => line.length > 10);
}
function parseAttackerResponse(raw) {
  const findingLines = parseBulletFindings(raw);
  return {
    role: "attacker",
    findings: findingLines.length > 0 ? findingLines : [raw.substring(0, 500)],
    reasoning: raw
  };
}
function parseDefenderResponse(raw) {
  const findingLines = parseBulletFindings(raw);
  return {
    role: "defender",
    findings: findingLines.length > 0 ? findingLines : [raw.substring(0, 500)],
    reasoning: raw
  };
}
function parseAuditorResponse(raw) {
  const scoreMatches = [...raw.matchAll(/(?:score|rating)[:\s]*(\d{1,3})\s*(?:\/\s*100)?/gi)];
  const scoreMatch = scoreMatches.length > 0 ? scoreMatches[0] : void 0;
  const score = scoreMatch ? Math.min(100, parseInt(scoreMatch[1], 10)) : 50;
  const riskMatches = [
    ...raw.matchAll(/(?:risk\s+level|overall\s+risk|severity)[:\s]*(critical|high|medium|low)/gi)
  ];
  const riskMatch = riskMatches.length > 0 ? riskMatches[0] : void 0;
  const riskLevel = riskMatch?.[1]?.toLowerCase() ?? "medium";
  const recommendations = raw.split("\n").filter((line) => {
    const bulletMatches = [...line.matchAll(/^[-*]\s+/g)];
    const numberedMatches = [...line.matchAll(/^\d+\.\s+/g)];
    return (bulletMatches.length > 0 || numberedMatches.length > 0) && line.length > 20;
  }).map((line) => line.replace(/^[-*\d.]+\s+/, "").trim()).slice(0, 10);
  return {
    overallAssessment: raw,
    riskLevel,
    recommendations: recommendations.length > 0 ? recommendations : ["Review the full audit output above"],
    score
  };
}

// src/opus/render.ts
import chalk3 from "chalk";
function renderOpusAnalysis(analysis) {
  const lines = [];
  lines.push("");
  lines.push(chalk3.bold.magenta("  Opus 4.6 Multi-Agent Security Analysis"));
  lines.push(chalk3.dim("  Three-perspective adversarial review"));
  lines.push("");
  lines.push(chalk3.bold.red("  Red Team (Attacker Perspective)"));
  lines.push(chalk3.dim("  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"));
  const attackerFindings = analysis.attacker.findings.slice(0, 8);
  for (const finding of attackerFindings) {
    lines.push(chalk3.red(`    * ${finding}`));
  }
  if (analysis.attacker.findings.length > 8) {
    lines.push(chalk3.dim(`    ... and ${analysis.attacker.findings.length - 8} more`));
  }
  lines.push("");
  lines.push(chalk3.bold.blue("  Blue Team (Defender Perspective)"));
  lines.push(chalk3.dim("  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"));
  const defenderFindings = analysis.defender.findings.slice(0, 8);
  for (const finding of defenderFindings) {
    lines.push(chalk3.blue(`    * ${finding}`));
  }
  if (analysis.defender.findings.length > 8) {
    lines.push(chalk3.dim(`    ... and ${analysis.defender.findings.length - 8} more`));
  }
  lines.push("");
  lines.push(chalk3.bold.cyan("  Auditor (Final Assessment)"));
  lines.push(chalk3.dim("  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"));
  const riskColor = analysis.auditor.riskLevel === "critical" ? chalk3.red.bold : analysis.auditor.riskLevel === "high" ? chalk3.yellow.bold : analysis.auditor.riskLevel === "medium" ? chalk3.blue.bold : chalk3.green.bold;
  lines.push(`  Risk Level: ${riskColor(analysis.auditor.riskLevel.toUpperCase())}`);
  lines.push(`  Opus Score: ${renderInlineScore(analysis.auditor.score)}`);
  lines.push("");
  lines.push(chalk3.bold("  Top Recommendations:"));
  const recs = analysis.auditor.recommendations.slice(0, 5);
  for (let i = 0; i < recs.length; i++) {
    lines.push(chalk3.cyan(`    ${i + 1}. ${recs[i]}`));
  }
  lines.push("");
  lines.push(chalk3.dim("  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"));
  lines.push(chalk3.dim("  Powered by Claude Opus 4.6 \u2014 three-agent adversarial analysis"));
  lines.push("");
  return lines.join("\n");
}
function renderInlineScore(score) {
  const width = 20;
  const filled = Math.round(score / 100 * width);
  const empty = width - filled;
  let colorFn;
  if (score >= 80) colorFn = chalk3.green;
  else if (score >= 60) colorFn = chalk3.yellow;
  else colorFn = chalk3.red;
  return `${colorFn("\u2588".repeat(filled))}${chalk3.dim("\u2591".repeat(empty))} ${colorFn(`${score}/100`)}`;
}

// src/fixer/index.ts
import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";

// src/fixer/transforms.ts
function replaceHardcodedSecret(content, finding) {
  if (!finding.fix) {
    return { content, applied: false };
  }
  const { before, after } = finding.fix;
  if (!content.includes(before)) {
    return { content, applied: false };
  }
  const updatedContent = content.replace(before, after);
  return {
    content: updatedContent,
    applied: updatedContent !== content
  };
}
function tightenWildcardPermission(content, finding) {
  if (!finding.fix) {
    return { content, applied: false };
  }
  const { before, after } = finding.fix;
  if (!content.includes(before)) {
    return { content, applied: false };
  }
  const updatedContent = content.replace(before, after);
  return {
    content: updatedContent,
    applied: updatedContent !== content
  };
}
function applyGenericTransform(content, finding) {
  if (!finding.fix) {
    return { content, applied: false };
  }
  const { before, after } = finding.fix;
  if (!content.includes(before)) {
    return { content, applied: false };
  }
  const updatedContent = content.replace(before, after);
  return {
    content: updatedContent,
    applied: updatedContent !== content
  };
}
function applyTransform(content, finding) {
  switch (finding.category) {
    case "secrets":
      return replaceHardcodedSecret(content, finding);
    case "permissions":
      return tightenWildcardPermission(content, finding);
    default:
      return applyGenericTransform(content, finding);
  }
}

// src/fixer/index.ts
function getAutoFixableFindings(findings) {
  return findings.filter(
    (f) => f.fix !== void 0 && f.fix.auto === true
  );
}
function groupByFile(findings) {
  const groups = /* @__PURE__ */ new Map();
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
function applyFixes(scanResult) {
  const autoFixable = getAutoFixableFindings(scanResult.findings);
  const grouped = groupByFile(autoFixable);
  const applied = [];
  const skipped = [];
  for (const [relPath, findings] of grouped) {
    const filePath = resolve(scanResult.target.path, relPath);
    let content;
    try {
      content = readFileSync(filePath, "utf-8");
    } catch {
      for (const finding of findings) {
        skipped.push({
          file: filePath,
          findingId: finding.id,
          title: finding.title,
          reason: `Could not read file: ${filePath}`
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
          after: finding.fix.after
        });
      } else {
        skipped.push({
          file: filePath,
          findingId: finding.id,
          title: finding.title,
          reason: "Pattern not found in file content"
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
    totalAutoFixable: autoFixable.length
  };
}
function renderFixSummary(result) {
  const lines = [];
  lines.push("");
  lines.push("  Fix Engine Results");
  lines.push("  " + "\u2500".repeat(40));
  if (result.applied.length === 0 && result.skipped.length === 0) {
    lines.push("  No auto-fixable findings to apply.");
    lines.push("");
    return lines.join("\n");
  }
  lines.push(
    `  Auto-fixable: ${String(result.totalAutoFixable)}, Applied: ${String(result.applied.length)}, Skipped: ${String(result.skipped.length)}`
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

// src/init/index.ts
import { existsSync, mkdirSync, writeFileSync as writeFileSync2 } from "fs";
import { join, resolve as resolve2 } from "path";
function getDefaultSettings() {
  const settings = {
    permissions: {
      allow: [
        "Bash(git *)",
        "Bash(npm *)",
        "Bash(npx *)",
        "Bash(node *)",
        "Bash(pnpm *)",
        "Bash(yarn *)",
        "Bash(tsc *)",
        "Bash(eslint *)",
        "Bash(prettier *)",
        "Bash(vitest *)",
        "Bash(jest *)",
        "Read(*)",
        "Edit(src/*)",
        "Edit(tests/*)",
        "Write(src/*)",
        "Write(tests/*)"
      ],
      deny: [
        "Bash(rm -rf *)",
        "Bash(sudo *)",
        "Bash(chmod 777 *)",
        "Bash(curl * | bash)",
        "Bash(wget * | bash)",
        "Bash(ssh *)",
        "Bash(> /dev/*)",
        "Bash(dd *)"
      ]
    },
    hooks: {
      PreToolUse: [
        {
          matcher: "Bash",
          hook: `# Warn on destructive commands
if echo "$TOOL_INPUT" | grep -qE '(rm -rf|sudo|chmod 777|mkfs|dd if=)'; then
  echo 'WARN: Potentially destructive command detected'
fi`
        }
      ],
      PostToolUse: [
        {
          matcher: "Write",
          hook: `# Check for accidentally written secrets
if echo "$TOOL_INPUT" | grep -qE '(sk-ant-|sk-proj-|ghp_|AKIA)'; then
  echo 'BLOCK: Possible secret detected in written file'
  exit 1
fi`
        }
      ]
    }
  };
  return JSON.stringify(settings, null, 2);
}
function getDefaultClaudeMd() {
  return `# Security Guidelines

## Secrets

- NEVER hardcode API keys, tokens, passwords, or credentials in any file
- Always use environment variable references: \`\${VAR_NAME}\` or \`process.env.VAR_NAME\`
- Never echo, log, or print secret values to the terminal

## Permissions

- Never use \`--dangerously-skip-permissions\` or \`--no-verify\`
- Do not run \`sudo\` commands
- Do not use \`rm -rf\` without explicit user confirmation
- Do not use \`chmod 777\` on any file or directory

## Code Safety

- Validate all user inputs before processing
- Use parameterized queries for database operations
- Sanitize HTML output to prevent XSS
- Never execute dynamically constructed shell commands with user input

## MCP Servers

- Only connect to trusted, verified MCP servers
- Review MCP server permissions before enabling
- Do not pass secrets as command-line arguments to MCP servers
- Use environment variables for MCP server credentials

## Hooks

- All hooks must be reviewed before activation
- Hooks should not exfiltrate data or make external network calls
- PostToolUse hooks should validate output, not modify it silently
`;
}
function getDefaultMcpConfig() {
  const config = {
    mcpServers: {}
  };
  return JSON.stringify(config, null, 2);
}
function safeWriteFile(filePath, content) {
  if (existsSync(filePath)) {
    return {
      path: filePath,
      status: "skipped",
      reason: "File already exists"
    };
  }
  writeFileSync2(filePath, content, "utf-8");
  return {
    path: filePath,
    status: "created"
  };
}
function runInit(targetDir) {
  const baseDir = targetDir ? resolve2(targetDir) : resolve2(process.cwd());
  const claudeDir = join(baseDir, ".claude");
  if (!existsSync(claudeDir)) {
    mkdirSync(claudeDir, { recursive: true });
  }
  const files = [];
  files.push(
    safeWriteFile(join(claudeDir, "settings.json"), getDefaultSettings())
  );
  files.push(
    safeWriteFile(join(claudeDir, "CLAUDE.md"), getDefaultClaudeMd())
  );
  files.push(
    safeWriteFile(join(claudeDir, "mcp.json"), getDefaultMcpConfig())
  );
  return {
    directory: claudeDir,
    files
  };
}
function renderInitSummary(result) {
  const lines = [];
  lines.push("");
  lines.push("  AgentShield Init");
  lines.push("  " + "\u2500".repeat(40));
  lines.push(`  Directory: ${result.directory}`);
  lines.push("");
  const created = result.files.filter((f) => f.status === "created");
  const skipped = result.files.filter((f) => f.status === "skipped");
  if (created.length > 0) {
    lines.push("  Created:");
    for (const file of created) {
      lines.push(`    + ${file.path}`);
    }
    lines.push("");
  }
  if (skipped.length > 0) {
    lines.push("  Skipped (already exist):");
    for (const file of skipped) {
      lines.push(`    ~ ${file.path}`);
      if (file.reason) {
        lines.push(`      ${file.reason}`);
      }
    }
    lines.push("");
  }
  if (created.length > 0) {
    lines.push("  Next steps:");
    lines.push("    1. Review the generated files in .claude/");
    lines.push("    2. Customize permissions for your project");
    lines.push("    3. Run 'agentshield scan' to verify your config");
    lines.push("");
  }
  return lines.join("\n");
}

// src/index.ts
var program = new Command();
program.name("agentshield").description("Security auditor for AI agent configurations").version("1.1.0");
program.command("scan").description("Scan a Claude Code configuration directory for security issues").option("-p, --path <path>", "Path to scan (default: ~/.claude or current dir)").option("-f, --format <format>", "Output format: terminal, json, markdown, html", "terminal").option("--fix", "Auto-apply safe fixes", false).option("--opus", "Enable Opus 4.6 multi-agent deep analysis", false).option("--stream", "Stream Opus analysis in real-time", false).option("--min-severity <severity>", "Minimum severity to report: critical, high, medium, low, info", "info").option("-v, --verbose", "Show detailed output", false).action(async (options) => {
  const targetPath = resolveTargetPath(options.path);
  if (!existsSync2(targetPath)) {
    console.error(`Error: Path does not exist: ${targetPath}`);
    process.exit(1);
  }
  const result = scan(targetPath);
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const minIndex = severityOrder.indexOf(options.minSeverity);
  const filteredResult = {
    ...result,
    findings: result.findings.filter(
      (f) => severityOrder.indexOf(f.severity) <= minIndex
    )
  };
  const report = calculateScore(filteredResult);
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
  if (options.fix) {
    const fixResult = applyFixes(filteredResult);
    console.log(renderFixSummary(fixResult));
  }
  if (options.opus) {
    if (!process.env.ANTHROPIC_API_KEY) {
      console.error(
        "\nError: ANTHROPIC_API_KEY environment variable required for --opus mode.\nSet it with: export ANTHROPIC_API_KEY=your-key-here\n"
      );
      process.exit(1);
    }
    try {
      const opusAnalysis = await runOpusPipeline(result, {
        verbose: options.verbose,
        stream: options.stream || options.format === "terminal"
      });
      console.log(renderOpusAnalysis(opusAnalysis));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`
Opus analysis failed: ${message}`);
      console.error("The static scan results above are still valid.\n");
    }
  }
  if (report.summary.critical > 0) {
    process.exit(2);
  }
});
program.command("init").description("Generate a secure baseline Claude Code configuration").option("-p, --path <path>", "Target directory (default: current directory)").action((options) => {
  const initResult = runInit(options.path);
  console.log(renderInitSummary(initResult));
});
var miniclaw = program.command("miniclaw").description("MiniClaw \u2014 minimal secure sandboxed AI agent runtime");
miniclaw.command("start").description("Start the MiniClaw server").option("-p, --port <port>", "Port to listen on", "3847").option("-H, --hostname <hostname>", "Hostname to bind to", "localhost").option("--network <policy>", "Network policy: none, localhost, allowlist", "none").option("--rate-limit <limit>", "Max requests per minute per IP", "10").option("--sandbox-root <path>", "Root path for sandbox directories", "/tmp/miniclaw-sandboxes").option("--max-duration <ms>", "Max session duration in milliseconds", "300000").action((options) => {
  const port = parseInt(options.port, 10);
  const rateLimit = parseInt(options.rateLimit, 10);
  const maxDuration = parseInt(options.maxDuration, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    console.error("Error: Invalid port number. Must be between 1 and 65535.");
    process.exit(1);
  }
  if (isNaN(rateLimit) || rateLimit < 1) {
    console.error("Error: Invalid rate limit. Must be a positive integer.");
    process.exit(1);
  }
  const networkPolicy = options.network;
  if (!["none", "localhost", "allowlist"].includes(networkPolicy)) {
    console.error("Error: Invalid network policy. Must be: none, localhost, or allowlist.");
    process.exit(1);
  }
  console.log(`
  MiniClaw \u2014 Secure Agent Runtime
`);
  console.log(`  Starting server...`);
  console.log(`  Port:           ${port}`);
  console.log(`  Hostname:       ${options.hostname}`);
  console.log(`  Network policy: ${networkPolicy}`);
  console.log(`  Rate limit:     ${rateLimit} req/min`);
  console.log(`  Sandbox root:   ${options.sandboxRoot}`);
  console.log(`  Max duration:   ${maxDuration}ms
`);
  const { server } = startMiniClaw({
    server: {
      port,
      hostname: options.hostname,
      corsOrigins: [
        `http://${options.hostname}:${port}`,
        "http://localhost:3000"
      ],
      rateLimit,
      maxRequestSize: 10240
    },
    sandbox: {
      rootPath: options.sandboxRoot,
      maxFileSize: 10485760,
      allowedExtensions: [
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".json",
        ".md",
        ".txt",
        ".css",
        ".html",
        ".yaml",
        ".yml",
        ".toml",
        ".xml",
        ".csv",
        ".svg",
        ".env.example"
      ],
      networkPolicy,
      maxDuration
    }
  });
  server.on("listening", () => {
    console.log(`  Listening on http://${options.hostname}:${port}`);
    console.log(`  Health check: http://${options.hostname}:${port}/api/health`);
    console.log(`
  Press Ctrl+C to stop.
`);
  });
  server.on("error", (err) => {
    if (err.code === "EADDRINUSE") {
      console.error(`
  Error: Port ${port} is already in use.`);
      console.error(`  Try a different port: agentshield miniclaw start --port 4000
`);
    } else {
      console.error(`
  Server error: ${err.message}
`);
    }
    process.exit(1);
  });
});
program.parse();
function resolveTargetPath(pathArg) {
  if (pathArg) {
    return resolve3(pathArg);
  }
  const localClaude = resolve3(process.cwd(), ".claude");
  if (existsSync2(localClaude)) {
    return localClaude;
  }
  const homeClaude = resolve3(
    process.env.HOME ?? process.env.USERPROFILE ?? ".",
    ".claude"
  );
  if (existsSync2(homeClaude)) {
    return homeClaude;
  }
  return process.cwd();
}
