import chalk from "chalk";
import type { OpusAnalysis } from "../types.js";

/**
 * Render the Opus multi-agent analysis to terminal.
 */
export function renderOpusAnalysis(analysis: OpusAnalysis): string {
  const lines: string[] = [];

  lines.push("");
  lines.push(chalk.bold.magenta("  Opus 4.6 Multi-Agent Security Analysis"));
  lines.push(chalk.dim("  Three-perspective adversarial review"));
  lines.push("");

  // Attacker perspective
  lines.push(chalk.bold.red("  Red Team (Attacker Perspective)"));
  lines.push(chalk.dim("  ─────────────────────────────────────"));
  const attackerFindings = analysis.attacker.findings.slice(0, 8);
  for (const finding of attackerFindings) {
    lines.push(chalk.red(`    * ${finding}`));
  }
  if (analysis.attacker.findings.length > 8) {
    lines.push(chalk.dim(`    ... and ${analysis.attacker.findings.length - 8} more`));
  }
  lines.push("");

  // Defender perspective
  lines.push(chalk.bold.blue("  Blue Team (Defender Perspective)"));
  lines.push(chalk.dim("  ─────────────────────────────────────"));
  const defenderFindings = analysis.defender.findings.slice(0, 8);
  for (const finding of defenderFindings) {
    lines.push(chalk.blue(`    * ${finding}`));
  }
  if (analysis.defender.findings.length > 8) {
    lines.push(chalk.dim(`    ... and ${analysis.defender.findings.length - 8} more`));
  }
  lines.push("");

  // Auditor synthesis
  lines.push(chalk.bold.cyan("  Auditor (Final Assessment)"));
  lines.push(chalk.dim("  ─────────────────────────────────────"));

  const riskColor =
    analysis.auditor.riskLevel === "critical"
      ? chalk.red.bold
      : analysis.auditor.riskLevel === "high"
      ? chalk.yellow.bold
      : analysis.auditor.riskLevel === "medium"
      ? chalk.blue.bold
      : chalk.green.bold;

  lines.push(`  Risk Level: ${riskColor(analysis.auditor.riskLevel.toUpperCase())}`);
  lines.push(`  Opus Score: ${renderInlineScore(analysis.auditor.score)}`);
  lines.push("");

  lines.push(chalk.bold("  Top Recommendations:"));
  const recs = analysis.auditor.recommendations.slice(0, 5);
  for (let i = 0; i < recs.length; i++) {
    lines.push(chalk.cyan(`    ${i + 1}. ${recs[i]}`));
  }
  lines.push("");

  lines.push(chalk.dim("  ─────────────────────────────────────────"));
  lines.push(chalk.dim("  Powered by Claude Opus 4.6 — three-agent adversarial analysis"));
  lines.push("");

  return lines.join("\n");
}

function renderInlineScore(score: number): string {
  const width = 20;
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;

  let colorFn: typeof chalk.green;
  if (score >= 80) colorFn = chalk.green;
  else if (score >= 60) colorFn = chalk.yellow;
  else colorFn = chalk.red;

  return `${colorFn("█".repeat(filled))}${chalk.dim("░".repeat(empty))} ${colorFn(`${score}/100`)}`;
}

/**
 * Render the full Opus analysis as markdown (for JSON/MD output).
 */
export function renderOpusMarkdown(analysis: OpusAnalysis): string {
  const lines: string[] = [];

  lines.push("## Opus 4.6 Multi-Agent Analysis");
  lines.push("");

  lines.push("### Red Team (Attacker Perspective)");
  lines.push("");
  lines.push(analysis.attacker.reasoning);
  lines.push("");

  lines.push("### Blue Team (Defender Perspective)");
  lines.push("");
  lines.push(analysis.defender.reasoning);
  lines.push("");

  lines.push("### Auditor (Final Assessment)");
  lines.push("");
  lines.push(`**Risk Level:** ${analysis.auditor.riskLevel.toUpperCase()}`);
  lines.push(`**Score:** ${analysis.auditor.score}/100`);
  lines.push("");
  lines.push(analysis.auditor.overallAssessment);
  lines.push("");

  return lines.join("\n");
}
