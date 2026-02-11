#!/usr/bin/env node

import { Command } from "commander";
import { resolve } from "node:path";
import { existsSync } from "node:fs";
import { scan } from "./scanner/index.js";
import { calculateScore } from "./reporter/score.js";
import { renderTerminalReport } from "./reporter/terminal.js";
import { renderJsonReport, renderMarkdownReport } from "./reporter/json.js";
import { runOpusPipeline, renderOpusAnalysis } from "./opus/index.js";

const program = new Command();

program
  .name("agentshield")
  .description("Security auditor for AI agent configurations")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a Claude Code configuration directory for security issues")
  .option("-p, --path <path>", "Path to scan (default: ~/.claude or current dir)")
  .option("-f, --format <format>", "Output format: terminal, json, markdown", "terminal")
  .option("--fix", "Auto-apply safe fixes", false)
  .option("--opus", "Enable Opus 4.6 multi-agent deep analysis", false)
  .option("--stream", "Stream Opus analysis in real-time", false)
  .option("--min-severity <severity>", "Minimum severity to report: critical, high, medium, low, info", "info")
  .option("-v, --verbose", "Show detailed output", false)
  .action(async (options) => {
    const targetPath = resolveTargetPath(options.path);

    if (!existsSync(targetPath)) {
      console.error(`Error: Path does not exist: ${targetPath}`);
      process.exit(1);
    }

    // Phase 1: Static rule-based scan
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

    // Output static scan
    switch (options.format) {
      case "json":
        console.log(renderJsonReport(report));
        break;
      case "markdown":
        console.log(renderMarkdownReport(report));
        break;
      default:
        console.log(renderTerminalReport(report));
    }

    // Phase 2: Opus multi-agent analysis (if enabled)
    if (options.opus) {
      if (!process.env.ANTHROPIC_API_KEY) {
        console.error(
          "\nError: ANTHROPIC_API_KEY environment variable required for --opus mode.\n" +
            "Set it with: export ANTHROPIC_API_KEY=your-key-here\n"
        );
        process.exit(1);
      }

      try {
        const opusAnalysis = await runOpusPipeline(result, {
          verbose: options.verbose,
          stream: options.stream || options.format === "terminal",
        });

        console.log(renderOpusAnalysis(opusAnalysis));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`\nOpus analysis failed: ${message}`);
        console.error("The static scan results above are still valid.\n");
      }
    }

    // Exit with non-zero if critical findings
    if (report.summary.critical > 0) {
      process.exit(2);
    }
  });

program
  .command("init")
  .description("Generate a secure baseline Claude Code configuration")
  .action(() => {
    console.log("TODO: Generate secure baseline config");
    console.log("This will create a hardened ~/.claude/ setup with:");
    console.log("  - Restrictive permissions");
    console.log("  - Security-focused hooks");
    console.log("  - Safe MCP server configs");
    console.log("  - Agent definitions with minimal privileges");
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
