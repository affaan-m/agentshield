#!/usr/bin/env node

import { Command } from "commander";
import { resolve } from "node:path";
import { existsSync } from "node:fs";
import { scan } from "./scanner/index.js";
import { calculateScore } from "./reporter/score.js";
import { renderTerminalReport } from "./reporter/terminal.js";
import { renderJsonReport, renderMarkdownReport } from "./reporter/json.js";
import { renderHtmlReport } from "./reporter/html.js";
import { runOpusPipeline, renderOpusAnalysis } from "./opus/index.js";
import { applyFixes, renderFixSummary } from "./fixer/index.js";
import { runInit, renderInitSummary } from "./init/index.js";
import { startMiniClaw } from "./miniclaw/index.js";

const program = new Command();

program
  .name("agentshield")
  .description("Security auditor for AI agent configurations")
  .version("1.1.0");

program
  .command("scan")
  .description("Scan a Claude Code configuration directory for security issues")
  .option("-p, --path <path>", "Path to scan (default: ~/.claude or current dir)")
  .option("-f, --format <format>", "Output format: terminal, json, markdown, html", "terminal")
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
      case "html":
        console.log(renderHtmlReport(report));
        break;
      default:
        console.log(renderTerminalReport(report));
    }

    // Phase 2: Auto-fix (if enabled)
    if (options.fix) {
      const fixResult = applyFixes(filteredResult);
      console.log(renderFixSummary(fixResult));
    }

    // Phase 3: Opus multi-agent analysis (if enabled)
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
  .option("-p, --path <path>", "Target directory (default: current directory)")
  .action((options) => {
    const initResult = runInit(options.path);
    console.log(renderInitSummary(initResult));
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

    if (isNaN(port) || port < 1 || port > 65535) {
      console.error("Error: Invalid port number. Must be between 1 and 65535.");
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
      console.log(`  Listening on http://${options.hostname}:${port}`);
      console.log(`  Health check: http://${options.hostname}:${port}/api/health`);
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
