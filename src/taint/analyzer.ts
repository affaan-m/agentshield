/**
 * Static taint analysis for AI agent configuration files.
 *
 * Tracks data flow from untrusted SOURCES (env vars, file content,
 * user input, network) through to dangerous SINKS (shell exec, eval,
 * network send, file write) and flags critical flows.
 */

import type { TaintFlow, TaintNode, TaintResult, Severity } from "../types.js";

// ─── Source Patterns ────────────────────────────────────────

interface SourcePattern {
  readonly regex: RegExp;
  readonly label: string;
  readonly sourceType: "env_var" | "file_content" | "user_input" | "network" | "cli_arg";
}

const SOURCE_PATTERNS: ReadonlyArray<SourcePattern> = [
  // Environment variable references (shell-style)
  { regex: /\$([A-Z_][A-Z0-9_]*)/g, label: "env:$1", sourceType: "env_var" },
  { regex: /\$\{([A-Z_][A-Z0-9_]*)\}/g, label: "env:$1", sourceType: "env_var" },
  { regex: /process\.env\.([A-Z_][A-Z0-9_]*)/g, label: "env:$1", sourceType: "env_var" },
  // JSON env block inline (single-line): "env": { "KEY": "val" }
  { regex: /env:\s*\{[^}]*"([A-Z_][A-Z0-9_]*)"\s*:/g, label: "env:$1", sourceType: "env_var" },
  { regex: /env:\s*\{[^}]*([A-Z_][A-Z0-9_]*)\s*:/g, label: "env:$1", sourceType: "env_var" },
  // JSON env block multi-line: lines like "SECRET_TOKEN": "value" inside env objects
  { regex: /"([A-Z_][A-Z0-9_]{2,})"\s*:\s*"/g, label: "env:$1", sourceType: "env_var" },

  // File content interpolation (common in hooks/agents)
  { regex: /\$\{file\}/gi, label: "interpolated:file", sourceType: "file_content" },
  { regex: /\$\{content\}/gi, label: "interpolated:content", sourceType: "file_content" },
  { regex: /\$\{filePath\}/gi, label: "interpolated:filePath", sourceType: "file_content" },
  { regex: /\$\{path\}/gi, label: "interpolated:path", sourceType: "file_content" },
  { regex: /\$\{input\}/gi, label: "interpolated:input", sourceType: "user_input" },
  { regex: /\$\{query\}/gi, label: "interpolated:query", sourceType: "user_input" },
  { regex: /\$\{prompt\}/gi, label: "interpolated:prompt", sourceType: "user_input" },
  { regex: /\$\{url\}/gi, label: "interpolated:url", sourceType: "network" },

  // stdin / user input
  { regex: /\bstdin\b/gi, label: "stdin", sourceType: "user_input" },
  { regex: /\bread\s+-/g, label: "bash:read", sourceType: "user_input" },

  // CLI arguments
  { regex: /\$[@*#\d]/g, label: "cli:positional", sourceType: "cli_arg" },
  { regex: /\$\{[@*#\d]\}/g, label: "cli:positional", sourceType: "cli_arg" },
];

// ─── Sink Patterns ──────────────────────────────────────────

interface SinkPattern {
  readonly regex: RegExp;
  readonly label: string;
  readonly sinkType: "shell_exec" | "network_send" | "file_write" | "eval" | "process_spawn";
}

// Note: These patterns detect dangerous sinks in *scanned config files*,
// not in this codebase. The strings here are detection signatures.
const SINK_PATTERNS: ReadonlyArray<SinkPattern> = [
  // Shell execution
  { regex: /\bsh\s+-c\b/g, label: "sh -c", sinkType: "shell_exec" },
  { regex: /\bbash\s+-c\b/g, label: "bash -c", sinkType: "shell_exec" },
  { regex: /\bexec\s+/g, label: "exec", sinkType: "shell_exec" },
  { regex: /\beval\s+/g, label: "eval", sinkType: "eval" },
  { regex: /\bsystem\s*\(/g, label: "system()", sinkType: "shell_exec" },
  { regex: /\bspawn\s*\(/g, label: "spawn()", sinkType: "process_spawn" },
  { regex: /\bexecSync\s*\(/g, label: "execSync()", sinkType: "shell_exec" },
  { regex: /\bexecFile\s*\(/g, label: "execFile()", sinkType: "process_spawn" },

  // Network sends
  { regex: /\bcurl\s+/g, label: "curl", sinkType: "network_send" },
  { regex: /\bwget\s+/g, label: "wget", sinkType: "network_send" },
  { regex: /\bfetch\s*\(/g, label: "fetch()", sinkType: "network_send" },
  { regex: /https?:\/\/[^\s"'`]+/g, label: "http_url", sinkType: "network_send" },
  { regex: /\bnc\s+-/g, label: "netcat", sinkType: "network_send" },

  // File writes
  { regex: />\s*[^\s&|]+/g, label: "redirect:>", sinkType: "file_write" },
  { regex: />>\s*[^\s&|]+/g, label: "redirect:>>", sinkType: "file_write" },
  { regex: /\btee\s+/g, label: "tee", sinkType: "file_write" },
  { regex: /writeFile/g, label: "writeFile", sinkType: "file_write" },

  // Pipe to dangerous commands
  { regex: /\|\s*sh\b/g, label: "pipe:sh", sinkType: "shell_exec" },
  { regex: /\|\s*bash\b/g, label: "pipe:bash", sinkType: "shell_exec" },
  { regex: /\|\s*xargs\b/g, label: "pipe:xargs", sinkType: "shell_exec" },

  // npx auto-install (supply chain)
  { regex: /npx\s+-y\s+/g, label: "npx -y (auto-install)", sinkType: "process_spawn" },
  { regex: /npx\s+--yes\s+/g, label: "npx --yes (auto-install)", sinkType: "process_spawn" },
];

// ─── Severity Classification ────────────────────────────────

/**
 * Determine the severity of a taint flow based on source/sink combination.
 * Untrusted input flowing to shell execution is always critical.
 */
function classifyFlowSeverity(
  sourceType: SourcePattern["sourceType"],
  sinkType: SinkPattern["sinkType"]
): Severity {
  // Critical: any untrusted source -> code execution
  if (
    (sourceType === "user_input" || sourceType === "file_content" || sourceType === "network") &&
    (sinkType === "shell_exec" || sinkType === "eval" || sinkType === "process_spawn")
  ) {
    return "critical";
  }

  // High: env vars -> shell (could contain secrets sent to network)
  if (sourceType === "env_var" && sinkType === "network_send") {
    return "high";
  }

  // High: any source -> eval
  if (sinkType === "eval") {
    return "high";
  }

  // High: file content / user input -> network (data exfiltration)
  if (
    (sourceType === "file_content" || sourceType === "user_input") &&
    sinkType === "network_send"
  ) {
    return "high";
  }

  // Medium: env var -> shell execution
  if (sourceType === "env_var" && (sinkType === "shell_exec" || sinkType === "process_spawn")) {
    return "medium";
  }

  // Medium: any source -> file write
  if (sinkType === "file_write") {
    return "medium";
  }

  // Low: everything else
  return "low";
}

// ─── Line-Level Matching ────────────────────────────────────

interface LineMatch {
  readonly line: number;
  readonly content: string;
  readonly captures: ReadonlyArray<string>;
}

function findMatchingLines(content: string, regex: RegExp): ReadonlyArray<LineMatch> {
  const lines = content.split("\n");
  const matches: LineMatch[] = [];

  for (let i = 0; i < lines.length; i++) {
    const testRegex = new RegExp(regex.source, regex.flags);
    const match = testRegex.exec(lines[i]);
    if (match) {
      matches.push({
        line: i + 1,
        content: lines[i].trim(),
        captures: match.slice(1),
      });
    }
  }

  return matches;
}

/**
 * Replace $1, $2, etc. in a template string with actual captured values.
 */
function resolveLabel(template: string, captures: ReadonlyArray<string>): string {
  let result = template;
  for (let i = 0; i < captures.length; i++) {
    result = result.replace(`$${i + 1}`, captures[i] ?? "");
  }
  return result;
}

// ─── Main Taint Analyzer ────────────────────────────────────

/**
 * Analyze configuration files for taint flows -- untrusted data
 * flowing from sources to dangerous sinks.
 *
 * This is a static, string-level analysis. It does not run code
 * or perform interprocedural analysis, but catches the most common
 * and dangerous patterns in AI agent configurations.
 */
export function analyzeTaint(
  files: ReadonlyArray<{ readonly path: string; readonly content: string }>
): TaintResult {
  const allSources: TaintNode[] = [];
  const allSinks: TaintNode[] = [];
  const allFlows: TaintFlow[] = [];

  for (const file of files) {
    const fileSources: Array<{ node: TaintNode; pattern: SourcePattern }> = [];
    const fileSinks: Array<{ node: TaintNode; pattern: SinkPattern }> = [];

    // Find all sources in this file
    for (const sourcePattern of SOURCE_PATTERNS) {
      const matches = findMatchingLines(file.content, sourcePattern.regex);
      for (const match of matches) {
        const label = resolveLabel(sourcePattern.label, match.captures);
        const node: TaintNode = {
          file: file.path,
          line: match.line,
          label,
          type: "source",
        };
        fileSources.push({ node, pattern: sourcePattern });
        allSources.push(node);
      }
    }

    // Find all sinks in this file
    for (const sinkPattern of SINK_PATTERNS) {
      const matches = findMatchingLines(file.content, sinkPattern.regex);
      for (const match of matches) {
        const label = resolveLabel(sinkPattern.label, match.captures);
        const node: TaintNode = {
          file: file.path,
          line: match.line,
          label,
          type: "sink",
        };
        fileSinks.push({ node, pattern: sinkPattern });
        allSinks.push(node);
      }
    }

    // Check for intra-line flows (source and sink on the same line)
    const lines = file.content.split("\n");
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const lineNum = lineIdx + 1;
      const lineContent = lines[lineIdx];

      const lineSources = fileSources.filter((s) => s.node.line === lineNum);
      const lineSinks = fileSinks.filter((s) => s.node.line === lineNum);

      for (const source of lineSources) {
        for (const sink of lineSinks) {
          const severity = classifyFlowSeverity(
            source.pattern.sourceType,
            sink.pattern.sinkType
          );

          allFlows.push({
            source: source.node,
            sink: sink.node,
            path: [
              `${source.node.label} on line ${lineNum}`,
              `flows directly to ${sink.node.label} on same line`,
            ],
            severity,
            description: `${source.pattern.sourceType} "${source.node.label}" flows to ${sink.pattern.sinkType} "${sink.node.label}" — ${lineContent.trim()}`,
          });
        }
      }
    }

    // Check for proximity flows (source near sink within a few lines)
    const PROXIMITY_WINDOW = 5;
    for (const source of fileSources) {
      for (const sink of fileSinks) {
        const sourceLine = source.node.line ?? 0;
        const sinkLine = sink.node.line ?? 0;

        // Skip same-line flows (already handled above)
        if (sourceLine === sinkLine) continue;

        // Only flag if source appears before sink and within window
        if (sinkLine > sourceLine && sinkLine - sourceLine <= PROXIMITY_WINDOW) {
          const severity = classifyFlowSeverity(
            source.pattern.sourceType,
            sink.pattern.sinkType
          );

          // Only report medium+ proximity flows to reduce noise
          if (severity === "low") continue;

          allFlows.push({
            source: source.node,
            sink: sink.node,
            path: [
              `${source.node.label} on line ${sourceLine}`,
              `flows to ${sink.node.label} on line ${sinkLine} (${sinkLine - sourceLine} lines apart)`,
            ],
            severity,
            description: `${source.pattern.sourceType} "${source.node.label}" (line ${sourceLine}) flows to ${sink.pattern.sinkType} "${sink.node.label}" (line ${sinkLine})`,
          });
        }
      }
    }
  }

  // Cross-file flow detection: env vars defined in one file, used in sinks in another
  const envDefinitions = allSources.filter((s) => s.label.startsWith("env:"));
  for (const envSource of envDefinitions) {
    const envName = envSource.label.replace("env:", "");

    for (const file of files) {
      if (file.path === envSource.file) continue;

      // Check if the env var name appears near sinks in another file
      const lines = file.content.split("\n");
      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const lineContent = lines[lineIdx];
        if (!lineContent.includes(envName)) continue;

        // Check if this line also contains a sink
        for (const sinkPattern of SINK_PATTERNS) {
          const testRegex = new RegExp(sinkPattern.regex.source, sinkPattern.regex.flags);
          if (testRegex.test(lineContent)) {
            const severity = classifyFlowSeverity("env_var", sinkPattern.sinkType);

            allFlows.push({
              source: envSource,
              sink: {
                file: file.path,
                line: lineIdx + 1,
                label: sinkPattern.label,
                type: "sink",
              },
              path: [
                `env var "${envName}" defined in ${envSource.file}:${envSource.line}`,
                `referenced near ${sinkPattern.label} in ${file.path}:${lineIdx + 1}`,
              ],
              severity,
              description: `Cross-file flow: env "${envName}" (${envSource.file}) -> ${sinkPattern.sinkType} (${file.path}:${lineIdx + 1})`,
            });
          }
        }
      }
    }
  }

  // Deduplicate flows by description
  const seenDescriptions = new Set<string>();
  const uniqueFlows = allFlows.filter((flow) => {
    if (seenDescriptions.has(flow.description)) return false;
    seenDescriptions.add(flow.description);
    return true;
  });

  // Sort by severity (critical first)
  const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sortedFlows = [...uniqueFlows].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  // Deduplicate sources and sinks
  const uniqueSources = deduplicateNodes(allSources);
  const uniqueSinks = deduplicateNodes(allSinks);

  return {
    flows: sortedFlows,
    sources: uniqueSources,
    sinks: uniqueSinks,
  };
}

function deduplicateNodes(nodes: ReadonlyArray<TaintNode>): ReadonlyArray<TaintNode> {
  const seen = new Set<string>();
  return nodes.filter((node) => {
    const key = `${node.file}:${node.line}:${node.label}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
