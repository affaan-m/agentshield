import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, basename, extname, relative } from "node:path";
import type { ConfigFile, ConfigFileType, ScanTarget } from "../types.js";

/**
 * Discover all Claude Code configuration files in a directory.
 * Looks for ~/.claude/ structure: CLAUDE.md, settings.json, mcp.json,
 * agents/, skills/, hooks/, rules/, contexts/
 */
export function discoverConfigFiles(rootPath: string): ScanTarget {
  const files: ConfigFile[] = [];

  // Direct config files
  const directFiles: ReadonlyArray<[string, ConfigFileType]> = [
    ["CLAUDE.md", "claude-md"],
    [".claude/CLAUDE.md", "claude-md"],
    ["settings.json", "settings-json"],
    [".claude/settings.json", "settings-json"],
    ["mcp.json", "mcp-json"],
    [".claude/mcp.json", "mcp-json"],
    [".claude.json", "mcp-json"],
  ];

  for (const [relativePath, type] of directFiles) {
    const fullPath = join(rootPath, relativePath);
    if (existsSync(fullPath)) {
      const content = readFileSync(fullPath, "utf-8");
      files.push({ path: relative(rootPath, fullPath), type, content });
    }
  }

  // Scan subdirectories
  const subdirs: ReadonlyArray<[string, ConfigFileType]> = [
    ["agents", "agent-md"],
    [".claude/agents", "agent-md"],
    ["skills", "skill-md"],
    [".claude/skills", "skill-md"],
    ["hooks", "hook-script"],
    [".claude/hooks", "hook-script"],
    ["rules", "rule-md"],
    [".claude/rules", "rule-md"],
    ["contexts", "context-md"],
    [".claude/contexts", "context-md"],
    ["commands", "skill-md"],
    [".claude/commands", "skill-md"],
  ];

  for (const [subdir, type] of subdirs) {
    const dirPath = join(rootPath, subdir);
    if (existsSync(dirPath) && statSync(dirPath).isDirectory()) {
      const entries = readdirSync(dirPath);
      for (const entry of entries) {
        const entryPath = join(dirPath, entry);
        if (statSync(entryPath).isFile()) {
          const content = readFileSync(entryPath, "utf-8");
          files.push({
            path: relative(rootPath, entryPath),
            type: inferType(entry, type),
            content,
          });
        }
      }
    }
  }

  return { path: rootPath, files };
}

function inferType(filename: string, defaultType: ConfigFileType): ConfigFileType {
  const ext = extname(filename).toLowerCase();
  const name = basename(filename).toLowerCase();

  if (name === "claude.md") return "claude-md";
  if (name === "settings.json") return "settings-json";
  if (name === "mcp.json" || name === ".claude.json") return "mcp-json";

  if (ext === ".sh" || ext === ".bash" || ext === ".zsh") return "hook-script";
  if (ext === ".json") return "settings-json";
  if (ext === ".md" || ext === ".markdown") return defaultType;

  return "unknown";
}
