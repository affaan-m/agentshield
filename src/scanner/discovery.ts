import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, basename, extname, relative } from "node:path";
import type { ConfigFile, ConfigFileType, ScanTarget } from "../types.js";
import { isExampleLikePath } from "../source-context.js";

const IGNORED_DIRS = new Set([
  ".dmux",
  ".git",
  "node_modules",
  ".next",
  ".nuxt",
  ".turbo",
  ".cache",
  "coverage",
  "dist",
  "build",
  "out",
  "target",
  "vendor",
]);

const CLAUDE_ROOT_MARKERS = new Set([
  "claude.md",
  "settings.json",
  "settings.local.json",
  "mcp.json",
  ".claude.json",
]);

const HOOK_SHELL_EXTENSIONS = new Set([
  ".sh",
  ".bash",
  ".zsh",
]);

const HOOK_CODE_EXTENSIONS = new Set([
  ".js",
  ".cjs",
  ".mjs",
  ".ts",
  ".cts",
  ".mts",
  ".py",
  ".rb",
]);

const HOOK_IMPLEMENTATION_EXTENSIONS = new Set([
  ...HOOK_SHELL_EXTENSIONS,
  ...HOOK_CODE_EXTENSIONS,
]);

const PROJECT_ROOT_HOOK_VARS = new Set([
  "CLAUDE_PLUGIN_ROOT",
  "CLAUDE_PROJECT_DIR",
  "PWD",
]);

/**
 * Discover all Claude Code configuration files in a directory.
 * Looks for ~/.claude/ structure: CLAUDE.md, settings.json, mcp.json,
 * agents/, skills/, hooks/, rules/, contexts/
 */
export function discoverConfigFiles(rootPath: string): ScanTarget {
  const files: ConfigFile[] = [];
  const seenFiles = new Set<string>();
  const claudeRoots = new Set<string>([rootPath]);
  const exampleClaudeFiles = new Set<string>();

  walkForClaudeRoots(rootPath, rootPath, claudeRoots, exampleClaudeFiles);

  for (const exampleClaudeFile of [...exampleClaudeFiles].sort()) {
    addDiscoveredFile(rootPath, exampleClaudeFile, "claude-md", files, seenFiles);
  }

  for (const claudeRoot of [...claudeRoots].sort()) {
    scanClaudeRoot(rootPath, claudeRoot, files, seenFiles);
  }

  return { path: rootPath, files };
}

function walkForClaudeRoots(
  scanRoot: string,
  dirPath: string,
  claudeRoots: Set<string>,
  exampleClaudeFiles: Set<string>
): void {
  if (!existsSync(dirPath) || !statSync(dirPath).isDirectory()) return;

  const entries = readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      if (entry.name === ".claude") {
        claudeRoots.add(dirPath);
        continue;
      }
      walkForClaudeRoots(scanRoot, join(dirPath, entry.name), claudeRoots, exampleClaudeFiles);
      continue;
    }

    if (!entry.isFile()) continue;
    if (CLAUDE_ROOT_MARKERS.has(entry.name.toLowerCase())) {
      if (isExampleOnlyClaudeRoot(scanRoot, dirPath, entry.name)) {
        exampleClaudeFiles.add(join(dirPath, entry.name));
        continue;
      }
      claudeRoots.add(dirPath);
    }
  }
}

function isExampleOnlyClaudeRoot(
  scanRoot: string,
  dirPath: string,
  markerName: string
): boolean {
  if (markerName.toLowerCase() !== "claude.md") return false;

  const relativeDir = relative(scanRoot, dirPath);
  const segments = relativeDir
    .split(/[\\/]/)
    .filter(Boolean)
    .map((segment) => segment.toLowerCase())
    .join("/");

  if (!isExampleLikePath(segments)) {
    return false;
  }

  const hasRuntimeCompanion = [
    "settings.json",
    "settings.local.json",
    "mcp.json",
    ".claude.json",
  ].some((name) => existsSync(join(dirPath, name))) || existsSync(join(dirPath, ".claude"));

  return !hasRuntimeCompanion;
}

function scanClaudeRoot(
  scanRoot: string,
  claudeRoot: string,
  files: ConfigFile[],
  seenFiles: Set<string>
): void {
  // Direct config files
  const directFiles: ReadonlyArray<[string, ConfigFileType]> = [
    ["CLAUDE.md", "claude-md"],
    [".claude/CLAUDE.md", "claude-md"],
    ["settings.json", "settings-json"],
    ["settings.local.json", "settings-json"],
    [".claude/settings.json", "settings-json"],
    [".claude/settings.local.json", "settings-json"],
    ["mcp.json", "mcp-json"],
    [".claude/mcp.json", "mcp-json"],
    [".claude.json", "mcp-json"],
  ];

  for (const [relativePath, type] of directFiles) {
    const fullPath = join(claudeRoot, relativePath);
    if (existsSync(fullPath)) {
      addDiscoveredFile(scanRoot, fullPath, type, files, seenFiles);
    }
  }

  // Scan subdirectories
  const subdirs: ReadonlyArray<[string, ConfigFileType]> = [
    ["agents", "agent-md"],
    [".claude/agents", "agent-md"],
    ["subagents", "agent-md"],
    [".claude/subagents", "agent-md"],
    ["mcp-configs", "mcp-json"],
    [".claude/mcp-configs", "mcp-json"],
    ["mcp", "mcp-json"],
    [".claude/mcp", "mcp-json"],
    ["configs/mcp", "mcp-json"],
    ["config/mcp", "mcp-json"],
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
    ["slash-commands", "skill-md"],
    [".claude/slash-commands", "skill-md"],
  ];

  for (const [subdir, type] of subdirs) {
    const dirPath = join(claudeRoot, subdir);
    if (existsSync(dirPath) && statSync(dirPath).isDirectory()) {
      const entries = readdirSync(dirPath);
      for (const entry of entries) {
        const entryPath = join(dirPath, entry);
        if (statSync(entryPath).isFile()) {
          addDiscoveredFile(scanRoot, entryPath, inferType(entry, type), files, seenFiles);
        }
      }
    }
  }

  discoverReferencedHookScripts(scanRoot, claudeRoot, files, seenFiles);
}

function inferType(filename: string, defaultType: ConfigFileType): ConfigFileType {
  const ext = extname(filename).toLowerCase();
  const name = basename(filename).toLowerCase();

  if (name === "claude.md") return "claude-md";
  if (name === "settings.json" || name === "settings.local.json") return "settings-json";
  if (name === "mcp.json" || name === ".claude.json") return "mcp-json";

  if (HOOK_SHELL_EXTENSIONS.has(ext) && defaultType === "hook-script") return "hook-script";
  if (HOOK_CODE_EXTENSIONS.has(ext) && defaultType === "hook-script") return "hook-code";
  if (ext === ".sh" || ext === ".bash" || ext === ".zsh") return "hook-script";
  if (defaultType === "hook-script" && (ext === ".md" || ext === ".markdown")) {
    return "unknown";
  }
  if (defaultType === "mcp-json" && ext === ".json") return "mcp-json";
  if (defaultType === "mcp-json" && (ext === ".md" || ext === ".markdown")) {
    return "unknown";
  }
  if (defaultType === "agent-md" && ext === ".json") return "agent-md";
  if (defaultType === "skill-md" && ext === ".json") return "skill-md";
  if (ext === ".json") return "settings-json";
  if (ext === ".md" || ext === ".markdown") return defaultType;

  return "unknown";
}

function discoverReferencedHookScripts(
  scanRoot: string,
  claudeRoot: string,
  files: ConfigFile[],
  seenFiles: Set<string>
): void {
  const hookConfigPaths = [
    "settings.json",
    "settings.local.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    "hooks/hooks.json",
    ".claude/hooks/hooks.json",
  ];

  for (const relativeConfigPath of hookConfigPaths) {
    const fullPath = join(claudeRoot, relativeConfigPath);
    if (!existsSync(fullPath) || !statSync(fullPath).isFile()) continue;

    const content = readFileSync(fullPath, "utf-8");
    for (const candidate of extractHookReferencedPaths(content)) {
      const resolvedPath = resolveHookReferencedPath(scanRoot, claudeRoot, candidate);
      if (!resolvedPath) continue;
      addDiscoveredFile(scanRoot, resolvedPath, inferType(resolvedPath, "hook-script"), files, seenFiles);
    }
  }
}

function extractHookReferencedPaths(content: string): ReadonlyArray<string> {
  const referencedPaths = new Set<string>();

  for (const command of extractHookCommands(content)) {
    for (const candidate of extractCommandPathCandidates(command)) {
      referencedPaths.add(candidate);
    }
  }

  return [...referencedPaths];
}

function extractHookCommands(content: string): ReadonlyArray<string> {
  try {
    const config = JSON.parse(content);
    const hookGroups = config?.hooks;
    if (!hookGroups || typeof hookGroups !== "object") return [];

    const commands: string[] = [];

    for (const group of Object.values(hookGroups)) {
      if (!Array.isArray(group)) continue;

      for (const entry of group) {
        commands.push(...extractHookEntryCommands(entry));
      }
    }

    return commands;
  } catch {
    return [];
  }
}

function extractHookEntryCommands(entry: unknown): ReadonlyArray<string> {
  if (!entry || typeof entry !== "object") return [];

  const record = entry as {
    hook?: unknown;
    command?: unknown;
    hooks?: unknown;
  };
  const commands: string[] = [];

  if (typeof record.hook === "string" && record.hook.length > 0) {
    commands.push(record.hook);
  }

  if (typeof record.command === "string" && record.command.length > 0) {
    commands.push(record.command);
  }

  if (Array.isArray(record.hooks)) {
    for (const nestedEntry of record.hooks) {
      if (!nestedEntry || typeof nestedEntry !== "object") continue;
      const nestedCommand = (nestedEntry as { command?: unknown }).command;
      if (typeof nestedCommand === "string" && nestedCommand.length > 0) {
        commands.push(nestedCommand);
      }
    }
  }

  return commands;
}

function extractCommandPathCandidates(command: string): ReadonlyArray<string> {
  const pathPattern = /(?:(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)\/)?(?:\.{1,2}\/)?(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+\.(?:sh|bash|zsh|js|cjs|mjs|ts|cts|mts|py|rb)/gi;
  const candidates: string[] = [];

  for (const match of command.matchAll(pathPattern)) {
    const index = match.index ?? 0;
    if (command.slice(Math.max(0, index - 3), index) === "://") {
      continue;
    }
    candidates.push(match[0]);
  }

  return candidates;
}

function resolveHookReferencedPath(
  scanRoot: string,
  claudeRoot: string,
  candidate: string
): string | null {
  let normalized = candidate.replace(/\\/g, "/");

  if (/^https?:\/\//i.test(normalized) || normalized.startsWith("/") || normalized.startsWith("~")) {
    return null;
  }

  const envVarMatch = normalized.match(/^(?:\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*))\/(.*)$/);
  if (envVarMatch) {
    const varName = envVarMatch[1] ?? envVarMatch[2];
    if (!PROJECT_ROOT_HOOK_VARS.has(varName)) {
      return null;
    }
    normalized = envVarMatch[3];
  }

  if (normalized.startsWith("/")) return null;

  const fullPath = join(claudeRoot, normalized);
  if (!existsSync(fullPath) || !statSync(fullPath).isFile()) {
    return null;
  }

  const ext = extname(fullPath).toLowerCase();
  if (!HOOK_IMPLEMENTATION_EXTENSIONS.has(ext)) {
    return null;
  }

  const relativePath = relative(scanRoot, fullPath);
  if (relativePath.startsWith("..")) {
    return null;
  }

  return fullPath;
}

function addDiscoveredFile(
  scanRoot: string,
  fullPath: string,
  type: ConfigFileType,
  files: ConfigFile[],
  seenFiles: Set<string>
): void {
  const relativePath = relative(scanRoot, fullPath);
  if (seenFiles.has(relativePath)) return;

  const content = readFileSync(fullPath, "utf-8");
  files.push({ path: relativePath, type, content });
  seenFiles.add(relativePath);
}
