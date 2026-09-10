import { readFileSync, existsSync, readdirSync, readlinkSync, statSync, lstatSync } from "node:fs";
import type { Stats } from "node:fs";
import { join, basename, extname, relative } from "node:path";
import type { ConfigFile, ConfigFileType, DanglingSymlink, ScanTarget } from "../types.js";
import { isExampleLikePath } from "../source-context.js";
import { toPosixPath } from "./paths.js";

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
  ".mcp.json",
  ".claude.json",
  "agents.md",
  "opencode.json",
]);

/** Directories whose presence makes their parent a scan root. */
const HARNESS_ROOT_DIRS = new Set([".codex", ".claude-plugin", ".cursor", ".gemini", ".opencode"]);

const CLAUDE_RUNTIME_COMPANION_NAMES: ReadonlyArray<string> = [
  "settings.json",
  "settings.local.json",
  "mcp.json",
  ".mcp.json",
  ".claude.json",
];

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

const PACKAGE_MANAGER_CONFIG_FILES = new Set([
  "package.json",
  "package-lock.json",
  ".npmrc",
  ".pnpmrc",
  ".yarnrc",
  ".yarnrc.yml",
  "pnpm-workspace.yaml",
  "pnpm-workspace.yml",
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
  const danglingSymlinks: DanglingSymlink[] = [];
  const seenFiles = new Set<string>();
  const claudeRoots = new Set<string>([rootPath]);
  const exampleClaudeFiles = new Set<string>();

  walkForClaudeRoots(rootPath, rootPath, claudeRoots, exampleClaudeFiles);

  for (const exampleClaudeFile of [...exampleClaudeFiles].sort()) {
    addDiscoveredFile(rootPath, exampleClaudeFile, "claude-md", files, seenFiles);
  }

  for (const claudeRoot of [...claudeRoots].sort()) {
    scanClaudeRoot(rootPath, claudeRoot, files, seenFiles, danglingSymlinks);
  }

  return { path: rootPath, files, danglingSymlinks };
}

/**
 * statSync that follows symlinks but never throws. Returns null when the
 * path is missing, a dangling symlink, or otherwise unreadable.
 */
function statOrNull(path: string): Stats | null {
  try {
    return statSync(path);
  } catch {
    return null;
  }
}

function isDanglingSymlink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

function readSymlinkTarget(path: string): string {
  try {
    return readlinkSync(path);
  } catch {
    return "";
  }
}

function walkForClaudeRoots(
  scanRoot: string,
  dirPath: string,
  claudeRoots: Set<string>,
  exampleClaudeFiles: Set<string>
): void {
  if (!statOrNull(dirPath)?.isDirectory()) return;

  const entries = readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      if (HARNESS_ROOT_DIRS.has(entry.name)) {
        claudeRoots.add(dirPath);
      }
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

  const hasRuntimeCompanion = CLAUDE_RUNTIME_COMPANION_NAMES.some((name) =>
    existsSync(join(dirPath, name))
  ) || existsSync(join(dirPath, ".claude"));

  return !hasRuntimeCompanion;
}

function scanClaudeRoot(
  scanRoot: string,
  claudeRoot: string,
  files: ConfigFile[],
  seenFiles: Set<string>,
  danglingSymlinks: DanglingSymlink[]
): void {
  // Direct config files
  const directFiles: ReadonlyArray<[string, ConfigFileType]> = [
    ["CLAUDE.md", "claude-md"],
    [".claude/CLAUDE.md", "claude-md"],
    ["settings.json", "settings-json"],
    ["settings.local.json", "settings-json"],
    [".claude/settings.json", "settings-json"],
    [".claude/settings.local.json", "settings-json"],
    [".claude/router_runtime.js", "hook-code"],
    [".claude/setup.mjs", "hook-code"],
    [".vscode/tasks.json", "settings-json"],
    [".zed/settings.json", "settings-json"],
    [".zed/tasks.json", "settings-json"],
    ["package.json", "package-manager-config"],
    ["package-lock.json", "package-manager-config"],
    [".npmrc", "package-manager-config"],
    [".pnpmrc", "package-manager-config"],
    [".yarnrc", "package-manager-config"],
    [".yarnrc.yml", "package-manager-config"],
    ["pnpm-workspace.yaml", "package-manager-config"],
    ["pnpm-workspace.yml", "package-manager-config"],
    [".github/workflows/codeql_analysis.yml", "settings-json"],
    [".github/workflows/codeql_analysis.yaml", "settings-json"],
    [".config/gh-token-monitor/token", "hook-script"],
    [".config/systemd/user/gh-token-monitor.service", "hook-script"],
    [".local/bin/gh-token-monitor.sh", "hook-script"],
    ["Library/LaunchAgents/com.user.gh-token-monitor.plist", "settings-json"],
    ["mcp.json", "mcp-json"],
    [".mcp.json", "mcp-json"],
    [".claude/mcp.json", "mcp-json"],
    [".claude.json", "mcp-json"],
    ["CLAUDE.local.md", "claude-md"],
    // Claude Code plugin manifests
    [".claude-plugin/plugin.json", "plugin-manifest"],
    [".claude-plugin/marketplace.json", "plugin-manifest"],
    // Shared and other-harness instruction files
    ["AGENTS.md", "agents-md"],
    ["AGENTS.override.md", "agents-md"],
    [".codex/AGENTS.md", "agents-md"],
    ["GEMINI.md", "agents-md"],
    [".gemini/GEMINI.md", "agents-md"],
    [".github/copilot-instructions.md", "agents-md"],
    [".cursorrules", "agents-md"],
    [".windsurfrules", "agents-md"],
    [".clinerules", "agents-md"],
    // OpenAI Codex CLI
    ["config.toml", "codex-toml"],
    [".codex/config.toml", "codex-toml"],
    [".codex/hooks.json", "harness-json"],
    // Hermes agent
    ["config.yaml", "hermes-yaml"],
    // Other harness MCP configs share the MCP rule set
    [".cursor/mcp.json", "mcp-json"],
    [".codeium/windsurf/mcp_config.json", "mcp-json"],
    ["mcp_config.json", "mcp-json"],
    [".roo/mcp.json", "mcp-json"],
    [".cline/mcp.json", "mcp-json"],
    ["cline_mcp_settings.json", "mcp-json"],
    ["mcp_settings.json", "mcp-json"],
    // Other harness settings and hooks
    [".cursor/hooks.json", "harness-json"],
    [".gemini/settings.json", "harness-json"],
    ["opencode.json", "harness-json"],
    ["opencode.jsonc", "harness-json"],
    [".opencode/opencode.json", "harness-json"],
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
    [".vscode", "hook-script"],
    [".zed", "hook-script"],
    ["rules", "rule-md"],
    [".claude/rules", "rule-md"],
    ["contexts", "context-md"],
    [".claude/contexts", "context-md"],
    ["commands", "command-md"],
    [".claude/commands", "command-md"],
    ["slash-commands", "command-md"],
    [".claude/slash-commands", "command-md"],
    // Other harness instruction and agent directories
    [".github/agents", "agents-md"],
    [".github/instructions", "agents-md"],
    [".cursor/rules", "agents-md"],
    [".windsurf/rules", "agents-md"],
    [".roo/rules", "agents-md"],
    [".clinerules", "agents-md"],
    // Codex agent roles
    [".codex/agents", "codex-toml"],
  ];

  for (const [subdir, type] of subdirs) {
    const dirPath = join(claudeRoot, subdir);
    if (!statOrNull(dirPath)?.isDirectory()) continue;

    const entries = readdirSync(dirPath);
    for (const entry of entries) {
      const entryPath = join(dirPath, entry);
      const entryStat = statOrNull(entryPath);
      if (entryStat === null) {
        if (isDanglingSymlink(entryPath)) {
          danglingSymlinks.push({
            path: toPosixPath(relative(scanRoot, entryPath)),
            target: readSymlinkTarget(entryPath),
            type,
          });
        }
        continue;
      }
      if (entryStat.isFile()) {
        addDiscoveredFile(scanRoot, entryPath, inferType(entry, type), files, seenFiles);
      }
    }
  }

  discoverHermesProfiles(scanRoot, claudeRoot, files, seenFiles);
  discoverReferencedHookScripts(scanRoot, claudeRoot, files, seenFiles);
}

/**
 * Hermes keeps one config.yaml per profile under profiles/<name>/.
 */
function discoverHermesProfiles(
  scanRoot: string,
  claudeRoot: string,
  files: ConfigFile[],
  seenFiles: Set<string>
): void {
  const profilesDir = join(claudeRoot, "profiles");
  if (!statOrNull(profilesDir)?.isDirectory()) return;
  for (const entry of readdirSync(profilesDir)) {
    const configPath = join(profilesDir, entry, "config.yaml");
    if (statOrNull(configPath)?.isFile()) {
      addDiscoveredFile(scanRoot, configPath, "hermes-yaml", files, seenFiles);
    }
  }
}

function inferType(filename: string, defaultType: ConfigFileType): ConfigFileType {
  const ext = extname(filename).toLowerCase();
  const name = basename(filename).toLowerCase();

  if (PACKAGE_MANAGER_CONFIG_FILES.has(name)) return "package-manager-config";
  if (name === "claude.md") return "claude-md";
  if (name === "settings.json" || name === "settings.local.json") return "settings-json";
  if (name === "mcp.json" || name === ".mcp.json" || name === ".claude.json")
    return "mcp-json";

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
  if (defaultType === "command-md" && ext === ".json") return "command-md";
  if (defaultType === "agents-md" && (ext === ".md" || ext === ".mdc" || ext === ".markdown" || ext === ""))
    return "agents-md";
  if (defaultType === "codex-toml") return ext === ".toml" ? "codex-toml" : "unknown";
  if (defaultType === "hermes-yaml") return ext === ".yaml" || ext === ".yml" ? "hermes-yaml" : "unknown";
  if (defaultType === "harness-json") return ext === ".json" || ext === ".jsonc" ? "harness-json" : "unknown";
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
    if (!statOrNull(fullPath)?.isFile()) continue;

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
  if (!statOrNull(fullPath)?.isFile()) {
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
  const relativePath = toPosixPath(relative(scanRoot, fullPath));
  if (seenFiles.has(relativePath)) return;

  const content = readFileSync(fullPath, "utf-8");
  files.push({ path: relativePath, type, content });
  seenFiles.add(relativePath);
}
