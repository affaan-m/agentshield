import type { ConfigFile } from "../types.js";
import type { ExtractedPackage } from "./types.js";

type JsonRecord = Record<string, unknown>;

interface NormalizedServerConfig {
  readonly command: string;
  readonly args: ReadonlyArray<string>;
}

/**
 * Extract npm package references from MCP config files.
 * Handles npx commands, direct package references, and git URLs.
 */
export function extractPackages(
  files: ReadonlyArray<ConfigFile>
): ReadonlyArray<ExtractedPackage> {
  const packages: ExtractedPackage[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    if (file.type !== "mcp-json" && file.type !== "settings-json") continue;

    const extracted = extractFromMcpConfig(file.content);
    for (const pkg of extracted) {
      const key = buildPackageDedupeKey(pkg);
      if (!seen.has(key)) {
        seen.add(key);
        packages.push(pkg);
      }
    }
  }

  return packages;
}

function extractFromMcpConfig(content: string): ReadonlyArray<ExtractedPackage> {
  try {
    const config = JSON.parse(content) as unknown;
    if (!isRecord(config) || !isRecord(config.mcpServers)) {
      return [];
    }

    const servers = config.mcpServers;
    const packages: ExtractedPackage[] = [];

    for (const [serverName, serverConfig] of Object.entries(servers)) {
      const server = normalizeServerConfig(serverConfig);
      if (!server) continue;

      const extracted = extractFromServerConfig(
        serverName,
        server.command,
        server.args ?? []
      );
      packages.push(...extracted);
    }

    return packages;
  } catch {
    return [];
  }
}

function extractFromServerConfig(
  serverName: string,
  command: string,
  args: ReadonlyArray<string>
): ReadonlyArray<ExtractedPackage> {
  const packages: ExtractedPackage[] = [];

  // Handle npx commands: npx @scope/package or npx package@version
  if (command === "npx" || command.endsWith("/npx")) {
    packages.push(...extractFromNpxArgs(serverName, args));
  }

  // Handle node commands running specific packages
  if (command === "node" || command.endsWith("/node")) {
    for (const arg of args) {
      if (arg.startsWith("-")) continue;
      // Check for node_modules paths
      const nodeModuleMatch = arg.match(
        /node_modules\/(@[^/]+\/[^/]+|[^/]+)/
      );
      if (nodeModuleMatch) {
        packages.push({
          name: nodeModuleMatch[1],
          source: "args",
          serverName,
        });
      }
    }
  }

  // Handle direct package commands (e.g., "mcp-server-git")
  if (!command.includes("/") && !command.startsWith(".")) {
    const parsed = parsePackageSpec(command);
    if (parsed && looksLikeNpmPackage(parsed.name)) {
      packages.push({
        ...parsed,
        source: "command",
        serverName,
      });
    }
  }

  // Check args for git URLs
  for (const arg of args) {
    const gitInfo = parseGitUrl(arg);
    if (gitInfo) {
      packages.push({
        name: gitInfo.repo,
        source: "git",
        serverName,
        gitUrl: arg,
        gitRef: gitInfo.ref,
      });
    }
  }

  return packages;
}

function buildPackageDedupeKey(pkg: ExtractedPackage): string {
  return [
    pkg.source,
    pkg.name,
    pkg.version ?? "latest",
    pkg.gitUrl ?? "",
    pkg.gitRef ?? "",
  ].join("|");
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeServerConfig(value: unknown): NormalizedServerConfig | null {
  if (!isRecord(value) || typeof value.command !== "string") {
    return null;
  }

  const args = Array.isArray(value.args)
    ? value.args.filter((arg): arg is string => typeof arg === "string")
    : [];

  return {
    command: value.command,
    args,
  };
}

function extractFromNpxArgs(
  serverName: string,
  args: ReadonlyArray<string>
): ReadonlyArray<ExtractedPackage> {
  const packages: ExtractedPackage[] = [];
  let sawExplicitPackageFlag = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-p" || arg === "--package") {
      sawExplicitPackageFlag = true;
      const spec = args[i + 1];
      const parsed = spec ? parsePackageSpec(spec) : null;
      if (parsed) {
        packages.push({
          ...parsed,
          source: "npx",
          serverName,
        });
      }
      i += 1;
      continue;
    }

    if (arg.startsWith("--package=")) {
      sawExplicitPackageFlag = true;
      const parsed = parsePackageSpec(arg.slice("--package=".length));
      if (parsed) {
        packages.push({
          ...parsed,
          source: "npx",
          serverName,
        });
      }
    }
  }

  if (packages.length > 0 || sawExplicitPackageFlag) {
    return packages;
  }

  for (const arg of args) {
    if (arg.startsWith("-")) continue;
    if (parseGitUrl(arg)) continue;
    const parsed = parsePackageSpec(arg);
    if (parsed) {
      packages.push({
        ...parsed,
        source: "npx",
        serverName,
      });
      break; // First non-flag arg is the package
    }
  }

  return packages;
}

/**
 * Parse a package specifier like "@scope/name@1.2.3" or "name@latest".
 */
function parsePackageSpec(
  spec: string
): { readonly name: string; readonly version?: string } | null {
  if (!spec || spec.startsWith("-") || spec.startsWith(".") || spec.startsWith("/")) {
    return null;
  }
  if (isUrlLikeSpec(spec)) {
    return null;
  }
  if (spec.includes("/") && !spec.startsWith("@")) {
    return null;
  }

  // Handle @scope/name@version
  if (spec.startsWith("@")) {
    const scopeEnd = spec.indexOf("/");
    if (scopeEnd === -1) return null;
    const afterScope = spec.slice(scopeEnd + 1);
    const versionIndex = afterScope.indexOf("@");
    if (versionIndex === -1) {
      return { name: spec };
    }
    return {
      name: spec.slice(0, scopeEnd + 1 + versionIndex),
      version: afterScope.slice(versionIndex + 1),
    };
  }

  // Handle name@version
  const atIndex = spec.indexOf("@");
  if (atIndex === -1) {
    return { name: spec };
  }
  return {
    name: spec.slice(0, atIndex),
    version: spec.slice(atIndex + 1),
  };
}

function isUrlLikeSpec(spec: string): boolean {
  return /^(?:[a-z][a-z0-9+.-]*:|git@)/i.test(spec) || spec.includes("://");
}

/**
 * Check if a string looks like an npm package name.
 */
function looksLikeNpmPackage(name: string): boolean {
  if (name.startsWith("@")) return true;
  if (name.includes("-mcp") || name.includes("mcp-")) return true;
  if (name.includes("-server") || name.includes("server-")) return true;
  return false;
}

/**
 * Parse a git URL and extract repo name and ref.
 */
function parseGitUrl(
  url: string
): { readonly repo: string; readonly ref?: string } | null {
  const patterns = [
    /^(?:git\+)?https?:\/\/github\.com\/([^#@]+?)(?:[#@](.+))?$/i,
    /^git:\/\/github\.com\/([^#@]+?)(?:[#@](.+))?$/i,
    /^git\+ssh:\/\/git@github\.com\/([^#@]+?)(?:[#@](.+))?$/i,
    /^git@github\.com:([^#@]+?)(?:[#@](.+))?$/i,
    /^github:([^#@]+?)(?:[#@](.+))?$/i,
  ];

  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (!match) continue;

    return {
      repo: match[1].replace(/\.git$/, ""),
      ref: match[2],
    };
  }

  return null;
}
