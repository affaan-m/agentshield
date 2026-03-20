import type { ConfigFile } from "../types.js";
import type { ExtractedPackage } from "./types.js";

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
      const key = `${pkg.name}@${pkg.version ?? "latest"}`;
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
    const config = JSON.parse(content);
    const servers = config.mcpServers ?? {};
    const packages: ExtractedPackage[] = [];

    for (const [serverName, serverConfig] of Object.entries(servers)) {
      const server = serverConfig as {
        command?: string;
        args?: string[];
        url?: string;
      };

      if (!server.command) continue;

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
    for (const arg of args) {
      if (arg.startsWith("-")) continue;
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

/**
 * Parse a package specifier like "@scope/name@1.2.3" or "name@latest".
 */
function parsePackageSpec(
  spec: string
): { readonly name: string; readonly version?: string } | null {
  if (!spec || spec.startsWith("-") || spec.startsWith(".") || spec.startsWith("/")) {
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
  // Match github.com/org/repo or git+https://... patterns
  const match = url.match(
    /(?:git\+)?https?:\/\/github\.com\/([^/]+\/[^/#@]+)(?:[#@](.+))?/
  );
  if (match) {
    return {
      repo: match[1].replace(/\.git$/, ""),
      ref: match[2],
    };
  }

  // Match git:// URLs
  const gitMatch = url.match(
    /git:\/\/github\.com\/([^/]+\/[^/#@]+)(?:[#@](.+))?/
  );
  if (gitMatch) {
    return {
      repo: gitMatch[1].replace(/\.git$/, ""),
      ref: gitMatch[2],
    };
  }

  return null;
}
