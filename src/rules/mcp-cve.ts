import type { ConfigFile, Finding, Rule } from "../types.js";
import {
  checkServerPackage,
  checkPackageName,
  type VulnerableServer,
  type MaliciousPackage,
} from "../threat-intel/cve-database.js";

/**
 * MCP rules that cross-reference scanned configurations against
 * the CVE database and known-malicious package list.
 */

function extractPackagesFromServer(
  serverConfig: Record<string, unknown>
): ReadonlyArray<string> {
  const command = (serverConfig.command ?? "") as string;
  const args = (serverConfig.args ?? []) as string[];
  const packages: string[] = [];

  // For npx, the package is in args (skip flags)
  if (command === "npx" || command === "bunx" || command === "pnpm" || command === "yarn") {
    for (const arg of args) {
      if (arg.startsWith("-")) continue;
      packages.push(arg.split("@").length > 2 ? arg.substring(0, arg.lastIndexOf("@")) : arg);
      break; // First non-flag arg is the package
    }
  }

  return packages;
}

const rawCveMcpRules: ReadonlyArray<Rule> = [
  {
    id: "mcp-known-vulnerable-server",
    name: "Known Vulnerable MCP Server Package",
    description:
      "Cross-references MCP server packages against the CVE database to detect known-vulnerable servers",
    severity: "critical",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = (server ?? {}) as Record<string, unknown>;
          const command = (serverConfig.command ?? "") as string;
          const args = (serverConfig.args ?? []) as string[];

          const vulnServer = checkServerPackage(command, args);
          if (vulnServer) {
            const cveList = vulnServer.cveIds.join(", ");
            findings.push({
              id: `mcp-known-vuln-${name}`,
              severity: "critical",
              category: "mcp",
              title: `MCP server "${name}" uses known-vulnerable package: ${vulnServer.packageName}`,
              description: `${vulnServer.description} Known CVEs: ${cveList}.${vulnServer.fixedIn ? ` Fixed in ${vulnServer.fixedIn}.` : " Check for updates."}`,
              file: file.path,
              evidence: `package: ${vulnServer.packageName}, CVEs: ${cveList}`,
              fix: {
                description: "Update to a patched version or replace with a secure alternative",
                before: vulnServer.packageName,
                after: `${vulnServer.packageName}@latest (verify patch)`,
                auto: false,
              },
            });
          }
        }
      } catch {
        // Not valid JSON
      }

      return findings;
    },
  },
  {
    id: "mcp-malicious-package",
    name: "Known Malicious Package in MCP Config",
    description:
      "Checks MCP server configurations for known-malicious and typosquatted packages",
    severity: "critical",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = (server ?? {}) as Record<string, unknown>;
          const command = (serverConfig.command ?? "") as string;
          const args = (serverConfig.args ?? []) as string[];

          // Check command itself
          const cmdMatch = checkPackageName(command);
          if (cmdMatch) {
            findings.push(buildMaliciousFinding(name, command, cmdMatch, file.path));
            continue;
          }

          // Check args for package names
          for (const arg of args) {
            if (arg.startsWith("-")) continue;

            // Strip version suffix for lookup
            const pkgName = arg.includes("@") && !arg.startsWith("@")
              ? arg.substring(0, arg.indexOf("@"))
              : arg.startsWith("@") && arg.split("@").length > 2
                ? arg.substring(0, arg.lastIndexOf("@"))
                : arg;

            const match = checkPackageName(pkgName);
            if (match) {
              findings.push(buildMaliciousFinding(name, pkgName, match, file.path));
              break;
            }
          }
        }
      } catch {
        // Not valid JSON
      }

      return findings;
    },
  },
];

function buildMaliciousFinding(
  serverName: string,
  packageName: string,
  match: MaliciousPackage,
  filePath: string
): Finding {
  const typeLabel = match.type === "typosquat"
    ? "typosquat"
    : match.type === "compromised"
      ? "compromised package"
      : "known-malicious package";

  return {
    id: `mcp-malicious-pkg-${serverName}`,
    severity: "critical",
    category: "mcp",
    title: `MCP server "${serverName}" uses ${typeLabel}: ${packageName}`,
    description: `${match.description}${match.legitimatePackage ? ` Did you mean "${match.legitimatePackage}"?` : ""}`,
    file: filePath,
    evidence: `package: ${packageName}, type: ${match.type}`,
    fix: {
      description: match.legitimatePackage
        ? `Replace with the legitimate package: ${match.legitimatePackage}`
        : "Remove this package immediately",
      before: packageName,
      after: match.legitimatePackage ?? "# REMOVE — malicious package",
      auto: false,
    },
  };
}

export const cveMcpRules: ReadonlyArray<Rule> = rawCveMcpRules;
