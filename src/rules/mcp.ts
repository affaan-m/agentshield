import type { ConfigFile, Finding, Rule } from "../types.js";

/**
 * Known MCP servers and their risk profiles.
 */
const MCP_RISK_PROFILES: ReadonlyArray<{
  readonly namePattern: RegExp;
  readonly risk: "critical" | "high" | "medium" | "low";
  readonly description: string;
  readonly recommendation: string;
}> = [
  {
    namePattern: /filesystem/i,
    risk: "high",
    description: "Filesystem MCP grants read/write access to the file system",
    recommendation:
      "Restrict to specific directories using allowedDirectories config",
  },
  {
    namePattern: /puppeteer|playwright|browser/i,
    risk: "high",
    description:
      "Browser automation MCP can navigate to arbitrary URLs and run JavaScript",
    recommendation: "Restrict to specific domains and disable script running where possible",
  },
  {
    namePattern: /shell|terminal|command/i,
    risk: "critical",
    description: "Shell/command MCP grants arbitrary command running",
    recommendation: "Use allowlist of specific commands instead of unrestricted shell access",
  },
  {
    namePattern: /database|postgres|mysql|sqlite|mongo/i,
    risk: "high",
    description: "Database MCP can read/write database contents",
    recommendation:
      "Use read-only connection and restrict to specific tables/schemas",
  },
  {
    namePattern: /slack|discord|email|sendgrid/i,
    risk: "medium",
    description: "Messaging MCP can send messages to external services",
    recommendation: "Restrict to specific channels and require confirmation for sends",
  },
];

export const mcpRules: ReadonlyArray<Rule> = [
  {
    id: "mcp-risky-servers",
    name: "Risky MCP Server Configuration",
    description: "Checks MCP server configs for servers that grant excessive capabilities",
    severity: "high",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const [name, _server] of Object.entries(servers)) {
          for (const profile of MCP_RISK_PROFILES) {
            if (profile.namePattern.test(name)) {
              findings.push({
                id: `mcp-risky-${name}`,
                severity: profile.risk,
                category: "mcp",
                title: `${profile.risk.toUpperCase()} risk MCP server: ${name}`,
                description: `${profile.description}. ${profile.recommendation}.`,
                file: file.path,
              });
            }
          }
        }
      } catch {
        // Not valid JSON — handled by other rules
      }

      return findings;
    },
  },
  {
    id: "mcp-hardcoded-env",
    name: "MCP Hardcoded Environment Variables",
    description: "Checks if MCP configs have hardcoded secrets instead of env var references",
    severity: "critical",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server as Record<string, unknown>;
          const env = (serverConfig.env ?? {}) as Record<string, string>;

          for (const [key, value] of Object.entries(env)) {
            // Check if value is hardcoded (not a ${VAR} reference)
            if (value && !value.startsWith("${") && !value.startsWith("$")) {
              // Check if this looks like a secret
              const isSecret =
                /key|token|secret|password|credential|auth/i.test(key);
              if (isSecret) {
                findings.push({
                  id: `mcp-hardcoded-env-${name}-${key}`,
                  severity: "critical",
                  category: "secrets",
                  title: `Hardcoded secret in MCP server "${name}": ${key}`,
                  description: `The environment variable "${key}" for MCP server "${name}" appears to contain a hardcoded secret instead of an environment variable reference.`,
                  file: file.path,
                  evidence: `${key}: "${value.substring(0, 4)}..."`,
                  fix: {
                    description: "Use environment variable reference",
                    before: `"${key}": "${value}"`,
                    after: `"${key}": "\${${key}}"`,
                    auto: true,
                  },
                });
              }
            }
          }
        }
      } catch {
        // Not valid JSON
      }

      return findings;
    },
  },
  {
    id: "mcp-npx-supply-chain",
    name: "MCP npx Supply Chain Risk",
    description: "Checks for MCP servers using npx -y which auto-installs packages without confirmation",
    severity: "medium",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server as Record<string, unknown>;
          const command = serverConfig.command as string;
          const args = (serverConfig.args ?? []) as string[];

          if (command === "npx" && args.includes("-y")) {
            findings.push({
              id: `mcp-npx-y-${name}`,
              severity: "medium",
              category: "mcp",
              title: `MCP server "${name}" uses npx -y (auto-install)`,
              description: `The MCP server "${name}" uses "npx -y" which automatically installs packages without confirmation. A typosquatting or supply chain attack could run malicious code.`,
              file: file.path,
              fix: {
                description:
                  "Install the package explicitly and reference it directly, or pin a specific version",
                before: `"command": "npx", "args": ["-y", "${args[1] ?? "package"}"]`,
                after: `Install with: npm install ${args[1] ?? "package"}, then reference directly`,
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
    id: "mcp-no-description",
    name: "MCP Server Missing Description",
    description: "MCP servers without descriptions make auditing harder",
    severity: "info",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server as Record<string, unknown>;
          if (!serverConfig.description) {
            findings.push({
              id: `mcp-no-desc-${name}`,
              severity: "info",
              category: "misconfiguration",
              title: `MCP server "${name}" has no description`,
              description: `Add a description to make security auditing easier: what does this server do and why is it needed?`,
              file: file.path,
            });
          }
        }
      } catch {
        // Not valid JSON
      }

      return findings;
    },
  },
];
