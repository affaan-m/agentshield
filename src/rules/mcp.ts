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
                  "Remove -y flag so npx prompts before installing, or install the package explicitly",
                before: `"args": ["-y", "${args[1] ?? "package"}"]`,
                after: `"args": ["${args[1] ?? "package"}"]`,
                auto: true,
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
  {
    id: "mcp-unrestricted-root-path",
    name: "MCP Unrestricted Root Path",
    description: "Checks for MCP servers with filesystem access to root or home directory",
    severity: "high",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        const rootPaths = ["/", "~", "C:\\", "C:/"];

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server as Record<string, unknown>;
          const args = (serverConfig.args ?? []) as string[];

          for (const arg of args) {
            if (rootPaths.includes(arg)) {
              findings.push({
                id: `mcp-root-path-${name}`,
                severity: "high",
                category: "mcp",
                title: `MCP server "${name}" has unrestricted path: ${arg}`,
                description: `The MCP server "${name}" is configured with path "${arg}" which grants access to the entire filesystem. This allows an agent to read, write, or delete any file on the system.`,
                file: file.path,
                evidence: `args: ${JSON.stringify(args)}`,
                fix: {
                  description: "Restrict to project-specific directories",
                  before: `"${arg}"`,
                  after: `"./src", "./docs"`,
                  auto: false,
                },
              });
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
    id: "mcp-no-version-pin",
    name: "MCP No Version Pin",
    description: "Checks for MCP servers using npx with unversioned packages",
    severity: "medium",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server as Record<string, unknown>;
          const command = serverConfig.command as string;
          const args = (serverConfig.args ?? []) as string[];

          if (command !== "npx") continue;

          // Find the package name arg (skip flags like -y, --yes)
          const packageArg = args.find(
            (a) => !a.startsWith("-") && a.includes("/")
          );
          if (!packageArg) continue;

          // Check if it has a version pin (contains @ after the scope)
          // Scoped packages look like @scope/name@version
          // @latest is NOT a real pin — it resolves dynamically
          const afterScope = packageArg.startsWith("@")
            ? packageArg.substring(packageArg.indexOf("/"))
            : packageArg;
          const versionPart = afterScope.includes("@")
            ? afterScope.substring(afterScope.indexOf("@") + 1)
            : "";
          const hasVersion =
            afterScope.includes("@") &&
            versionPart !== "latest" &&
            versionPart !== "next";

          if (!hasVersion) {
            findings.push({
              id: `mcp-no-version-${name}`,
              severity: "medium",
              category: "mcp",
              title: `MCP server "${name}" uses unversioned package: ${packageArg}`,
              description: `The MCP server "${name}" uses "${packageArg}" without a pinned version. A compromised package update would run automatically via npx.`,
              file: file.path,
              evidence: `command: npx, package: ${packageArg}`,
              fix: {
                description: "Pin to a specific version",
                before: `"${packageArg}"`,
                after: `"${packageArg}@1.0.0"`,
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
    id: "mcp-url-transport",
    name: "MCP External URL Transport",
    description: "Checks for MCP servers using URL-based transport connecting to external hosts",
    severity: "high",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server as Record<string, unknown>;
          const url = serverConfig.url as string | undefined;

          if (!url) continue;

          // Check if it's connecting to an external host
          const isLocal =
            /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/i.test(url);

          if (!isLocal) {
            findings.push({
              id: `mcp-url-transport-${name}`,
              severity: "high",
              category: "mcp",
              title: `MCP server "${name}" connects to external URL`,
              description: `The MCP server "${name}" uses URL transport connecting to "${url}". External MCP connections send all tool calls and results over the network, potentially exposing code, secrets, and session data to a remote server. Prefer local stdio-based MCP servers.`,
              file: file.path,
              evidence: url.substring(0, 100),
              fix: {
                description: "Use a local stdio-based MCP server instead",
                before: `"url": "${url.substring(0, 40)}"`,
                after: '"command": "node", "args": ["./local-server.js"]',
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
    id: "mcp-remote-command",
    name: "MCP Remote Command Execution",
    description: "Checks for MCP servers that download and execute remote code",
    severity: "critical",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server as Record<string, unknown>;
          const command = (serverConfig.command ?? "") as string;
          const args = (serverConfig.args ?? []) as string[];
          const fullCommand = `${command} ${args.join(" ")}`;

          // Check for pipe-to-shell patterns: curl/wget ... | sh/bash
          if (/\b(curl|wget)\b.*\|\s*(sh|bash|zsh|node|python)/i.test(fullCommand)) {
            findings.push({
              id: `mcp-remote-exec-${name}`,
              severity: "critical",
              category: "mcp",
              title: `MCP server "${name}" pipes remote download to shell`,
              description: `The MCP server "${name}" downloads remote code and pipes it directly to a shell interpreter. This is a critical remote code execution vulnerability — a compromised URL silently runs arbitrary commands.`,
              file: file.path,
              evidence: fullCommand.substring(0, 100),
              fix: {
                description: "Download, verify, then execute separately",
                before: fullCommand.substring(0, 60),
                after: "Install the package locally with npm/pip and reference it directly",
                auto: false,
              },
            });
            continue;
          }

          // Check for URLs in command args that suggest remote fetching
          const hasRemoteUrl = args.some(
            (a) => /^https?:\/\/.+\.(sh|py|js|ts|exe|bin)$/i.test(a)
          );
          if (
            hasRemoteUrl &&
            /^(sh|bash|zsh|node|python|ruby)$/.test(command)
          ) {
            findings.push({
              id: `mcp-remote-script-${name}`,
              severity: "high",
              category: "mcp",
              title: `MCP server "${name}" executes remote script URL`,
              description: `The MCP server "${name}" runs a shell interpreter with a remote script URL as an argument. The remote script could be changed at any time, making this a supply chain risk.`,
              file: file.path,
              evidence: fullCommand.substring(0, 100),
              fix: {
                description: "Download the script locally and reference the local copy",
                before: fullCommand.substring(0, 60),
                after: "Use a locally installed package or script",
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
    id: "mcp-shell-metacharacters",
    name: "MCP Shell Metacharacters in Args",
    description: "Checks for shell metacharacters in MCP server arguments that could enable command injection",
    severity: "medium",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        const shellMetachars = /[;|&`$(){}]/;

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server as Record<string, unknown>;
          const command = (serverConfig.command ?? "") as string;
          const args = (serverConfig.args ?? []) as string[];

          // Skip if command is sh/bash (expected to have shell syntax)
          if (/^(sh|bash|zsh|cmd)$/.test(command)) continue;

          for (const arg of args) {
            // Skip flags
            if (arg.startsWith("-")) continue;

            if (shellMetachars.test(arg)) {
              findings.push({
                id: `mcp-shell-metachar-${name}`,
                severity: "medium",
                category: "mcp",
                title: `MCP server "${name}" has shell metacharacters in args`,
                description: `The argument "${arg.substring(0, 60)}" for MCP server "${name}" contains shell metacharacters (;|&\`$). If the command spawns a shell, these could enable command injection. Use separate args instead of shell syntax.`,
                file: file.path,
                evidence: arg.substring(0, 80),
                fix: {
                  description: "Split into separate arguments without shell metacharacters",
                  before: `"${arg.substring(0, 40)}"`,
                  after: "Split into separate args array elements",
                  auto: false,
                },
              });
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
  {
    id: "mcp-env-override",
    name: "MCP Environment Variable Override",
    description: "Checks for MCP servers that override system-critical environment variables like PATH or LD_PRELOAD",
    severity: "critical",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        const dangerousEnvVars: ReadonlyArray<{
          readonly name: string;
          readonly description: string;
        }> = [
          { name: "PATH", description: "Controls which executables are found — can redirect to malicious binaries" },
          { name: "LD_PRELOAD", description: "Injects shared libraries into every process — classic privilege escalation" },
          { name: "LD_LIBRARY_PATH", description: "Redirects dynamic library loading — can intercept system calls" },
          { name: "NODE_OPTIONS", description: "Injects flags into every Node.js process — can load arbitrary code" },
          { name: "PYTHONPATH", description: "Redirects Python module imports — can load malicious modules" },
          { name: "HOME", description: "Changes home directory — can redirect config file loading" },
        ];

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server as Record<string, unknown>;
          const env = (serverConfig.env ?? {}) as Record<string, string>;

          for (const envVar of dangerousEnvVars) {
            if (envVar.name in env) {
              findings.push({
                id: `mcp-env-override-${name}-${envVar.name}`,
                severity: "critical",
                category: "mcp",
                title: `MCP server "${name}" overrides ${envVar.name}`,
                description: `The MCP server "${name}" sets ${envVar.name} in its environment. ${envVar.description}. If a malicious MCP config is injected (e.g., via a cloned repo), this could compromise the entire system.`,
                file: file.path,
                evidence: `${envVar.name}=${(env[envVar.name] ?? "").substring(0, 40)}`,
                fix: {
                  description: `Remove ${envVar.name} from the MCP server's env block`,
                  before: `"${envVar.name}": "${(env[envVar.name] ?? "").substring(0, 20)}"`,
                  after: `# Remove ${envVar.name} override`,
                  auto: false,
                },
              });
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
    id: "mcp-excessive-server-count",
    name: "MCP Excessive Server Count",
    description: "Flags configurations with too many MCP servers",
    severity: "low",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const count = Object.keys(servers).length;

        if (count > 10) {
          return [
            {
              id: "mcp-excessive-servers",
              severity: "low",
              category: "mcp",
              title: `${count} MCP servers configured — large attack surface`,
              description: `This configuration has ${count} MCP servers. Each server expands the attack surface through supply chain risk, environment variable exposure, and additional capabilities granted to the agent. Consider removing servers that are not actively needed.`,
              file: file.path,
            },
          ];
        }
      } catch {
        // Not valid JSON
      }

      return [];
    },
  },
];
