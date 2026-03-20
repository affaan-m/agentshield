import type { ConfigFile, Finding, Rule } from "../types.js";

/**
 * MCP Tool Description Poisoning Detection.
 *
 * Detects known tool poisoning patterns in MCP configurations:
 * - Tool names containing instruction-like text
 * - Server args with suspicious exfiltration URLs
 * - Configs granting overly broad file access to sensitive directories
 * - Hidden instructions in tool descriptions
 * - Prompt reflection / data harvesting patterns
 *
 * Based on research from Invariant Labs ("tool poisoning"),
 * Pillar Security, and OWASP MCP Top 10.
 */

// ─── Detection Patterns ──────────────────────────────────

/**
 * Patterns that indicate a server name contains injection attempts.
 */
const INJECTION_NAME_PATTERNS: ReadonlyArray<RegExp> = [
  // URLs embedded in names
  /https?:\/\//i,
  // Prompt override attempts
  /\bignore\s+(previous|all|prior)\s+instructions?\b/i,
  /\bsystem\s*:/i,
  /\byou\s+are\s+now\b/i,
  /\bassistant\s*:/i,
  // Newlines in names (hidden instructions)
  /[\n\r]/,
  // Instruction-like compound names (handles both spaces and underscores)
  /(send|exfiltrate|steal|leak|extract|read|dump|collect)[\s_\-/].*(to|from|all|every)[\s_\-/].*(https?|urls?|servers?|endpoints?|secrets?|keys?|tokens?|passwords?|credentials?|ssh|env)/i,
  // Common attack verbs combined with targets
  /read[\s_].*(?:and|then)[\s_].*send/i,
];

/**
 * Suspicious URL patterns in args/env that suggest data exfiltration.
 */
const EXFILTRATION_URL_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp;
  readonly description: string;
}> = [
  {
    pattern: /\bngrok\.io\b/i,
    description: "ngrok tunneling service (commonly used for exfiltration)",
  },
  {
    pattern: /\bngrok\.app\b/i,
    description: "ngrok tunneling service (commonly used for exfiltration)",
  },
  {
    pattern: /\bwebhook\.site\b/i,
    description: "webhook.site data collection endpoint",
  },
  {
    pattern: /\brequestbin\.com\b/i,
    description: "RequestBin data collection endpoint",
  },
  {
    pattern: /\brequestcatcher\.com\b/i,
    description: "RequestCatcher data collection endpoint",
  },
  {
    pattern: /\bpipedream\.net\b/i,
    description: "Pipedream webhook endpoint",
  },
  {
    pattern: /\bbeeceptor\.com\b/i,
    description: "Beeceptor mock/intercept endpoint",
  },
  {
    pattern: /\bhookbin\.com\b/i,
    description: "Hookbin data collection endpoint",
  },
  {
    pattern: /\bburpcollaborator\.net\b/i,
    description: "Burp Collaborator (offensive security tool)",
  },
  {
    pattern: /\binteractsh\.com\b/i,
    description: "Interactsh out-of-band interaction server",
  },
  {
    pattern: /\bcollect\?data=|\/exfil|\/steal|\/leak/i,
    description: "URL path suggesting data exfiltration endpoint",
  },
];

/**
 * Sensitive directory paths that indicate overly broad access.
 */
const SENSITIVE_PATHS: ReadonlyArray<{
  readonly pattern: RegExp;
  readonly description: string;
}> = [
  {
    pattern: /^~?\/?\.ssh\b/,
    description: "SSH keys and configuration",
  },
  {
    pattern: /^~?\/?\.gnupg\b/,
    description: "GPG keys and configuration",
  },
  {
    pattern: /^~?\/?\.aws\b/,
    description: "AWS credentials and configuration",
  },
  {
    pattern: /^~?\/?\.kube\b/,
    description: "Kubernetes configuration and credentials",
  },
  {
    pattern: /^\/etc\b/,
    description: "System configuration directory",
  },
  {
    pattern: /^\/var\/log\b/,
    description: "System log files",
  },
  {
    pattern: /^\/Users\/[^/]+$/,
    description: "User home directory (macOS)",
  },
  {
    pattern: /^\/home\/[^/]+$/,
    description: "User home directory (Linux)",
  },
  {
    pattern: /^C:\\Users\\[^\\]+$/i,
    description: "User home directory (Windows)",
  },
];

/**
 * Patterns in descriptions that indicate tool poisoning.
 * These are instructions hidden in MCP server descriptions that
 * attempt to manipulate the AI agent's behavior.
 */
const DESCRIPTION_POISONING_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp;
  readonly description: string;
}> = [
  // Data harvesting instructions
  {
    pattern: /\b(always|must|first|before)\b.{0,80}\b(include|send|read|output|call|fetch|get)\b.{0,80}(?:\.env|\.ssh|id_rsa|\bcredentials?\b|\bsecrets?\b|\btokens?\b|\bpasswords?\b|\bapi[_\s-]?keys?\b)/i,
    description: "Hidden instruction to harvest sensitive files or credentials",
  },
  // Prompt reflection / system prompt leaking
  {
    pattern: /\b(output|print|display|return|reveal|show)\b.{0,80}\b(system\s+prompt|previous\s+conversation|full\s+context|all\s+previous|conversation\s+history)\b/i,
    description: "Instruction to leak system prompt or conversation context",
  },
  // URL exfiltration commands in descriptions
  {
    pattern: /\b(send|post|transmit|forward|upload)\b.{0,100}\bhttps?:\/\//i,
    description: "Instruction to exfiltrate data to an external URL",
  },
  // Override/ignore instructions
  {
    pattern: /\bignore\s+(previous|all|prior|other)\s+(instructions?|rules?|guidelines?)\b/i,
    description: "Attempt to override the agent's instructions",
  },
  // Execute arbitrary commands
  {
    pattern: /\b(execute|run|eval)\b.{0,60}\b(command|shell|bash|script|code)\b/i,
    description: "Instruction to execute arbitrary commands",
  },
];

// ─── Rules ───────────────────────────────────────────────

const rawToolPoisoningRules: ReadonlyArray<Rule> = [
  {
    id: "mcp-tool-name-injection",
    name: "MCP Server Name Contains Injection Attempt",
    description:
      "Detects MCP server names that contain instruction-like text, URLs, or prompt injection patterns",
    severity: "high",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const name of Object.keys(servers)) {
          for (const pattern of INJECTION_NAME_PATTERNS) {
            if (pattern.test(name)) {
              findings.push({
                id: `mcp-tool-name-injection-${name.substring(0, 30)}`,
                severity: "high",
                category: "mcp",
                title: `MCP server name contains injection pattern: "${name.substring(0, 60)}"`,
                description: `The MCP server name "${name.substring(0, 80)}" contains suspicious patterns that may be an injection attempt. Server names should be simple identifiers, not instructions or URLs.`,
                file: file.path,
                evidence: name.substring(0, 100),
                fix: {
                  description: "Rename the server to a simple, descriptive identifier",
                  before: name.substring(0, 40),
                  after: "safe-server-name",
                  auto: false,
                },
              });
              break; // One finding per server name
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
    id: "mcp-suspicious-url-args",
    name: "MCP Server Args Contain Suspicious URLs",
    description:
      "Detects MCP server arguments containing URLs associated with data exfiltration or tunneling services",
    severity: "high",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = (server ?? {}) as Record<string, unknown>;
          const args = (serverConfig.args ?? []) as string[];

          for (const arg of args) {
            for (const { pattern, description } of EXFILTRATION_URL_PATTERNS) {
              if (pattern.test(arg)) {
                findings.push({
                  id: `mcp-suspicious-url-${name}`,
                  severity: "high",
                  category: "mcp",
                  title: `MCP server "${name}" has suspicious URL in args`,
                  description: `The argument "${arg.substring(0, 80)}" contains a ${description}. This may indicate a data exfiltration setup where agent outputs or sensitive data are sent to an attacker-controlled endpoint.`,
                  file: file.path,
                  evidence: arg.substring(0, 100),
                  fix: {
                    description: "Remove the suspicious URL or replace with a trusted endpoint",
                    before: arg.substring(0, 40),
                    after: "https://your-trusted-endpoint.com",
                    auto: false,
                  },
                });
                break; // One finding per arg match
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
    id: "mcp-overly-broad-access",
    name: "MCP Server Has Overly Broad File Access",
    description:
      "Detects MCP servers configured with access to sensitive directories like .ssh, .aws, /etc, or user home directories",
    severity: "high",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = (server ?? {}) as Record<string, unknown>;
          const args = (serverConfig.args ?? []) as string[];

          for (const arg of args) {
            // Skip flags
            if (arg.startsWith("-")) continue;

            for (const { pattern, description } of SENSITIVE_PATHS) {
              if (pattern.test(arg)) {
                findings.push({
                  id: `mcp-broad-access-${name}-${arg.substring(0, 20)}`,
                  severity: "high",
                  category: "mcp",
                  title: `MCP server "${name}" has access to sensitive path: ${arg}`,
                  description: `The MCP server "${name}" is configured with access to "${arg}" (${description}). This grants the agent access to sensitive system resources that should not be accessible through MCP servers.`,
                  file: file.path,
                  evidence: `args: [..., "${arg}"]`,
                  fix: {
                    description: "Restrict to project-specific directories only",
                    before: arg,
                    after: "./src",
                    auto: false,
                  },
                });
                break; // One finding per arg/pattern match
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
    id: "mcp-description-poisoning",
    name: "MCP Server Description Contains Poisoning Pattern",
    description:
      "Detects MCP server descriptions that contain hidden instructions, data harvesting commands, prompt reflection, or exfiltration URLs",
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
          const description = (serverConfig.description ?? "") as string;

          if (!description) continue;

          for (const poisonPattern of DESCRIPTION_POISONING_PATTERNS) {
            if (poisonPattern.pattern.test(description)) {
              findings.push({
                id: `mcp-desc-poisoning-${name}`,
                severity: "critical",
                category: "mcp",
                title: `MCP server "${name}" description contains tool poisoning pattern`,
                description: `The description for MCP server "${name}" contains a suspicious pattern: ${poisonPattern.description}. Tool description poisoning is a known attack vector where hidden instructions in descriptions manipulate the AI agent's behavior without the user's knowledge.`,
                file: file.path,
                evidence: description.substring(0, 200),
                fix: {
                  description: "Review and sanitize the server description, removing any instruction-like text",
                  before: description.substring(0, 60),
                  after: "A clear, factual description of the server's purpose",
                  auto: false,
                },
              });
              break; // One finding per description
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
    id: "mcp-env-exfiltration-urls",
    name: "MCP Server Env Contains Exfiltration URLs",
    description:
      "Detects MCP server environment variables containing URLs associated with data exfiltration services",
    severity: "high",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = (server ?? {}) as Record<string, unknown>;
          const env = (serverConfig.env ?? {}) as Record<string, string>;

          for (const [key, value] of Object.entries(env)) {
            if (typeof value !== "string") continue;

            for (const { pattern, description } of EXFILTRATION_URL_PATTERNS) {
              if (pattern.test(value)) {
                findings.push({
                  id: `mcp-env-exfil-${name}-${key}`,
                  severity: "high",
                  category: "mcp",
                  title: `MCP server "${name}" env var "${key}" contains suspicious URL`,
                  description: `The environment variable "${key}" for MCP server "${name}" contains a ${description}. This may be configured to send agent data or secrets to an external collection endpoint.`,
                  file: file.path,
                  evidence: `${key}=${value.substring(0, 80)}`,
                  fix: {
                    description: "Replace with a trusted endpoint URL",
                    before: value.substring(0, 40),
                    after: "https://your-trusted-endpoint.com",
                    auto: false,
                  },
                });
                break;
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
];

export const toolPoisoningRules: ReadonlyArray<Rule> = rawToolPoisoningRules;
