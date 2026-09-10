import type { ConfigFile, Finding, FindingCategory, Rule, Severity } from "../types.js";
import { parseYamlSafe } from "../scanner/parsers.js";
import { isLiteralCredential, redactSecret } from "./codex.js";

/**
 * Rules for Hermes agent config.yaml (HERMES_HOME/config.yaml and
 * profiles/<name>/config.yaml). config.yaml is Hermes's security policy:
 * approvals, the permanent command allowlist, terminal backend, and the
 * toolsets exposed to inbound chat platforms all live here.
 *
 * Every rule fails closed: an unparseable file or a YAML file with none of
 * the Hermes keys produces no findings.
 */

type Mapping = Record<string, unknown>;

function isMapping(value: unknown): value is Mapping {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asMapping(value: unknown): Mapping | undefined {
  return isMapping(value) ? value : undefined;
}

function asStringArray(value: unknown): ReadonlyArray<string> {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Best-effort line lookup for a dotted YAML key path: walks from the
 * deepest segment up and returns the first line where that segment appears
 * as a mapping key.
 */
export function findLineNumber(content: string, keyPath: string): number | undefined {
  const segments = keyPath.split(".").filter((segment) => segment.length > 0).reverse();
  const lines = content.split("\n");

  for (const segment of segments) {
    const pattern = new RegExp(`^\\s*(?:-\\s+)?["']?${escapeRegExp(segment)}["']?\\s*:`);
    for (let index = 0; index < lines.length; index += 1) {
      if (pattern.test(lines[index])) return index + 1;
    }
  }
  return undefined;
}

function parseHermesConfig(file: ConfigFile): Mapping | null {
  if (file.type !== "hermes-yaml") return null;
  return parseYamlSafe(file.content);
}

function makeFinding(
  file: ConfigFile,
  id: string,
  severity: Severity,
  category: FindingCategory,
  title: string,
  description: string,
  keyPath: string,
  evidence: string,
): Finding {
  return {
    id,
    severity,
    category,
    title,
    description,
    file: file.path,
    line: findLineNumber(file.content, keyPath),
    evidence,
  };
}

/** YAML 1.1 parsers turn `off` into false; treat both spellings as off. */
function approvalsMode(config: Mapping): string | undefined {
  const mode = asMapping(config.approvals)?.mode;
  if (mode === false) return "off";
  if (typeof mode === "string") return mode.trim().toLowerCase();
  return undefined;
}

function isLoopbackUrl(url: string): boolean {
  const match = url.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#]+)/i);
  if (!match) return false;
  const host = match[1].toLowerCase();
  return (
    host === "localhost" ||
    host === "[::1]" ||
    host === "0.0.0.0" ||
    host.endsWith(".localhost") ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
  );
}

function isPlainHttpRemote(url: unknown): url is string {
  return typeof url === "string" && /^http:\/\//i.test(url.trim()) && !isLoopbackUrl(url.trim());
}

function isSecretKeyName(name: string): boolean {
  return /^authorization$/i.test(name) || /key|token|secret|password|passwd|credential|auth/i.test(name);
}

const BROAD_ALLOWLIST_PREFIX = /^(?:rm|sudo|curl|wget|eval|bash\s+-c|sh\s+-c|zsh\s+-c)(?:\s|$)/i;
const GLOB_ONLY = /^[*?[\]\s.]+$/;

function allowlistReason(entry: string): string | undefined {
  const trimmed = entry.trim();
  if (trimmed === "*") return "matches every command";
  if (trimmed.length > 0 && GLOB_ONLY.test(trimmed)) return "contains only glob characters";
  if (BROAD_ALLOWLIST_PREFIX.test(trimmed)) return `permanently approves ${trimmed.split(/\s+/)[0]} commands`;
  return undefined;
}

const PUBLIC_PLATFORMS: ReadonlyArray<string> = ["telegram", "slack", "whatsapp", "discord", "email", "sms"];
const SHELL_TOOLSET = /terminal|shell|exec|file|code_execution/i;

const PERMISSIVE_DM = /^(?:allow|respond|accept)/i;

function mcpServersOf(config: Mapping): ReadonlyArray<{ readonly name: string; readonly server: Mapping }> {
  const servers = asMapping(config.mcp_servers);
  if (!servers) return [];
  return Object.entries(servers)
    .filter((entry): entry is [string, Mapping] => isMapping(entry[1]))
    .map(([name, server]) => ({ name, server }));
}

export const hermesRules: ReadonlyArray<Rule> = [
  {
    id: "hermes-approvals-off",
    name: "Hermes approvals off, smart, or auto for cron",
    description: "Flags approvals.mode off (yolo), approvals.mode smart, and approvals.cron_mode approve",
    severity: "critical",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHermesConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      const mode = approvalsMode(config);

      if (mode === "off") {
        findings.push(
          makeFinding(
            file,
            "hermes-approvals-off",
            "critical",
            "permissions",
            "Hermes runs with approvals off",
            "approvals.mode: off is the same as --yolo. Dangerous commands (rm -r, sudo, network fetches into the shell) run without a prompt, and only the small hardline blocklist remains. Anything that reaches the agent through chat, files, or MCP results can run on the host. Set approvals.mode: manual.",
            "approvals.mode",
            "approvals.mode: off",
          ),
        );
      } else if (mode === "smart") {
        findings.push(
          makeFinding(
            file,
            "hermes-approvals-smart",
            "medium",
            "permissions",
            "Hermes lets a model auto-approve commands",
            "approvals.mode: smart hands the approval decision for \"low-risk\" commands to an auxiliary LLM. A crafted command or injected context can talk that model into approving something a human would refuse. Use manual approvals for any agent that runs on a host with real credentials.",
            "approvals.mode",
            "approvals.mode: smart",
          ),
        );
      }

      const cronMode = asMapping(config.approvals)?.cron_mode;
      if (typeof cronMode === "string" && cronMode.trim().toLowerCase() === "approve") {
        findings.push(
          makeFinding(
            file,
            "hermes-cron-auto-approve",
            "high",
            "permissions",
            "Hermes cron jobs auto-approve dangerous commands",
            "approvals.cron_mode: approve lets scheduled jobs run commands that would otherwise wait for a human. Cron jobs run unattended, so this is unattended approval of dangerous commands. Set cron_mode: deny and allowlist specific commands if a job needs them.",
            "approvals.cron_mode",
            "approvals.cron_mode: approve",
          ),
        );
      }
      return findings;
    },
  },
  {
    id: "hermes-command-allowlist-broad",
    name: "Hermes command allowlist too broad",
    description: "Flags command_allowlist entries that permanently approve rm, sudo, curl, wget, shells, eval, or match everything",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHermesConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const entry of asStringArray(config.command_allowlist)) {
        const reason = allowlistReason(entry);
        if (!reason) continue;
        findings.push(
          makeFinding(
            file,
            "hermes-command-allowlist-broad",
            "high",
            "permissions",
            `Allowlist entry "${entry}" bypasses the dangerous-command gate`,
            `command_allowlist entries are permanently approved and skip Hermes's dangerous-command check. The entry "${entry}" ${reason}, so the agent can run it in any form without a prompt. Replace it with the exact command lines you intend to allow.`,
            "command_allowlist",
            `command_allowlist: "${entry}"`,
          ),
        );
      }
      return findings;
    },
  },
  {
    id: "hermes-local-terminal-unattended",
    name: "Hermes host terminal without manual approvals",
    description: "Flags terminal.backend local or ssh while approvals.mode is set to something other than manual",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHermesConfig(file);
      if (!config) return [];

      const backend = asMapping(config.terminal)?.backend;
      if (typeof backend !== "string") return [];
      const normalizedBackend = backend.trim().toLowerCase();
      if (normalizedBackend !== "local" && normalizedBackend !== "ssh") return [];

      const mode = approvalsMode(config);
      if (mode === undefined || mode === "manual") return [];

      return [
        makeFinding(
          file,
          "hermes-local-terminal-unattended",
          "high",
          "permissions",
          `Hermes runs on a ${normalizedBackend} terminal with ${mode} approvals`,
          `terminal.backend: ${normalizedBackend} executes commands directly on a real host, and approvals.mode: ${mode} means dangerous commands are not reviewed by a person. Together that is unsupervised shell access to the machine. Use approvals.mode: manual, or move the agent into the docker backend.`,
          "terminal.backend",
          `terminal.backend: ${normalizedBackend}; approvals.mode: ${mode}`,
        ),
      ];
    },
  },
  {
    id: "hermes-docker-mount-cwd",
    name: "Hermes docker backend mounts the working directory",
    description: "Flags terminal.docker_mount_cwd_to_workspace: true",
    severity: "medium",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHermesConfig(file);
      if (!config) return [];
      if (asMapping(config.terminal)?.docker_mount_cwd_to_workspace !== true) return [];

      return [
        makeFinding(
          file,
          "hermes-docker-mount-cwd",
          "medium",
          "permissions",
          "Hermes container can write the host working directory",
          "terminal.docker_mount_cwd_to_workspace: true bind-mounts the host cwd into the container. Hermes ships this off by default for a reason: the container's isolation no longer protects the project directory, and cwd is often a home directory when the gateway starts. Leave it false and copy files in explicitly.",
          "terminal.docker_mount_cwd_to_workspace",
          "terminal.docker_mount_cwd_to_workspace: true",
        ),
      ];
    },
  },
  {
    id: "hermes-mcp-secret-inline",
    name: "Hermes MCP server has inline secret or plain HTTP URL",
    description: "Flags mcp_servers.<n>.headers or env with literal credentials and url over http:// to a non-loopback host",
    severity: "high",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHermesConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const { name, server } of mcpServersOf(config)) {
        for (const section of ["headers", "env"]) {
          const values = asMapping(server[section]);
          if (!values) continue;
          for (const [key, value] of Object.entries(values)) {
            if (!isSecretKeyName(key) || !isLiteralCredential(value)) continue;
            const keyPath = `mcp_servers.${name}.${section}.${key}`;
            findings.push(
              makeFinding(
                file,
                "hermes-mcp-secret-inline",
                "high",
                "secrets",
                `MCP server "${name}" stores ${key} inline`,
                `mcp_servers.${name}.${section}.${key} holds a literal credential in config.yaml. Hermes keeps many config.yaml.bak-* copies and profile replicas, so the value spreads across the profile tree. Reference it from .env or the secrets (1Password) integration instead.`,
                keyPath,
                `${keyPath}: "${redactSecret(value)}"`,
              ),
            );
          }
        }

        if (isPlainHttpRemote(server.url)) {
          const keyPath = `mcp_servers.${name}.url`;
          findings.push(
            makeFinding(
              file,
              "hermes-mcp-remote-http",
              "high",
              "mcp",
              `MCP server "${name}" connects over plain HTTP`,
              `mcp_servers.${name}.url is ${server.url}. Tool definitions, arguments, and headers travel unencrypted, so an on-path attacker can read credentials or rewrite tool results into prompt injections. Use https://.`,
              keyPath,
              `${keyPath}: ${server.url}`,
            ),
          );
        }
      }
      return findings;
    },
  },
  {
    id: "hermes-public-platform-shell",
    name: "Hermes exposes shell toolsets to a chat platform",
    description: "Flags platform_toolsets for public messaging platforms that include terminal, shell, exec, file, or code_execution toolsets",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHermesConfig(file);
      if (!config) return [];

      const platformToolsets = asMapping(config.platform_toolsets);
      if (!platformToolsets) return [];

      const findings: Finding[] = [];
      for (const [platform, toolsets] of Object.entries(platformToolsets)) {
        if (!PUBLIC_PLATFORMS.includes(platform.toLowerCase())) continue;
        const risky = asStringArray(toolsets).filter((toolset) => SHELL_TOOLSET.test(toolset));
        if (risky.length === 0) continue;
        const keyPath = `platform_toolsets.${platform}`;
        findings.push(
          makeFinding(
            file,
            "hermes-public-platform-shell",
            "high",
            "permissions",
            `${platform} messages can reach ${risky.join(", ")}`,
            `platform_toolsets.${platform} includes ${risky.map((toolset) => `"${toolset}"`).join(", ")}. Inbound messages on ${platform} come from whoever the platform allowlist admits, and this gives them a path to the shell or filesystem. Keep host-touching toolsets on the cli platform only.`,
            keyPath,
            `${keyPath}: [${risky.join(", ")}]`,
          ),
        );
      }
      return findings;
    },
  },
  {
    id: "hermes-delegation-unbounded",
    name: "Hermes delegation unbounded with approvals off",
    description: "Flags delegation.max_iterations over 50 or unset while approvals.mode is off",
    severity: "low",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHermesConfig(file);
      if (!config) return [];
      if (approvalsMode(config) !== "off") return [];

      const maxIterations = asMapping(config.delegation)?.max_iterations;
      const unset = typeof maxIterations !== "number";
      if (!unset && maxIterations <= 50) return [];

      return [
        makeFinding(
          file,
          "hermes-delegation-unbounded",
          "low",
          "permissions",
          "Hermes sub-agents run unbounded with approvals off",
          `delegation.max_iterations is ${unset ? "unset" : String(maxIterations)} while approvals.mode is off. Delegated children inherit yolo mode and can loop for long stretches with no checkpoint. Set max_iterations to a small bound and restore approvals.`,
          unset ? "approvals.mode" : "delegation.max_iterations",
          `delegation.max_iterations: ${unset ? "(unset)" : String(maxIterations)}; approvals.mode: off`,
        ),
      ];
    },
  },
  {
    id: "hermes-gateway-open-dm",
    name: "Hermes gateway answers unauthorized DMs",
    description: "Flags gateway.unauthorized_dm_behavior set to allow, respond, or accept",
    severity: "medium",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHermesConfig(file);
      if (!config) return [];

      const behavior = asMapping(config.gateway)?.unauthorized_dm_behavior;
      if (typeof behavior !== "string" || !PERMISSIVE_DM.test(behavior.trim())) return [];

      return [
        makeFinding(
          file,
          "hermes-gateway-open-dm",
          "medium",
          "permissions",
          "Hermes gateway responds to unauthorized senders",
          `gateway.unauthorized_dm_behavior: ${behavior} means anyone who can DM the bot gets a response from the agent, with whatever toolsets the platform exposes. Set it to ignore or block and manage senders through the platform allowlist.`,
          "gateway.unauthorized_dm_behavior",
          `gateway.unauthorized_dm_behavior: ${behavior}`,
        ),
      ];
    },
  },
];
