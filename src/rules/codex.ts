import type { ConfigFile, Finding, FindingCategory, Rule, Severity } from "../types.js";
import { parseJsonLenient, parseTomlSafe } from "../scanner/parsers.js";

/**
 * Rules for OpenAI Codex CLI configuration: config.toml (user, project, and
 * profile scopes), .codex/agents/*.toml role files, and .codex/hooks.json.
 *
 * Every rule fails closed: a file that does not parse produces no findings,
 * and a TOML file with none of the Codex keys produces no findings.
 */

type Table = Record<string, unknown>;

interface Scope {
  readonly prefix: string;
  readonly table: Table;
}

function isTable(value: unknown): value is Table {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asTable(value: unknown): Table | undefined {
  return isTable(value) ? value : undefined;
}

function asStringArray(value: unknown): ReadonlyArray<string> {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

function joinPath(prefix: string, key: string): string {
  return prefix ? `${prefix}.${key}` : key;
}

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").toLowerCase();
}

function isProjectScopedPath(filePath: string): boolean {
  const normalized = normalizePath(filePath);
  return normalized.startsWith(".codex/") || normalized.includes("/.codex/");
}

function isAgentRolePath(filePath: string): boolean {
  return /(?:^|\/)\.codex\/agents\/[^/]+\.toml$/.test(normalizePath(filePath));
}

function isCodexHooksPath(filePath: string): boolean {
  return /(?:^|\/)\.codex\/hooks\.json$/.test(normalizePath(filePath));
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Best-effort line lookup for a dotted TOML key path. Table segments are
 * resolved first so a key inside [profiles.<name>] resolves to the line in
 * that table rather than the same key at top level. Falls back to the
 * deepest segment that can be located anywhere in the file.
 */
export function findLineNumber(content: string, keyPath: string): number | undefined {
  const segments = keyPath
    .split(".")
    .map((segment) => segment.replace(/^"|"$/g, ""))
    .filter((segment) => segment.length > 0);
  if (segments.length === 0) return undefined;
  const lines = content.split("\n");

  const keyPatternFor = (segment: string): RegExp => new RegExp(`^\\s*"?${escapeRegExp(segment)}"?\\s*=`);
  const headerPatternFor = (segment: string): RegExp =>
    new RegExp(`^\\s*\\[\\[?[^\\]]*(?:^|[.\\["])${escapeRegExp(segment)}(?:$|[.\\]"])`);
  const quotedPatternFor = (segment: string): RegExp => new RegExp(`"${escapeRegExp(segment)}"`);

  const findFrom = (start: number, patterns: ReadonlyArray<RegExp>): number => {
    for (let index = start; index < lines.length; index += 1) {
      if (patterns.some((pattern) => pattern.test(lines[index]))) return index;
    }
    return -1;
  };

  let start = 0;
  let best: number | undefined;
  for (const segment of segments.slice(0, -1)) {
    const headerIndex = findFrom(start, [headerPatternFor(segment)]);
    if (headerIndex === -1) continue;
    start = headerIndex;
    best = headerIndex + 1;
  }

  const last = segments[segments.length - 1];
  const scoped = findFrom(start, [keyPatternFor(last), headerPatternFor(last), quotedPatternFor(last)]);
  if (scoped !== -1) return scoped + 1;
  if (best !== undefined) return best;

  for (const segment of [...segments].reverse()) {
    const anywhere = findFrom(0, [keyPatternFor(segment), headerPatternFor(segment), quotedPatternFor(segment)]);
    if (anywhere !== -1) return anywhere + 1;
  }
  return undefined;
}

export function redactSecret(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 4) return "***";
  return `${trimmed.substring(0, 4)}***`;
}

function isEnvReference(value: string): boolean {
  const trimmed = value.trim();
  return /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(trimmed) || /\$\{[A-Za-z_][A-Za-z0-9_]*\}/.test(trimmed);
}

function isPlaceholderValue(value: string): boolean {
  const trimmed = value.trim();
  return (
    /^YOUR_[A-Z0-9_]+$/i.test(trimmed) ||
    /^REPLACE(?:_|-)?ME(?:_[A-Z0-9_]+)?$/i.test(trimmed) ||
    /^CHANGE(?:_|-)?ME$/i.test(trimmed) ||
    /^<[^>]+>$/.test(trimmed) ||
    /^\{\{[^}]+\}\}$/.test(trimmed) ||
    /^(?:xxx+|\.\.\.|\*+)$/i.test(trimmed)
  );
}

/**
 * A header or env value that looks like a real credential: not an env
 * reference, not a placeholder, and a single opaque token of meaningful
 * length after an optional auth scheme prefix.
 */
export function isLiteralCredential(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (trimmed.length === 0) return false;
  if (isEnvReference(trimmed) || isPlaceholderValue(trimmed)) return false;

  const withoutScheme = trimmed.replace(/^(?:Bearer|Basic|Token|token|ApiKey|Api-Key)\s+/i, "");
  if (isEnvReference(withoutScheme) || isPlaceholderValue(withoutScheme)) return false;
  if (/\s/.test(withoutScheme)) return false;
  if (withoutScheme.length < 8) return false;

  return /^[A-Za-z0-9_\-./+=:]+$/.test(withoutScheme);
}

function isSecretHeaderName(name: string): boolean {
  return /^authorization$/i.test(name) || /key|token|secret|password|credential/i.test(name);
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

function scopesOf(config: Table): ReadonlyArray<Scope> {
  const scopes: Scope[] = [{ prefix: "", table: config }];
  const profiles = asTable(config.profiles);
  if (profiles) {
    for (const [name, profile] of Object.entries(profiles)) {
      if (isTable(profile)) {
        scopes.push({ prefix: `profiles.${name}`, table: profile });
      }
    }
  }
  return scopes;
}

function effectiveSandboxMode(scope: Scope, root: Table): string | undefined {
  const own = scope.table.sandbox_mode;
  if (typeof own === "string") return own;
  const inherited = root.sandbox_mode;
  return typeof inherited === "string" ? inherited : undefined;
}

function effectiveApprovalPolicy(scope: Scope, root: Table): unknown {
  return scope.table.approval_policy ?? root.approval_policy;
}

function hasNetworkProxyAllowlist(scope: Scope, root: Table): boolean {
  const candidates = [scope.table, root];
  return candidates.some((table) => {
    const proxy = asTable(asTable(table.features)?.network_proxy);
    const domains = asTable(proxy?.domains);
    return domains !== undefined && Object.keys(domains).length > 0;
  });
}

function mcpServersOf(scope: Scope): ReadonlyArray<{ readonly name: string; readonly path: string; readonly server: Table }> {
  const servers = asTable(scope.table.mcp_servers);
  if (!servers) return [];
  return Object.entries(servers)
    .filter((entry): entry is [string, Table] => isTable(entry[1]))
    .map(([name, server]) => ({ name, path: joinPath(scope.prefix, `mcp_servers.${name}`), server }));
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

function parseCodexConfig(file: ConfigFile): Table | null {
  if (file.type !== "codex-toml") return null;
  return parseTomlSafe(file.content);
}

const BROAD_WRITABLE_ROOTS: ReadonlyArray<RegExp> = [
  /^\/$/,
  /^~$/,
  /^\$\{?HOME\}?$/,
  /^~\/\.codex$/,
  /^~\/\.ssh$/,
  /^\$\{?HOME\}?\/\.codex$/,
  /^\$\{?HOME\}?\/\.ssh$/,
  /^\/etc$/,
  /^\/usr\/local\/bin$/,
  /^\/(?:Users|home)\/[^/]+$/,
  /^\/(?:Users|home)\/[^/]+\/\.(?:codex|ssh)$/,
];

function isBroadWritableRoot(root: string): boolean {
  const normalized = root.trim().replace(/\\/g, "/").replace(/\/+$/, "") || "/";
  return BROAD_WRITABLE_ROOTS.some((pattern) => pattern.test(normalized));
}

function isHomeOrRootProjectPath(projectPath: string): boolean {
  const normalized = projectPath.trim().replace(/[\\/]+$/, "");
  if (normalized === "" || normalized === "/" || normalized === "~") return true;
  if (/^\/(?:Users|home)\/[^\\/]+$/.test(normalized)) return true;
  return /^[A-Za-z]:[\\/]Users[\\/][^\\/]+$/.test(normalized);
}

const SHELL_BINARIES = new Set(["sh", "bash", "zsh", "dash", "fish", "ksh", "pwsh", "powershell", "cmd"]);

function baseName(command: string): string {
  const parts = command.trim().replace(/\\/g, "/").split("/");
  return (parts[parts.length - 1] ?? "").toLowerCase();
}

interface PackageSpec {
  readonly name: string;
  readonly version?: string;
}

function parseNpmPackageSpec(spec: string): PackageSpec {
  const at = spec.lastIndexOf("@");
  if (at <= 0) return { name: spec };
  return { name: spec.substring(0, at), version: spec.substring(at + 1) };
}

function isUnpinnedVersion(version: string | undefined): boolean {
  if (version === undefined || version.length === 0) return true;
  return /^(?:latest|next|\*|x)$/i.test(version) || /^[\^~>]/.test(version);
}

interface UnpinnedResult {
  readonly spec: string;
  readonly reason: string;
}

function detectUnpinnedPackage(command: string, args: ReadonlyArray<string>): UnpinnedResult | undefined {
  const bin = baseName(command);

  if (bin === "npx" || bin === "bunx" || bin === "pnpx") {
    const hasYes = args.some((arg) => arg === "-y" || arg === "--yes");
    const spec = args.find((arg) => !arg.startsWith("-"));
    if (!hasYes || spec === undefined) return undefined;
    const parsed = parseNpmPackageSpec(spec);
    if (isUnpinnedVersion(parsed.version)) {
      return {
        spec,
        reason: parsed.version === undefined ? "no version pinned" : `version "${parsed.version}" floats`,
      };
    }
    return undefined;
  }

  if (bin === "uvx" || bin === "pipx") {
    const positional = args.filter((arg, index) => {
      if (arg.startsWith("-")) return false;
      const previous = args[index - 1];
      if (previous === "--from" || previous === "--with" || previous === "--python" || previous === "-p") return false;
      return arg !== "run";
    });
    const fromIndex = args.indexOf("--from");
    const spec = fromIndex >= 0 && typeof args[fromIndex + 1] === "string" ? args[fromIndex + 1] : positional[0];
    if (spec === undefined) return undefined;
    const pinned = /==|@[0-9]|@v[0-9]|git\+|\.whl$|\.tar\.gz$/.test(spec);
    if (!pinned) return { spec, reason: "no version pinned" };
    return undefined;
  }

  return undefined;
}

const BRIDGE_PATTERN = /\b(?:mcp-remote|supergateway|mcp-proxy)\b/i;

function detectRemoteBridge(command: string, args: ReadonlyArray<string>): { readonly bridge: string; readonly url?: string; readonly reason: string } | undefined {
  const tokens = [command, ...args];
  const bridgeToken = tokens.find((token) => BRIDGE_PATTERN.test(token));
  if (bridgeToken === undefined) return undefined;
  const bridgeMatch = bridgeToken.match(BRIDGE_PATTERN);
  const bridge = bridgeMatch ? bridgeMatch[0] : bridgeToken;
  const url = tokens.find((token) => /^https?:\/\//i.test(token.trim()));
  const allowHttp = tokens.some((token) => token === "--allow-http");

  if (allowHttp) {
    return { bridge, url, reason: "--allow-http disables the transport security check" };
  }
  if (url !== undefined && isPlainHttpRemote(url)) {
    return { bridge, url, reason: "bridges to a plain http:// remote" };
  }
  return undefined;
}

function isShellNotify(notify: ReadonlyArray<string>): string | undefined {
  if (notify.length === 0) return undefined;
  const first = baseName(notify[0]);
  if (SHELL_BINARIES.has(first)) return `notify runs a shell (${notify[0]})`;
  const joined = notify.join(" ");
  if (/\b(?:curl|wget)\b/i.test(joined)) return "notify invokes a network client";
  if (/\bosascript\b/i.test(joined) && /https?:\/\//i.test(joined)) return "notify runs osascript with a URL";
  if (notify.some((arg) => arg === "-c")) return "notify passes -c to its command";
  return undefined;
}

const INJECTION_PHRASES: ReadonlyArray<RegExp> = [
  /ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+instructions/i,
  /disregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+instructions/i,
  /\bexfiltrat/i,
  /\bsend\s+(?:it|them|this|that|everything|the\s+\S+|all\s+\S+)?\s*to\s+https?:\/\//i,
  /\b(?:post|upload)\s+(?:it|them|this|everything|.{0,40}?)\s*to\s+https?:\/\//i,
];

function findInjectionPhrase(text: string): string | undefined {
  for (const pattern of INJECTION_PHRASES) {
    const match = text.match(pattern);
    if (match) return match[0];
  }
  return undefined;
}

function isOpenAiHost(url: string): boolean {
  const match = url.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?([^:/?#]+)/i);
  if (!match) return false;
  const host = match[1].toLowerCase();
  return host === "openai.com" || host.endsWith(".openai.com") || host.endsWith(".openai.azure.com");
}

const PROJECT_ESCALATION_KEYS: ReadonlyArray<string> = [
  "approval_policy",
  "sandbox_mode",
  "mcp_servers",
  "notify",
  "model_providers",
];

function projectEscalationKeys(scope: Scope): ReadonlyArray<string> {
  const keys: string[] = [];
  for (const key of PROJECT_ESCALATION_KEYS) {
    if (scope.table[key] !== undefined) keys.push(joinPath(scope.prefix, key));
  }
  if (asTable(scope.table.shell_environment_policy)?.set !== undefined) {
    keys.push(joinPath(scope.prefix, "shell_environment_policy.set"));
  }
  if (asTable(scope.table.features)?.hooks !== undefined) {
    keys.push(joinPath(scope.prefix, "features.hooks"));
  }
  return keys;
}

const UNCONDITIONAL_ALLOW_PATTERN = /permissionDecision\\?["']?\s*[:=]\s*\\?["']?allow\b/i;
const CONDITIONAL_PATTERN = /\bif\b|\bcase\b|\[\[|(?:^|\s)\[\s|&&|\|\||\?|\bselect\(|\btest\b|\bwhen\b|\bunless\b|\bgrep\b/;

function hookCommandsOf(config: Table, event: string): ReadonlyArray<string> {
  const container = asTable(config.hooks) ?? config;
  const groups = container[event];
  if (!Array.isArray(groups)) return [];
  const commands: string[] = [];
  for (const group of groups) {
    if (!isTable(group)) continue;
    const hooks = Array.isArray(group.hooks) ? group.hooks : [group];
    for (const hook of hooks) {
      if (isTable(hook) && typeof hook.command === "string") commands.push(hook.command);
    }
  }
  return commands;
}

export const codexRules: ReadonlyArray<Rule> = [
  {
    id: "codex-danger-full-access",
    name: "Codex sandbox disabled",
    description: "Flags sandbox_mode = \"danger-full-access\" in any Codex config scope or profile",
    severity: "critical",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseCodexConfig(file);
      if (!config || isAgentRolePath(file.path)) return [];

      return scopesOf(config)
        .filter((scope) => scope.table.sandbox_mode === "danger-full-access")
        .map((scope) => {
          const keyPath = joinPath(scope.prefix, "sandbox_mode");
          return makeFinding(
            file,
            "codex-danger-full-access",
            "critical",
            "permissions",
            "Codex runs with the sandbox disabled",
            "sandbox_mode = \"danger-full-access\" removes every filesystem and network restriction from commands Codex runs. Any prompt injection in a file, tool result, or web page becomes arbitrary code execution on the host. Use \"workspace-write\" or \"read-only\" and grant extra writable_roots only where needed.",
            keyPath,
            `${keyPath} = "danger-full-access"`,
          );
        });
    },
  },
  {
    id: "codex-approval-never",
    name: "Codex approvals disabled",
    description: "Flags approval_policy = \"never\" and granular approval sub-flags turned off",
    severity: "critical",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const scope of scopesOf(config)) {
        const policy = scope.table.approval_policy;
        const keyPath = joinPath(scope.prefix, "approval_policy");

        if (policy === "never") {
          const sandbox = effectiveSandboxMode(scope, config) ?? "unset";
          const severity: Severity = sandbox === "read-only" ? "high" : "critical";
          findings.push(
            makeFinding(
              file,
              "codex-approval-never",
              severity,
              "permissions",
              "Codex never asks for approval",
              `approval_policy = "never" lets Codex run every command, edit, and MCP call without a human in the loop. With sandbox_mode ${sandbox === "unset" ? "unset (defaults to workspace-write)" : `"${sandbox}"`} this means unattended writes${sandbox === "read-only" ? " are blocked by the sandbox, but reads and network-capable tools still run unreviewed" : " to the workspace and beyond"}. Prefer "on-request" or "on-failure".`,
              keyPath,
              `${keyPath} = "never" (sandbox_mode: ${sandbox})`,
            ),
          );
          continue;
        }

        const granular = asTable(asTable(policy)?.granular);
        if (!granular) continue;
        const disabled = Object.entries(granular)
          .filter(([, value]) => value === false)
          .map(([flag]) => flag);
        if (disabled.length === 0) continue;

        findings.push(
          makeFinding(
            file,
            "codex-granular-approval-off",
            "high",
            "permissions",
            "Codex granular approval gates disabled",
            `The granular approval_policy turns off ${disabled.join(", ")}. Each disabled flag removes a class of approval prompt, so the corresponding actions run without review. Re-enable the flags or switch to a named policy such as "on-request".`,
            `${keyPath}.granular`,
            disabled.map((flag) => `${keyPath}.granular.${flag} = false`).join("; "),
          ),
        );
      }
      return findings;
    },
  },
  {
    id: "codex-network-without-allowlist",
    name: "Codex workspace network without allowlist",
    description: "Flags [sandbox_workspace_write] network_access = true with no [features.network_proxy] domain allowlist",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const scope of scopesOf(config)) {
        const workspace = asTable(scope.table.sandbox_workspace_write);
        if (workspace?.network_access !== true) continue;
        if (hasNetworkProxyAllowlist(scope, config)) continue;
        const keyPath = joinPath(scope.prefix, "sandbox_workspace_write.network_access");
        findings.push(
          makeFinding(
            file,
            "codex-network-without-allowlist",
            "high",
            "permissions",
            "Codex sandbox has unrestricted network access",
            "network_access = true opens outbound network from sandboxed commands to every host, and no [features.network_proxy] domains table restricts it. Injected instructions can reach arbitrary endpoints with workspace contents. Keep network off, or enable network_proxy with an explicit domain allowlist.",
            keyPath,
            `${keyPath} = true; features.network_proxy.domains missing`,
          ),
        );
      }
      return findings;
    },
  },
  {
    id: "codex-writable-roots-broad",
    name: "Codex writable roots too broad",
    description: "Flags writable_roots entries that cover the home directory, system directories, or the whole filesystem",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const scope of scopesOf(config)) {
        const workspace = asTable(scope.table.sandbox_workspace_write);
        const roots = asStringArray(workspace?.writable_roots).filter(isBroadWritableRoot);
        if (roots.length === 0) continue;
        const keyPath = joinPath(scope.prefix, "sandbox_workspace_write.writable_roots");
        findings.push(
          makeFinding(
            file,
            "codex-writable-roots-broad",
            "high",
            "permissions",
            "Codex can write outside the workspace",
            `writable_roots grants write access to ${roots.map((root) => `"${root}"`).join(", ")}. That covers shell profiles, SSH keys, Codex's own config, or system binaries, so a compromised session can persist or escalate. Limit writable_roots to specific project directories.`,
            keyPath,
            `${keyPath} = [${roots.map((root) => `"${root}"`).join(", ")}]`,
          ),
        );
      }
      return findings;
    },
  },
  {
    id: "codex-trusted-home",
    name: "Codex trusts the home directory",
    description: "Flags [projects.\"<home>\"] or [projects.\"/\"] with trust_level = \"trusted\"",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const scope of scopesOf(config)) {
        const projects = asTable(scope.table.projects);
        if (!projects) continue;
        for (const [projectPath, project] of Object.entries(projects)) {
          if (!isTable(project) || project.trust_level !== "trusted") continue;
          if (!isHomeOrRootProjectPath(projectPath)) continue;
          const keyPath = joinPath(scope.prefix, `projects."${projectPath}".trust_level`);
          findings.push(
            makeFinding(
              file,
              "codex-trusted-home",
              "high",
              "permissions",
              `Codex trusts every project under ${projectPath}`,
              `Marking "${projectPath}" as trusted makes every directory beneath it a trusted project, so any cloned repository's .codex/config.toml, hooks.json, and agents load automatically and can change approval and sandbox policy. Trust individual project paths instead.`,
              keyPath,
              `${keyPath} = "trusted"`,
            ),
          );
        }
      }
      return findings;
    },
  },
  {
    id: "codex-project-config-escalates",
    name: "Project Codex config drives policy",
    description: "Flags a repo .codex/config.toml that sets approval, sandbox, MCP, notify, provider, env, or hook policy",
    severity: "medium",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isProjectScopedPath(file.path) || isAgentRolePath(file.path)) return [];
      const config = parseCodexConfig(file);
      if (!config) return [];

      const keys = scopesOf(config).flatMap(projectEscalationKeys);
      if (keys.length === 0) return [];

      const escalates = scopesOf(config).some(
        (scope) => scope.table.approval_policy === "never" || scope.table.sandbox_mode === "danger-full-access",
      );
      const severity: Severity = escalates ? "high" : "medium";

      return [
        makeFinding(
          file,
          "codex-project-config-escalates",
          severity,
          "misconfiguration",
          "Repository Codex config overrides user policy",
          `This project-scoped config sets ${keys.join(", ")}. Once the project is trusted these keys override the user's own config, so a repository can loosen approvals, disable the sandbox, register MCP servers, or run notify commands.${escalates ? " It sets approval_policy = \"never\" or sandbox_mode = \"danger-full-access\", which is also reported by the dedicated rule; both findings describe the same lines." : ""} Keep policy keys in ~/.codex/config.toml and limit project files to model and instruction settings.`,
          keys[0],
          keys.join(", "),
        ),
      ];
    },
  },
  {
    id: "codex-mcp-header-secret",
    name: "Codex MCP header carries a literal secret",
    description: "Flags [mcp_servers.<n>] http_headers with a literal Authorization, key, or token value",
    severity: "high",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const scope of scopesOf(config)) {
        for (const { name, path, server } of mcpServersOf(scope)) {
          const headers = asTable(server.http_headers);
          if (!headers) continue;
          for (const [header, value] of Object.entries(headers)) {
            if (!isSecretHeaderName(header) || !isLiteralCredential(value)) continue;
            const keyPath = `${path}.http_headers.${header}`;
            findings.push(
              makeFinding(
                file,
                "codex-mcp-header-secret",
                "high",
                "secrets",
                `MCP server "${name}" has a hardcoded ${header} header`,
                `The ${header} header for MCP server "${name}" contains a literal credential in config.toml. It is readable by anything that can read the file and ends up in backups and dotfile repos. Move it to env_http_headers = { ${header} = "ENV_VAR_NAME" } or bearer_token_env_var and keep the value in the environment.`,
                keyPath,
                `${keyPath} = "${redactSecret(value)}"`,
              ),
            );
          }
        }
      }
      return findings;
    },
  },
  {
    id: "codex-mcp-env-passthrough",
    name: "Codex passes secrets through the environment",
    description: "Flags env_vars globs that forward credentials and shell_environment_policy that inherits everything",
    severity: "medium",
    category: "exposure",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const scope of scopesOf(config)) {
        for (const { name, path, server } of mcpServersOf(scope)) {
          const risky = asStringArray(server.env_vars).filter(
            (entry) => entry.trim() === "*" || (entry.includes("*") && /AWS|TOKEN|SECRET|KEY|PASS|CRED/i.test(entry)),
          );
          if (risky.length === 0) continue;
          const keyPath = `${path}.env_vars`;
          findings.push(
            makeFinding(
              file,
              "codex-mcp-env-passthrough",
              "medium",
              "exposure",
              `MCP server "${name}" inherits credential environment variables`,
              `env_vars forwards ${risky.map((entry) => `"${entry}"`).join(", ")} from the Codex process into the MCP server "${name}". Wildcards hand cloud and API credentials to a third-party process. List only the exact variables the server needs.`,
              keyPath,
              `${keyPath} = [${risky.map((entry) => `"${entry}"`).join(", ")}]`,
            ),
          );
        }

        const envPolicy = asTable(scope.table.shell_environment_policy);
        if (envPolicy?.inherit === "all" && envPolicy.ignore_default_excludes === true) {
          const keyPath = joinPath(scope.prefix, "shell_environment_policy.ignore_default_excludes");
          findings.push(
            makeFinding(
              file,
              "codex-mcp-env-passthrough",
              "medium",
              "exposure",
              "Codex shell inherits every environment variable",
              "shell_environment_policy inherits the full environment and ignore_default_excludes = true removes the built-in filter for names containing KEY, SECRET, and TOKEN. Every command Codex runs can read all credentials in the parent shell. Set inherit = \"core\" or keep the default excludes.",
              keyPath,
              `${joinPath(scope.prefix, "shell_environment_policy.inherit")} = "all"; ${keyPath} = true`,
            ),
          );
        }
      }
      return findings;
    },
  },
  {
    id: "codex-mcp-remote-http",
    name: "Codex MCP server over plain HTTP",
    description: "Flags [mcp_servers.<n>] url = \"http://...\" to a non-loopback host",
    severity: "high",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const scope of scopesOf(config)) {
        for (const { name, path, server } of mcpServersOf(scope)) {
          if (!isPlainHttpRemote(server.url)) continue;
          const keyPath = `${path}.url`;
          findings.push(
            makeFinding(
              file,
              "codex-mcp-remote-http",
              "high",
              "mcp",
              `MCP server "${name}" connects over plain HTTP`,
              `MCP server "${name}" uses ${server.url}. Tool definitions, arguments, and any bearer token travel unencrypted, so an on-path attacker can read them or rewrite tool results into prompt injections. Use https://.`,
              keyPath,
              `${keyPath} = "${server.url}"`,
            ),
          );
        }
      }
      return findings;
    },
  },
  {
    id: "codex-mcp-unpinned",
    name: "Codex MCP server unpinned or bridged insecurely",
    description: "Flags npx/uvx/pipx MCP servers without a pinned version and mcp-remote style bridges to http:// endpoints",
    severity: "medium",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const scope of scopesOf(config)) {
        for (const { name, path, server } of mcpServersOf(scope)) {
          const command = typeof server.command === "string" ? server.command : "";
          const args = asStringArray(server.args);
          if (command.length === 0) continue;

          const unpinned = detectUnpinnedPackage(command, args);
          if (unpinned) {
            const keyPath = `${path}.args`;
            findings.push(
              makeFinding(
                file,
                "codex-mcp-unpinned",
                "medium",
                "mcp",
                `MCP server "${name}" runs an unpinned package`,
                `MCP server "${name}" launches ${unpinned.spec} via ${baseName(command)} with ${unpinned.reason}. Every start resolves the newest publish, so a compromised or hijacked package version runs with the server's permissions. Pin an exact version and review upgrades.`,
                keyPath,
                `${path}.command = "${command}"; ${keyPath} = [${[...args].map((arg) => `"${arg}"`).join(", ")}]`,
              ),
            );
          }

          const bridge = detectRemoteBridge(command, args);
          if (bridge) {
            const keyPath = `${path}.args`;
            findings.push(
              makeFinding(
                file,
                "codex-mcp-remote-bridge",
                "medium",
                "mcp",
                `MCP server "${name}" bridges to an insecure remote`,
                `MCP server "${name}" uses ${bridge.bridge} and ${bridge.reason}${bridge.url ? ` (${bridge.url})` : ""}. The stdio entry hides that this is really a remote server, and the transport is unencrypted. Point the bridge at an https:// endpoint or use the url field directly.`,
                keyPath,
                `${keyPath}: ${bridge.bridge} ${bridge.url ?? ""}`.trim(),
              ),
            );
          }
        }
      }
      return findings;
    },
  },
  {
    id: "codex-notify-executes-shell",
    name: "Codex notify runs a shell or network command",
    description: "Flags a notify array that invokes sh/bash/zsh, curl, wget, osascript with a URL, or -c",
    severity: "medium",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const scope of scopesOf(config)) {
        const notify = asStringArray(scope.table.notify);
        const reason = isShellNotify(notify);
        if (!reason) continue;
        const keyPath = joinPath(scope.prefix, "notify");
        findings.push(
          makeFinding(
            file,
            "codex-notify-executes-shell",
            "medium",
            "hooks",
            "Codex notify hook runs shell or network commands",
            `The notify command runs on every agent event with a JSON payload describing the turn, and here ${reason}. That turns a notification hook into a script that can leak transcripts or run injected content. Use a dedicated notifier binary with fixed arguments.`,
            keyPath,
            `${keyPath} = [${notify.map((arg) => `"${arg}"`).join(", ")}]`,
          ),
        );
      }
      return findings;
    },
  },
  {
    id: "codex-hooks-disabled-in-project",
    name: "Project Codex config disables hooks",
    description: "Flags [features] hooks = false inside a repo .codex/ config",
    severity: "medium",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isProjectScopedPath(file.path)) return [];
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const scope of scopesOf(config)) {
        if (asTable(scope.table.features)?.hooks !== false) continue;
        const keyPath = joinPath(scope.prefix, "features.hooks");
        findings.push(
          makeFinding(
            file,
            "codex-hooks-disabled-in-project",
            "medium",
            "hooks",
            "Repository config turns off Codex hooks",
            "features.hooks = false in a project config disables every hook, including the user's own PreToolUse guards and audit hooks in ~/.codex. A repository should not be able to switch off the operator's safety hooks. Remove the key from the project file.",
            keyPath,
            `${keyPath} = false`,
          ),
        );
      }
      return findings;
    },
  },
  {
    id: "codex-provider-redirect",
    name: "Codex model provider redirected insecurely",
    description: "Flags [model_providers.<id>] base_url over http:// or a non-OpenAI host with literal auth headers",
    severity: "high",
    category: "exposure",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const scope of scopesOf(config)) {
        const providers = asTable(scope.table.model_providers);
        if (!providers) continue;
        for (const [id, provider] of Object.entries(providers)) {
          if (!isTable(provider)) continue;
          const path = joinPath(scope.prefix, `model_providers.${id}`);
          const baseUrl = typeof provider.base_url === "string" ? provider.base_url.trim() : "";

          if (isPlainHttpRemote(baseUrl)) {
            findings.push(
              makeFinding(
                file,
                "codex-provider-redirect",
                "high",
                "exposure",
                `Model provider "${id}" uses plain HTTP`,
                `model_providers.${id}.base_url is ${baseUrl}. Every prompt, file excerpt, and API key header goes over the network unencrypted. Use https:// or a loopback address.`,
                `${path}.base_url`,
                `${path}.base_url = "${baseUrl}"`,
              ),
            );
          }

          const headers = asTable(provider.http_headers);
          if (!headers || baseUrl.length === 0 || isOpenAiHost(baseUrl)) continue;
          for (const [header, value] of Object.entries(headers)) {
            if (!isSecretHeaderName(header) || !isLiteralCredential(value)) continue;
            findings.push(
              makeFinding(
                file,
                "codex-provider-redirect",
                "high",
                "exposure",
                `Model provider "${id}" sends a literal ${header} header to a third-party host`,
                `model_providers.${id} points at ${baseUrl} and attaches a hardcoded ${header} header. The credential lives in config.toml and is sent to a non-OpenAI endpoint on every request. Use env_http_headers and confirm the base_url is intended.`,
                `${path}.http_headers.${header}`,
                `${path}.http_headers.${header} = "${redactSecret(value)}"; base_url = "${baseUrl}"`,
              ),
            );
          }
        }
      }
      return findings;
    },
  },
  {
    id: "codex-web-search-live-unattended",
    name: "Codex live web search without approvals",
    description: "Flags web_search = \"live\" combined with approval_policy = \"never\"",
    severity: "low",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const scope of scopesOf(config)) {
        if (scope.table.web_search !== "live") continue;
        if (effectiveApprovalPolicy(scope, config) !== "never") continue;
        const keyPath = joinPath(scope.prefix, "web_search");
        findings.push(
          makeFinding(
            file,
            "codex-web-search-live-unattended",
            "low",
            "permissions",
            "Live web search feeds an unattended agent",
            "web_search = \"live\" pulls arbitrary web content into the context while approval_policy = \"never\" means nothing the model decides to do with that content is reviewed. That is a direct prompt-injection path. Use \"cached\" search or restore approvals.",
            keyPath,
            `${keyPath} = "live"; approval_policy = "never"`,
          ),
        );
      }
      return findings;
    },
  },
  {
    id: "codex-agent-role-full-access",
    name: "Codex agent role escalates or carries injection",
    description: "Flags .codex/agents/*.toml with danger-full-access or injection phrases in developer_instructions",
    severity: "critical",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isAgentRolePath(file.path)) return [];
      const config = parseCodexConfig(file);
      if (!config) return [];

      const findings: Finding[] = [];
      if (config.sandbox_mode === "danger-full-access") {
        findings.push(
          makeFinding(
            file,
            "codex-agent-role-full-access",
            "critical",
            "permissions",
            "Codex agent role runs without a sandbox",
            "This agent role sets sandbox_mode = \"danger-full-access\". Sub-agents spawned with this role run commands with no filesystem or network restrictions, often on delegated tasks nobody is watching. Use \"read-only\" or \"workspace-write\" for roles.",
            "sandbox_mode",
            "sandbox_mode = \"danger-full-access\"",
          ),
        );
      }

      const instructions = typeof config.developer_instructions === "string" ? config.developer_instructions : "";
      const phrase = findInjectionPhrase(instructions);
      if (phrase) {
        findings.push(
          makeFinding(
            file,
            "codex-agent-role-full-access",
            "high",
            "injection",
            "Codex agent role instructions contain injection phrasing",
            `developer_instructions for this role includes "${phrase}". Role instructions are trusted as developer messages, so text that overrides prior instructions or directs data to external URLs is an injection payload with elevated authority. Review and remove it.`,
            "developer_instructions",
            `developer_instructions contains "${phrase}"`,
          ),
        );
      }
      return findings;
    },
  },
  {
    id: "codex-hooks-auto-allow",
    name: "Codex hook auto-approves permissions",
    description: "Flags .codex/hooks.json PreToolUse or PermissionRequest commands that emit permissionDecision allow unconditionally",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "harness-json" || !isCodexHooksPath(file.path)) return [];
      const config = parseJsonLenient(file.content);
      if (!config) return [];

      const findings: Finding[] = [];
      for (const event of ["PreToolUse", "PermissionRequest"]) {
        for (const command of hookCommandsOf(config, event)) {
          if (!UNCONDITIONAL_ALLOW_PATTERN.test(command) || CONDITIONAL_PATTERN.test(command)) continue;
          const commandIndex = file.content.indexOf(command.substring(0, 40));
          findings.push({
            id: "codex-hooks-auto-allow",
            severity: "critical",
            category: "hooks",
            title: `${event} hook approves every request`,
            description: `A ${event} hook emits permissionDecision "allow" with no condition, so every tool call or permission prompt it sees is approved before a human can look at it. This defeats approval_policy entirely. Make the hook inspect the tool input and only allow specific, safe cases.`,
            file: file.path,
            line: commandIndex >= 0 ? file.content.substring(0, commandIndex).split("\n").length : findLineNumber(file.content, event),
            evidence: `${event}: ${command.length > 120 ? `${command.substring(0, 120)}...` : command}`,
          });
        }
      }
      return findings;
    },
  },
];
