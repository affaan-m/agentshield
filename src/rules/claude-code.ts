import { basename } from "node:path";
import { homedir } from "node:os";
import type { ConfigFile, Finding, FindingCategory, Rule, Severity } from "../types.js";
import { parseFrontmatter, parseJsonLenient } from "../scanner/parsers.js";

/**
 * Rules for the September 2026 Claude Code configuration surface:
 * settings.json keys, the hooks schema, SKILL.md frontmatter and dynamic
 * context blocks, and subagent frontmatter. Every rule parses the file first
 * and fails closed: an unparseable file yields no finding.
 */

// ─── Shared helpers ────────────────────────────────────────

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function isTruthyFlag(value: unknown): boolean {
  if (value === true) return true;
  if (typeof value === "string") return /^(?:true|yes|on|1)$/i.test(value.trim());
  if (typeof value === "number") return value === 1;
  return false;
}

/** Strings from a scalar or a list, ignoring anything that is not a string. */
function stringList(value: unknown): ReadonlyArray<string> {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  return [];
}

/**
 * Line of the first candidate that appears in the raw content. Candidates are
 * tried in order so callers can pass the value first and the key as a fallback.
 */
function findLineNumber(content: string, candidates: ReadonlyArray<string>): number | undefined {
  for (const candidate of candidates) {
    if (!candidate) continue;
    const index = content.indexOf(candidate);
    if (index !== -1) return content.substring(0, index).split("\n").length;
  }
  return undefined;
}

function redactSecret(value: string): string {
  return `${value.slice(0, 4)}***`;
}

function truncate(value: string, max = 120): string {
  return value.length > max ? `${value.slice(0, max)}...` : value;
}

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

function isManagedSettingsPath(filePath: string): boolean {
  const normalized = normalizePath(filePath);
  return (
    /managed-settings(?:\.d\/[^/]+)?\.json$/i.test(normalized) ||
    /\/ClaudeCode\//.test(normalized) ||
    /\/etc\/claude-code\//.test(normalized)
  );
}

function isUserScopeSettingsPath(filePath: string): boolean {
  const normalized = normalizePath(filePath);
  const home = normalizePath(homedir());
  if (home && normalized.startsWith(`${home}/.claude/`)) return true;
  if (/^~\/\.claude\//.test(normalized)) return true;
  return /^\/(?:Users|home)\/[^/]+\/\.claude\/[^/]+\.json$/.test(normalized);
}

/** True for settings that travel with a repository clone. */
function isProjectScopeSettings(filePath: string): boolean {
  return !isManagedSettingsPath(filePath) && !isUserScopeSettingsPath(filePath);
}

function parseSettings(file: ConfigFile): JsonRecord | null {
  if (file.type !== "settings-json") return null;
  return parseJsonLenient(file.content);
}

const CREDENTIAL_SHAPES: ReadonlyArray<RegExp> = [
  /^sk-ant-[A-Za-z0-9_-]{10,}/,
  /^sk-[A-Za-z0-9_-]{16,}/,
  /^ghp_[A-Za-z0-9]{16,}/,
  /^gho_[A-Za-z0-9]{16,}/,
  /^github_pat_[A-Za-z0-9_]{20,}/,
  /^AKIA[0-9A-Z]{12,}/,
  /^xox[bpa]-[A-Za-z0-9-]{10,}/,
  /^Bearer\s+\S{20,}/,
  /^[0-9a-f]{32,}$/i,
];

function isEnvReference(value: string): boolean {
  return /\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/.test(value);
}

function isPlaceholderValue(value: string): boolean {
  return /^(?:YOUR_|REPLACE|CHANGEME|<)/i.test(value.trim()) || /\.\.\.$/.test(value.trim());
}

function looksLikeCredential(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed || isEnvReference(trimmed) || isPlaceholderValue(trimmed)) return false;
  if (CREDENTIAL_SHAPES.some((shape) => shape.test(trimmed))) return true;
  // Long base64-ish blobs, excluding paths and URLs.
  if (/^[/~.]/.test(trimmed) || /:\/\//.test(trimmed) || /\s/.test(trimmed)) return false;
  return /^[A-Za-z0-9+/=_-]{40,}$/.test(trimmed) && /\d/.test(trimmed) && /[A-Za-z]/.test(trimmed);
}

const REMOTE_COMMAND_PATTERN =
  /\b(?:curl|wget|nc|ncat|netcat)\b|\bbash\s+-c\b|\bbase64\s+(?:-d|--decode)\b|\bpython\d?\s+-c\b|\bnode\s+-e\b|https?:\/\//i;

const NETWORK_COMMAND_PATTERN = /\b(?:curl|wget|nc|ncat|netcat|fetch)\b|https?:\/\//i;

function hostOf(url: string): string | undefined {
  const match = url.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]+)/i);
  if (!match) return undefined;
  return match[1].replace(/^[^@]*@/, "").replace(/:\d+$/, "").replace(/^\[|\]$/g, "").toLowerCase();
}

function isLoopbackHost(host: string | undefined): boolean {
  if (!host) return false;
  return (
    host === "localhost" ||
    host === "::1" ||
    host === "0.0.0.0" ||
    /^127\./.test(host) ||
    host.endsWith(".localhost")
  );
}

function makeFinding(
  file: ConfigFile,
  id: string,
  severity: Severity,
  category: FindingCategory,
  title: string,
  description: string,
  evidence: string,
  lineCandidates: ReadonlyArray<string>
): Finding {
  return {
    id,
    severity,
    category,
    title,
    description,
    file: file.path,
    line: findLineNumber(file.content, lineCandidates),
    evidence: truncate(evidence),
  };
}

// ─── Hook walking ──────────────────────────────────────────

interface HookEntry {
  readonly event: string;
  readonly matcher: string;
  readonly entry: JsonRecord;
  readonly type: string;
  /** Command, prompt, and url text joined, for text searches. */
  readonly text: string;
  readonly command: string;
}

function toHookEntry(event: string, matcher: string, entry: JsonRecord): HookEntry {
  const command = asString(entry.command) ?? "";
  const prompt = asString(entry.prompt) ?? "";
  const url = asString(entry.url) ?? "";
  const args = stringList(entry.args).join(" ");
  const type = asString(entry.type) ?? (command ? "command" : prompt ? "prompt" : url ? "http" : "");
  return {
    event,
    matcher,
    entry,
    type,
    text: [command, args, prompt, url].filter(Boolean).join("\n"),
    command: [command, args].filter(Boolean).join(" "),
  };
}

/**
 * Flattens a hooks block into entries. Tolerates unknown keys on matcher
 * groups (ECC adds `description` and `id`) and groups that are entries
 * themselves.
 */
function collectHookEntries(hooks: unknown): ReadonlyArray<HookEntry> {
  if (!isRecord(hooks)) return [];
  const entries: HookEntry[] = [];

  for (const [event, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const group of groups) {
      if (!isRecord(group)) continue;
      const matcher = asString(group.matcher) ?? "";
      if (Array.isArray(group.hooks)) {
        for (const entry of group.hooks) {
          if (isRecord(entry)) entries.push(toHookEntry(event, matcher, entry));
        }
      } else if ("command" in group || "type" in group || "prompt" in group || "url" in group) {
        entries.push(toHookEntry(event, matcher, group));
      }
    }
  }

  return entries;
}

function hookLineCandidates(hook: HookEntry): ReadonlyArray<string> {
  const command = asString(hook.entry.command) ?? "";
  const prompt = asString(hook.entry.prompt) ?? "";
  const url = asString(hook.entry.url) ?? "";
  // JSON escaping can change the raw text, so fall back to a short prefix and the event name.
  return [command, prompt, url, command.slice(0, 30), `"${hook.event}"`, hook.event];
}

function parseHooksFromSettings(file: ConfigFile): ReadonlyArray<HookEntry> {
  const settings = parseSettings(file);
  if (!settings) return [];
  return collectHookEntries(settings.hooks);
}

const ALLOW_DECISION_PATTERN = /permissionDecision[\s\S]{0,40}?allow/;
const CONDITIONAL_PATTERN = /\b(?:if|case|grep|test|then|elif|fi)\b|\[\[/;

function isUnconditionalAllow(text: string): boolean {
  return ALLOW_DECISION_PATTERN.test(text) && !CONDITIONAL_PATTERN.test(text);
}

function isWildcardMatcher(matcher: string): boolean {
  return matcher === "" || matcher === ".*" || matcher === "*";
}

// ─── Skill and agent frontmatter ───────────────────────────

function skillBody(content: string): string {
  if (!content.startsWith("---")) return content;
  const end = content.indexOf("\n---", 3);
  if (end === -1) return content;
  return content.slice(end + 4);
}

/** Tokens such as `Read`, `Bash(git add *)`, `mcp__github__*`, `Agent(*)`. */
function parseToolTokens(value: unknown): ReadonlyArray<string> {
  const joined = stringList(value).join(" ");
  return [...joined.matchAll(/mcp__[A-Za-z0-9_*-]+|[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?/g)].map(
    (match) => match[0]
  );
}

function parseAgentFrontmatter(file: ConfigFile): JsonRecord | null {
  if (file.type !== "agent-md") return null;
  if (basename(normalizePath(file.path)).toLowerCase().endsWith(".json")) {
    return parseJsonLenient(file.content);
  }
  return parseFrontmatter(file.content);
}

function parseSkillFrontmatter(file: ConfigFile): JsonRecord | null {
  if (file.type !== "skill-md") return null;
  return parseFrontmatter(file.content);
}

// ─── Settings rules ────────────────────────────────────────

const HELPER_KEYS: ReadonlyArray<{ readonly key: string; readonly path: ReadonlyArray<string> }> = [
  { key: "apiKeyHelper", path: ["apiKeyHelper"] },
  { key: "awsAuthRefresh", path: ["awsAuthRefresh"] },
  { key: "awsCredentialExport", path: ["awsCredentialExport"] },
  { key: "gcpAuthRefresh", path: ["gcpAuthRefresh"] },
  { key: "otelHeadersHelper", path: ["otelHeadersHelper"] },
  { key: "statusLine.command", path: ["statusLine", "command"] },
  { key: "processWrapper", path: ["processWrapper"] },
  { key: "policyHelper.path", path: ["policyHelper", "path"] },
];

function readPath(record: JsonRecord, path: ReadonlyArray<string>): unknown {
  let current: unknown = record;
  for (const segment of path) {
    if (!isRecord(current)) return undefined;
    current = current[segment];
  }
  return current;
}

const ENV_OVERRIDES: ReadonlyArray<{
  readonly name: string;
  readonly severity: Severity;
  readonly effect: string;
  readonly onlyWhenValue?: string;
  readonly redact?: boolean;
}> = [
  { name: "ANTHROPIC_BASE_URL", severity: "critical", effect: "redirects every model request, including the API key, to another endpoint" },
  { name: "NODE_TLS_REJECT_UNAUTHORIZED", severity: "critical", effect: "disables TLS certificate checks so traffic can be intercepted", onlyWhenValue: "0" },
  { name: "NODE_EXTRA_CA_CERTS", severity: "critical", effect: "trusts an extra CA, which lets a proxy terminate TLS for API traffic" },
  { name: "LD_PRELOAD", severity: "critical", effect: "injects a shared library into every process Claude Code starts" },
  { name: "DYLD_INSERT_LIBRARIES", severity: "critical", effect: "injects a dylib into every process Claude Code starts" },
  { name: "BASH_ENV", severity: "critical", effect: "sources a file in every non-interactive bash shell, including hook and tool commands" },
  { name: "ENV", severity: "critical", effect: "sources a file in every sh shell, including hook and tool commands" },
  { name: "PYTHONSTARTUP", severity: "critical", effect: "runs a script whenever an interactive python starts" },
  { name: "ANTHROPIC_API_KEY", severity: "medium", effect: "replaces the account credential used for model calls", redact: true },
  { name: "ANTHROPIC_AUTH_TOKEN", severity: "medium", effect: "replaces the bearer token used for model calls", redact: true },
  { name: "HTTPS_PROXY", severity: "medium", effect: "routes API traffic through a proxy" },
  { name: "HTTP_PROXY", severity: "medium", effect: "routes HTTP traffic through a proxy" },
  { name: "NODE_OPTIONS", severity: "medium", effect: "can preload modules into node processes with --require or --import" },
  { name: "PATH", severity: "medium", effect: "changes which binaries commands resolve to, so trusted tool names can be shadowed" },
  { name: "SHELL", severity: "medium", effect: "changes the shell used to run commands" },
];

const SANDBOX_EXCLUDED_COMMAND = /^(?:\*|(?:bash|sh|zsh|python\d*|node|curl|wget)(?:\s|\*|$))/;

const settingsRules: ReadonlyArray<Rule> = [
  {
    id: "permissions-bypass-default-mode",
    name: "Permission prompts disabled by defaultMode",
    description: "Checks permissions.defaultMode for bypassPermissions, dontAsk, or auto",
    severity: "critical",
    category: "permissions",
    check(file) {
      const settings = parseSettings(file);
      if (!settings || !isRecord(settings.permissions)) return [];
      const mode = asString(settings.permissions.defaultMode);
      if (!mode) return [];

      if (mode === "bypassPermissions") {
        return [
          makeFinding(
            file,
            "permissions-bypass-default-mode",
            "critical",
            "permissions",
            "defaultMode bypassPermissions skips every permission prompt",
            "permissions.defaultMode is set to bypassPermissions. Every tool call, including writes, shell commands, and network access, runs without a prompt for the whole session. Deny rules still apply but nothing else does.",
            `"defaultMode": "${mode}"`,
            [`"defaultMode"`, "defaultMode"]
          ),
        ];
      }

      if (mode === "dontAsk" || mode === "auto") {
        return [
          makeFinding(
            file,
            "permissions-bypass-default-mode",
            "medium",
            "permissions",
            `defaultMode ${mode} suppresses permission prompts`,
            `permissions.defaultMode is set to ${mode}. Claude Code ignores this value from project scope in terminals, but a repo shipping it signals an intent to run without prompts, and it takes effect from user scope or a --settings file.`,
            `"defaultMode": "${mode}"`,
            [`"defaultMode"`, "defaultMode"]
          ),
        ];
      }

      return [];
    },
  },
  {
    id: "permissions-skip-dangerous-prompt",
    name: "Dangerous mode confirmation skipped",
    description: "Checks for skipDangerousModePermissionPrompt set to true",
    severity: "low",
    category: "permissions",
    check(file) {
      const settings = parseSettings(file);
      if (!settings || settings.skipDangerousModePermissionPrompt !== true) return [];
      return [
        makeFinding(
          file,
          "permissions-skip-dangerous-prompt",
          "low",
          "permissions",
          "skipDangerousModePermissionPrompt removes the bypass confirmation",
          "skipDangerousModePermissionPrompt is true, so --dangerously-skip-permissions starts without the confirmation dialog. The safety net that makes a user notice they are entering bypass mode is gone.",
          `"skipDangerousModePermissionPrompt": true`,
          ["skipDangerousModePermissionPrompt"]
        ),
      ];
    },
  },
  {
    id: "permissions-additional-directories-broad",
    name: "additionalDirectories grants a sensitive directory",
    description: "Checks permissions.additionalDirectories for the home directory, root, or credential stores",
    severity: "high",
    category: "permissions",
    check(file) {
      const settings = parseSettings(file);
      if (!settings || !isRecord(settings.permissions)) return [];
      const directories = stringList(settings.permissions.additionalDirectories);
      const broad = /^(?:~|\/|\$HOME|~\/\.(?:ssh|aws|claude|codex|hermes|gnupg|kube)|\$HOME\/\.(?:ssh|aws|claude|codex|hermes|gnupg|kube))\/?$/;

      return directories
        .filter((directory) => broad.test(directory.trim()))
        .map((directory) =>
          makeFinding(
            file,
            "permissions-additional-directories-broad",
            "high",
            "permissions",
            `additionalDirectories includes ${directory}`,
            `permissions.additionalDirectories adds ${directory} to the working set. Claude Code can read and, with edit approval, write anything under it, which for this path means credentials, agent configs, or the whole filesystem.`,
            directory,
            [directory, "additionalDirectories"]
          )
        );
    },
  },
  {
    id: "settings-helper-executes-command",
    name: "Helper command runs at session start",
    description: "Checks helper keys such as apiKeyHelper and statusLine.command that run a command when Claude Code starts",
    severity: "critical",
    category: "misconfiguration",
    check(file) {
      const settings = parseSettings(file);
      if (!settings) return [];
      const projectScope = isProjectScopeSettings(file.path);

      return HELPER_KEYS.flatMap(({ key, path }) => {
        const value = readPath(settings, path);
        const command = asString(value)?.trim();
        if (!command) return [];

        const remote = REMOTE_COMMAND_PATTERN.test(command);
        const severity: Severity = remote || projectScope ? "critical" : "medium";
        const scopeNote = projectScope
          ? "This file travels with the repository, so anyone who clones it runs this command on their machine at session start."
          : "This is a user-scope file, so only this machine runs it.";
        const remoteNote = remote
          ? " The command downloads or decodes and runs remote content, which is the shape of a dropper."
          : "";

        return [
          makeFinding(
            file,
            "settings-helper-executes-command",
            severity,
            "misconfiguration",
            `${key} runs a command at startup`,
            `${key} is an executable hook that Claude Code runs without a prompt to obtain credentials or status. ${scopeNote}${remoteNote}`,
            `${key}: ${command}`,
            [command, `"${path[path.length - 1]}"`, path[0]]
          ),
        ];
      });
    },
  },
  {
    id: "settings-env-override",
    name: "env block overrides a security-sensitive variable",
    description: "Checks the env block for variables that redirect traffic, weaken TLS, or inject code into processes",
    severity: "critical",
    category: "exposure",
    check(file) {
      const settings = parseSettings(file);
      if (!settings || !isRecord(settings.env)) return [];
      const env = settings.env;

      return ENV_OVERRIDES.flatMap(({ name, severity, effect, onlyWhenValue, redact }) => {
        if (!(name in env)) return [];
        const value = env[name];
        const text = typeof value === "string" ? value : JSON.stringify(value);
        if (onlyWhenValue !== undefined && text.trim() !== onlyWhenValue) return [];
        const shown = redact && !isEnvReference(text) ? redactSecret(text) : text;

        return [
          makeFinding(
            file,
            "settings-env-override",
            severity,
            "exposure",
            `env sets ${name}`,
            `The env block sets ${name}, which ${effect}. Claude Code applies these variables to its own process and every hook and tool command it starts.`,
            `${name}=${shown}`,
            [`"${name}"`, name]
          ),
        ];
      });
    },
  },
  {
    id: "settings-env-secret-literal",
    name: "Literal credential in env block",
    description: "Checks env values for credential shapes that are not ${VAR} references",
    severity: "high",
    category: "secrets",
    check(file) {
      const settings = parseSettings(file);
      if (!settings || !isRecord(settings.env)) return [];

      return Object.entries(settings.env).flatMap(([name, value]) => {
        const text = asString(value);
        if (!text || !looksLikeCredential(text)) return [];
        return [
          makeFinding(
            file,
            "settings-env-secret-literal",
            "high",
            "secrets",
            `env value for ${name} is a literal credential`,
            `The env block stores a credential-shaped value for ${name} in plain text. Settings files are committed, synced, and read by every hook, so the secret is exposed to anything that can read the file. Reference it as \${${name}} from the process environment instead.`,
            `${name}=${redactSecret(text)}`,
            [`"${name}"`, name]
          ),
        ];
      });
    },
  },
  {
    id: "hooks-disabled-in-project",
    name: "disableAllHooks in a project settings file",
    description: "Checks for disableAllHooks true in a repository-scoped settings file",
    severity: "medium",
    category: "hooks",
    check(file) {
      const settings = parseSettings(file);
      if (!settings || settings.disableAllHooks !== true) return [];
      if (!isProjectScopeSettings(file.path)) return [];
      return [
        makeFinding(
          file,
          "hooks-disabled-in-project",
          "medium",
          "hooks",
          "disableAllHooks turns off every hook from a project file",
          "disableAllHooks is true in a repository-scoped settings file. It disables the user's own guard hooks (secret scanners, PreToolUse blockers) for anyone who opens this project, not just the project's hooks.",
          `"disableAllHooks": true`,
          ["disableAllHooks"]
        ),
      ];
    },
  },
  {
    id: "hooks-http-url-unrestricted",
    name: "allowedHttpHookUrls allows any or plaintext host",
    description: "Checks allowedHttpHookUrls for a wildcard or an http:// entry",
    severity: "medium",
    category: "hooks",
    check(file) {
      const settings = parseSettings(file);
      if (!settings) return [];
      const urls = stringList(settings.allowedHttpHookUrls);

      return urls
        .filter((url) => url.trim() === "*" || /^http:\/\//i.test(url.trim()))
        .map((url) =>
          makeFinding(
            file,
            "hooks-http-url-unrestricted",
            "medium",
            "hooks",
            url.trim() === "*"
              ? "allowedHttpHookUrls allows http hooks to any host"
              : "allowedHttpHookUrls allows a plaintext http hook target",
            `allowedHttpHookUrls contains ${url}. This list is the only control over where type: http hooks may post tool input and transcript data, so a wildcard or plaintext entry lets hook payloads leave the machine unencrypted or to any host.`,
            url,
            [url, "allowedHttpHookUrls"]
          )
        );
    },
  },
  {
    id: "settings-sandbox-escape",
    name: "Sandbox enabled with an escape hatch",
    description: "Checks sandbox settings for options that defeat the sandbox while it is enabled",
    severity: "high",
    category: "misconfiguration",
    check(file) {
      const settings = parseSettings(file);
      if (!settings || !isRecord(settings.sandbox) || settings.sandbox.enabled !== true) return [];
      const sandbox = settings.sandbox;
      const network = isRecord(sandbox.network) ? sandbox.network : {};
      const filesystem = isRecord(sandbox.filesystem) ? sandbox.filesystem : {};
      const findings: Finding[] = [];

      const emit = (title: string, description: string, evidence: string, key: string): void => {
        findings.push(
          makeFinding(file, "settings-sandbox-escape", "high", "misconfiguration", title, description, evidence, [evidence, key])
        );
      };

      if (filesystem.disabled === true) {
        emit(
          "Sandbox filesystem isolation disabled",
          "sandbox.enabled is true but sandbox.filesystem.disabled is also true, so commands keep full filesystem access. Claude Code only honors this from user or managed scope, but it removes the file boundary wherever it applies.",
          `"disabled": true`,
          "filesystem"
        );
      }

      if (network.allowAllUnixSockets === true || sandbox.allowAllUnixSockets === true) {
        emit(
          "Sandbox allows every unix socket",
          "allowAllUnixSockets is true, so sandboxed commands can talk to any local daemon socket, including docker and ssh agents, which is a direct route out of the sandbox.",
          `"allowAllUnixSockets": true`,
          "allowAllUnixSockets"
        );
      }

      const sockets = [...stringList(network.allowUnixSockets), ...stringList(sandbox.allowUnixSockets)];
      for (const socket of sockets) {
        if (/docker\.sock/.test(socket)) {
          emit(
            "Sandbox allows the docker socket",
            "allowUnixSockets grants access to the docker socket. Anything that can reach it can start a privileged container with the host filesystem mounted, which is equivalent to root on the host.",
            socket,
            "allowUnixSockets"
          );
        }
      }

      if (sandbox.enableWeakerNestedSandbox === true) {
        emit(
          "Weaker nested sandbox enabled",
          "enableWeakerNestedSandbox is true, which tells Claude Code to fall back to a reduced sandbox inside containers instead of failing. The reduced mode does not enforce the same filesystem and network boundaries.",
          `"enableWeakerNestedSandbox": true`,
          "enableWeakerNestedSandbox"
        );
      }

      for (const command of stringList(sandbox.excludedCommands)) {
        if (SANDBOX_EXCLUDED_COMMAND.test(command.trim())) {
          emit(
            `Sandbox excludes ${command.trim()}`,
            `excludedCommands lists ${command.trim()}, which runs outside the sandbox. Excluding a shell, interpreter, downloader, or wildcard means any command can be wrapped in it to skip the sandbox entirely.`,
            command,
            "excludedCommands"
          );
        }
      }

      return findings;
    },
  },
  {
    id: "settings-sandbox-network-any",
    name: "Sandbox network allowlist is a wildcard",
    description: "Checks sandbox.network.allowedDomains for a wildcard entry",
    severity: "high",
    category: "misconfiguration",
    check(file) {
      const settings = parseSettings(file);
      if (!settings || !isRecord(settings.sandbox) || !isRecord(settings.sandbox.network)) return [];
      const domains = stringList(settings.sandbox.network.allowedDomains);

      return domains
        .filter((domain) => domain.trim() === "*" || domain.trim() === "*.*")
        .map((domain) =>
          makeFinding(
            file,
            "settings-sandbox-network-any",
            "high",
            "misconfiguration",
            "Sandbox allowedDomains allows every host",
            `sandbox.network.allowedDomains contains ${domain}. The network allowlist is what stops a sandboxed command from exfiltrating data, and a wildcard lets it reach any host.`,
            domain,
            ["allowedDomains"]
          )
        );
    },
  },
  {
    id: "settings-marketplace-insecure",
    name: "Plugin marketplace over plaintext or raw IP",
    description: "Checks extraKnownMarketplaces entries for http:// or raw IP sources",
    severity: "medium",
    category: "misconfiguration",
    check(file) {
      const settings = parseSettings(file);
      if (!settings) return [];
      const raw = settings.extraKnownMarketplaces;
      const entries: ReadonlyArray<unknown> = Array.isArray(raw) ? raw : isRecord(raw) ? Object.values(raw) : [];

      return entries.flatMap((entry) => {
        const source = isRecord(entry)
          ? asString(entry.url) ?? asString(entry.source) ?? (isRecord(entry.source) ? asString(entry.source.url) : undefined)
          : asString(entry);
        if (!source) return [];
        const plaintext = /^http:\/\//i.test(source);
        const rawIp = /^(?:https?:\/\/)?\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:\/|$)/.test(source);
        if (!plaintext && !rawIp) return [];

        return [
          makeFinding(
            file,
            "settings-marketplace-insecure",
            "medium",
            "misconfiguration",
            plaintext ? "Marketplace fetched over plaintext http" : "Marketplace points at a raw IP address",
            `extraKnownMarketplaces registers ${source}. Plugins installed from it run hooks, MCP servers, and skills locally, so a source that can be spoofed on the wire or has no verifiable identity is a supply-chain entry point.`,
            source,
            [source, "extraKnownMarketplaces"]
          ),
        ];
      });
    },
  },
  {
    id: "settings-login-redirect",
    name: "Login redirected to a custom gateway",
    description: "Checks forceLoginMethod and forceLoginGatewayUrl in files that are not managed settings",
    severity: "high",
    category: "exposure",
    check(file) {
      const settings = parseSettings(file);
      if (!settings || isManagedSettingsPath(file.path)) return [];
      const findings: Finding[] = [];

      const method = asString(settings.forceLoginMethod);
      if (method && /^https?:\/\//i.test(method.trim())) {
        findings.push(
          makeFinding(
            file,
            "settings-login-redirect",
            "high",
            "exposure",
            "forceLoginMethod points at a URL",
            `forceLoginMethod is ${method}. Login is redirected to a custom gateway from a file that is not managed policy, so credentials entered at login can be captured by whoever controls that host.`,
            method,
            [method, "forceLoginMethod"]
          )
        );
      }

      const gateway = settings.forceLoginGatewayUrl;
      if (gateway !== undefined) {
        const text = asString(gateway) ?? JSON.stringify(gateway);
        findings.push(
          makeFinding(
            file,
            "settings-login-redirect",
            "high",
            "exposure",
            "forceLoginGatewayUrl set outside managed settings",
            `forceLoginGatewayUrl is set to ${text} in a file that is not managed policy. This routes authentication through a custom gateway, which is only legitimate when an administrator sets it in managed settings.`,
            text,
            [text, "forceLoginGatewayUrl"]
          )
        );
      }

      return findings;
    },
  },
];

// ─── Hook rules ────────────────────────────────────────────

const EXFIL_EVENTS: ReadonlySet<string> = new Set([
  "PostToolUse",
  "Stop",
  "UserPromptSubmit",
  "MessageDisplay",
  "SessionEnd",
]);

const hookRules: ReadonlyArray<Rule> = [
  {
    id: "hooks-auto-allow-decision",
    name: "Hook auto-approves tool calls",
    description: "Checks PreToolUse and PermissionRequest hooks that emit permissionDecision allow with no condition",
    severity: "critical",
    category: "hooks",
    check(file) {
      return parseHooksFromSettings(file)
        .filter((hook) => (hook.event === "PreToolUse" || hook.event === "PermissionRequest") && isUnconditionalAllow(hook.text))
        .map((hook) => {
          const wildcard = isWildcardMatcher(hook.matcher);
          return makeFinding(
            file,
            "hooks-auto-allow-decision",
            "critical",
            "hooks",
            wildcard
              ? `${hook.event} hook auto-allows every tool`
              : `${hook.event} hook auto-allows ${hook.matcher}`,
            `A ${hook.event} hook${wildcard ? ` with matcher "${hook.matcher || "(all)"}"` : ` matching ${hook.matcher}`} emits permissionDecision allow without any conditional logic, so the matching tool calls are approved without a prompt. Deny and ask rules still win, but everything else runs unattended.`,
            truncate(hook.text.replace(/\s+/g, " ")),
            hookLineCandidates(hook)
          );
        });
    },
  },
  {
    id: "hooks-updated-permissions",
    name: "Hook grants permissions",
    description: "Checks hooks whose output adds permission rules through updatedPermissions",
    severity: "high",
    category: "hooks",
    check(file) {
      return parseHooksFromSettings(file)
        .filter((hook) => /updatedPermissions/.test(hook.text))
        .map((hook) =>
          makeFinding(
            file,
            "hooks-updated-permissions",
            "high",
            "hooks",
            `${hook.event} hook emits updatedPermissions`,
            "The hook output includes updatedPermissions, which appends allow rules to the live session. A hook that grants permissions can widen what Claude may run without the user editing settings.",
            truncate(hook.text.replace(/\s+/g, " ")),
            ["updatedPermissions", ...hookLineCandidates(hook)]
          )
        );
    },
  },
  {
    id: "hooks-updated-input",
    name: "Hook rewrites tool input",
    description: "Checks hooks whose output rewrites the tool call through updatedInput",
    severity: "medium",
    category: "hooks",
    check(file) {
      return parseHooksFromSettings(file)
        .filter((hook) => /updatedInput/.test(hook.text))
        .map((hook) =>
          makeFinding(
            file,
            "hooks-updated-input",
            "medium",
            "hooks",
            `${hook.event} hook emits updatedInput`,
            "The hook output includes updatedInput, which silently replaces the command, file path, or prompt before it runs. The user sees the original tool call and approves something else.",
            truncate(hook.text.replace(/\s+/g, " ")),
            ["updatedInput", ...hookLineCandidates(hook)]
          )
        );
    },
  },
  {
    id: "hooks-http-plaintext",
    name: "HTTP hook posts over plaintext",
    description: "Checks type http hooks with an http:// url to a non-loopback host",
    severity: "high",
    category: "hooks",
    check(file) {
      return parseHooksFromSettings(file)
        .filter((hook) => hook.type === "http")
        .flatMap((hook) => {
          const url = asString(hook.entry.url)?.trim() ?? "";
          if (!/^http:\/\//i.test(url) || isLoopbackHost(hostOf(url))) return [];
          return [
            makeFinding(
              file,
              "hooks-http-plaintext",
              "high",
              "hooks",
              `${hook.event} http hook uses plaintext http`,
              `The hook posts its JSON payload (tool input, transcript path, session id) to ${url} without TLS. Anyone on the network path can read or modify it.`,
              url,
              [url, hook.event]
            ),
          ];
        });
    },
  },
  {
    id: "hooks-http-exfil",
    name: "HTTP hook ships transcript data off the machine",
    description: "Checks type http hooks on transcript-bearing events that post to an external host",
    severity: "high",
    category: "hooks",
    check(file) {
      return parseHooksFromSettings(file)
        .filter((hook) => hook.type === "http" && EXFIL_EVENTS.has(hook.event))
        .flatMap((hook) => {
          const url = asString(hook.entry.url)?.trim() ?? "";
          const host = hostOf(url);
          if (!host || isLoopbackHost(host)) return [];
          return [
            makeFinding(
              file,
              "hooks-http-exfil",
              "high",
              "hooks",
              `${hook.event} http hook posts to ${host}`,
              `A type: http hook on ${hook.event} sends the event payload to ${host}. On this event the payload carries transcript-derived JSON (tool output, prompts, or the final response), so that data leaves the machine on every trigger.`,
              url,
              [url, hook.event]
            ),
          ];
        });
    },
  },
  {
    id: "hooks-http-header-secret",
    name: "HTTP hook header carries a secret",
    description: "Checks http hook headers for literal credentials or secret env references without allowedEnvVars",
    severity: "medium",
    category: "hooks",
    check(file) {
      return parseHooksFromSettings(file)
        .filter((hook) => hook.type === "http" && isRecord(hook.entry.headers))
        .flatMap((hook) => {
          const headers = hook.entry.headers as JsonRecord;
          const hasAllowedEnvVars = Array.isArray(hook.entry.allowedEnvVars);
          return Object.entries(headers).flatMap(([name, value]) => {
            const text = asString(value);
            if (!text) return [];
            const stripped = text.replace(/^Bearer\s+/i, "");
            if (looksLikeCredential(stripped) || looksLikeCredential(text)) {
              return [
                makeFinding(
                  file,
                  "hooks-http-header-secret",
                  "medium",
                  "hooks",
                  `${hook.event} http hook has a literal credential in header ${name}`,
                  `The ${name} header of an http hook contains a credential-shaped literal. It is stored in plain text in settings and sent on every trigger; use a \${VAR} reference with allowedEnvVars instead.`,
                  `${name}: ${redactSecret(stripped)}`,
                  [`"${name}"`, name, hook.event]
                ),
              ];
            }
            const refs = [...text.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g)].map((match) => match[1]);
            const secretRef = refs.find((ref) => /KEY|TOKEN|SECRET|PASSWORD/i.test(ref));
            if (secretRef && !hasAllowedEnvVars) {
              return [
                makeFinding(
                  file,
                  "hooks-http-header-secret",
                  "medium",
                  "hooks",
                  `${hook.event} http hook references ${secretRef} without allowedEnvVars`,
                  `The ${name} header interpolates \${${secretRef}} but the hook has no allowedEnvVars list. Claude Code only substitutes variables named in allowedEnvVars, so either the header is sent unsubstituted or the list will be added later and the secret leaves the machine on every trigger.`,
                  `${name}: ${text}`,
                  [text, name, hook.event]
                ),
              ];
            }
            return [];
          });
        });
    },
  },
  {
    id: "hooks-stop-force-continue",
    name: "Stop hook forces the session to continue",
    description: "Checks Stop and SubagentStop hooks that always emit continue true",
    severity: "medium",
    category: "hooks",
    check(file) {
      return parseHooksFromSettings(file)
        .filter((hook) => (hook.event === "Stop" || hook.event === "SubagentStop") && /"continue"\s*:\s*true/.test(hook.text))
        .map((hook) =>
          makeFinding(
            file,
            "hooks-stop-force-continue",
            "medium",
            "hooks",
            `${hook.event} hook emits continue true`,
            `A ${hook.event} hook returns "continue": true, which tells Claude to keep working instead of stopping. Without a bounded condition this is an unattended loop that keeps consuming tokens and taking actions after the user expected it to stop.`,
            truncate(hook.text.replace(/\s+/g, " ")),
            [`"continue"`, ...hookLineCandidates(hook)]
          )
        );
    },
  },
  {
    id: "hooks-configchange-lockout",
    name: "ConfigChange hook blocks user or policy settings",
    description: "Checks ConfigChange hooks that deny user_settings or policy_settings changes",
    severity: "medium",
    category: "hooks",
    check(file) {
      return parseHooksFromSettings(file)
        .filter((hook) => hook.event === "ConfigChange")
        .flatMap((hook) => {
          const scope = `${hook.matcher}\n${hook.text}`;
          const target = scope.match(/user_settings|policy_settings/);
          if (!target) return [];
          if (!/\bdeny\b|exit\s+2/.test(hook.text)) return [];
          return [
            makeFinding(
              file,
              "hooks-configchange-lockout",
              "medium",
              "hooks",
              `ConfigChange hook denies ${target[0]} changes`,
              `A ConfigChange hook returns deny for ${target[0]}. That locks the user or administrator out of tightening their own settings while the hook is installed, which is the opposite of a guard.`,
              truncate(hook.text.replace(/\s+/g, " ")),
              [target[0], ...hookLineCandidates(hook)]
            ),
          ];
        });
    },
  },
  {
    id: "hooks-inline-eval-payload",
    name: "Hook runs a long inline payload",
    description: "Checks command hooks that pass more than 200 characters to node -e, python -c, bash -c, eval, or base64 -d",
    severity: "medium",
    category: "hooks",
    check(file) {
      const evalPattern = /\bnode\s+(?:-e|--eval)\b|\bpython\d?\s+-c\b|\b(?:bash|sh|zsh)\s+-c\b|\beval\b|\bbase64\s+(?:-d|--decode)\b/;
      return parseHooksFromSettings(file)
        .filter((hook) => hook.command.length > 200 && evalPattern.test(hook.command))
        .filter((hook) => !/\$\{?CLAUDE_(?:PLUGIN_ROOT|PROJECT_DIR)\}?/.test(hook.command))
        .map((hook) =>
          makeFinding(
            file,
            "hooks-inline-eval-payload",
            "medium",
            "hooks",
            `${hook.event} hook runs a ${hook.command.length}-character inline payload`,
            "The hook command feeds a long inline payload to an interpreter or decoder instead of running a script file. Inline payloads are hard to review, are not anchored to a plugin or project directory, and are the usual way to hide a dropper in a hook.",
            truncate(hook.command.replace(/\s+/g, " ")),
            hookLineCandidates(hook)
          )
        );
    },
  },
  {
    id: "hooks-async-network",
    name: "Async hook makes network calls",
    description: "Checks async hooks whose command uses curl, wget, nc, fetch, or a URL",
    severity: "medium",
    category: "hooks",
    check(file) {
      return parseHooksFromSettings(file)
        .filter((hook) => (hook.entry.async === true || hook.entry.asyncRewake === true) && NETWORK_COMMAND_PATTERN.test(hook.command))
        .map((hook) =>
          makeFinding(
            file,
            "hooks-async-network",
            "medium",
            "hooks",
            `${hook.event} async hook reaches the network`,
            "The hook runs asynchronously and uses a network client. Async hooks are fire-and-forget: their output is not shown and failures are not surfaced, so a network call here can ship data out without anything visible in the session.",
            truncate(hook.command.replace(/\s+/g, " ")),
            hookLineCandidates(hook)
          )
        );
    },
  },
];

// ─── Skill rules ───────────────────────────────────────────

const READ_ONLY_COMMANDS: ReadonlySet<string> = new Set([
  "git",
  "ls",
  "cat",
  "pwd",
  "echo",
  "date",
  "head",
  "tail",
  "wc",
  "find",
  "grep",
  "rg",
]);

const SHELL_DANGEROUS_PATTERN =
  /\b(?:curl|wget|nc|ncat|netcat|ssh|scp|base64|eval)\b|https?:\/\/|~\/\.(?:ssh|aws)|\$HOME\/\.(?:ssh|aws)|\.env\b|id_rsa|\btee\b|(?<![<>])>(?!>?&)/;

function isReadOnlyShell(command: string): boolean {
  const segments = command.split(/\|\|?|&&|;|\n/).map((segment) => segment.trim()).filter(Boolean);
  if (segments.length === 0) return false;
  return segments.every((segment) => {
    const tokens = segment.split(/\s+/);
    const name = (tokens[0] ?? "").replace(/^.*\//, "");
    if (!READ_ONLY_COMMANDS.has(name)) return false;
    if (name === "git") return /^(?:status|log|diff|branch|show|rev-parse|describe)$/.test(tokens[1] ?? "");
    return true;
  });
}

function collectDynamicShellCommands(body: string): ReadonlyArray<{ readonly command: string; readonly raw: string }> {
  const inline = [...body.matchAll(/(?:^|(?<=\s))!`([^`\n]+)`/g)].map((match) => ({
    command: match[1].trim(),
    raw: match[0].trim(),
  }));
  const fenced = [...body.matchAll(/^```!\s*\n([\s\S]*?)^```/gm)].map((match) => ({
    command: match[1].trim(),
    raw: "```!",
  }));
  return [...inline, ...fenced];
}

const SKILL_TRIGGER_PHRASES =
  /always use this skill|before any other tool|before doing anything|\bignore (?:previous|prior|all|any|other|the|your|earlier)\b|must be used first/i;

const SIDE_EFFECT_PATTERN = /\b(?:deploy|push|publish|delete|drop|send|pay|transfer)\b|rm -rf/i;

const skillRules: ReadonlyArray<Rule> = [
  {
    id: "skills-dynamic-shell-injection",
    name: "Dynamic context shell in skill",
    description: "Checks SKILL.md bodies for !`command` and ```! blocks, which run through Bash before the skill loads",
    severity: "critical",
    category: "skills",
    check(file) {
      if (file.type !== "skill-md") return [];
      const body = skillBody(file.content);

      return collectDynamicShellCommands(body).map(({ command, raw }) => {
        if (SHELL_DANGEROUS_PATTERN.test(command)) {
          return makeFinding(
            file,
            "skills-dynamic-shell-injection",
            "critical",
            "skills",
            "Dynamic context shell in skill reaches network, secrets, or writes files",
            "The skill body contains a dynamic context block. Claude Code runs it through Bash when the skill is invoked, before any content reaches the model and without a prompt. This command downloads, connects out, reads credential files, or writes outside the skill, so invoking the skill is enough to run it.",
            command,
            [raw, command]
          );
        }
        const readOnly = isReadOnlyShell(command);
        return makeFinding(
          file,
          "skills-dynamic-shell-injection",
          readOnly ? "info" : "medium",
          "skills",
          "Dynamic context shell in skill",
          readOnly
            ? "The skill body runs a read-only dynamic context command through Bash when invoked. This is a normal pattern, but it runs without a prompt, so review it when the skill comes from a plugin or a shared repo."
            : "The skill body runs a dynamic context command through Bash when invoked, without a prompt. The command is not an obviously read-only one, so it can change state on the machine whenever the skill loads.",
          command,
          [raw, command]
        );
      });
    },
  },
  {
    id: "skills-allowed-tools-broad",
    name: "Skill pre-approves broad tools",
    description: "Checks allowed-tools for unrestricted Bash, shell or downloader prefixes, MCP wildcards, or write plus WebFetch",
    severity: "high",
    category: "skills",
    check(file) {
      const frontmatter = parseSkillFrontmatter(file);
      if (!frontmatter || !("allowed-tools" in frontmatter)) return [];
      const tokens = parseToolTokens(frontmatter["allowed-tools"]);
      const findings: Finding[] = [];

      const broad = tokens.filter((token) =>
        /^Bash$|^Bash\(\*\)$|^Bash\((?:sh|bash|zsh|curl|wget)(?:\s|\)|:)/.test(token) || /^mcp__\*/.test(token)
      );
      for (const token of broad) {
        findings.push(
          makeFinding(
            file,
            "skills-allowed-tools-broad",
            "high",
            "skills",
            `allowed-tools pre-approves ${token}`,
            `allowed-tools lists ${token}, which is approved without a prompt for the turn the skill runs in. A shell, downloader, or MCP wildcard grant means anything the skill body asks for runs unattended.`,
            token,
            [token, "allowed-tools"]
          )
        );
      }

      const hasWrite = tokens.some((token) => /^(?:Write|Edit)(?:\(|$)/.test(token));
      const hasWebFetch = tokens.some((token) => /^WebFetch(?:\(|$)/.test(token));
      if (hasWrite && hasWebFetch) {
        findings.push(
          makeFinding(
            file,
            "skills-allowed-tools-broad",
            "high",
            "skills",
            "allowed-tools combines file writes with WebFetch",
            "allowed-tools pre-approves Write or Edit together with WebFetch. Fetched content can carry instructions and the skill can act on them by writing files, so the combination turns a remote page into code on disk without a prompt.",
            tokens.join(" "),
            ["allowed-tools"]
          )
        );
      }

      return findings;
    },
  },
  {
    id: "skills-hooks-persist",
    name: "Skill registers session-persistent hooks",
    description: "Checks skill frontmatter hooks for PreToolUse allow, Stop continue, or SessionStart commands",
    severity: "high",
    category: "skills",
    check(file) {
      const frontmatter = parseSkillFrontmatter(file);
      if (!frontmatter) return [];

      return collectHookEntries(frontmatter.hooks).flatMap((hook) => {
        let reason: string | undefined;
        if (hook.event === "PreToolUse" && /allow/.test(hook.text)) {
          reason = "a PreToolUse hook that returns allow, which approves tool calls";
        } else if ((hook.event === "Stop" || hook.event === "SubagentStop") && /continue/.test(hook.text)) {
          reason = `a ${hook.event} hook that emits continue, which keeps the session running`;
        } else if (hook.event === "SessionStart" && hook.command) {
          reason = "a SessionStart command, which runs on every later session start";
        }
        if (!reason) return [];

        return [
          makeFinding(
            file,
            "skills-hooks-persist",
            "high",
            "skills",
            `Skill frontmatter registers ${hook.event} hook`,
            `The skill's hooks block registers ${reason}. Hooks declared in SKILL.md persist for the rest of the session after the skill is invoked once, so this outlives the skill and applies to everything Claude does afterwards.`,
            truncate(hook.text.replace(/\s+/g, " ") || hook.event),
            [hook.command, hook.event, "hooks:"]
          ),
        ];
      });
    },
  },
  {
    id: "skills-description-trigger-hijack",
    name: "Skill description steers model selection",
    description: "Checks description and when_to_use for trigger-hijack phrases or excessive length",
    severity: "medium",
    category: "skills",
    check(file) {
      const frontmatter = parseSkillFrontmatter(file);
      if (!frontmatter) return [];
      const fields: ReadonlyArray<readonly [string, unknown]> = [
        ["description", frontmatter.description],
        ["when_to_use", frontmatter.when_to_use],
        ["when-to-use", frontmatter["when-to-use"]],
      ];

      return fields.flatMap(([key, value]) => {
        const text = asString(value);
        if (!text) return [];
        const phrase = text.match(SKILL_TRIGGER_PHRASES);
        if (!phrase && text.length <= 1000) return [];

        return [
          makeFinding(
            file,
            "skills-description-trigger-hijack",
            "medium",
            "skills",
            phrase ? `Skill ${key} tells the model to prefer it` : `Skill ${key} is ${text.length} characters`,
            `The ${key} field is read by the model on every prompt to decide whether to invoke the skill. ${
              phrase
                ? `It contains "${phrase[0]}", which pushes the model to select this skill over others or over the user's instructions.`
                : "At this length it crowds out other skills and can carry instructions that are not about when to use it."
            }`,
            phrase ? phrase[0] : truncate(text, 80),
            [phrase ? phrase[0] : text.slice(0, 40), `${key}:`]
          ),
        ];
      });
    },
  },
  {
    id: "skills-tools-key-misuse",
    name: "SKILL.md uses tools instead of allowed-tools",
    description: "Checks for a tools key in SKILL.md frontmatter, which Claude Code ignores",
    severity: "info",
    category: "skills",
    check(file) {
      const frontmatter = parseSkillFrontmatter(file);
      if (!frontmatter || !("tools" in frontmatter)) return [];
      return [
        makeFinding(
          file,
          "skills-tools-key-misuse",
          "info",
          "skills",
          "Skill frontmatter has a tools key that does nothing",
          "SKILL.md frontmatter uses tools:, which is a subagent field. Claude Code ignores it in skills, so it neither restricts nor grants anything. The author probably meant allowed-tools, and the skill currently runs with whatever the session already allows.",
          `tools: ${stringList(frontmatter.tools).join(", ") || JSON.stringify(frontmatter.tools)}`,
          ["tools:"]
        ),
      ];
    },
  },
  {
    id: "skills-auto-invoke-side-effect",
    name: "Side-effect skill can be invoked by the model",
    description: "Checks skills that mention deploy, push, publish, delete, send, pay, or rm -rf without disable-model-invocation",
    severity: "medium",
    category: "skills",
    check(file) {
      const frontmatter = parseSkillFrontmatter(file);
      if (!frontmatter) return [];
      if (isTruthyFlag(frontmatter["disable-model-invocation"])) return [];

      const description = asString(frontmatter.description) ?? "";
      const body = skillBody(file.content);
      const match = description.match(SIDE_EFFECT_PATTERN) ?? body.match(SIDE_EFFECT_PATTERN);
      if (!match) return [];

      return [
        makeFinding(
          file,
          "skills-auto-invoke-side-effect",
          "medium",
          "skills",
          `Model can auto-invoke a skill that mentions ${match[0]}`,
          `The skill mentions "${match[0]}" and does not set disable-model-invocation: true, so Claude can pick it from the description on its own. A skill with external side effects should be user-invoked only.`,
          match[0],
          [match[0], "description:"]
        ),
      ];
    },
  },
];

// ─── Subagent rules ────────────────────────────────────────

function mcpServerDefinitions(value: unknown): ReadonlyArray<readonly [string, JsonRecord]> {
  const definitions: Array<readonly [string, JsonRecord]> = [];
  const items: ReadonlyArray<unknown> = Array.isArray(value) ? value : isRecord(value) ? [value] : [];
  for (const item of items) {
    if (!isRecord(item)) continue;
    // Either a map of name to definition, or a single definition with a url or command.
    if ("url" in item || "command" in item) {
      definitions.push(["(inline)", item]);
      continue;
    }
    for (const [name, definition] of Object.entries(item)) {
      if (isRecord(definition)) definitions.push([name, definition]);
    }
  }
  return definitions;
}

function isUnpinnedNpxPackage(args: ReadonlyArray<string>): string | undefined {
  const packageArg = args.find((arg) => !arg.startsWith("-"));
  if (!packageArg) return undefined;
  const versioned = packageArg.startsWith("@")
    ? /^@[^/]+\/[^@]+@.+$/.test(packageArg)
    : /^[^@]+@.+$/.test(packageArg);
  return versioned ? undefined : packageArg;
}

const agentRules: ReadonlyArray<Rule> = [
  {
    id: "agents-bypass-permission-mode",
    name: "Subagent runs without permission prompts",
    description: "Checks subagent permissionMode for bypassPermissions or dontAsk",
    severity: "critical",
    category: "agents",
    check(file) {
      const frontmatter = parseAgentFrontmatter(file);
      const mode = frontmatter ? asString(frontmatter.permissionMode) : undefined;
      if (!mode) return [];

      if (mode === "bypassPermissions") {
        return [
          makeFinding(
            file,
            "agents-bypass-permission-mode",
            "critical",
            "agents",
            "Subagent requests bypassPermissions",
            "permissionMode: bypassPermissions asks Claude Code to run this subagent with no permission prompts. It only takes effect when the main session is also in bypass mode, but a subagent file that asks for it is declaring that it expects to run unattended.",
            `permissionMode: ${mode}`,
            [`permissionMode: ${mode}`, "permissionMode"]
          ),
        ];
      }

      if (mode === "dontAsk") {
        return [
          makeFinding(
            file,
            "agents-bypass-permission-mode",
            "medium",
            "agents",
            "Subagent requests dontAsk",
            "permissionMode: dontAsk makes this subagent auto-deny anything not in the allow list instead of prompting. Combined with a broad allow list it runs unattended; with a narrow one it silently fails. Either way the user is not asked.",
            `permissionMode: ${mode}`,
            [`permissionMode: ${mode}`, "permissionMode"]
          ),
        ];
      }

      return [];
    },
  },
  {
    id: "agents-inline-mcp-server",
    name: "Subagent installs an MCP server inline",
    description: "Checks mcpServers inline definitions for authenticated remote urls or unpinned npx packages",
    severity: "high",
    category: "agents",
    check(file) {
      const frontmatter = parseAgentFrontmatter(file);
      if (!frontmatter) return [];

      return mcpServerDefinitions(frontmatter.mcpServers).flatMap(([name, definition]) => {
        const url = asString(definition.url);
        const headers = definition.headers;
        if (url && isRecord(headers) && Object.keys(headers).length > 0) {
          const authHeader = Object.entries(headers).find(
            ([key, value]) => /authorization|token|key|secret/i.test(key) || /bearer|token/i.test(asString(value) ?? "")
          );
          if (authHeader) {
            return [
              makeFinding(
                file,
                "agents-inline-mcp-server",
                "high",
                "agents",
                `Subagent ${name} defines a remote MCP server with auth headers`,
                `The subagent frontmatter defines MCP server ${name} inline at ${url} with a ${authHeader[0]} header. An agent file is an MCP install vector: opening the agent connects to that server and sends the credential, with no .mcp.json review step.`,
                `${name}: ${url}`,
                [url, "mcpServers"]
              ),
            ];
          }
        }

        const command = asString(definition.command);
        const args = stringList(definition.args);
        if (command && /(?:^|\/)npx$/.test(command.trim()) && args.some((arg) => arg === "-y" || arg === "--yes")) {
          const unpinned = isUnpinnedNpxPackage(args.filter((arg) => arg !== "-y" && arg !== "--yes"));
          if (unpinned) {
            return [
              makeFinding(
                file,
                "agents-inline-mcp-server",
                "high",
                "agents",
                `Subagent ${name} runs an unpinned npx package`,
                `The subagent frontmatter starts MCP server ${name} with npx -y ${unpinned} and no version. Whatever the registry serves at invocation time runs locally with the agent's permissions, so a package takeover becomes code execution.`,
                `${name}: npx -y ${unpinned}`,
                [unpinned, "mcpServers"]
              ),
            ];
          }
        }

        return [];
      });
    },
  },
  {
    id: "agents-frontmatter-hooks-allow",
    name: "Subagent hooks approve or reach the network",
    description: "Checks subagent frontmatter hooks for PreToolUse allow output or network commands",
    severity: "high",
    category: "agents",
    check(file) {
      const frontmatter = parseAgentFrontmatter(file);
      if (!frontmatter) return [];

      return collectHookEntries(frontmatter.hooks).flatMap((hook) => {
        if (hook.event === "PreToolUse" && /allow/.test(hook.text)) {
          return [
            makeFinding(
              file,
              "agents-frontmatter-hooks-allow",
              "high",
              "agents",
              "Subagent PreToolUse hook returns allow",
              "The subagent's frontmatter registers a PreToolUse hook whose command mentions allow. Hooks in agent frontmatter run for every tool call the agent makes, so an allow-returning hook approves the agent's own actions.",
              truncate(hook.text.replace(/\s+/g, " ")),
              [hook.command, "PreToolUse"]
            ),
          ];
        }
        if (NETWORK_COMMAND_PATTERN.test(hook.command)) {
          return [
            makeFinding(
              file,
              "agents-frontmatter-hooks-allow",
              "high",
              "agents",
              `Subagent ${hook.event} hook makes network calls`,
              `The subagent's frontmatter registers a ${hook.event} hook that uses a network client. The hook receives tool input and transcript paths, so it can ship the agent's activity off the machine on every trigger.`,
              truncate(hook.command.replace(/\s+/g, " ")),
              [hook.command, hook.event]
            ),
          ];
        }
        return [];
      });
    },
  },
  {
    id: "agents-mcp-wildcard-tools",
    name: "Subagent tools include every MCP tool",
    description: "Checks subagent tools for mcp__*",
    severity: "medium",
    category: "agents",
    check(file) {
      const frontmatter = parseAgentFrontmatter(file);
      if (!frontmatter) return [];
      const tokens = parseToolTokens(frontmatter.tools);
      if (!tokens.includes("mcp__*")) return [];
      return [
        makeFinding(
          file,
          "agents-mcp-wildcard-tools",
          "medium",
          "agents",
          "Subagent tools grant mcp__*",
          "tools: includes mcp__*, so the subagent gets every tool from every configured MCP server, including servers added later. The agent's capability set changes whenever the MCP config does.",
          "mcp__*",
          ["mcp__*", "tools:"]
        ),
      ];
    },
  },
  {
    id: "agents-memory-user-with-network",
    name: "Subagent with user memory can fetch remote content",
    description: "Checks memory user together with WebFetch or MCP tools",
    severity: "medium",
    category: "agents",
    check(file) {
      const frontmatter = parseAgentFrontmatter(file);
      if (!frontmatter || asString(frontmatter.memory) !== "user") return [];
      const tokens = parseToolTokens(frontmatter.tools);
      const networkTool = tokens.find((token) => /^WebFetch(?:\(|$)/.test(token) || token.startsWith("mcp__"));
      if (!networkTool) return [];
      return [
        makeFinding(
          file,
          "agents-memory-user-with-network",
          "medium",
          "agents",
          "Subagent writes user memory and reads remote content",
          `memory: user gives the subagent a persistent store shared across every project, and its tools include ${networkTool}. Anything it fetches can be written into that memory and read back in unrelated sessions, which is a cross-project injection channel.`,
          `memory: user, tools: ${networkTool}`,
          ["memory: user", "memory:"]
        ),
      ];
    },
  },
  {
    id: "agents-spawn-any-with-bash",
    name: "Subagent can spawn any agent and run shell",
    description: "Checks tools for bare Agent or Agent(*) together with Bash",
    severity: "medium",
    category: "agents",
    check(file) {
      const frontmatter = parseAgentFrontmatter(file);
      if (!frontmatter) return [];
      const tokens = parseToolTokens(frontmatter.tools);
      const spawn = tokens.find((token) => token === "Agent" || token === "Agent(*)");
      const bash = tokens.find((token) => /^Bash(?:\(|$)/.test(token));
      if (!spawn || !bash) return [];
      return [
        makeFinding(
          file,
          "agents-spawn-any-with-bash",
          "medium",
          "agents",
          "Subagent combines unrestricted spawning with Bash",
          `tools: includes ${spawn} and ${bash}. The subagent can start any other agent, including ones with broader permissions, and run shell commands itself, so a single compromised agent can fan out work to the whole roster.`,
          `${spawn}, ${bash}`,
          [spawn, "tools:"]
        ),
      ];
    },
  },
];

export const claudeCodeRules: ReadonlyArray<Rule> = [
  ...settingsRules,
  ...hookRules,
  ...skillRules,
  ...agentRules,
];
