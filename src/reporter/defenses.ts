import { basename } from "node:path";
import type { ConfigFile, Defense, DefenseHarness } from "../types.js";
import {
  parseFrontmatter,
  parseJsonLenient,
  parseTomlSafe,
  parseYamlSafe,
} from "../scanner/parsers.js";

/**
 * Recognized defenses: protective configuration the scanner found while
 * reading the same files it audits. Defenses are listed for credit only.
 * They never change the score in either direction, so a decorative deny
 * rule cannot buy points and a real one is never mistaken for attack
 * surface.
 */

export type { Defense, DefenseHarness };

type JsonObject = Record<string, unknown>;

const CONTAINER_BACKENDS = new Set(["docker", "singularity", "modal", "daytona"]);
const READ_ONLY_TOOLS = new Set(["read", "grep", "glob"]);
const MUTATING_TOOLS = new Set(["write", "edit", "bash", "multiedit", "notebookedit"]);
const BLOCKING_HOOK_EVENTS = ["PreToolUse", "PermissionRequest", "UserPromptSubmit"] as const;

const DENY_SIGNALS: ReadonlyArray<RegExp> = [
  /\bexit\s+2\b/,
  /process\.exit\(\s*2\s*\)/,
  /sys\.exit\(\s*2\s*\)/,
  /["']?permissionDecision["']?\s*:\s*["']deny["']/,
  /["']decision["']\s*:\s*["']deny["']/,
];

const DENY_COVERAGE: ReadonlyArray<{ readonly label: string; readonly pattern: RegExp }> = [
  { label: ".env", pattern: /\.env\b/i },
  { label: "~/.ssh", pattern: /\.ssh\b/i },
  { label: "curl", pattern: /\bcurl\b/i },
  { label: "sudo", pattern: /\bsudo\b/i },
  { label: "rm -rf", pattern: /\brm\s+-rf?\b/i },
];

/**
 * Detect protective configuration across every discovered config file.
 * Parsing is fail closed: a file that does not parse yields no defenses.
 */
export function detectDefenses(files: ReadonlyArray<ConfigFile>): ReadonlyArray<Defense> {
  const defenses: Defense[] = [];
  for (const file of files) {
    defenses.push(...detectFileDefenses(file, files));
  }
  return defenses;
}

function detectFileDefenses(
  file: ConfigFile,
  allFiles: ReadonlyArray<ConfigFile>
): ReadonlyArray<Defense> {
  const path = normalizePath(file.path);
  const name = basename(path);

  if (isCursorHooks(path, name)) return detectCursorHooks(file);
  if (isGeminiSettings(path, name)) return detectGemini(file);
  if (isOpenCodeConfig(name)) return detectOpenCode(file);
  if (isCodexRulesFile(name)) return detectCodexRules(file);
  if (isCodexToml(file, name)) return detectCodex(file);
  if (isHermesConfig(file, name)) return detectHermes(file);
  if (file.type === "skill-md") return detectSkill(file);
  if (file.type === "agent-md") return detectAgent(file);
  if (isClaudeSettings(path, name)) return detectClaudeSettings(file, allFiles);
  if (isHooksManifest(path, name)) {
    const harness: DefenseHarness = path.includes(".codex/") ? "codex" : "claude-code";
    const parsed = parseJsonLenient(file.content);
    if (!parsed) return [];
    return detectHookDefenses(file, parsed, allFiles, harness);
  }
  return [];
}

// ─── File classification ─────────────────────────────────────

function normalizePath(path: string): string {
  return path.replace(/\\/g, "/").toLowerCase();
}

function underDir(path: string, dir: string): boolean {
  return path.startsWith(`${dir}/`) || path.includes(`/${dir}/`);
}

function isCursorHooks(path: string, name: string): boolean {
  return name === "hooks.json" && underDir(path, ".cursor");
}

function isGeminiSettings(path: string, name: string): boolean {
  return name === "settings.json" && underDir(path, ".gemini");
}

function isOpenCodeConfig(name: string): boolean {
  return name === "opencode.json" || name === "opencode.jsonc";
}

function isCodexRulesFile(name: string): boolean {
  return name.endsWith(".rules");
}

function isCodexToml(file: ConfigFile, name: string): boolean {
  return file.type === "codex-toml" || name === "config.toml";
}

function isHermesConfig(file: ConfigFile, name: string): boolean {
  return file.type === "hermes-yaml" || name === "config.yaml" || name === "config.yml";
}

function isClaudeSettings(path: string, name: string): boolean {
  if (underDir(path, ".gemini") || underDir(path, ".cursor") || underDir(path, ".zed") || underDir(path, ".vscode")) {
    return false;
  }
  if (name === "settings.json" || name === "settings.local.json" || name === "managed-settings.json") {
    return true;
  }
  return underDir(path, "managed-settings.d") && name.endsWith(".json");
}

function isHooksManifest(path: string, name: string): boolean {
  return name === "hooks.json" && !underDir(path, ".cursor");
}

// ─── Claude Code settings ────────────────────────────────────

function detectClaudeSettings(
  file: ConfigFile,
  allFiles: ReadonlyArray<ConfigFile>
): ReadonlyArray<Defense> {
  const settings = parseJsonLenient(file.content);
  if (!settings) return [];

  const defenses: Defense[] = [];
  const harness: DefenseHarness = "claude-code";
  const make = (id: string, title: string, detail: string): Defense => ({
    id,
    title,
    file: file.path,
    detail,
    harness,
  });

  const permissions = asObject(settings.permissions);
  const deny = asStringArray(permissions?.deny);
  if (deny.length > 0) {
    const covered = DENY_COVERAGE.filter((entry) => deny.some((rule) => entry.pattern.test(rule)));
    const missing = DENY_COVERAGE.filter((entry) => !covered.includes(entry));
    const coverage =
      covered.length > 0 ? `covers ${covered.map((c) => c.label).join(", ")}` : "covers none of the common targets";
    const gap = missing.length > 0 ? `; not covered: ${missing.map((m) => m.label).join(", ")}` : "";
    defenses.push(
      make(
        "defense-deny-list",
        "Permission deny list",
        `${deny.length} deny ${deny.length === 1 ? "rule" : "rules"}; ${coverage}${gap}. Deny wins over allow regardless of specificity.`
      )
    );
  }

  const ask = asStringArray(permissions?.ask);
  if (ask.length > 0) {
    defenses.push(
      make(
        "defense-ask-list",
        "Permission ask list",
        `${ask.length} ask ${ask.length === 1 ? "rule prompts" : "rules prompt"} before matching tool calls: ${ask.slice(0, 5).join(", ")}${ask.length > 5 ? ", ..." : ""}`
      )
    );
  }

  const defaultMode = permissions?.defaultMode;
  if (defaultMode === "plan" || defaultMode === "default") {
    defenses.push(
      make(
        "defense-default-mode",
        `Permission mode "${defaultMode}"`,
        defaultMode === "plan"
          ? "Plan mode: the agent reads and proposes, edits and commands still need approval."
          : "Default mode: every tool call outside the allow list prompts."
      )
    );
  }

  if (permissions?.disableBypassPermissionsMode === "disable") {
    defenses.push(
      make(
        "defense-bypass-disabled",
        "Bypass permissions mode disabled",
        "disableBypassPermissionsMode is set to disable, so --dangerously-skip-permissions cannot be used from this layer down."
      )
    );
  }

  if (permissions?.blockReadsOutsideWorkingDirectories === true) {
    defenses.push(
      make(
        "defense-block-reads-outside-cwd",
        "Reads outside working directories blocked",
        "blockReadsOutsideWorkingDirectories is true, so Read cannot reach files outside the configured working directories."
      )
    );
  }

  const sandbox = asObject(settings.sandbox);
  if (sandbox?.enabled === true) {
    defenses.push(make("defense-sandbox-enabled", "Sandbox enabled", describeSandbox(sandbox)));
  }

  const managedFlags: ReadonlyArray<{ readonly key: string; readonly id: string; readonly title: string; readonly detail: string }> = [
    {
      key: "allowManagedPermissionRulesOnly",
      id: "defense-managed-permission-rules-only",
      title: "Only managed permission rules honored",
      detail: "allowManagedPermissionRulesOnly is true, so user and project permission rules are ignored.",
    },
    {
      key: "allowManagedHooksOnly",
      id: "defense-managed-hooks-only",
      title: "Only managed hooks honored",
      detail: "allowManagedHooksOnly is true, so hooks from user, project, and plugin scopes do not run.",
    },
    {
      key: "allowManagedMcpServersOnly",
      id: "defense-managed-mcp-servers-only",
      title: "Only managed MCP servers honored",
      detail: "allowManagedMcpServersOnly is true, so project and user MCP servers are not loaded.",
    },
    {
      key: "strictKnownMarketplaces",
      id: "defense-strict-marketplaces",
      title: "Plugin marketplaces restricted",
      detail: "strictKnownMarketplaces is true, so plugins install only from the known marketplace list.",
    },
    {
      key: "disableSkillShellExecution",
      id: "defense-skill-shell-disabled",
      title: "Skill shell execution disabled",
      detail: "disableSkillShellExecution is true, so !`...` blocks in skills never run.",
    },
  ];
  for (const flag of managedFlags) {
    if (settings[flag.key] === true) {
      defenses.push(make(flag.id, flag.title, flag.detail));
    }
  }

  const enabledServers = asStringArray(settings.enabledMcpjsonServers);
  if (enabledServers.length > 0 && settings.enableAllProjectMcpServers !== true) {
    defenses.push(
      make(
        "defense-explicit-mcp-servers",
        "Explicit MCP server allow list",
        `enabledMcpjsonServers names ${enabledServers.length} ${enabledServers.length === 1 ? "server" : "servers"} (${enabledServers.join(", ")}) instead of enabling every project server.`
      )
    );
  }

  defenses.push(...detectHookDefenses(file, settings, allFiles, harness));
  return defenses;
}

function describeSandbox(sandbox: JsonObject): string {
  const extras: string[] = [];
  if (sandbox.failIfUnavailable === true) extras.push("fails closed when the sandbox is unavailable");

  const network = asObject(sandbox.network);
  const allowedDomains = asStringArray(network?.allowedDomains);
  if (allowedDomains.length > 0 && !allowedDomains.some((domain) => domain.includes("*"))) {
    extras.push(`network allow list of ${allowedDomains.length} ${allowedDomains.length === 1 ? "domain" : "domains"} with no wildcard`);
  }

  const filesystem = asObject(sandbox.filesystem);
  const denyRead = asStringArray(filesystem?.denyRead);
  if (denyRead.length > 0) {
    extras.push(`filesystem denyRead on ${denyRead.join(", ")}`);
  }

  const credentials = asObject(sandbox.credentials);
  const credentialModes = credentialModesOf(credentials);
  if (credentialModes.length > 0) {
    extras.push(`credentials ${credentialModes.join(" and ")}`);
  }

  return extras.length > 0
    ? `sandbox.enabled is true; ${extras.join("; ")}.`
    : "sandbox.enabled is true with default network and filesystem policy.";
}

function credentialModesOf(credentials: JsonObject | null): ReadonlyArray<string> {
  if (!credentials) return [];
  const modes = new Set<string>();
  const candidates = [credentials, asObject(credentials.files), asObject(credentials.envVars)];
  for (const candidate of candidates) {
    const mode = candidate?.mode;
    if (mode === "mask" || mode === "deny") modes.add(mode === "mask" ? "masked" : "denied");
  }
  return [...modes];
}

// ─── Hooks (Claude Code and Codex hooks.json) ────────────────

interface HookCommand {
  readonly event: string;
  readonly command: string;
}

function detectHookDefenses(
  file: ConfigFile,
  settings: JsonObject,
  allFiles: ReadonlyArray<ConfigFile>,
  harness: DefenseHarness
): ReadonlyArray<Defense> {
  const hooks = asObject(settings.hooks);
  if (!hooks) return [];

  const defenses: Defense[] = [];
  for (const event of BLOCKING_HOOK_EVENTS) {
    const commands = hookCommandsFor(hooks, event);
    const blocking = commands.filter((hook) => hookHasDenySignal(hook.command, allFiles));
    if (blocking.length === 0) continue;
    defenses.push({
      id: `defense-blocking-${event.toLowerCase()}-hook`,
      title: `Blocking ${event} hook`,
      file: file.path,
      detail: `${blocking.length} ${event} command ${blocking.length === 1 ? "hook" : "hooks"} can deny a call (exit 2 or a deny decision): ${blocking.map((hook) => truncate(hook.command, 60)).join("; ")}`,
      harness,
    });
  }

  const configChange = hookCommandsFor(hooks, "ConfigChange");
  if (configChange.length > 0) {
    defenses.push({
      id: "defense-configchange-hook",
      title: "ConfigChange hook",
      file: file.path,
      detail: `${configChange.length} ConfigChange ${configChange.length === 1 ? "hook watches" : "hooks watch"} settings edits during the session: ${configChange.map((hook) => truncate(hook.command, 60)).join("; ")}`,
      harness,
    });
  }

  return defenses;
}

function hookCommandsFor(hooks: JsonObject, event: string): ReadonlyArray<HookCommand> {
  const entries = hooks[event];
  if (!Array.isArray(entries)) return [];
  const commands: HookCommand[] = [];
  for (const entry of entries) {
    const record = asObject(entry);
    if (!record) continue;
    if (typeof record.command === "string") commands.push({ event, command: record.command });
    if (typeof record.hook === "string") commands.push({ event, command: record.hook });
    if (Array.isArray(record.hooks)) {
      for (const nested of record.hooks) {
        const hook = asObject(nested);
        if (hook && typeof hook.command === "string" && (hook.type === undefined || hook.type === "command")) {
          commands.push({ event, command: hook.command });
        }
      }
    }
  }
  return commands;
}

function hookHasDenySignal(command: string, allFiles: ReadonlyArray<ConfigFile>): boolean {
  if (containsDenySignal(command)) return true;
  for (const script of referencedScripts(command, allFiles)) {
    if (containsDenySignal(script.content)) return true;
  }
  return false;
}

function containsDenySignal(text: string): boolean {
  return DENY_SIGNALS.some((signal) => signal.test(text));
}

/**
 * Resolve script files a hook command points at. Tokens are matched by
 * trailing path segments so `$CLAUDE_PROJECT_DIR/.claude/hooks/guard.sh`
 * and `bash ./hooks/guard.sh` both find `.claude/hooks/guard.sh`.
 */
function referencedScripts(
  command: string,
  allFiles: ReadonlyArray<ConfigFile>
): ReadonlyArray<ConfigFile> {
  const tokens = command
    .split(/[\s;&|]+/)
    .map((token) => token.replace(/^["']+|["']+$/g, ""))
    .map((token) => token.replace(/^\$\{?[A-Z_]+\}?\/?/, "").replace(/^\.\//, ""))
    .filter((token) => /\.[a-z0-9]+$/i.test(token) && !token.startsWith("-"));

  const matches: ConfigFile[] = [];
  for (const token of tokens) {
    const suffix = normalizePath(token);
    for (const file of allFiles) {
      const path = normalizePath(file.path);
      if (path === suffix || path.endsWith(`/${suffix}`)) {
        if (!matches.includes(file)) matches.push(file);
      }
    }
  }
  return matches;
}

// ─── Skills and agents ───────────────────────────────────────

function detectSkill(file: ConfigFile): ReadonlyArray<Defense> {
  const frontmatter = parseSkillOrAgentMetadata(file);
  if (!frontmatter) return [];

  const defenses: Defense[] = [];
  if (frontmatter["disable-model-invocation"] === true) {
    defenses.push({
      id: "defense-skill-no-model-invocation",
      title: "Skill cannot be invoked by the model",
      file: file.path,
      detail: "disable-model-invocation is true, so only the user can trigger this skill.",
      harness: "claude-code",
    });
  }

  const allowedTools = toolList(frontmatter["allowed-tools"] ?? frontmatter.allowedTools);
  if (allowedTools.length > 0 && allowedTools.every(isNarrowTool)) {
    defenses.push({
      id: "defense-skill-narrow-tools",
      title: "Skill limited to narrow tools",
      file: file.path,
      detail: `allowed-tools is restricted to ${allowedTools.join(", ")}.`,
      harness: "claude-code",
    });
  }
  return defenses;
}

function detectAgent(file: ConfigFile): ReadonlyArray<Defense> {
  const metadata = parseSkillOrAgentMetadata(file);
  if (!metadata) return [];

  const defenses: Defense[] = [];
  const toolsValue = metadata.tools ?? metadata.allowedTools ?? metadata["allowed-tools"];
  const tools = toolList(toolsValue);
  if (tools.length > 0 && !tools.some((tool) => MUTATING_TOOLS.has(toolName(tool)))) {
    defenses.push({
      id: "defense-agent-tools-allowlist",
      title: "Agent tool allow list without Write, Edit, or Bash",
      file: file.path,
      detail: `tools is limited to ${tools.join(", ")}.`,
      harness: "claude-code",
    });
  }

  const disallowed = toolList(metadata.disallowedTools ?? metadata["disallowed-tools"]);
  if (disallowed.length > 0) {
    defenses.push({
      id: "defense-agent-disallowed-tools",
      title: "Agent disallowed tools",
      file: file.path,
      detail: `disallowedTools blocks ${disallowed.join(", ")}.`,
      harness: "claude-code",
    });
  }
  return defenses;
}

function parseSkillOrAgentMetadata(file: ConfigFile): JsonObject | null {
  if (file.path.toLowerCase().endsWith(".json")) return parseJsonLenient(file.content);
  return parseFrontmatter(file.content);
}

function toolList(value: unknown): ReadonlyArray<string> {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean);
  }
  if (typeof value === "string") {
    return splitToolString(value);
  }
  return [];
}

/** Split "Read, Grep, Bash(git add *)" without breaking inside parentheses. */
function splitToolString(value: string): ReadonlyArray<string> {
  const tools: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of value) {
    if (ch === "(") depth += 1;
    if (ch === ")") depth = Math.max(0, depth - 1);
    if ((ch === "," || /\s/.test(ch)) && depth === 0) {
      if (current.trim()) tools.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) tools.push(current.trim());
  return tools;
}

function toolName(tool: string): string {
  return tool.replace(/\(.*$/, "").trim().toLowerCase();
}

function isNarrowTool(tool: string): boolean {
  const name = toolName(tool);
  if (READ_ONLY_TOOLS.has(name)) return true;
  if (name !== "bash") return false;
  const scoped = /^bash\(([^)]*)\)$/i.exec(tool.trim());
  if (!scoped) return false;
  const inner = scoped[1].trim();
  return inner.length > 0 && inner !== "*" && !inner.startsWith("*");
}

// ─── Codex ───────────────────────────────────────────────────

function detectCodex(file: ConfigFile): ReadonlyArray<Defense> {
  const config = parseTomlSafe(file.content);
  if (!config) return [];

  const defenses: Defense[] = [];
  const sandboxMode = config.sandbox_mode;
  if (sandboxMode === "read-only") {
    defenses.push({
      id: "defense-codex-sandbox",
      title: "Codex sandbox read-only",
      file: file.path,
      detail: "sandbox_mode is read-only, so the agent cannot write files or reach the network.",
      harness: "codex",
    });
  } else if (sandboxMode === "workspace-write") {
    const workspace = asObject(config.sandbox_workspace_write);
    if (workspace?.network_access !== true) {
      defenses.push({
        id: "defense-codex-sandbox",
        title: "Codex sandbox workspace-write without network",
        file: file.path,
        detail:
          workspace?.network_access === false
            ? "sandbox_mode is workspace-write and network_access is false."
            : "sandbox_mode is workspace-write and network_access is unset (defaults to false).",
        harness: "codex",
      });
    }
  }

  const approval = config.approval_policy;
  if (approval === "on-request" || approval === "on-failure") {
    defenses.push({
      id: "defense-codex-approval-policy",
      title: `Codex approval policy "${approval}"`,
      file: file.path,
      detail: `approval_policy is ${approval}, so escalations outside the sandbox prompt the user.`,
      harness: "codex",
    });
  }

  const headerOwners = findKeyOwners(config, "env_http_headers");
  if (headerOwners.length > 0) {
    defenses.push({
      id: "defense-codex-env-http-headers",
      title: "Codex MCP headers sourced from environment",
      file: file.path,
      detail: `env_http_headers is used ${headerOwners.length === 1 ? "once" : `${headerOwners.length} times`} instead of literal http_headers.`,
      harness: "codex",
    });
  }
  return defenses;
}

function detectCodexRules(file: ConfigFile): ReadonlyArray<Defense> {
  const decisions = [...file.content.matchAll(/decision\s*=\s*["'](forbidden|prompt)["']/g)];
  if (decisions.length === 0) return [];
  const forbidden = decisions.filter((match) => match[1] === "forbidden").length;
  const prompt = decisions.length - forbidden;
  return [
    {
      id: "defense-codex-rules-file",
      title: "Codex exec policy rules",
      file: file.path,
      detail: `${forbidden} forbidden and ${prompt} prompt ${decisions.length === 1 ? "decision" : "decisions"} gate command prefixes.`,
      harness: "codex",
    },
  ];
}

// ─── Hermes ──────────────────────────────────────────────────

function detectHermes(file: ConfigFile): ReadonlyArray<Defense> {
  const config = parseYamlSafe(file.content);
  if (!config) return [];

  const defenses: Defense[] = [];
  const approvals = asObject(config.approvals);
  if (approvals?.mode === "manual") {
    defenses.push({
      id: "defense-hermes-manual-approvals",
      title: "Hermes approvals manual",
      file: file.path,
      detail: "approvals.mode is manual, so every gated action waits for a human.",
      harness: "hermes",
    });
  }
  if (approvals?.cron_mode === "deny") {
    defenses.push({
      id: "defense-hermes-cron-deny",
      title: "Hermes cron approvals denied",
      file: file.path,
      detail: "approvals.cron_mode is deny, so unattended jobs cannot self-approve.",
      harness: "hermes",
    });
  }

  const terminal = asObject(config.terminal);
  const backend = typeof terminal?.backend === "string" ? terminal.backend.toLowerCase() : "";
  if (CONTAINER_BACKENDS.has(backend)) {
    defenses.push({
      id: "defense-hermes-container-terminal",
      title: `Hermes terminal runs in ${backend}`,
      file: file.path,
      detail: `terminal.backend is ${backend}, so shell commands execute inside a container.`,
      harness: "hermes",
    });
  }

  const allowlistOwners = findKeyOwners(config, "command_allowlist");
  const emptyAllowlist = allowlistOwners.some(
    (owner) => Array.isArray(owner.command_allowlist) && owner.command_allowlist.length === 0
  );
  if (emptyAllowlist) {
    defenses.push({
      id: "defense-hermes-empty-allowlist",
      title: "Hermes command allow list empty",
      file: file.path,
      detail: "command_allowlist is empty, so no command is pre-approved.",
      harness: "hermes",
    });
  }
  return defenses;
}

// ─── Gemini ──────────────────────────────────────────────────

function detectGemini(file: ConfigFile): ReadonlyArray<Defense> {
  const settings = parseJsonLenient(file.content);
  if (!settings) return [];

  const defenses: Defense[] = [];
  const security = asObject(settings.security);
  if (security?.disableYoloMode === true) {
    defenses.push({
      id: "defense-gemini-yolo-disabled",
      title: "Gemini YOLO mode disabled",
      file: file.path,
      detail: "security.disableYoloMode is true, so auto-approval of every tool call cannot be turned on.",
      harness: "gemini",
    });
  }
  const folderTrust = asObject(security?.folderTrust);
  if (folderTrust?.enabled === true) {
    defenses.push({
      id: "defense-gemini-folder-trust",
      title: "Gemini folder trust enabled",
      file: file.path,
      detail: "security.folderTrust.enabled is true, so untrusted folders run with reduced capabilities.",
      harness: "gemini",
    });
  }
  return defenses;
}

// ─── OpenCode ────────────────────────────────────────────────

function detectOpenCode(file: ConfigFile): ReadonlyArray<Defense> {
  const config = parseJsonLenient(file.content);
  if (!config) return [];

  const permission = asObject(config.permission);
  const bash = permission?.bash;
  const gated = isGatedPermission(bash);
  if (!gated) return [];

  const description = typeof bash === "string" ? bash : "ask or deny for every pattern";
  return [
    {
      id: "defense-opencode-bash-gate",
      title: "OpenCode bash permission gated",
      file: file.path,
      detail: `permission.bash is ${description}, so shell commands are not auto-approved.`,
      harness: "opencode",
    },
  ];
}

function isGatedPermission(value: unknown): boolean {
  if (value === "ask" || value === "deny") return true;
  const map = asObject(value);
  if (!map) return false;
  const entries = Object.values(map);
  return entries.length > 0 && entries.every((entry) => entry === "ask" || entry === "deny");
}

// ─── Cursor ──────────────────────────────────────────────────

function detectCursorHooks(file: ConfigFile): ReadonlyArray<Defense> {
  const config = parseJsonLenient(file.content);
  if (!config) return [];
  const hooks = asObject(config.hooks);
  if (!hooks) return [];

  const events: string[] = [];
  for (const [event, entries] of Object.entries(hooks)) {
    if (!Array.isArray(entries)) continue;
    if (entries.some((entry) => asObject(entry)?.failClosed === true)) events.push(event);
  }
  if (events.length === 0) return [];

  return [
    {
      id: "defense-cursor-fail-closed-hook",
      title: "Cursor hooks fail closed",
      file: file.path,
      detail: `failClosed is true on ${events.join(", ")}, so a crashed guard blocks instead of allowing.`,
      harness: "cursor",
    },
  ];
}

// ─── Helpers ─────────────────────────────────────────────────

function asObject(value: unknown): JsonObject | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonObject) : null;
}

function asStringArray(value: unknown): ReadonlyArray<string> {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

/** Every object in the tree that owns the given key. */
function findKeyOwners(root: JsonObject, key: string): ReadonlyArray<JsonObject> {
  const owners: JsonObject[] = [];
  const visit = (node: unknown, depth: number): void => {
    if (depth > 8) return;
    const record = asObject(node);
    if (!record) return;
    if (key in record) owners.push(record);
    for (const child of Object.values(record)) {
      if (Array.isArray(child)) {
        for (const item of child) visit(item, depth + 1);
      } else {
        visit(child, depth + 1);
      }
    }
  };
  visit(root, 0);
  return owners;
}

function truncate(text: string, max: number): string {
  const single = text.replace(/\s+/g, " ").trim();
  return single.length > max ? `${single.slice(0, max - 3)}...` : single;
}
