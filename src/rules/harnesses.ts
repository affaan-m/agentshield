import { posix } from "node:path";
import type { ConfigFile, Finding, FindingCategory, Rule, Severity } from "../types.js";
import { parseFrontmatter, parseJsonLenient } from "../scanner/parsers.js";
import { SUSPICIOUS_COMMENT_INSTRUCTION_PATTERN } from "./agents.js";

/**
 * Rules for harness surfaces beyond Claude Code settings: plugin manifests,
 * Gemini CLI settings, OpenCode config, Cursor hooks, Copilot custom agents,
 * and @imports in instruction files. Every JSON rule fails closed: content
 * that does not parse produces no findings, and a harness-json file is only
 * treated as a given harness when its path or key shape says so.
 */

type JsonRecord = Record<string, unknown>;

// ─── Shared helpers ───────────────────────────────────────

function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split("\n").length;
}

function findAllMatches(content: string, pattern: RegExp): ReadonlyArray<RegExpMatchArray> {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return [...content.matchAll(new RegExp(pattern.source, flags))];
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

function basenameOf(filePath: string): string {
  return posix.basename(normalizePath(filePath)).toLowerCase();
}

function parentDirOf(filePath: string): string {
  return posix.basename(posix.dirname(normalizePath(filePath))).toLowerCase();
}

/** Line of the first occurrence of `needle` in the raw text, trying its JSON-escaped form too. */
function lineOf(content: string, needle: string): number | undefined {
  const index = content.indexOf(needle);
  if (index !== -1) return findLineNumber(content, index);
  const encoded = JSON.stringify(needle).slice(1, -1);
  const encodedIndex = encoded === needle ? -1 : content.indexOf(encoded);
  return encodedIndex === -1 ? undefined : findLineNumber(content, encodedIndex);
}

/** Line of the first `"key"` occurrence in raw JSON text. */
function lineOfKey(content: string, key: string): number | undefined {
  return lineOf(content, `"${key}"`);
}

function redactSecret(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 4) return "***";
  return `${trimmed.slice(0, 4)}***`;
}

function truncate(value: string, max = 160): string {
  return value.length > max ? `${value.slice(0, max)}...` : value;
}

function getPath(root: unknown, dotted: string): unknown {
  let current: unknown = root;
  for (const segment of dotted.split(".")) {
    if (!isRecord(current)) return undefined;
    current = current[segment];
  }
  return current;
}

function stringsOf(value: unknown): ReadonlyArray<string> {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  return [];
}

/** Every string value reachable from `value`, with its key path. */
function walkStrings(
  value: unknown,
  currentPath: ReadonlyArray<string> = []
): ReadonlyArray<{ readonly path: ReadonlyArray<string>; readonly value: string }> {
  if (typeof value === "string") return [{ path: currentPath, value }];
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => walkStrings(item, [...currentPath, String(index)]));
  }
  if (isRecord(value)) {
    return Object.entries(value).flatMap(([key, child]) => walkStrings(child, [...currentPath, key]));
  }
  return [];
}

function isAbsolutePathLike(value: string): boolean {
  return /^(?:\/|~\/|[A-Za-z]:[\\/]|\\\\)/.test(value.trim());
}

function hasTraversal(value: string): boolean {
  return /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(value.trim());
}

function isRawIpUrl(value: string): boolean {
  return /^[a-z+]+:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:[/?#]|$)/i.test(value.trim());
}

function isPlainHttpUrl(value: string): boolean {
  return /^http:\/\//i.test(value.trim());
}

function looksLikeSecretName(name: string): boolean {
  return /token|secret|key|password|credential/i.test(name);
}

/** True when a header or env value is a literal, not a `${VAR}` style reference. */
function isLiteralCredentialValue(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 8) return false;
  if (/\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/.test(trimmed)) return false;
  if (/\{(?:env|file):[^}]*\}/.test(trimmed)) return false;
  if (/^(?:YOUR_[A-Z0-9_]+|REPLACE(?:_|-)?ME(?:_[A-Z0-9_]+)?|CHANGEME|<[^>]+>)$/i.test(trimmed)) return false;
  return true;
}

function makeFinding(
  file: ConfigFile,
  id: string,
  severity: Severity,
  category: FindingCategory,
  title: string,
  description: string,
  extra: { readonly line?: number; readonly evidence?: string } = {}
): Finding {
  return {
    id,
    severity,
    category,
    title,
    description,
    file: file.path,
    ...(extra.line !== undefined ? { line: extra.line } : {}),
    ...(extra.evidence !== undefined ? { evidence: extra.evidence } : {}),
  };
}

// ─── Harness detection for harness-json files ─────────────

type HarnessKind = "gemini" | "opencode" | "cursor-hooks" | "unknown";

const GEMINI_KEY_SIGNATURE: ReadonlySet<string> = new Set([
  "general",
  "security",
  "autoAccept",
  "approvalMode",
  "coreTools",
  "excludeTools",
  "hooksConfig",
  "sandboxNetworkAccess",
]);

const OPENCODE_KEY_SIGNATURE: ReadonlySet<string> = new Set([
  "permission",
  "share",
  "default_agent",
  "subagent_depth",
  "instructions",
  "plugin",
  "autoupdate",
]);

const CURSOR_HOOK_EVENTS: ReadonlySet<string> = new Set([
  "sessionstart",
  "sessionend",
  "pretooluse",
  "posttooluse",
  "posttoolusefailure",
  "subagentstart",
  "subagentstop",
  "beforeshellexecution",
  "aftershellexecution",
  "beforemcpexecution",
  "aftermcpexecution",
  "beforereadfile",
  "afterfileedit",
  "beforesubmitprompt",
  "precompact",
  "stop",
  "afteragentresponse",
  "afteragentthought",
  "beforetabfileread",
  "aftertabfileedit",
  "workspaceopen",
]);

function isCodexOwnedPath(file: ConfigFile): boolean {
  return parentDirOf(file.path) === ".codex";
}

function detectHarness(file: ConfigFile, config: JsonRecord): HarnessKind {
  if (file.type !== "harness-json" || isCodexOwnedPath(file)) return "unknown";

  const base = basenameOf(file.path);
  const parent = parentDirOf(file.path);
  const keys = Object.keys(config);

  if (parent === ".gemini" && base === "settings.json") return "gemini";
  if (base === "opencode.json" || base === "opencode.jsonc") return "opencode";
  if (parent === ".cursor" && base === "hooks.json") return "cursor-hooks";

  const schema = typeof config.$schema === "string" ? config.$schema : "";
  if (/opencode/i.test(schema)) return "opencode";

  const hooks = config.hooks;
  if (isRecord(hooks) && Object.keys(hooks).some((event) => CURSOR_HOOK_EVENTS.has(event.toLowerCase()))) {
    return "cursor-hooks";
  }
  if (keys.some((key) => GEMINI_KEY_SIGNATURE.has(key))) return "gemini";
  if (keys.some((key) => OPENCODE_KEY_SIGNATURE.has(key))) return "opencode";

  return "unknown";
}

function parseHarness(file: ConfigFile, wanted: HarnessKind): JsonRecord | null {
  if (file.type !== "harness-json") return null;
  const config = parseJsonLenient(file.content);
  if (!config) return null;
  return detectHarness(file, config) === wanted ? config : null;
}

// ─── Plugin manifests ─────────────────────────────────────

function parsePluginManifest(file: ConfigFile): JsonRecord | null {
  if (file.type !== "plugin-manifest") return null;
  return parseJsonLenient(file.content);
}

function marketplacePlugins(manifest: JsonRecord): ReadonlyArray<{ readonly name: string; readonly source: unknown }> {
  if (!Array.isArray(manifest.plugins)) return [];
  return manifest.plugins.filter(isRecord).map((entry, index) => ({
    name: typeof entry.name === "string" ? entry.name : `plugins[${index}]`,
    source: entry.source,
  }));
}

/** Keys in plugin.json and marketplace.json whose values are filesystem paths. */
const PLUGIN_PATH_KEYS: ReadonlySet<string> = new Set([
  "skills",
  "commands",
  "agents",
  "hooks",
  "mcpServers",
  "lspServers",
  "workflows",
  "outputStyles",
  "themes",
  "monitors",
  "source",
  "path",
]);

/** Leaves under inline hooks and mcpServers that hold shell text, not manifest paths. */
const PLUGIN_NON_PATH_LEAVES: ReadonlySet<string> = new Set([
  "command",
  "args",
  "env",
  "headers",
  "url",
  "description",
  "title",
  "matcher",
]);

function pluginRootOf(file: ConfigFile): string {
  const manifestDir = posix.dirname(normalizePath(file.path));
  return posix.basename(manifestDir) === ".claude-plugin" ? posix.dirname(manifestDir) : manifestDir;
}

function findReferencedFile(
  file: ConfigFile,
  reference: string,
  allFiles: ReadonlyArray<ConfigFile> | undefined
): ConfigFile | undefined {
  if (!allFiles) return undefined;
  const resolved = posix.normalize(posix.join(pluginRootOf(file), normalizePath(reference)));
  return allFiles.find((candidate) => posix.normalize(normalizePath(candidate.path)) === resolved);
}

function collectHookCommands(value: unknown): ReadonlyArray<string> {
  return walkStrings(value)
    .filter((entry) => entry.path[entry.path.length - 1] === "command")
    .map((entry) => entry.value);
}

const SCRIPT_TOKEN_PATTERN = /^(?:\.\/|\.\.\/)?[\w@./-]+\.(?:sh|bash|zsh|js|mjs|cjs|ts|mts|py|rb|pl)$/i;
const INTERPRETER_PATTERN = /^(?:node|nodejs|deno|bun|bunx|npx|tsx|ts-node|python3?|py|bash|sh|zsh|ruby|perl)$/i;

/** True when a hook command runs a script by a relative path with no plugin-root anchor. */
function runsRelativeScript(command: string): boolean {
  if (/\$\{?CLAUDE_PLUGIN_ROOT\}?/.test(command)) return false;
  const tokens = command.trim().split(/\s+/);
  for (const [index, rawToken] of tokens.entries()) {
    const token = rawToken.replace(/^["']|["']$/g, "");
    if (index === 0 && INTERPRETER_PATTERN.test(token)) continue;
    if (token.startsWith("-")) continue;
    if (/^[/~$]/.test(token)) return false;
    if (SCRIPT_TOKEN_PATTERN.test(token)) return true;
    if (index === 0 && INTERPRETER_PATTERN.test(token) === false) return false;
  }
  return false;
}

const pluginRules: ReadonlyArray<Rule> = [
  {
    id: "plugins-marketplace-source-command",
    name: "Marketplace Plugin Source Runs a Command",
    description: "Marketplace entries whose source is produced by running a command or a headers helper",
    severity: "critical",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const manifest = parsePluginManifest(file);
      if (!manifest) return [];
      const findings: Finding[] = [];

      for (const plugin of marketplacePlugins(manifest)) {
        if (!isRecord(plugin.source)) continue;
        const sourceType = typeof plugin.source.type === "string" ? plugin.source.type : "";
        if (sourceType === "command") {
          const command = typeof plugin.source.command === "string" ? plugin.source.command : "";
          findings.push(
            makeFinding(
              file,
              `plugins-marketplace-source-command-${plugin.name}`,
              "critical",
              "misconfiguration",
              `Marketplace plugin "${plugin.name}" is installed by running a command`,
              "A source of type command lets the marketplace run an arbitrary shell command on the installing machine to produce the plugin. Anyone who can edit the marketplace controls that command. Use a pinned github, git, npm, or relative source instead.",
              { line: lineOfKey(file.content, "command"), evidence: truncate(command || '"type": "command"') }
            )
          );
        }
        if (typeof plugin.source.headersHelper === "string") {
          findings.push(
            makeFinding(
              file,
              `plugins-marketplace-headers-helper-${plugin.name}`,
              "critical",
              "misconfiguration",
              `Marketplace plugin "${plugin.name}" uses a headersHelper command`,
              "headersHelper is a command the client runs to compute request headers for fetching the plugin. It runs with the user's environment and can read credentials or run anything else. Remove it and use static, non-secret headers or an authenticated registry.",
              { line: lineOfKey(file.content, "headersHelper"), evidence: truncate(plugin.source.headersHelper) }
            )
          );
        }
      }
      return findings;
    },
  },
  {
    id: "plugins-source-unpinned",
    name: "Marketplace Plugin Source Not Pinned",
    description: "github or git sources without a ref, npm or pip sources without a version",
    severity: "medium",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const manifest = parsePluginManifest(file);
      if (!manifest) return [];
      const findings: Finding[] = [];

      for (const plugin of marketplacePlugins(manifest)) {
        if (!isRecord(plugin.source)) continue;
        const sourceType = typeof plugin.source.type === "string" ? plugin.source.type : "";
        const hasRef = typeof plugin.source.ref === "string" && plugin.source.ref.trim().length > 0;
        const hasVersion = typeof plugin.source.version === "string" && plugin.source.version.trim().length > 0;
        const unpinned =
          ((sourceType === "github" || sourceType === "git") && !hasRef) ||
          ((sourceType === "npm" || sourceType === "pip") && !hasVersion);
        if (!unpinned) continue;

        const missing = sourceType === "github" || sourceType === "git" ? "ref" : "version";
        findings.push(
          makeFinding(
            file,
            `plugins-source-unpinned-${plugin.name}`,
            "medium",
            "misconfiguration",
            `Marketplace plugin "${plugin.name}" has a ${sourceType} source without a ${missing}`,
            `Without a ${missing}, every install fetches whatever the upstream currently publishes. A compromised or rotated upstream changes the plugin contents on the next install without any change in this marketplace. Pin a ${missing}.`,
            { line: lineOfKey(file.content, "type"), evidence: truncate(JSON.stringify(plugin.source)) }
          )
        );
      }
      return findings;
    },
  },
  {
    id: "plugins-source-insecure",
    name: "Marketplace Plugin Source Over Insecure Transport",
    description: "git or url sources fetched over plain http or from a raw IP address",
    severity: "high",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const manifest = parsePluginManifest(file);
      if (!manifest) return [];
      const findings: Finding[] = [];

      for (const plugin of marketplacePlugins(manifest)) {
        const candidates: string[] = [];
        if (typeof plugin.source === "string") candidates.push(plugin.source);
        if (isRecord(plugin.source)) {
          candidates.push(...stringsOf(plugin.source.url), ...stringsOf(plugin.source.repo));
        }
        for (const candidate of candidates) {
          if (!isPlainHttpUrl(candidate) && !isRawIpUrl(candidate)) continue;
          const reason = isRawIpUrl(candidate) ? "a raw IP address" : "plain http";
          findings.push(
            makeFinding(
              file,
              `plugins-source-insecure-${plugin.name}`,
              "high",
              "misconfiguration",
              `Marketplace plugin "${plugin.name}" is fetched from ${reason}`,
              "Plugin code fetched over http or from a bare IP has no transport integrity or host identity. Anyone on the path can swap the plugin contents during install. Use https with a hostname you control and pin a ref.",
              { line: lineOf(file.content, candidate), evidence: truncate(candidate) }
            )
          );
        }
      }
      return findings;
    },
  },
  {
    id: "plugins-userconfig-secret-not-sensitive",
    name: "Plugin userConfig Secret Not Marked Sensitive",
    description: "userConfig keys that name a credential but are not flagged sensitive",
    severity: "medium",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const manifest = parsePluginManifest(file);
      if (!manifest) return [];
      const findings: Finding[] = [];

      const configBlocks: Array<{ readonly scope: string; readonly block: unknown }> = [
        { scope: "userConfig", block: manifest.userConfig },
      ];
      if (Array.isArray(manifest.channels)) {
        manifest.channels.filter(isRecord).forEach((channel, index) => {
          const server = typeof channel.server === "string" ? channel.server : String(index);
          configBlocks.push({ scope: `channels.${server}.userConfig`, block: channel.userConfig });
        });
      }

      for (const { scope, block } of configBlocks) {
        if (!isRecord(block)) continue;
        for (const [key, definition] of Object.entries(block)) {
          if (!looksLikeSecretName(key)) continue;
          if (isRecord(definition) && definition.sensitive === true) continue;
          findings.push(
            makeFinding(
              file,
              `plugins-userconfig-secret-not-sensitive-${scope}.${key}`,
              "medium",
              "secrets",
              `Plugin userConfig "${key}" looks like a credential but is not sensitive`,
              `${scope}.${key} names a token, key, or password but does not set "sensitive": true. The value the user enters is stored in plain text in their settings and can be echoed in prompts and logs. Set "sensitive": true so the harness stores and masks it as a secret.`,
              { line: lineOfKey(file.content, key), evidence: truncate(`${key}: ${JSON.stringify(definition)}`) }
            )
          );
        }
      }
      return findings;
    },
  },
  {
    id: "plugins-path-traversal",
    name: "Plugin Manifest Path Escapes the Plugin",
    description: "Manifest path values that traverse with ../ or point at an absolute path",
    severity: "high",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const manifest = parsePluginManifest(file);
      if (!manifest) return [];
      const findings: Finding[] = [];
      const seen = new Set<string>();

      for (const entry of walkStrings(manifest)) {
        const onPathKey = entry.path.some((segment) => PLUGIN_PATH_KEYS.has(segment));
        if (!onPathKey) continue;
        if (entry.path.some((segment) => PLUGIN_NON_PATH_LEAVES.has(segment))) continue;
        if (/^[a-z][a-z0-9+.-]*:\/\//i.test(entry.value)) continue;
        const traversal = hasTraversal(entry.value);
        const absolute = isAbsolutePathLike(entry.value);
        if (!traversal && !absolute) continue;
        const dotted = entry.path.join(".");
        if (seen.has(dotted)) continue;
        seen.add(dotted);
        findings.push(
          makeFinding(
            file,
            `plugins-path-traversal-${dotted}`,
            "high",
            "misconfiguration",
            `Plugin manifest path "${dotted}" ${traversal ? "traverses outside the plugin" : "is absolute"}`,
            "Plugin manifest paths must be relative to the plugin root and start with ./. A ../ or absolute path makes the plugin load skills, hooks, or servers from outside its own tree, which lets a plugin read or run files it does not ship. Replace it with a ./ path inside the plugin.",
            { line: lineOf(file.content, entry.value), evidence: truncate(`${dotted}: ${entry.value}`) }
          )
        );
      }
      return findings;
    },
  },
  {
    id: "plugins-hooks-relative-script",
    name: "Plugin Hook Runs a Relative Script",
    description: "Hook commands that run scripts by a relative path without ${CLAUDE_PLUGIN_ROOT}",
    severity: "medium",
    category: "misconfiguration",
    check(file: ConfigFile, allFiles?: ReadonlyArray<ConfigFile>): ReadonlyArray<Finding> {
      const manifest = parsePluginManifest(file);
      if (!manifest || manifest.hooks === undefined) return [];
      const findings: Finding[] = [];

      const sources: Array<{ readonly file: ConfigFile; readonly hooks: unknown }> = [];
      const hookRefs = stringsOf(manifest.hooks);
      if (hookRefs.length > 0) {
        for (const reference of hookRefs) {
          const referenced = findReferencedFile(file, reference, allFiles);
          if (!referenced) continue;
          const parsed = parseJsonLenient(referenced.content);
          if (parsed) sources.push({ file: referenced, hooks: parsed });
        }
      }
      if (isRecord(manifest.hooks) || (Array.isArray(manifest.hooks) && hookRefs.length === 0)) {
        sources.push({ file, hooks: manifest.hooks });
      }

      for (const source of sources) {
        for (const command of collectHookCommands(source.hooks)) {
          if (!runsRelativeScript(command)) continue;
          findings.push(
            makeFinding(
              source.file,
              `plugins-hooks-relative-script-${source.file.path}-${command}`,
              "medium",
              "misconfiguration",
              "Plugin hook runs a script by relative path",
              "Hook commands run with the user's project as the working directory, not the plugin directory. A relative script path resolves inside whatever repository the user has open, so a repository can ship a same-named file and hijack the hook. Anchor the script with ${CLAUDE_PLUGIN_ROOT}.",
              { line: lineOf(source.file.content, command), evidence: truncate(command) }
            )
          );
        }
      }
      return findings;
    },
  },
  {
    id: "plugins-bundled-remote-mcp",
    name: "Plugin Bundles a Remote MCP Server With Static Credentials",
    description: "Inline mcpServers entries with a url and a literal credential in headers",
    severity: "high",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const manifest = parsePluginManifest(file);
      if (!manifest || !isRecord(manifest.mcpServers)) return [];
      const findings: Finding[] = [];

      for (const [name, server] of Object.entries(manifest.mcpServers)) {
        if (!isRecord(server) || typeof server.url !== "string" || !isRecord(server.headers)) continue;
        for (const [header, value] of Object.entries(server.headers)) {
          if (typeof value !== "string" || !isLiteralCredentialValue(value)) continue;
          if (!/auth|token|key|secret|cookie|session|bearer/i.test(`${header} ${value}`)) continue;
          findings.push(
            makeFinding(
              file,
              `plugins-bundled-remote-mcp-${name}-${header}`,
              "high",
              "misconfiguration",
              `Plugin MCP server "${name}" ships a literal credential in header ${header}`,
              "The plugin connects to a remote MCP server with a static credential baked into the manifest. Every installer shares the same secret, it is committed to the plugin repository, and rotating it means republishing the plugin. Use ${VAR} references or an oauth block instead.",
              { line: lineOfKey(file.content, header), evidence: `${header}: ${redactSecret(value)}` }
            )
          );
        }
      }
      return findings;
    },
  },
  {
    id: "plugins-dependency-unpinned",
    name: "Plugin Dependency Not Pinned",
    description: "dependencies entries given as bare names without a version",
    severity: "low",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const manifest = parsePluginManifest(file);
      if (!manifest || !Array.isArray(manifest.dependencies)) return [];
      const findings: Finding[] = [];

      for (const entry of manifest.dependencies) {
        let name: string | undefined;
        if (typeof entry === "string") {
          const pinned = /^(?:@[^/@\s]+\/)?[^@\s]+@\S+$/.test(entry.trim());
          if (!pinned) name = entry;
        } else if (isRecord(entry) && typeof entry.name === "string") {
          if (typeof entry.version !== "string" || entry.version.trim().length === 0) name = entry.name;
        }
        if (!name) continue;
        findings.push(
          makeFinding(
            file,
            `plugins-dependency-unpinned-${name}`,
            "low",
            "misconfiguration",
            `Plugin dependency "${name}" has no version`,
            "A bare dependency name resolves to whatever the marketplace currently serves under that name. Pin a version so an upstream change cannot silently swap what this plugin loads.",
            { line: lineOf(file.content, name), evidence: truncate(name) }
          )
        );
      }
      return findings;
    },
  },
];

// ─── Gemini CLI ───────────────────────────────────────────

const geminiRules: ReadonlyArray<Rule> = [
  {
    id: "gemini-yolo-mode",
    name: "Gemini CLI YOLO Approval Mode",
    description: "Gemini settings that approve every tool call without asking",
    severity: "critical",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHarness(file, "gemini");
      if (!config) return [];

      const nested = getPath(config, "general.defaultApprovalMode");
      const legacyMode = config.approvalMode;
      const hits: Array<{ readonly key: string; readonly evidence: string }> = [];
      if (typeof nested === "string" && nested.toLowerCase() === "yolo") {
        hits.push({ key: "defaultApprovalMode", evidence: `general.defaultApprovalMode: ${nested}` });
      }
      if (typeof legacyMode === "string" && legacyMode.toLowerCase() === "yolo") {
        hits.push({ key: "approvalMode", evidence: `approvalMode: ${legacyMode}` });
      }
      if (config.autoAccept === true) {
        hits.push({ key: "autoAccept", evidence: "autoAccept: true" });
      }

      return hits.map((hit) =>
        makeFinding(
          file,
          `gemini-yolo-mode-${hit.key}`,
          "critical",
          "permissions",
          "Gemini CLI runs every tool call without approval",
          "YOLO mode (or the legacy autoAccept flag) tells Gemini CLI to run shell commands, file edits, and MCP tools without prompting. Any prompt injection in a file or web page the model reads becomes a command that runs immediately. Use the default approval mode and, if needed, allow specific tools instead.",
          { line: lineOfKey(file.content, hit.key), evidence: hit.evidence }
        )
      );
    },
  },
  {
    id: "gemini-trusted-server",
    name: "Gemini CLI Trusted MCP Server",
    description: "MCP servers with trust true, which skips all tool confirmations",
    severity: "high",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHarness(file, "gemini");
      if (!config || !isRecord(config.mcpServers)) return [];

      return Object.entries(config.mcpServers)
        .filter(([, server]) => isRecord(server) && server.trust === true)
        .map(([name]) =>
          makeFinding(
            file,
            `gemini-trusted-server-${name}`,
            "high",
            "mcp",
            `Gemini CLI trusts MCP server "${name}" without confirmation`,
            "trust: true bypasses every tool confirmation for this server. Whatever tools the server exposes, including ones it adds after you reviewed it, run without a prompt. Remove trust and use includeTools to allow only the tools you need.",
            { line: lineOfKey(file.content, name), evidence: `mcpServers.${name}.trust: true` }
          )
        );
    },
  },
  {
    id: "gemini-sandbox-off",
    name: "Gemini CLI Tool Sandboxing Disabled",
    description: "security.toolSandboxing false or tools.sandboxNetworkAccess true",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHarness(file, "gemini");
      if (!config) return [];
      const findings: Finding[] = [];

      if (getPath(config, "security.toolSandboxing") === false) {
        findings.push(
          makeFinding(
            file,
            "gemini-sandbox-off-toolSandboxing",
            "high",
            "permissions",
            "Gemini CLI tool sandboxing is disabled",
            "With toolSandboxing off, shell commands and file tools run directly on the host with the user's full permissions rather than inside the sandbox. A single bad command reaches the whole filesystem and network. Re-enable security.toolSandboxing.",
            { line: lineOfKey(file.content, "toolSandboxing"), evidence: "security.toolSandboxing: false" }
          )
        );
      }
      if (getPath(config, "tools.sandboxNetworkAccess") === true) {
        findings.push(
          makeFinding(
            file,
            "gemini-sandbox-off-sandboxNetworkAccess",
            "high",
            "permissions",
            "Gemini CLI sandbox has network access",
            "sandboxNetworkAccess: true lets sandboxed tools reach the network, so a sandboxed command can still exfiltrate files or pull remote payloads. Leave it false unless a specific tool needs it, and scope that tool instead.",
            { line: lineOfKey(file.content, "sandboxNetworkAccess"), evidence: "tools.sandboxNetworkAccess: true" }
          )
        );
      }
      return findings;
    },
  },
  {
    id: "gemini-folder-trust-off",
    name: "Gemini CLI Folder Trust Disabled",
    description: "security.folderTrust.enabled false, so every folder is treated as trusted",
    severity: "medium",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHarness(file, "gemini");
      if (!config) return [];
      const disabled =
        getPath(config, "security.folderTrust.enabled") === false ||
        getPath(config, "folderTrust.enabled") === false ||
        config.folderTrust === false;
      if (!disabled) return [];
      return [
        makeFinding(
          file,
          "gemini-folder-trust-off",
          "medium",
          "permissions",
          "Gemini CLI folder trust is disabled",
          "Folder trust is what stops a freshly cloned repository's GEMINI.md, settings, and MCP servers from loading before you have looked at them. With it disabled, opening an untrusted checkout applies that checkout's config immediately. Set security.folderTrust.enabled to true.",
          { line: lineOfKey(file.content, "folderTrust"), evidence: "security.folderTrust.enabled: false" }
        ),
      ];
    },
  },
  {
    id: "gemini-disable-yolo-guard-missing",
    name: "Gemini CLI YOLO Guard Not Set",
    description: "Posture note: security.disableYoloMode is not true",
    severity: "info",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHarness(file, "gemini");
      if (!config) return [];
      if (getPath(config, "security.disableYoloMode") === true) return [];
      return [
        makeFinding(
          file,
          "gemini-disable-yolo-guard-missing",
          "info",
          "permissions",
          "Gemini CLI does not lock out YOLO mode",
          "security.disableYoloMode: true prevents anyone from switching this Gemini CLI install into YOLO mode, from a flag, a lower-precedence settings file, or a slash command. It is not set here. This is a posture note with no score deduction; add it if you want the guard.",
          { evidence: "security.disableYoloMode is not true" }
        ),
      ];
    },
  },
];

// ─── OpenCode ─────────────────────────────────────────────

const OPENCODE_SECRET_SUBSTITUTION =
  /\{file:(?:~\/\.ssh|~\/\.aws|(?:\.\/)?\.env)[^}]*\}|\{env:[A-Za-z0-9_]*_(?:TOKEN|SECRET)[A-Za-z0-9_]*\}/;

const BARE_NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i;

function isBareNpmName(value: string): boolean {
  const trimmed = value.trim();
  if (/^(?:\.\/|\.\.\/|\/|~\/|file:|[A-Za-z]:[\\/])/.test(trimmed)) return false;
  return BARE_NPM_NAME.test(trimmed);
}

const opencodeRules: ReadonlyArray<Rule> = [
  {
    id: "opencode-permission-allow-all",
    name: "OpenCode Permission Allows Everything",
    description: "permission.bash or permission[*] set to allow at top level or on an agent",
    severity: "critical",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHarness(file, "opencode");
      if (!config) return [];
      const findings: Finding[] = [];

      const isAllow = (value: unknown): boolean =>
        value === "allow" || (isRecord(value) && value["*"] === "allow");

      const scopes: Array<{ readonly label: string; readonly permission: unknown }> = [
        { label: "permission", permission: config.permission },
      ];
      if (isRecord(config.agent)) {
        for (const [agentName, agent] of Object.entries(config.agent)) {
          if (isRecord(agent)) scopes.push({ label: `agent.${agentName}.permission`, permission: agent.permission });
        }
      }

      for (const scope of scopes) {
        if (!isRecord(scope.permission)) continue;
        const hits: string[] = [];
        if (isAllow(scope.permission.bash)) hits.push("bash");
        if (scope.permission["*"] === "allow") hits.push("*");
        for (const key of hits) {
          findings.push(
            makeFinding(
              file,
              `opencode-permission-allow-all-${scope.label}.${key}`,
              "critical",
              "permissions",
              `OpenCode ${scope.label}.${key} is set to allow`,
              `"allow" on ${key === "*" ? "every tool" : "bash"} removes the approval prompt entirely. The agent runs shell commands as soon as the model emits them, so prompt injection from any file or page it reads turns into code that runs on your machine. Use "ask" and allow narrow per-pattern entries instead.`,
              { line: lineOfKey(file.content, key), evidence: `${scope.label}.${key}: "allow"` }
            )
          );
        }
      }
      return findings;
    },
  },
  {
    id: "opencode-share-auto",
    name: "OpenCode Auto-Shares Sessions",
    description: "share set to auto, which publishes every session",
    severity: "medium",
    category: "exposure",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHarness(file, "opencode");
      if (!config || config.share !== "auto") return [];
      return [
        makeFinding(
          file,
          "opencode-share-auto",
          "medium",
          "exposure",
          "OpenCode publishes every session automatically",
          'share: "auto" uploads each session transcript to a public share link as it happens. Anything the agent reads, including source, env output, and secrets in tool results, leaves the machine. Set share to "manual" or "disabled".',
          { line: lineOfKey(file.content, "share"), evidence: 'share: "auto"' }
        ),
      ];
    },
  },
  {
    id: "opencode-plugin-unpinned",
    name: "OpenCode Plugin Not Pinned",
    description: "plugin entries that are bare npm names without a version",
    severity: "low",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHarness(file, "opencode");
      if (!config) return [];
      return stringsOf(config.plugin)
        .filter(isBareNpmName)
        .map((name) =>
          makeFinding(
            file,
            `opencode-plugin-unpinned-${name}`,
            "low",
            "misconfiguration",
            `OpenCode plugin "${name}" has no pinned version`,
            "A bare npm name installs the latest published version on every load. A hijacked or mistaken publish of that package runs inside the agent with full tool access. Pin a version, for example name@1.2.3.",
            { line: lineOf(file.content, name), evidence: name }
          )
        );
    },
  },
  {
    id: "opencode-file-substitution-secret",
    name: "OpenCode Substitution Pulls a Secret",
    description: "{file:} or {env:} substitutions that load credentials into prompts, headers, or instructions",
    severity: "high",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHarness(file, "opencode");
      if (!config) return [];
      const findings: Finding[] = [];

      for (const entry of walkStrings(config)) {
        const inScope = entry.path.some((segment) => /^(?:prompt|headers|instructions)$/.test(segment));
        if (!inScope) continue;
        const match = entry.value.match(OPENCODE_SECRET_SUBSTITUTION);
        if (!match) continue;
        const dotted = entry.path.join(".");
        findings.push(
          makeFinding(
            file,
            `opencode-file-substitution-secret-${dotted}`,
            "high",
            "secrets",
            `OpenCode ${dotted} substitutes a secret with ${match[0]}`,
            "OpenCode expands {file:} and {env:} at load time, so this value inlines a credential or private key into a prompt, MCP header, or instruction text. From there it is sent to the model provider, written to session logs, and shared if sharing is on. Reference secrets only where the provider needs them, and never in prompts.",
            { line: lineOf(file.content, match[0]), evidence: truncate(`${dotted}: ${match[0]}`) }
          )
        );
      }
      return findings;
    },
  },
  {
    id: "opencode-instructions-external",
    name: "OpenCode Instructions Reach Outside the Repository",
    description: "instructions entries with ../ or an absolute path",
    severity: "medium",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHarness(file, "opencode");
      if (!config) return [];
      return stringsOf(config.instructions)
        .filter((entry) => hasTraversal(entry) || isAbsolutePathLike(entry))
        .map((entry) =>
          makeFinding(
            file,
            `opencode-instructions-external-${entry}`,
            "medium",
            "misconfiguration",
            `OpenCode instruction file "${entry}" is outside the repository`,
            "Instruction files become part of the system prompt. A path that climbs out of the repository or points at an absolute location loads text that is not reviewed with this project and can differ per machine, which is an easy way to slip instructions past code review. Keep instruction paths inside the repository.",
            { line: lineOf(file.content, entry), evidence: truncate(entry) }
          )
        );
    },
  },
];

// ─── Cursor hooks ─────────────────────────────────────────

const CURSOR_PERMISSION_GATE_EVENTS: ReadonlySet<string> = new Set([
  "beforeshellexecution",
  "beforemcpexecution",
  "beforereadfile",
  "pretooluse",
]);

const CURSOR_GUARD_EVENTS: ReadonlySet<string> = new Set(["beforeshellexecution", "beforemcpexecution"]);

const EMITS_ALLOW_PATTERN = /["']?permission["']?\s*:\s*["']allow["']/i;
const CONDITIONAL_PATTERN = /\b(?:if|then|else|case|esac|grep|jq|test|unless|when|match|switch|for|while)\b|\[\[|\[ |&&|\|\|/;

function cursorHookEntries(
  config: JsonRecord
): ReadonlyArray<{ readonly event: string; readonly entry: JsonRecord }> {
  if (!isRecord(config.hooks)) return [];
  const entries: Array<{ readonly event: string; readonly entry: JsonRecord }> = [];
  for (const [event, list] of Object.entries(config.hooks)) {
    if (!Array.isArray(list)) continue;
    for (const entry of list) {
      if (isRecord(entry)) entries.push({ event, entry });
    }
  }
  return entries;
}

const cursorRules: ReadonlyArray<Rule> = [
  {
    id: "cursor-hook-auto-allow",
    name: "Cursor Hook Auto-Allows Tool Calls",
    description: "A permission-gate hook whose command unconditionally emits permission allow",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHarness(file, "cursor-hooks");
      if (!config) return [];
      const findings: Finding[] = [];

      for (const { event, entry } of cursorHookEntries(config)) {
        if (!CURSOR_PERMISSION_GATE_EVENTS.has(event.toLowerCase())) continue;
        const command = typeof entry.command === "string" ? entry.command : "";
        if (!EMITS_ALLOW_PATTERN.test(command) || CONDITIONAL_PATTERN.test(command)) continue;
        findings.push(
          makeFinding(
            file,
            `cursor-hook-auto-allow-${event}`,
            "critical",
            "hooks",
            `Cursor ${event} hook allows every call unconditionally`,
            `The hook command on ${event} prints {"permission":"allow"} with no condition, so Cursor treats every shell command, MCP call, or file read on that event as approved. This turns the approval gate into a no-op. Make the hook inspect its input and return deny or ask for anything it does not recognise.`,
            { line: lineOf(file.content, command), evidence: truncate(command) }
          )
        );
      }
      return findings;
    },
  },
  {
    id: "cursor-hook-guard-fail-open",
    name: "Cursor Guard Hook Fails Open",
    description: "Posture note: guard hooks on shell or MCP execution without failClosed true",
    severity: "info",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseHarness(file, "cursor-hooks");
      if (!config) return [];
      const findings: Finding[] = [];

      for (const { event, entry } of cursorHookEntries(config)) {
        if (!CURSOR_GUARD_EVENTS.has(event.toLowerCase())) continue;
        if (entry.failClosed === true) continue;
        const command = typeof entry.command === "string" ? entry.command : "";
        findings.push(
          makeFinding(
            file,
            `cursor-hook-guard-fail-open-${event}-${command}`,
            "info",
            "hooks",
            `Cursor ${event} guard fails open`,
            `This guard hook on ${event} does not set failClosed: true. If the hook script crashes, times out, or is missing, Cursor proceeds as if it had allowed the call. This is a posture note with no score deduction; set failClosed: true so a broken guard blocks instead of waving calls through.`,
            { line: lineOf(file.content, command) ?? lineOfKey(file.content, event), evidence: truncate(command || event) }
          )
        );
      }
      return findings;
    },
  },
];

// ─── GitHub Copilot custom agents ─────────────────────────

function isCopilotAgentFile(file: ConfigFile): boolean {
  if (file.type !== "agents-md") return false;
  return /(?:^|\/)\.github\/agents\/[^/]+\.md$/i.test(normalizePath(file.path));
}

function frontmatterList(value: unknown): ReadonlyArray<string> {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  if (typeof value === "string") return value.split(/[,\s]+/).filter((item) => item.length > 0);
  return [];
}

function copilotMcpServers(frontmatter: JsonRecord): ReadonlyArray<{ readonly name: string; readonly server: JsonRecord }> {
  const raw = frontmatter["mcp-servers"] ?? frontmatter.mcpServers;
  if (isRecord(raw)) {
    return Object.entries(raw)
      .filter((pair): pair is [string, JsonRecord] => isRecord(pair[1]))
      .map(([name, server]) => ({ name, server }));
  }
  if (Array.isArray(raw)) {
    return raw
      .filter(isRecord)
      .map((server, index) => ({ name: typeof server.name === "string" ? server.name : String(index), server }));
  }
  return [];
}

function isRemoteMcpServer(server: JsonRecord): boolean {
  if (typeof server.url === "string") return true;
  return typeof server.type === "string" && /^(?:http|sse|streamable-?http)$/i.test(server.type);
}

const copilotRules: ReadonlyArray<Rule> = [
  {
    id: "copilot-agent-shell-with-remote-mcp",
    name: "Copilot Agent Combines Shell With Remote MCP",
    description: "Custom agent with the shell tool and an inline remote MCP server",
    severity: "high",
    category: "agents",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isCopilotAgentFile(file)) return [];
      const frontmatter = parseFrontmatter(file.content);
      if (!frontmatter) return [];
      const tools = frontmatterList(frontmatter.tools);
      if (!tools.some((tool) => tool.toLowerCase() === "shell")) return [];
      const remote = copilotMcpServers(frontmatter).filter(({ server }) => isRemoteMcpServer(server));
      if (remote.length === 0) return [];

      const names = remote.map((entry) => entry.name).join(", ");
      return [
        makeFinding(
          file,
          `copilot-agent-shell-with-remote-mcp-${file.path}`,
          "high",
          "agents",
          "Copilot agent has shell access and a remote MCP server",
          `This agent can run shell commands and also talks to remote MCP server(s) ${names} defined inline in the agent file. Tool results from a remote server are untrusted input; combined with shell, a poisoned response becomes command execution in the coding agent's environment. Drop shell from tools or move the server to the repository's reviewed MCP settings with a tools allowlist.`,
          { line: lineOf(file.content, "shell"), evidence: `tools include shell; remote mcp-servers: ${names}` }
        ),
      ];
    },
  },
  {
    id: "copilot-mcp-tools-star",
    name: "Copilot MCP Server Allows All Tools",
    description: "mcp-servers entry with tools [\"*\"]",
    severity: "high",
    category: "mcp",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isCopilotAgentFile(file)) return [];
      const frontmatter = parseFrontmatter(file.content);
      if (!frontmatter) return [];
      return copilotMcpServers(frontmatter)
        .filter(({ server }) => frontmatterList(server.tools).includes("*"))
        .map(({ name }) =>
          makeFinding(
            file,
            `copilot-mcp-tools-star-${name}`,
            "high",
            "mcp",
            `Copilot MCP server "${name}" exposes every tool`,
            'tools: ["*"] hands the agent every tool the server publishes now or later, with no review step when the server adds one. List the specific tools this agent needs.',
            { line: lineOf(file.content, name), evidence: `mcp-servers.${name}.tools: ["*"]` }
          )
        );
    },
  },
];

// ─── Instruction file imports and hidden payloads ─────────

function isImportHost(file: ConfigFile): boolean {
  return file.type === "claude-md" || file.type === "agents-md" || file.type === "rule-md";
}

/** Blank out fenced code blocks and inline code spans while keeping line offsets. */
function maskCode(content: string): string {
  const withoutFences = content.replace(/```[\s\S]*?```|~~~[\s\S]*?~~~/g, (block) => block.replace(/[^\n]/g, " "));
  return withoutFences.replace(/`[^`\n]*`/g, (span) => " ".repeat(span.length));
}

const IMPORT_TOKEN_PATTERN = /(?<![\w@./-])@((?:~\/|\.{1,2}\/|\/)[^\s)>\]"'`,;]+|[A-Za-z0-9_.-][^\s)>\]"'`,;]*)/g;

const SENSITIVE_IMPORT_TARGET =
  /(?:^|[\\/])\.env(?:[.\\/]|$)|\.pem$|id_rsa|credentials|(?:^|[\\/])\.netrc$|(?:^|[\\/])\.npmrc$|\.claude[\\/]settings\.json$|(?:^|~|[\\/])\.ssh(?:[\\/]|$)|(?:^|~|[\\/])\.aws(?:[\\/]|$)/i;

function importEscapesRepo(file: ConfigFile, target: string): boolean {
  if (target.startsWith("~/") || target.startsWith("/")) return true;
  if (!target.includes("../")) return false;
  const resolved = posix.normalize(posix.join(posix.dirname(normalizePath(file.path)), target));
  return resolved === ".." || resolved.startsWith("../");
}

function isScopedPackageNotImport(target: string): boolean {
  return /^[A-Za-z0-9-]+\/[A-Za-z0-9-]+$/.test(target) && !/[.]/.test(target);
}

const URL_PATTERN = /https?:\/\/[^\s<>"')]+/i;
const HIDDEN_IMPERATIVE_PATTERN = /\b(?:run|execute|curl|wget|install|send|post)\b/i;

function isGlobalRulesGlob(value: unknown): boolean {
  return stringsOf(value).some((glob) => glob.trim() === "**" || glob.trim() === "**/*");
}

function isRulesFile(file: ConfigFile): boolean {
  const path = normalizePath(file.path);
  if (file.type === "rule-md") return true;
  return file.type === "agents-md" && /(?:^|\/)\.cursor\/rules\/.+\.mdc?$/i.test(path);
}

const RULES_IMPERATIVE_PATTERN =
  /\b(?:always|must|should|run|execute|fetch|download|install|pipe|send|post|use)\b[^\n]*(?:\bcurl\b|\bwget\b|\bssh\b|https?:\/\/)/i;

const instructionRules: ReadonlyArray<Rule> = [
  {
    id: "instructions-import-external",
    name: "Instruction File Imports Outside the Repository",
    description: "@imports that resolve to home, absolute, or parent paths outside the repository",
    severity: "medium",
    category: "exposure",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isImportHost(file)) return [];
      const masked = maskCode(file.content);
      const findings: Finding[] = [];
      const seen = new Set<string>();

      for (const match of findAllMatches(masked, IMPORT_TOKEN_PATTERN)) {
        const target = (match[1] ?? "").replace(/[.:!?]+$/, "");
        if (target.length === 0 || isScopedPackageNotImport(target)) continue;
        if (!importEscapesRepo(file, target)) continue;
        if (seen.has(target)) continue;
        seen.add(target);

        const sensitive = SENSITIVE_IMPORT_TARGET.test(target);
        findings.push(
          makeFinding(
            file,
            `instructions-import-external-${target}`,
            sensitive ? "high" : "medium",
            "exposure",
            sensitive
              ? `Instruction file imports a sensitive path: ${target}`
              : `Instruction file imports outside the repository: ${target}`,
            sensitive
              ? "An @import in a project instruction file pulls the target's contents into the model context on every session. This target is a credential or key store, so its contents are read and sent to the model provider, and Claude Code prompts the user to approve it as an external import. Remove the import."
              : "An @import that resolves outside the repository loads content that is not versioned with this project and is not visible in code review. What ends up in the model context depends on the machine it runs on, and Claude Code prompts to approve it as an external import. Keep imports inside the repository.",
            { line: findLineNumber(file.content, match.index ?? 0), evidence: `@${target}` }
          )
        );
      }
      return findings;
    },
  },
  {
    id: "instructions-hidden-comment-payload",
    name: "Hidden Comment Contains a Network Instruction",
    description: "HTML comments that pair a URL with an imperative not caught by agents-comment-injection",
    severity: "medium",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "claude-md" && file.type !== "agents-md") return [];
      const findings: Finding[] = [];

      for (const match of findAllMatches(file.content, /<!--([\s\S]*?)-->/g)) {
        const body = match[1] ?? "";
        if (!URL_PATTERN.test(body) || !HIDDEN_IMPERATIVE_PATTERN.test(body)) continue;
        if (SUSPICIOUS_COMMENT_INSTRUCTION_PATTERN.test(body)) continue;
        findings.push(
          makeFinding(
            file,
            `instructions-hidden-comment-payload-${match.index ?? 0}`,
            "medium",
            "injection",
            "Hidden comment pairs a URL with an instruction",
            "HTML comments are stripped from the rendered markdown a human reads but the Read tool and several harnesses still hand them to the model. This comment names a URL together with a run, fetch, or send instruction, which is the shape of a payload hidden from reviewers. Remove it or move the instruction into visible text.",
            { line: findLineNumber(file.content, match.index ?? 0), evidence: truncate(body.trim(), 200) }
          )
        );
      }
      return findings;
    },
  },
  {
    id: "instructions-rules-paths-global",
    name: "Global Rules File Carries a Network Instruction",
    description: "Rules applied to every path that tell the agent to use curl, wget, ssh, or a URL",
    severity: "low",
    category: "exposure",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isRulesFile(file)) return [];
      const frontmatter = parseFrontmatter(file.content);
      if (!frontmatter) return [];
      const globalPaths = isGlobalRulesGlob(frontmatter.paths) || isGlobalRulesGlob(frontmatter.globs);
      const alwaysApply = frontmatter.alwaysApply === true;
      if (!globalPaths && !alwaysApply) return [];

      const bodyStart = file.content.indexOf("\n---", 3);
      const body = bodyStart === -1 ? "" : file.content.slice(bodyStart + 4);
      const match = body.match(RULES_IMPERATIVE_PATTERN);
      if (!match) return [];

      const scope = [globalPaths ? "paths match every file" : "", alwaysApply ? "alwaysApply is true" : ""]
        .filter((part) => part.length > 0)
        .join(" and ");
      return [
        makeFinding(
          file,
          `instructions-rules-paths-global-${file.path}`,
          "low",
          "exposure",
          "Always-on rules file instructs the agent to reach the network",
          `This rules file is loaded for every task (${scope}) and contains an instruction that points the agent at curl, wget, ssh, or a URL. A rule like that runs in every session regardless of what the user is working on, which makes it a convenient place to plant an exfiltration or download step. Scope the rule to the paths that need it and review the instruction.`,
          {
            line: findLineNumber(file.content, bodyStart + 4 + (match.index ?? 0)),
            evidence: truncate(match[0].trim(), 200),
          }
        ),
      ];
    },
  },
];

export const harnessRules: ReadonlyArray<Rule> = [
  ...pluginRules,
  ...geminiRules,
  ...opencodeRules,
  ...cursorRules,
  ...copilotRules,
  ...instructionRules,
];
