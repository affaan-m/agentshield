import type {
  ConfigFile,
  Finding,
  FindingCategory,
  Rule,
  RuntimeConfidence,
  Severity,
} from "../types.js";
import { parseJsonLenient } from "../scanner/parsers.js";
import { isPluginCachePath, isStrongDocumentationExamplePath } from "../source-context.js";

/**
 * Remote MCP transport, OAuth, stdio bridge, cross-harness auto-approval,
 * and tool-description poisoning rules.
 *
 * Every rule here runs over one server iterator so each server definition is
 * seen regardless of which harness wrote the file:
 * - `mcpServers` maps at any depth (Claude .mcp.json, ~/.claude.json
 *   including projects.<path>.mcpServers, Cursor, Windsurf, Roo, Cline,
 *   Gemini settings, Copilot, plugin catalogs)
 * - top-level `mcp` map (OpenCode), where `command` may be an array and env
 *   lives under `environment`
 * - `url`, `serverUrl` (Windsurf) and `httpUrl` (Gemini) as URL aliases
 *
 * Content that does not parse as (lenient) JSON produces no findings.
 *
 * Deliberately not duplicated from src/rules/mcp.ts and mcp-tool-poisoning.ts:
 * enableAllProjectMcpServers, non-wildcard autoApprove, sh/bash -c wrappers,
 * curl|wget piped to a shell, npx -c, PATH/LD_PRELOAD/PYTHONPATH overrides,
 * and server-level description poisoning.
 */

type JsonObject = Record<string, unknown>;

interface McpServer {
  readonly name: string;
  readonly config: JsonObject;
  readonly keyPath: string;
  readonly command?: string;
  readonly args: ReadonlyArray<string>;
  readonly env: Readonly<Record<string, string>>;
  readonly url?: string;
  readonly urlKey?: string;
  readonly type?: string;
}

interface ToolEntry {
  readonly server: string;
  readonly name: string;
  readonly description: string;
  readonly keyPath: string;
}

interface ParsedUrl {
  readonly scheme: string;
  readonly userinfo?: string;
  readonly host: string;
  readonly query: string;
}

const SCANNED_FILE_TYPES: ReadonlySet<string> = new Set([
  "mcp-json",
  "settings-json",
  "harness-json",
]);

const MAX_WALK_DEPTH = 8;

const SERVER_SHAPE_KEYS: ReadonlyArray<string> = [
  "command",
  "args",
  "url",
  "serverUrl",
  "httpUrl",
  "type",
  "headers",
  "env",
  "environment",
  "oauth",
  "auth",
  "tools",
  "alwaysAllow",
  "autoApprove",
  "trust",
  "disabled",
  "headersHelper",
];

const URL_KEYS: ReadonlyArray<string> = ["url", "serverUrl", "httpUrl"];

// ─── Generic helpers ──────────────────────────────────────

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringArray(value: unknown): ReadonlyArray<string> {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function stringMap(value: unknown): Readonly<Record<string, string>> {
  if (!isObject(value)) return {};
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === "string") out[key] = item;
  }
  return out;
}

function basename(command: string): string {
  return (command.split(/[\\/]/).pop() ?? "").toLowerCase();
}

function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split("\n").length;
}

/** Line of the first needle found in the raw text, trying JSON-escaped form first. */
function lineOf(content: string, needles: ReadonlyArray<string>): number | undefined {
  for (const needle of needles) {
    if (!needle) continue;
    const escaped = JSON.stringify(needle).slice(1, -1);
    const idx = content.indexOf(escaped);
    if (idx !== -1) return findLineNumber(content, idx);
    const rawIdx = content.indexOf(needle);
    if (rawIdx !== -1) return findLineNumber(content, rawIdx);
  }
  return undefined;
}

function redact(value: string): string {
  if (value.length <= 8) return "****";
  return `${value.substring(0, 4)}...${value.substring(value.length - 2)} (${value.length} chars)`;
}

function slug(value: string): string {
  return value.replace(/[^A-Za-z0-9_.-]+/g, "_").substring(0, 40);
}

function isLikelyMcpTemplatePath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  return /(^|\/)(mcp-configs|configs?\/mcp)\//.test(normalized);
}

function classifyRuntimeConfidence(file: ConfigFile): RuntimeConfidence {
  if (isPluginCachePath(file.path)) return "plugin-cache";
  if (isLikelyMcpTemplatePath(file.path)) return "template-example";
  const normalized = file.path.replace(/\\/g, "/").toLowerCase();
  if (normalized === "settings.local.json" || normalized.endsWith("/settings.local.json")) {
    return "project-local-optional";
  }
  if (isStrongDocumentationExamplePath(file.path)) return "docs-example";
  return "active-runtime";
}

function isUserScopeFile(file: ConfigFile): boolean {
  const normalized = file.path.replace(/\\/g, "/");
  return /(^|\/)\.claude\.json$/.test(normalized) || /^(?:\/Users\/[^/]+|\/home\/[^/]+|~)\//.test(normalized);
}

// ─── Reference and credential detection ───────────────────

const PURE_REFERENCE = /^(?:\$\{(?:env:|file:)?[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{(?:env|file):[^}]+\})$/;
const DEFAULTED_REFERENCE = /\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]*)\}/g;
const CONTAINS_INTERPOLATION = /\$\{|\{env:|\{file:|(?:^|[\s:=])\$[A-Za-z_]/;

const PLACEHOLDER_VALUE =
  /^(?:<[^>]*>|\[[^\]]*\]|\.{3,}|x{3,}|\*{3,}|(?:your|my|the|replace|change|insert|placeholder|example|sample|dummy|fake|todo|xxx)[-_a-z0-9 ]*)$/i;

const KNOWN_CREDENTIAL_PREFIX =
  /^(?:sk-|sk_live_|sk_test_|rk_live_|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[abpr]-|AKIA|ASIA|eyJ[A-Za-z0-9_-]{10,}\.|AIza|sntrys_|pypi-|npm_|dop_v1_|hf_|shpat_|sq0atp-|pk_live_|lin_api_|figd_|xkeysib-)/;

function isReference(value: string): boolean {
  return PURE_REFERENCE.test(value.trim());
}

function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_VALUE.test(value.trim());
}

function literalCredentialBody(text: string): string | null {
  const body = text.trim().replace(/^(?:bearer|basic|token|apikey|api-key)\s+/i, "").trim();
  if (!body) return null;
  if (isReference(body) || CONTAINS_INTERPOLATION.test(body)) return null;
  if (isPlaceholder(body)) return null;
  if (KNOWN_CREDENTIAL_PREFIX.test(body)) return body;
  if (/^[A-Za-z0-9_\-./+=]{20,}$/.test(body) && /\d/.test(body) && /[A-Za-z]/.test(body)) {
    return body;
  }
  return null;
}

/**
 * Returns the literal credential inside a header or config value, or null.
 * `${VAR}` references are fine; `${VAR:-literal}` defaults are inspected.
 */
function credentialLiteral(raw: string): string | null {
  const value = raw.trim();
  if (!value) return null;
  for (const match of [...value.matchAll(DEFAULTED_REFERENCE)]) {
    const hit = literalCredentialBody(match[1]);
    if (hit) return hit;
  }
  if (CONTAINS_INTERPOLATION.test(value)) return null;
  return literalCredentialBody(value);
}

function cookieCredential(raw: string): string | null {
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const hit = credentialLiteral(part.substring(eq + 1));
    if (hit) return hit;
  }
  return null;
}

const CREDENTIAL_HEADER = /^(?:authorization|proxy-authorization|x-api-key|cookie|set-cookie)$|key|token|secret|auth|credential|password/i;

function headerCredential(name: string, value: string): string | null {
  if (!CREDENTIAL_HEADER.test(name)) return null;
  return /^(?:set-)?cookie$/i.test(name) ? cookieCredential(value) : credentialLiteral(value);
}

// ─── URL helpers ──────────────────────────────────────────

function parseUrl(raw: string): ParsedUrl | null {
  const value = raw.trim();
  if (!value || value.startsWith("$") || value.startsWith("{")) return null;
  const match = value.match(
    /^([a-z][a-z0-9+.-]*):\/\/(?:([^@/?#\s]*)@)?(\[[^\]]*\]|[^:/?#\s]*)(?::\d+)?[^?#]*(?:\?([^#]*))?/i,
  );
  if (!match) {
    const bare = value.match(/^([a-z][a-z0-9+.-]*):/i);
    return bare ? { scheme: bare[1].toLowerCase(), host: "", query: "" } : null;
  }
  return {
    scheme: match[1].toLowerCase(),
    userinfo: match[2],
    host: match[3].toLowerCase(),
    query: match[4] ?? "",
  };
}

function isLoopbackHost(host: string): boolean {
  const bare = host.replace(/^\[|\]$/g, "");
  return (
    bare === "localhost" ||
    bare === "::1" ||
    bare === "0.0.0.0" ||
    bare === "host.docker.internal" ||
    bare.endsWith(".localhost") ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bare)
  );
}

function ipv4Octets(host: string): ReadonlyArray<number> | null {
  const match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return null;
  const octets = match.slice(1).map((part) => Number(part));
  return octets.every((octet) => octet <= 255) ? octets : null;
}

type PrivateRange = { readonly label: string; readonly metadata: boolean } | null;

function privateRange(host: string): PrivateRange {
  const bare = host.replace(/^\[|\]$/g, "");
  if (isLoopbackHost(bare)) return null;
  if (bare === "169.254.169.254" || bare === "metadata.google.internal" || bare === "fd00:ec2::254") {
    return { label: "cloud metadata endpoint", metadata: true };
  }
  const octets = ipv4Octets(bare);
  if (octets) {
    const [a, b] = octets;
    if (a === 10) return { label: "10.0.0.0/8 private range", metadata: false };
    if (a === 172 && b >= 16 && b <= 31) return { label: "172.16.0.0/12 private range", metadata: false };
    if (a === 192 && b === 168) return { label: "192.168.0.0/16 private range", metadata: false };
    if (a === 169 && b === 254) return { label: "169.254.0.0/16 link-local range", metadata: false };
    return null;
  }
  if (/^f[cd][0-9a-f]{0,2}:/i.test(bare)) return { label: "fc00::/7 unique local range", metadata: false };
  if (bare.endsWith(".internal")) return { label: ".internal hostname", metadata: false };
  return null;
}

const URL_CREDENTIAL_PARAM = /(?:^|[&;])(token|api_key|apikey|api-key|access_token|key|auth_token|auth|secret|password|pwd)=([^&#;]+)/gi;

function urlCredentialParam(parsed: ParsedUrl): { readonly param: string; readonly value: string } | null {
  for (const match of [...parsed.query.matchAll(URL_CREDENTIAL_PARAM)]) {
    const value = decodeURIComponentSafe(match[2]);
    if (!value || isReference(value) || CONTAINS_INTERPOLATION.test(value) || isPlaceholder(value)) continue;
    return { param: match[1], value };
  }
  return null;
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function redactUrl(url: string): string {
  return url
    .replace(/(:\/\/[^:/@\s]+:)[^@/\s]+@/, "$1****@")
    .replace(/([?&;](?:token|api_key|apikey|api-key|access_token|key|auth_token|auth|secret|password|pwd)=)[^&#;]+/gi, "$1****")
    .substring(0, 120);
}

// ─── Server iterator ──────────────────────────────────────

function looksLikeServer(value: unknown): value is JsonObject {
  return isObject(value) && SERVER_SHAPE_KEYS.some((key) => key in value);
}

function buildServer(name: string, raw: JsonObject, keyPath: string): McpServer {
  let command: string | undefined;
  let args: ReadonlyArray<string> = stringArray(raw.args);
  if (typeof raw.command === "string") {
    command = raw.command;
  } else if (Array.isArray(raw.command)) {
    const parts = stringArray(raw.command);
    command = parts[0];
    args = [...parts.slice(1), ...args];
  }
  const env = { ...stringMap(raw.env), ...stringMap(raw.environment) };
  const urlKey = URL_KEYS.find((key) => typeof raw[key] === "string" && (raw[key] as string).trim() !== "");
  return {
    name,
    config: raw,
    keyPath,
    command,
    args,
    env,
    url: urlKey ? (raw[urlKey] as string) : undefined,
    urlKey,
    type: typeof raw.type === "string" ? raw.type : undefined,
  };
}

function walkServers(value: unknown, path: string, depth: number, out: McpServer[]): void {
  if (depth > MAX_WALK_DEPTH || !isObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    const childPath = path ? `${path}.${key}` : key;
    const isServerMap = key === "mcpServers" || (key === "mcp" && depth === 0);
    if (isServerMap && isObject(child)) {
      for (const [name, raw] of Object.entries(child)) {
        if (looksLikeServer(raw)) out.push(buildServer(name, raw, `${childPath}.${name}`));
      }
      continue;
    }
    if (isObject(child)) walkServers(child, childPath, depth + 1, out);
  }
}

/**
 * Every MCP server definition in a parsed config, across harness shapes.
 * Exported for tests and for other modules that need the same view.
 */
export function collectMcpServers(config: JsonObject): ReadonlyArray<McpServer> {
  const servers: McpServer[] = [];
  walkServers(config, "", 0, servers);
  return servers;
}

function parseScannedFile(file: ConfigFile): JsonObject | null {
  if (!SCANNED_FILE_TYPES.has(file.type)) return null;
  return parseJsonLenient(file.content);
}

// ─── Tool list collection ─────────────────────────────────

function toolEntriesFromArray(server: string, tools: ReadonlyArray<unknown>, keyPath: string): ReadonlyArray<ToolEntry> {
  const entries: ToolEntry[] = [];
  tools.forEach((tool, index) => {
    if (!isObject(tool)) return;
    const name = typeof tool.name === "string" ? tool.name : `#${index}`;
    const description = typeof tool.description === "string" ? tool.description : "";
    entries.push({ server, name, description, keyPath: `${keyPath}[${index}]` });
  });
  return entries;
}

function walkTools(value: unknown, path: string, depth: number, server: string, out: ToolEntry[]): void {
  if (depth > MAX_WALK_DEPTH || !isObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    const childPath = path ? `${path}.${key}` : key;
    if (key === "tools" && Array.isArray(child)) {
      out.push(...toolEntriesFromArray(server, child, childPath));
      continue;
    }
    if (key === "toolDescriptions" && isObject(child)) {
      for (const [name, description] of Object.entries(child)) {
        if (typeof description === "string") {
          out.push({ server, name, description, keyPath: `${childPath}.${name}` });
        }
      }
      continue;
    }
    if (!isObject(child)) continue;
    const isServerMap = key === "mcpServers" || (key === "mcp" && depth === 0);
    if (isServerMap) {
      for (const [name, raw] of Object.entries(child)) {
        walkTools(raw, `${childPath}.${name}`, depth + 1, name, out);
      }
      continue;
    }
    walkTools(child, childPath, depth + 1, server || key, out);
  }
}

function collectToolEntries(config: JsonObject): ReadonlyArray<ToolEntry> {
  const entries: ToolEntry[] = [];
  walkTools(config, "", 0, "", entries);
  return entries;
}

/** Tool names a server declares in its own config (strings or {name} objects). */
function declaredToolNames(server: McpServer): ReadonlyArray<string> {
  const names = new Set<string>();
  const tools = server.config.tools;
  if (Array.isArray(tools)) {
    for (const tool of tools) {
      if (typeof tool === "string" && tool !== "*") names.add(tool);
      else if (isObject(tool) && typeof tool.name === "string") names.add(tool.name);
    }
  }
  if (isObject(server.config.toolDescriptions)) {
    for (const name of Object.keys(server.config.toolDescriptions)) names.add(name);
  }
  return [...names];
}

// ─── Finding construction ─────────────────────────────────

interface FindingInput {
  readonly id: string;
  readonly severity: Severity;
  readonly category: FindingCategory;
  readonly title: string;
  readonly description: string;
  readonly evidence: string;
  readonly needles: ReadonlyArray<string>;
  readonly fix?: Finding["fix"];
}

function makeFinding(file: ConfigFile, input: FindingInput): Finding {
  return {
    id: input.id,
    severity: input.severity,
    category: input.category,
    title: input.title,
    description: input.description,
    file: file.path,
    line: lineOf(file.content, input.needles),
    evidence: input.evidence.substring(0, 200),
    runtimeConfidence: classifyRuntimeConfidence(file),
    ...(input.fix ? { fix: input.fix } : {}),
  };
}

function serverRule(
  meta: Pick<Rule, "id" | "name" | "description" | "severity" | "category">,
  perServer: (server: McpServer, file: ConfigFile, config: JsonObject) => ReadonlyArray<FindingInput>,
): Rule {
  return {
    ...meta,
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const config = parseScannedFile(file);
      if (!config) return [];
      const findings: Finding[] = [];
      for (const server of collectMcpServers(config)) {
        for (const input of perServer(server, file, config)) {
          findings.push(makeFinding(file, input));
        }
      }
      return findings;
    },
  };
}

// ─── Shared remote URL checks (used directly and via bridges) ──

function remoteUrlFindings(
  server: McpServer,
  url: string,
  via: string | undefined,
): ReadonlyArray<FindingInput> {
  const parsed = parseUrl(url);
  if (!parsed) return [];
  const findings: FindingInput[] = [];
  const viaSuffix = via ? ` via ${via} bridge` : "";
  const idSuffix = via ? `-bridge-${slug(server.name)}` : `-${slug(server.name)}`;
  const label = via ? `${via} bridge in MCP server "${server.name}"` : `MCP server "${server.name}"`;

  const isPlaintext = (parsed.scheme === "http" || parsed.scheme === "ws") && !isLoopbackHost(parsed.host);
  if (isPlaintext) {
    findings.push({
      id: `mcp-remote-plaintext${idSuffix}`,
      severity: "high",
      category: "mcp",
      title: `${label} uses plaintext ${parsed.scheme}:// transport${viaSuffix}`,
      description: `The ${label} connects to "${redactUrl(url)}" over ${parsed.scheme}:// to a non-loopback host. Tool calls, results, and any Authorization header travel unencrypted and can be read or rewritten on the network. Use https:// or wss://.`,
      evidence: `${via ? `${via} ` : `${server.urlKey ?? "url"}: `}${redactUrl(url)}`,
      needles: [url],
      fix: {
        description: "Switch the transport to TLS",
        before: url.substring(0, 60),
        after: url.replace(/^http:/i, "https:").replace(/^ws:/i, "wss:").substring(0, 60),
        auto: false,
      },
    });
  }

  const range = privateRange(parsed.host);
  if (range) {
    findings.push({
      id: `mcp-url-private-range${idSuffix}`,
      severity: range.metadata ? "high" : "medium",
      category: "mcp",
      title: `${label} points at ${range.label}${viaSuffix}`,
      description: range.metadata
        ? `The ${label} URL targets the cloud instance metadata endpoint. An MCP client that follows this URL becomes an SSRF pivot that can read instance credentials.`
        : `The ${label} URL host "${parsed.host}" is in a private or link-local range (${range.label}). Committed configs that point agents at internal addresses turn the harness into an SSRF pivot into the network it runs in.`,
      evidence: `host: ${parsed.host}`,
      needles: [url],
    });
  }

  const param = urlCredentialParam(parsed);
  if (param) {
    findings.push({
      id: `mcp-token-in-url${idSuffix}`,
      severity: "critical",
      category: "secrets",
      title: `${label} carries a credential in the URL query (${param.param})${viaSuffix}`,
      description: `The ${label} URL passes "${param.param}" in the query string. The MCP authorization spec forbids tokens in the URI; query strings land in logs, proxies, browser history, and referrers. Send the credential in an Authorization header sourced from an environment variable.`,
      evidence: `${param.param}=${redact(param.value)} in ${redactUrl(url)}`,
      needles: [param.value, url],
      fix: {
        description: "Move the credential into a header referencing an environment variable",
        before: redactUrl(url).substring(0, 60),
        after: '"headers": { "Authorization": "Bearer ${TOKEN}" }',
        auto: false,
      },
    });
  }

  if (parsed.userinfo && parsed.userinfo.includes(":")) {
    const password = parsed.userinfo.substring(parsed.userinfo.indexOf(":") + 1);
    if (password && !isReference(password) && !CONTAINS_INTERPOLATION.test(password) && !isPlaceholder(password)) {
      findings.push({
        id: `mcp-token-in-url-userinfo${idSuffix}`,
        severity: "critical",
        category: "secrets",
        title: `${label} embeds basic-auth credentials in the URL${viaSuffix}`,
        description: `The ${label} URL contains user:password userinfo. Credentials embedded in URLs are logged by proxies and clients and cannot be rotated without editing committed config.`,
        evidence: redactUrl(url),
        needles: [password, url],
      });
    }
  }

  return findings;
}

// ─── Bridge and shell helpers ─────────────────────────────

const BRIDGE_PATTERN = /(?:^|[\\/])(mcp-remote|supergateway|mcp-proxy)(?:@[^\\/\s]*)?$/i;

function detectBridge(server: McpServer): string | undefined {
  const candidates = [server.command ?? "", ...server.args];
  for (const candidate of candidates) {
    const match = candidate.match(BRIDGE_PATTERN);
    if (match) return match[1].toLowerCase();
  }
  return undefined;
}

function bridgeUrl(args: ReadonlyArray<string>): string | undefined {
  for (const arg of args) {
    if (/^(?:https?|wss?):\/\//i.test(arg)) return arg;
    const attached = arg.match(/^--(?:sse|streamableHttp|streamable-http|url|remote)=(.+)$/i);
    if (attached && /^(?:https?|wss?):\/\//i.test(attached[1])) return attached[1];
  }
  return undefined;
}

function bridgeHeaderValues(args: ReadonlyArray<string>): ReadonlyArray<string> {
  const values: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--header" || arg === "-H") {
      if (args[i + 1]) values.push(args[i + 1]);
      continue;
    }
    const attached = arg.match(/^(?:--header|-H)=(.+)$/);
    if (attached) values.push(attached[1]);
  }
  return values;
}

const SHELL_BASENAMES: ReadonlySet<string> = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
  "fish",
  "cmd",
  "cmd.exe",
  "powershell",
  "powershell.exe",
  "pwsh",
  "pwsh.exe",
]);

const INTERPRETER_EVAL_FLAGS: ReadonlyArray<{ readonly names: ReadonlyArray<string>; readonly flag: RegExp }> = [
  { names: ["node", "node.exe", "nodejs"], flag: /^(?:-e|--eval|-p|--print)$/ },
  { names: ["python", "python3", "python.exe", "py"], flag: /^-c$/ },
  { names: ["deno", "deno.exe"], flag: /^eval$/ },
  { names: ["bun", "bun.exe"], flag: /^(?:-e|--eval)$/ },
  { names: ["ruby", "perl", "php"], flag: /^(?:-e|-r)$/ },
];

const EXISTING_SHELL_WRAPPER = /^(?:sh|bash|zsh|cmd)$/;
const EXISTING_CURL_PIPE = /\b(curl|wget)\b.*\|\s*(sh|bash|zsh|node|python)/i;

const PIPE_TO_SHELL = /\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|node|python3?|perl|ruby|pwsh|powershell)\b/i;
const DOWNLOADER = /(?:^|[\s;&|(])(?:curl|wget|Invoke-WebRequest|iwr)\s+/i;
const BASE64_DECODE = /\bbase64\s+(?:-d|--decode|-D)\b|\[System\.Convert\]::FromBase64String/i;

const DOCKER_VALUE_FLAGS: ReadonlySet<string> = new Set([
  "-v",
  "--volume",
  "-e",
  "--env",
  "--env-file",
  "--name",
  "-p",
  "--publish",
  "--network",
  "--net",
  "-w",
  "--workdir",
  "--entrypoint",
  "--mount",
  "-u",
  "--user",
  "--platform",
  "-l",
  "--label",
  "-m",
  "--memory",
  "--cpus",
  "--add-host",
  "--cap-add",
  "--cap-drop",
  "--security-opt",
  "--tmpfs",
  "--ulimit",
  "-h",
  "--hostname",
  "--pull",
  "--restart",
  "--log-driver",
  "--device",
  "--gpus",
  "--shm-size",
  "--pid",
  "--ipc",
  "--userns",
  "--cidfile",
  "--stop-timeout",
  "--health-cmd",
  "--dns",
  "--expose",
  "--group-add",
  "--sysctl",
  "--annotation",
]);

function dockerImage(args: ReadonlyArray<string>): string | undefined {
  let runIndex = args.indexOf("run");
  if (runIndex === -1) {
    const containerIndex = args.indexOf("container");
    if (containerIndex !== -1 && args[containerIndex + 1] === "run") runIndex = containerIndex + 1;
  }
  if (runIndex === -1) return undefined;
  for (let i = runIndex + 1; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("-")) {
      if (!arg.includes("=") && DOCKER_VALUE_FLAGS.has(arg)) i++;
      continue;
    }
    return arg;
  }
  return undefined;
}

// ─── OAuth helpers ────────────────────────────────────────

const OAUTH_CONTAINERS: ReadonlyArray<string> = ["oauth", "auth"];
const OAUTH_SECRET_KEYS: ReadonlyArray<string> = ["clientSecret", "client_secret", "CLIENT_SECRET", "clientsecret"];
const OAUTH_ENDPOINT_KEYS: ReadonlyArray<string> = [
  "authServerMetadataUrl",
  "authorizationUrl",
  "tokenUrl",
  "authorization_url",
  "token_url",
  "metadataUrl",
  "issuerUrl",
];
const OAUTH_REDIRECT_KEYS: ReadonlyArray<string> = ["redirectUri", "redirect_uri", "redirectUrl", "callbackUrl"];

const WILDCARD_SCOPE = /^(?:\*|\*:\*|all|full[-_]access|admin:\*|write:\*|delete_repo|[a-z_.-]+:\*)$/i;

function oauthBlocks(server: McpServer): ReadonlyArray<{ readonly key: string; readonly block: JsonObject }> {
  const blocks: { readonly key: string; readonly block: JsonObject }[] = [];
  for (const key of OAUTH_CONTAINERS) {
    const block = server.config[key];
    if (isObject(block)) blocks.push({ key, block });
  }
  return blocks;
}

function scopeList(value: unknown): ReadonlyArray<string> {
  if (typeof value === "string") return value.split(/[\s,]+/).filter((scope) => scope !== "");
  return stringArray(value);
}

// ─── Auto-approve helpers ─────────────────────────────────

const AUTO_APPROVE_LIST_KEYS: ReadonlyArray<string> = ["autoApprove", "alwaysAllow", "auto_approve", "always_allow"];
const AUTO_APPROVE_LIKE_KEYS: ReadonlyArray<string> = [
  ...AUTO_APPROVE_LIST_KEYS,
  "autoRun",
  "autoConfirm",
  "auto_confirm",
  "trust",
];

function isTruthySetting(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  return value === true;
}

function openCodePermissionAllow(config: JsonObject, serverName: string): string | undefined {
  const permission = config.permission;
  if (!isObject(permission)) return undefined;
  for (const [key, value] of Object.entries(permission)) {
    if (value !== "allow") continue;
    if (key === serverName) return key;
    if (key.startsWith(serverName) && /^[_*]/.test(key.substring(serverName.length))) return key;
    if (key === `mcp_${serverName}` || key === `mcp_${serverName}*` || key === `mcp_${serverName}_*`) return key;
  }
  return undefined;
}

// ─── Tool description injection patterns ──────────────────

const TOOL_DESCRIPTION_PATTERNS: ReadonlyArray<{ readonly pattern: RegExp; readonly label: string }> = [
  { pattern: /<\s*important\s*>/i, label: "hidden <IMPORTANT> instruction block" },
  {
    pattern: /\bdo\s*n[o']t\s+(?:tell|inform|notify|alert|show|mention(?:\s+(?:this|it))?\s+to|reveal\s+(?:this\s+)?to)\s+the\s+user\b/i,
    label: "instruction to hide behavior from the user",
  },
  { pattern: /\bbefore\s+(?:using|calling|invoking|running)\s+this\s+tool\b/i, label: "precondition that redirects the agent before the tool runs" },
  { pattern: /~\/\.ssh\b|\bid_rsa\b|\bid_ed25519\b|~\/\.aws\b|~\/\.gnupg\b|\/etc\/passwd\b/i, label: "reference to SSH or cloud credential paths" },
  { pattern: /\binclude\s+the\s+(?:full\s+|entire\s+|complete\s+)?contents?\s+of\b/i, label: "instruction to include file contents in a tool call" },
  {
    pattern: /\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|other)\s+(?:instructions?|rules?|guidelines?|prompts?)\b/i,
    label: "prompt override attempt",
  },
];

const HIDDEN_UNICODE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/;
const BASE64_RUN = /(?:[A-Za-z0-9+/]{4}){10,}(?:={0,2})/;

function hasBase64Run(text: string): boolean {
  for (const match of [...text.matchAll(new RegExp(BASE64_RUN.source, "g"))]) {
    const run = match[0];
    if (/[A-Z]/.test(run) && /[a-z]/.test(run) && /[0-9+/]/.test(run)) return true;
  }
  return false;
}

function visibleEvidence(text: string): string {
  return text
    .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`)
    .replace(/\s+/g, " ")
    .substring(0, 160);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function nameMentionPattern(name: string): RegExp {
  return new RegExp(`(?<![A-Za-z0-9_])${escapeRegExp(name)}(?![A-Za-z0-9_])`);
}

const CROSS_TOOL_PHRASES: ReadonlyArray<RegExp> = [
  /\bwhen\s+(?:calling|using|invoking|running)\s+(?:the\s+)?[`"']?([A-Za-z0-9_.-]{3,})/gi,
  /\binstead\s+of\s+(?:the\s+|using\s+|calling\s+)?[`"']?([A-Za-z0-9_.-]{3,})/gi,
  /\b(?:also|always)\s+(?:call|invoke|run|use)\s+(?:the\s+)?[`"']?([A-Za-z0-9_.-]{3,})/gi,
];

// ─── Rules ────────────────────────────────────────────────

const headerLiteralTokenRule = serverRule(
  {
    id: "mcp-header-literal-token",
    name: "MCP Header Contains Literal Credential",
    description:
      "Authorization, X-Api-Key, Cookie, or any key/token header on an MCP server whose value is a literal credential or a ${VAR:-literal} default carrying one",
    severity: "critical",
    category: "secrets",
  },
  (server) => {
    const headers = stringMap(server.config.headers);
    const findings: FindingInput[] = [];
    for (const [name, value] of Object.entries(headers)) {
      const literal = headerCredential(name, value);
      if (!literal) continue;
      findings.push({
        id: `mcp-header-literal-token-${slug(server.name)}-${slug(name)}`,
        severity: "critical",
        category: "secrets",
        title: `MCP server "${server.name}" has a literal credential in header ${name}`,
        description: `The "${name}" header for MCP server "${server.name}" contains a literal credential instead of a \${VAR} reference. Anyone with read access to this file, including every clone of the repository, can replay it against the remote server.`,
        evidence: `headers.${name}: ${redact(literal)}`,
        needles: [literal, `"${name}"`],
        fix: {
          description: "Reference an environment variable instead of the literal value",
          before: `"${name}": "${redact(literal)}"`,
          after: `"${name}": "Bearer \${${slug(server.name).toUpperCase()}_TOKEN}"`,
          auto: false,
        },
      });
    }
    return findings;
  },
);

const tokenInUrlRule = serverRule(
  {
    id: "mcp-token-in-url",
    name: "MCP URL Carries Credential",
    description: "MCP server url containing ?token=, api_key=, access_token=, apikey=, key= with a value, or user:pass@ userinfo",
    severity: "critical",
    category: "secrets",
  },
  (server) => {
    if (!server.url) return [];
    return remoteUrlFindings(server, server.url, undefined).filter((f) => f.id.startsWith("mcp-token-in-url"));
  },
);

const remotePlaintextRule = serverRule(
  {
    id: "mcp-remote-plaintext",
    name: "MCP Remote Transport Without TLS",
    description: "Remote MCP transport (http, sse, ws, streamable-http) over http:// or ws:// to a non-loopback host; info-level note for deprecated SSE over https",
    severity: "high",
    category: "mcp",
  },
  (server) => {
    if (!server.url) return [];
    const findings = [...remoteUrlFindings(server, server.url, undefined).filter((f) => f.id.startsWith("mcp-remote-plaintext"))];
    const parsed = parseUrl(server.url);
    if (server.type && /^sse$/i.test(server.type) && parsed && parsed.scheme === "https") {
      findings.push({
        id: `mcp-sse-deprecated-${slug(server.name)}`,
        severity: "info",
        category: "mcp",
        title: `MCP server "${server.name}" uses the deprecated SSE transport`,
        description: `The MCP server "${server.name}" is declared with type "sse". The HTTP+SSE transport was deprecated in favor of Streamable HTTP; SSE servers do not receive the newer authorization and session hardening. Migrate when the server supports it.`,
        evidence: `type: ${server.type}, ${server.urlKey ?? "url"}: ${redactUrl(server.url)}`,
        needles: [server.url],
      });
    }
    return findings;
  },
);

const urlPrivateRangeRule = serverRule(
  {
    id: "mcp-url-private-range",
    name: "MCP URL Targets Private or Metadata Address",
    description: "MCP server url host in 10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7, or a .internal name; metadata endpoints are high",
    severity: "medium",
    category: "mcp",
  },
  (server) => {
    if (!server.url) return [];
    return remoteUrlFindings(server, server.url, undefined).filter((f) => f.id.startsWith("mcp-url-private-range"));
  },
);

const oauthSecretInlineRule = serverRule(
  {
    id: "mcp-oauth-secret-inline",
    name: "MCP OAuth Client Secret Inline",
    description: "oauth.clientSecret, oauth.client_secret, or auth.CLIENT_SECRET set to a literal instead of a ${VAR} reference",
    severity: "high",
    category: "secrets",
  },
  (server) => {
    const findings: FindingInput[] = [];
    for (const { key, block } of oauthBlocks(server)) {
      for (const secretKey of OAUTH_SECRET_KEYS) {
        const value = block[secretKey];
        if (typeof value !== "string") continue;
        const trimmed = value.trim();
        if (!trimmed || isReference(trimmed) || CONTAINS_INTERPOLATION.test(trimmed) || isPlaceholder(trimmed)) continue;
        findings.push({
          id: `mcp-oauth-secret-inline-${slug(server.name)}-${key}`,
          severity: "high",
          category: "secrets",
          title: `MCP server "${server.name}" has an inline OAuth client secret (${key}.${secretKey})`,
          description: `The OAuth client secret for MCP server "${server.name}" is written literally in config. A leaked client secret lets anyone impersonate this client at the authorization server. Reference an environment variable and register a fresh secret.`,
          evidence: `${key}.${secretKey}: ${redact(trimmed)}`,
          needles: [trimmed, `"${secretKey}"`],
          fix: {
            description: "Reference an environment variable",
            before: `"${secretKey}": "${redact(trimmed)}"`,
            after: `"${secretKey}": "\${OAUTH_CLIENT_SECRET}"`,
            auto: false,
          },
        });
      }
    }
    return findings;
  },
);

const oauthScopeWildcardRule = serverRule(
  {
    id: "mcp-oauth-scope-wildcard",
    name: "MCP OAuth Scope Too Broad",
    description: "oauth.scopes containing *, all, full-access, admin:*, delete_repo, or write:* style wildcards",
    severity: "medium",
    category: "mcp",
  },
  (server) => {
    const findings: FindingInput[] = [];
    for (const { key, block } of oauthBlocks(server)) {
      const scopes = [...scopeList(block.scopes), ...scopeList(block.scope)];
      const broad = scopes.filter((scope) => WILDCARD_SCOPE.test(scope));
      if (broad.length === 0) continue;
      findings.push({
        id: `mcp-oauth-scope-wildcard-${slug(server.name)}-${key}`,
        severity: "medium",
        category: "mcp",
        title: `MCP server "${server.name}" requests broad OAuth scopes: ${broad.join(", ")}`,
        description: `The OAuth scopes for MCP server "${server.name}" include ${broad.map((scope) => `"${scope}"`).join(", ")}. The MCP authorization guidance requires scope minimization; a wildcard or admin scope means a compromised server or token can act on every resource the user owns.`,
        evidence: `${key}.scopes: ${scopes.join(" ").substring(0, 120)}`,
        needles: [...broad, '"scopes"'],
      });
    }
    return findings;
  },
);

const oauthEndpointInsecureRule = serverRule(
  {
    id: "mcp-oauth-endpoint-insecure",
    name: "MCP OAuth Endpoint Not HTTPS",
    description: "authServerMetadataUrl, authorizationUrl, or tokenUrl over http://, or a redirectUri that is neither loopback nor https",
    severity: "high",
    category: "mcp",
  },
  (server) => {
    const findings: FindingInput[] = [];
    for (const { key, block } of oauthBlocks(server)) {
      for (const endpointKey of OAUTH_ENDPOINT_KEYS) {
        const value = block[endpointKey];
        if (typeof value !== "string") continue;
        const parsed = parseUrl(value);
        if (!parsed || parsed.scheme === "https") continue;
        if (parsed.scheme === "http" && isLoopbackHost(parsed.host)) continue;
        const dangerousScheme = !/^https?$/.test(parsed.scheme);
        findings.push({
          id: `mcp-oauth-endpoint-insecure-${slug(server.name)}-${endpointKey}`,
          severity: "high",
          category: "mcp",
          title: `MCP server "${server.name}" OAuth ${endpointKey} uses ${parsed.scheme}:`,
          description: dangerousScheme
            ? `The OAuth ${endpointKey} for MCP server "${server.name}" uses the "${parsed.scheme}:" scheme. Authorization URLs must be validated and opened only as https; a javascript:, data:, or file: URL handed to the system opener is a code execution path.`
            : `The OAuth ${endpointKey} for MCP server "${server.name}" is served over plaintext http. The authorization spec requires every authorization server endpoint to be HTTPS; a network attacker can substitute metadata or capture the authorization code and tokens.`,
          evidence: `${key}.${endpointKey}: ${redactUrl(value)}`,
          needles: [value],
        });
      }
      for (const redirectKey of OAUTH_REDIRECT_KEYS) {
        const value = block[redirectKey];
        if (typeof value !== "string") continue;
        const parsed = parseUrl(value);
        if (!parsed) continue;
        if (parsed.scheme === "https") continue;
        if (parsed.scheme === "http" && isLoopbackHost(parsed.host)) continue;
        findings.push({
          id: `mcp-oauth-endpoint-insecure-${slug(server.name)}-${redirectKey}`,
          severity: "high",
          category: "mcp",
          title: `MCP server "${server.name}" OAuth ${redirectKey} is neither loopback nor https`,
          description: `The OAuth redirect for MCP server "${server.name}" points at "${redactUrl(value)}". Redirect URIs must be localhost or HTTPS; anything else lets a network attacker intercept the authorization code.`,
          evidence: `${key}.${redirectKey}: ${redactUrl(value)}`,
          needles: [value],
        });
      }
    }
    return findings;
  },
);

const headersHelperRule = serverRule(
  {
    id: "mcp-headers-helper",
    name: "MCP headersHelper Executable",
    description: "headersHelper points the harness at an executable that produces request headers; in project scope a cloned repo controls what runs",
    severity: "high",
    category: "mcp",
  },
  (server, file) => {
    const helper = server.config.headersHelper;
    if (typeof helper !== "string" || helper.trim() === "") return [];
    const userScope = isUserScopeFile(file);
    return [
      {
        id: `mcp-headers-helper-${slug(server.name)}`,
        severity: userScope ? "medium" : "high",
        category: "mcp",
        title: `MCP server "${server.name}" runs a headersHelper executable`,
        description: `The MCP server "${server.name}" sets headersHelper to "${helper.substring(0, 80)}". The harness executes this program to obtain request headers, so it runs with the user's privileges and sees the resulting credentials. ${userScope ? "This is user-scope config; confirm the script is one you wrote." : "In a project-scope file, anyone who can commit to the repository chooses what gets executed."}`,
        evidence: `headersHelper: ${helper.substring(0, 100)}`,
        needles: [helper, '"headersHelper"'],
      },
    ];
  },
);

const stdioRemoteBridgeRule = serverRule(
  {
    id: "mcp-stdio-remote-bridge",
    name: "MCP stdio Bridge to Remote Server",
    description: "mcp-remote, supergateway, or mcp-proxy wrapping a remote URL; the URL gets the remote checks and --allow-http or literal --header credentials are flagged",
    severity: "medium",
    category: "mcp",
  },
  (server) => {
    const bridge = detectBridge(server);
    if (!bridge) return [];
    const findings: FindingInput[] = [];
    const url = bridgeUrl(server.args);
    const commandLine = `${server.command ?? ""} ${server.args.join(" ")}`.trim();

    findings.push({
      id: `mcp-stdio-remote-bridge-${slug(server.name)}`,
      severity: "medium",
      category: "mcp",
      title: `MCP server "${server.name}" bridges stdio to a remote server through ${bridge}`,
      description: `The MCP server "${server.name}" runs ${bridge}, which proxies a local stdio transport to ${url ? `"${redactUrl(url)}"` : "a remote URL"}. The harness treats it as a local server, so remote-transport prompts and trust boundaries do not apply even though every tool call leaves the machine.`,
      evidence: commandLine.substring(0, 160),
      needles: [url ?? bridge, `"${server.name}"`],
    });

    if (url) {
      findings.push(...remoteUrlFindings(server, url, bridge));
    }

    if (server.args.includes("--allow-http")) {
      findings.push({
        id: `mcp-stdio-remote-bridge-allow-http-${slug(server.name)}`,
        severity: "high",
        category: "mcp",
        title: `MCP server "${server.name}" passes --allow-http to ${bridge}`,
        description: `The ${bridge} bridge for MCP server "${server.name}" is started with --allow-http, which disables the bridge's refusal to send OAuth tokens over plaintext. Remove the flag and use an https endpoint.`,
        evidence: "--allow-http",
        needles: ["--allow-http"],
      });
    }

    for (const header of bridgeHeaderValues(server.args)) {
      const colon = header.indexOf(":");
      if (colon === -1) continue;
      const name = header.substring(0, colon).trim();
      const value = header.substring(colon + 1).trim();
      const literal = headerCredential(name, value);
      if (!literal) continue;
      findings.push({
        id: `mcp-stdio-remote-bridge-header-${slug(server.name)}-${slug(name)}`,
        severity: "high",
        category: "secrets",
        title: `MCP server "${server.name}" passes a literal ${name} header to ${bridge}`,
        description: `The ${bridge} bridge for MCP server "${server.name}" receives "${name}" on the command line with a literal credential. Command-line arguments are visible to every process on the machine and end up in shell history and crash reports. Use an environment variable reference.`,
        evidence: `--header ${name}: ${redact(literal)}`,
        needles: [literal, header],
      });
    }

    return findings;
  },
);

const stdioShellCommandRule = serverRule(
  {
    id: "mcp-stdio-shell-command",
    name: "MCP stdio Server Spawns a Shell or Inline Code",
    description:
      "command is a shell (sh, bash, zsh, cmd, cmd.exe, powershell, pwsh), an interpreter with -e/-c/eval inline code, or args carry a pipe to a shell, curl/wget, or base64 -d",
    severity: "critical",
    category: "mcp",
  },
  (server) => {
    if (!server.command) return [];
    const name = basename(server.command);
    const findings: FindingInput[] = [];
    const commandLine = `${server.command} ${server.args.join(" ")}`.trim();

    const coveredByShellWrapper = EXISTING_SHELL_WRAPPER.test(server.command) && server.args.includes("-c");
    if (SHELL_BASENAMES.has(name) && !coveredByShellWrapper) {
      findings.push({
        id: `mcp-stdio-shell-command-${slug(server.name)}`,
        severity: "critical",
        category: "mcp",
        title: `MCP server "${server.name}" is launched through ${name}`,
        description: `The MCP server "${server.name}" uses "${server.command}" as its command, so whatever follows is interpreted by a shell rather than executed as a fixed binary with fixed arguments. Any value that reaches the args array becomes shell syntax. Point command at the server binary directly.`,
        evidence: commandLine.substring(0, 160),
        needles: [server.command, `"${server.name}"`],
        fix: {
          description: "Run the server binary directly instead of through a shell",
          before: `"command": "${server.command}"`,
          after: '"command": "node", "args": ["./server.js"]',
          auto: false,
        },
      });
    }

    const interpreter = INTERPRETER_EVAL_FLAGS.find((entry) => entry.names.includes(name));
    if (interpreter) {
      const flagIndex = server.args.findIndex((arg) => interpreter.flag.test(arg));
      const inline = flagIndex !== -1 ? server.args[flagIndex + 1] : undefined;
      if (inline !== undefined) {
        findings.push({
          id: `mcp-stdio-shell-command-inline-${slug(server.name)}`,
          severity: "critical",
          category: "mcp",
          title: `MCP server "${server.name}" runs inline ${name} code (${server.args[flagIndex]})`,
          description: `The MCP server "${server.name}" passes source code on the command line to ${name}. Inline code in an MCP config cannot be reviewed like a package, is invisible to lockfiles and audits, and runs with the user's privileges on every session start.`,
          evidence: `${name} ${server.args[flagIndex]} ${inline.substring(0, 120)}`,
          needles: [inline, server.args[flagIndex]],
        });
      }
    }

    if (!EXISTING_CURL_PIPE.test(commandLine)) {
      const suspicious = server.args.find(
        (arg) => PIPE_TO_SHELL.test(arg) || DOWNLOADER.test(` ${arg}`) || BASE64_DECODE.test(arg),
      );
      if (suspicious) {
        const reason = PIPE_TO_SHELL.test(suspicious)
          ? "pipes output into a shell interpreter"
          : BASE64_DECODE.test(suspicious)
            ? "decodes base64 at launch, a common way to hide a payload from review"
            : "downloads content with curl or wget at launch";
        findings.push({
          id: `mcp-stdio-shell-command-args-${slug(server.name)}`,
          severity: "critical",
          category: "mcp",
          title: `MCP server "${server.name}" argument ${reason}`,
          description: `An argument for MCP server "${server.name}" ${reason}. Server arguments should be plain options for a fixed binary; shell pipelines, downloaders, and decoders in args indicate the config is being used as a code execution vector.`,
          evidence: suspicious.substring(0, 160),
          needles: [suspicious],
        });
      }
    }

    return findings;
  },
);

const ENV_PROXY_KEYS: ReadonlyArray<{ readonly pattern: RegExp; readonly reason: string; readonly requireValue?: RegExp }> = [
  { pattern: /^(?:https?_proxy|all_proxy)$/i, reason: "routes the server's traffic through a proxy, which can read or rewrite every request including bearer tokens" },
  { pattern: /^NODE_EXTRA_CA_CERTS$/, reason: "adds a trusted CA, letting a matching proxy terminate TLS for this server without warnings" },
  { pattern: /^(?:SSL_CERT_FILE|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE)$/, reason: "replaces the CA bundle, letting an attacker-issued certificate pass verification" },
  { pattern: /^NODE_TLS_REJECT_UNAUTHORIZED$/, reason: "disables TLS certificate verification for every connection the server makes", requireValue: /^\s*0\s*$/ },
  { pattern: /^DYLD_INSERT_LIBRARIES$/, reason: "injects a dynamic library into the server process on macOS" },
];

const stdioEnvProxyRule = serverRule(
  {
    id: "mcp-stdio-env-proxy",
    name: "MCP stdio Env Enables Interception",
    description: "env sets HTTPS_PROXY/HTTP_PROXY, NODE_EXTRA_CA_CERTS, NODE_TLS_REJECT_UNAUTHORIZED=0, or DYLD_INSERT_LIBRARIES (LD_PRELOAD and PYTHONPATH are covered by mcp-env-override)",
    severity: "high",
    category: "mcp",
  },
  (server) => {
    const findings: FindingInput[] = [];
    for (const [key, value] of Object.entries(server.env)) {
      const entry = ENV_PROXY_KEYS.find((candidate) => candidate.pattern.test(key));
      if (!entry) continue;
      if (entry.requireValue && !entry.requireValue.test(value)) continue;
      if (!entry.requireValue && isReference(value)) continue;
      findings.push({
        id: `mcp-stdio-env-proxy-${slug(server.name)}-${slug(key)}`,
        severity: "high",
        category: "mcp",
        title: `MCP server "${server.name}" sets ${key} in its environment`,
        description: `The MCP server "${server.name}" sets ${key}, which ${entry.reason}. Set from a committed config, this is a ready-made interception path for the credentials the server carries.`,
        evidence: `${key}=${value.substring(0, 80)}`,
        needles: [`"${key}"`],
        fix: {
          description: `Remove ${key} from the server env`,
          before: `"${key}": "${value.substring(0, 40)}"`,
          after: `# remove ${key}`,
          auto: false,
        },
      });
    }
    return findings;
  },
);

const SECRET_ENV_KEY = /KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL/i;
const THIRD_PARTY_LAUNCHERS: ReadonlySet<string> = new Set(["npx", "npx.cmd", "uvx", "pipx", "bunx", "pnpx", "dlx", "docker", "podman", "deno"]);

function referencedEnvName(value: string): string | undefined {
  const match = value.trim().match(/^\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}$|^\$([A-Za-z_][A-Za-z0-9_]*)$|^\{env:([A-Za-z_][A-Za-z0-9_]*)\}$/);
  return match ? (match[1] ?? match[2] ?? match[3]) : undefined;
}

function isThirdPartyServer(server: McpServer): boolean {
  if (server.url || detectBridge(server)) return true;
  if (!server.command) return false;
  return THIRD_PARTY_LAUNCHERS.has(basename(server.command));
}

const envMirrorsHostSecretRule = serverRule(
  {
    id: "mcp-env-mirrors-host-secret",
    name: "MCP Env Forwards Host Secret",
    description: "env entry whose key matches KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL and whose value is ${SAME_NAME}, forwarding a host secret into a third-party server, or Codex-style env_vars [\"*\"]",
    severity: "medium",
    category: "exposure",
  },
  (server) => {
    const findings: FindingInput[] = [];
    for (const passthroughKey of ["env_vars", "envVars", "passthroughEnv", "inheritEnv"]) {
      const list = stringArray(server.config[passthroughKey]);
      if (list.includes("*")) {
        findings.push({
          id: `mcp-env-mirrors-host-secret-${slug(server.name)}-${passthroughKey}`,
          severity: "medium",
          category: "exposure",
          title: `MCP server "${server.name}" passes the entire host environment through`,
          description: `The MCP server "${server.name}" declares ${passthroughKey}: ["*"], forwarding every host environment variable, including unrelated API keys and cloud credentials, into the server process.`,
          evidence: `${passthroughKey}: ["*"]`,
          needles: [`"${passthroughKey}"`],
        });
      }
    }
    if (!isThirdPartyServer(server)) return findings;
    for (const [key, value] of Object.entries(server.env)) {
      if (!SECRET_ENV_KEY.test(key)) continue;
      const referenced = referencedEnvName(value);
      if (!referenced || referenced !== key) continue;
      findings.push({
        id: `mcp-env-mirrors-host-secret-${slug(server.name)}-${slug(key)}`,
        severity: "medium",
        category: "exposure",
        title: `MCP server "${server.name}" forwards host secret ${key}`,
        description: `The MCP server "${server.name}" sets ${key} to \${${key}}, handing the host's own ${key} to a third-party server process. If that package or endpoint is compromised, the secret goes with it. Issue a scoped credential for this server instead of mirroring the host one.`,
        evidence: `${key}: ${value}`,
        needles: [`"${key}"`],
      });
    }
    return findings;
  },
);

const autoApproveWildcardRule = serverRule(
  {
    id: "mcp-auto-approve-wildcard",
    name: "MCP Server Tools Auto-Approved Wholesale",
    description:
      "Cline/Roo autoApprove or alwaysAllow containing * or every declared tool, Gemini trust: true, Copilot tools: [\"*\"], OpenCode permission allow for the server, or Cursor/Windsurf empty disabledTools alongside an auto-approve key",
    severity: "high",
    category: "permissions",
  },
  (server, _file, config) => {
    const findings: FindingInput[] = [];
    const declared = declaredToolNames(server);
    let wildcardFound = false;

    for (const key of AUTO_APPROVE_LIST_KEYS) {
      const list = stringArray(server.config[key]);
      if (list.length === 0) continue;
      const wildcard = list.includes("*");
      const everyTool = declared.length > 0 && declared.every((tool) => list.includes(tool));
      if (!wildcard && !everyTool) continue;
      wildcardFound = true;
      findings.push({
        id: `mcp-auto-approve-wildcard-${slug(server.name)}-${key}`,
        severity: "high",
        category: "permissions",
        title: `MCP server "${server.name}" auto-approves ${wildcard ? "every tool" : "all declared tools"} via ${key}`,
        description: `The MCP server "${server.name}" lists ${wildcard ? '"*"' : "every declared tool"} in ${key}. No tool call from this server will be shown for confirmation, so a poisoned description or a rug-pulled tool executes without a human in the loop.`,
        evidence: `${key}: ${JSON.stringify(list).substring(0, 100)}`,
        needles: [`"${key}"`],
        fix: {
          description: "Approve only the specific read-only tools you need",
          before: `"${key}": ${JSON.stringify(list).substring(0, 40)}`,
          after: `"${key}": ["read_only_tool"]`,
          auto: false,
        },
      });
    }

    if (server.config.trust === true) {
      wildcardFound = true;
      findings.push({
        id: `mcp-auto-approve-wildcard-${slug(server.name)}-trust`,
        severity: "high",
        category: "permissions",
        title: `MCP server "${server.name}" is fully trusted (trust: true)`,
        description: `The MCP server "${server.name}" sets trust: true, which in Gemini CLI bypasses every tool confirmation for that server. Combined with a remote or npm-installed server, this hands the server unattended execution.`,
        evidence: "trust: true",
        needles: ['"trust"'],
        fix: { description: "Drop trust and confirm tool calls", before: '"trust": true', after: '"trust": false', auto: true },
      });
    }

    const tools = stringArray(server.config.tools);
    if (tools.includes("*")) {
      wildcardFound = true;
      findings.push({
        id: `mcp-auto-approve-wildcard-${slug(server.name)}-tools`,
        severity: "high",
        category: "permissions",
        title: `MCP server "${server.name}" enables every tool with tools: ["*"]`,
        description: `The MCP server "${server.name}" declares tools: ["*"], which in the Copilot coding agent enables every tool the server exposes, including any added later. Enumerate the tools you actually need.`,
        evidence: 'tools: ["*"]',
        needles: ['"tools"'],
      });
    }

    const permissionKey = openCodePermissionAllow(config, server.name);
    if (permissionKey) {
      findings.push({
        id: `mcp-auto-approve-wildcard-${slug(server.name)}-permission`,
        severity: "high",
        category: "permissions",
        title: `MCP server "${server.name}" tools are allowed without prompting (permission.${permissionKey})`,
        description: `The OpenCode permission map sets "${permissionKey}": "allow", so tool calls from MCP server "${server.name}" run without confirmation.`,
        evidence: `permission.${permissionKey}: allow`,
        needles: [`"${permissionKey}"`],
      });
    }

    const disabledTools = server.config.disabledTools;
    if (!wildcardFound && Array.isArray(disabledTools) && disabledTools.length === 0) {
      const autoKey = AUTO_APPROVE_LIKE_KEYS.find((key) => isTruthySetting(server.config[key]));
      if (autoKey) {
        findings.push({
          id: `mcp-auto-approve-wildcard-${slug(server.name)}-disabledTools`,
          severity: "high",
          category: "permissions",
          title: `MCP server "${server.name}" has no disabled tools and ${autoKey} set`,
          description: `The MCP server "${server.name}" combines an empty disabledTools list with ${autoKey}, so every tool the server exposes is both enabled and pre-approved.`,
          evidence: `disabledTools: [], ${autoKey}: ${JSON.stringify(server.config[autoKey]).substring(0, 60)}`,
          needles: ['"disabledTools"'],
        });
      }
    }

    return findings;
  },
);

const toolDescriptionInjectionRule: Rule = {
  id: "mcp-tool-description-injection",
  name: "MCP Tool Description Injection",
  description:
    "Tool descriptions in config or cached tool lists containing <IMPORTANT>, do-not-tell-the-user, before-using-this-tool, credential paths, include-the-contents-of, ignore-previous, another server's tool name, hidden unicode, or a base64 run",
  severity: "critical",
  category: "injection",
  check(file: ConfigFile): ReadonlyArray<Finding> {
    const config = parseScannedFile(file);
    if (!config) return [];
    const entries = collectToolEntries(config);
    if (entries.length === 0) return [];
    const findings: Finding[] = [];

    for (const entry of entries) {
      if (!entry.description) continue;
      const reasons: string[] = [];
      for (const { pattern, label } of TOOL_DESCRIPTION_PATTERNS) {
        if (pattern.test(entry.description)) reasons.push(label);
      }
      if (HIDDEN_UNICODE.test(entry.description)) reasons.push("zero-width or bidi control characters");
      if (hasBase64Run(entry.description)) reasons.push("base64 run of 40+ characters");
      const foreign = entries.find(
        (other) =>
          other.server !== entry.server &&
          other.name.length >= 4 &&
          !other.name.startsWith("#") &&
          nameMentionPattern(other.name).test(entry.description),
      );
      if (foreign) reasons.push(`references tool "${foreign.name}" from server "${foreign.server}"`);
      if (reasons.length === 0) continue;

      findings.push(
        makeFinding(file, {
          id: `mcp-tool-description-injection-${slug(entry.server)}-${slug(entry.name)}`,
          severity: "critical",
          category: "injection",
          title: `Tool "${entry.name}" on MCP server "${entry.server}" has a poisoned description`,
          description: `The description of tool "${entry.name}" (server "${entry.server}") contains: ${reasons.join("; ")}. Tool descriptions are injected into the model context as trusted text, so instructions hidden here steer the agent without the user seeing them (Invariant Labs, tool poisoning, April 2025).`,
          evidence: `${entry.keyPath}: ${visibleEvidence(entry.description)}`,
          needles: [entry.description.substring(0, 40), entry.name],
        }),
      );
    }
    return findings;
  },
};

const toolShadowingRule: Rule = {
  id: "mcp-tool-shadowing",
  name: "MCP Tool Shadowing",
  description:
    "Two servers in the same file declare the same tool name, or a description steers calls with \"when calling <other tool>\" or \"instead of <other server>\"",
  severity: "high",
  category: "mcp",
  check(file: ConfigFile): ReadonlyArray<Finding> {
    const config = parseScannedFile(file);
    if (!config) return [];
    const servers = collectMcpServers(config);
    const entries = collectToolEntries(config);
    const findings: Finding[] = [];

    const owners = new Map<string, Set<string>>();
    for (const server of servers) {
      for (const tool of declaredToolNames(server)) {
        const set = owners.get(tool) ?? new Set<string>();
        set.add(server.name);
        owners.set(tool, set);
      }
    }
    for (const [tool, set] of owners) {
      if (set.size < 2) continue;
      const names = [...set];
      findings.push(
        makeFinding(file, {
          id: `mcp-tool-shadowing-${slug(tool)}`,
          severity: "high",
          category: "mcp",
          title: `Tool "${tool}" is declared by ${set.size} MCP servers: ${names.join(", ")}`,
          description: `Servers ${names.map((n) => `"${n}"`).join(" and ")} both expose a tool named "${tool}". Whichever the harness resolves last wins, so a later-added or lower-trust server can silently take over calls meant for the other.`,
          evidence: `tool "${tool}" in ${names.join(", ")}`,
          needles: [`"${tool}"`],
        }),
      );
    }

    const knownTargets = new Map<string, string>();
    for (const server of servers) knownTargets.set(server.name.toLowerCase(), server.name);
    for (const entry of entries) knownTargets.set(entry.name.toLowerCase(), entry.server);

    for (const entry of entries) {
      if (!entry.description) continue;
      for (const phrase of CROSS_TOOL_PHRASES) {
        for (const match of [...entry.description.matchAll(phrase)]) {
          const target = match[1].replace(/[.,;:]+$/, "");
          const owner = knownTargets.get(target.toLowerCase());
          if (owner === undefined || owner === entry.server) continue;
          findings.push(
            makeFinding(file, {
              id: `mcp-tool-shadowing-${slug(entry.server)}-${slug(entry.name)}-${slug(target)}`,
              severity: "high",
              category: "mcp",
              title: `Tool "${entry.name}" on "${entry.server}" steers calls to "${target}" on "${owner}"`,
              description: `The description of tool "${entry.name}" (server "${entry.server}") says "${match[0].substring(0, 60)}", attaching behavior to another server's tool. This is the cross-server shadowing pattern: one server's text changes how the agent uses a different, trusted server.`,
              evidence: `${entry.keyPath}: ${visibleEvidence(entry.description)}`,
              needles: [match[0], entry.name],
            }),
          );
          break;
        }
      }
    }

    return findings;
  },
};

const unpinnedDockerImageRule = serverRule(
  {
    id: "mcp-unpinned-docker-image",
    name: "MCP Docker Image Not Pinned by Digest",
    description: "command docker (or podman) run with an image reference lacking an @sha256: digest",
    severity: "medium",
    category: "mcp",
  },
  (server) => {
    if (!server.command) return [];
    const name = basename(server.command);
    if (name !== "docker" && name !== "docker.exe" && name !== "podman" && name !== "nerdctl") return [];
    const image = dockerImage(server.args);
    if (!image || image.includes("@sha256:")) return [];
    return [
      {
        id: `mcp-unpinned-docker-image-${slug(server.name)}`,
        severity: "medium",
        category: "mcp",
        title: `MCP server "${server.name}" runs Docker image "${image}" without a digest`,
        description: `The MCP server "${server.name}" runs "${image}" by tag. Tags are mutable, so the registry owner or anyone who compromises the repository can replace the image that this config launches. Pin with @sha256:<digest>.`,
        evidence: `${name} run ... ${image}`,
        needles: [image],
        fix: {
          description: "Pin the image to a content digest",
          before: `"${image}"`,
          after: `"${image.replace(/:[^/:@]+$/, "")}@sha256:<digest>"`,
          auto: false,
        },
      },
    ];
  },
);

export const mcpRemoteRules: ReadonlyArray<Rule> = [
  headerLiteralTokenRule,
  tokenInUrlRule,
  remotePlaintextRule,
  urlPrivateRangeRule,
  oauthSecretInlineRule,
  oauthScopeWildcardRule,
  oauthEndpointInsecureRule,
  headersHelperRule,
  stdioRemoteBridgeRule,
  stdioShellCommandRule,
  stdioEnvProxyRule,
  envMirrorsHostSecretRule,
  autoApproveWildcardRule,
  toolDescriptionInjectionRule,
  toolShadowingRule,
  unpinnedDockerImageRule,
];
