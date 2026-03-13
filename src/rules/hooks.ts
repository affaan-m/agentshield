import type { ConfigFile, Finding, Rule } from "../types.js";

// ─── Safe-context detection ────────────────────────────────
// Deny-list entries and PreToolUse block hooks (exit 2) are security
// controls, not threats.  We compute byte-ranges for those contexts
// so individual rules can skip matches that fall inside them.

interface SafeRange {
  readonly start: number;
  readonly end: number;
}

/**
 * Find the start and end byte offsets of every JSON string literal
 * that is a child of a given JSON path.  Works on the raw text so
 * it handles any formatting/indentation.
 */
function findStringRangesAtPath(
  content: string,
  path: ReadonlyArray<string>,
): ReadonlyArray<SafeRange> {
  const ranges: Array<SafeRange> = [];

  // Walk through JSON tokens manually to find strings under the target path.
  // This is simpler and more reliable than trying to match JSON.stringify output.
  try {
    const config = JSON.parse(content);
    // Navigate to the target path
    let target: unknown = config;
    for (const key of path) {
      if (target && typeof target === "object" && !Array.isArray(target)) {
        target = (target as Record<string, unknown>)[key];
      } else {
        return ranges;
      }
    }
    if (!Array.isArray(target)) return ranges;

    // Find the JSON array region for the target path in the raw text,
    // then only match string literals within that region (not globally).
    let searchFrom = 0;
    for (const key of path) {
      const keyStr = JSON.stringify(key);
      const keyIdx = content.indexOf(keyStr, searchFrom);
      if (keyIdx === -1) return ranges;
      searchFrom = keyIdx + keyStr.length;
    }
    // Find the array brackets after the last key
    const colonIdx = content.indexOf(":", searchFrom);
    if (colonIdx === -1) return ranges;
    const bracketIdx = content.indexOf("[", colonIdx);
    if (bracketIdx === -1) return ranges;
    // Find matching closing bracket
    // String-aware bracket matching to handle brackets inside JSON string values
    let depth = 0;
    let arrayEnd = bracketIdx;
    let inString = false;
    let escaped = false;
    for (let i = bracketIdx; i < content.length; i++) {
      const ch = content[i];
      if (inString) {
        if (escaped) escaped = false;
        else if (ch === "\\") escaped = true;
        else if (ch === '"') inString = false;
        continue;
      }
      if (ch === '"') {
        inString = true;
        continue;
      }
      if (ch === "[") depth++;
      else if (ch === "]") {
        depth--;
        if (depth === 0) { arrayEnd = i + 1; break; }
      }
    }
    const regionStart = bracketIdx;
    const regionEnd = arrayEnd;

    // Now search only within the identified array region
    for (const entry of target) {
      if (typeof entry !== "string") continue;
      const needle = JSON.stringify(entry);
      let idx = regionStart;
      while ((idx = content.indexOf(needle, idx)) !== -1 && idx < regionEnd) {
        ranges.push({ start: idx, end: idx + needle.length });
        idx += needle.length;
      }
    }
  } catch {
    // Not valid JSON
  }
  return ranges;
}

/**
 * Find ranges of PreToolUse block hooks (hooks that exit 1 or exit 2).
 * These are security controls that block actions, not threats.
 * We mark a broad region around each such hook entry.
 */
function findBlockHookRanges(content: string): ReadonlyArray<SafeRange> {
  const ranges: Array<SafeRange> = [];
  try {
    const config = JSON.parse(content);
    const preToolUseHooks: ReadonlyArray<unknown> = config?.hooks?.PreToolUse ?? [];

    for (const hookEntry of preToolUseHooks) {
      const h = hookEntry as Record<string, unknown>;

      // Collect all command strings from the hook
      const commands: Array<string> = [];
      if (typeof h.command === "string") commands.push(h.command);
      if (typeof h.hook === "string") commands.push(h.hook);
      if (Array.isArray(h.hooks)) {
        for (const sub of h.hooks) {
          const s = sub as Record<string, unknown>;
          if (typeof s.command === "string") commands.push(s.command);
          if (typeof s.hook === "string") commands.push(s.hook);
        }
      }

      // Only mark as safe if the hook blocks/rejects (exit 1 or exit 2)
      const isBlock = commands.some(
        (command) => Array.from(command.matchAll(/exit\s+[12]\b/g)).length > 0,
      );
      if (!isBlock) continue;

      // Find the hook entry's exact region in the raw JSON text using
      // string-aware brace counting (handles formatted/indented JSON).
      // We locate the entry by finding a unique key value within the
      // PreToolUse array region, then walk back to the opening '{'.
      let hookStart = 0;
      let hookEnd = content.length;

      // Find "PreToolUse" array region first
      const preToolUseKey = '"PreToolUse"';
      const preToolUseIdx = content.indexOf(preToolUseKey);
      if (preToolUseIdx !== -1) {
        const preToolUseColon = content.indexOf(":", preToolUseIdx + preToolUseKey.length);
        const preToolUseBracket = preToolUseColon !== -1 ? content.indexOf("[", preToolUseColon) : -1;
        if (preToolUseBracket !== -1) {
          // Find objects within the PreToolUse array by locating each '{' ... '}' pair
          // Use a unique string from this hook entry to identify which object it is
          const firstString = collectStrings(hookEntry).find((s) => s.length > 3);
          const needle = firstString ? JSON.stringify(firstString) : null;
          if (needle) {
            const needleIdx = content.indexOf(needle, preToolUseBracket);
            if (needleIdx !== -1) {
              // Walk backwards to find the opening '{' of this object
              let braceDepth = 0;
              let objStart = needleIdx;
              for (let i = needleIdx; i >= preToolUseBracket; i--) {
                const ch = content[i];
                if (ch === '}') braceDepth++;
                else if (ch === '{') {
                  if (braceDepth === 0) { objStart = i; break; }
                  braceDepth--;
                }
              }
              // Walk forward from objStart to find the matching '}'
              let fwdDepth = 0;
              let inStr = false;
              let esc = false;
              let objEnd = content.length;
              for (let i = objStart; i < content.length; i++) {
                const ch = content[i];
                if (inStr) {
                  if (esc) esc = false;
                  else if (ch === "\\") esc = true;
                  else if (ch === '"') inStr = false;
                  continue;
                }
                if (ch === '"') { inStr = true; continue; }
                if (ch === '{') fwdDepth++;
                else if (ch === '}') {
                  fwdDepth--;
                  if (fwdDepth === 0) { objEnd = i + 1; break; }
                }
              }
              hookStart = objStart;
              hookEnd = objEnd;
            }
          }
        }
      }
      const strings = collectStrings(hookEntry);
      for (const s of strings) {
        const needle = JSON.stringify(s);
        let idx = hookStart;
        while ((idx = content.indexOf(needle, idx)) !== -1 && idx < hookEnd) {
          ranges.push({ start: idx, end: idx + needle.length });
          idx += needle.length;
        }
      }
    }
  } catch {
    // Not valid JSON
  }
  return ranges;
}

/** Recursively collect all string values from an object/array. */
function collectStrings(obj: unknown): ReadonlyArray<string> {
  const result: Array<string> = [];
  if (typeof obj === "string") {
    result.push(obj);
  } else if (Array.isArray(obj)) {
    for (const item of obj) result.push(...collectStrings(item));
  } else if (obj && typeof obj === "object") {
    for (const val of Object.values(obj as Record<string, unknown>)) {
      result.push(...collectStrings(val));
    }
  }
  return result;
}

/**
 * Build safe ranges: deny list entries, allow list entries (permissions,
 * not hooks), and PreToolUse block hooks.
 */
function buildSafeRanges(content: string): ReadonlyArray<SafeRange> {
  return [
    ...findStringRangesAtPath(content, ["permissions", "deny"]),
    ...findStringRangesAtPath(content, ["permissions", "allow"]),
    ...findBlockHookRanges(content),
  ];
}

function isInSafeRange(ranges: ReadonlyArray<SafeRange>, matchIndex: number): boolean {
  return ranges.some((r) => matchIndex >= r.start && matchIndex < r.end);
}

/**
 * Patterns in hooks that could enable injection or information disclosure.
 */
const INJECTION_PATTERNS: ReadonlyArray<{
  readonly name: string;
  readonly pattern: RegExp;
  readonly description: string;
  readonly severity: "critical" | "high" | "medium";
}> = [
  {
    name: "var-interpolation",
    pattern: /\$\{(?:file|command|content|input|args?)\}/gi,
    description:
      "Hook uses variable interpolation that could be influenced by file content or command arguments. An attacker could craft filenames or content to inject commands.",
    severity: "critical",
  },
  {
    name: "shell-interpolation",
    pattern: /\bsh\s+-c\s+["'].*\$\{/g,
    description:
      "Shell invocation with variable interpolation — classic command injection vector.",
    severity: "critical",
  },
  {
    name: "curl-interpolation",
    pattern: /\bcurl\b.*\$\{/g,
    description:
      "HTTP request with variable interpolation — could be used for data exfiltration.",
    severity: "high",
  },
  {
    name: "wget-interpolation",
    pattern: /\bwget\b.*\$\{/g,
    description: "Download with variable interpolation — could fetch malicious payloads.",
    severity: "high",
  },
];

/**
 * Hooks that send data to external services.
 */
const EXFILTRATION_PATTERNS: ReadonlyArray<{
  readonly name: string;
  readonly pattern: RegExp;
  readonly description: string;
}> = [
  {
    name: "curl-external",
    pattern: /\bcurl\s+(-X\s+POST\s+)?https?:\/\//g,
    description: "Hook sends data to external URL via curl",
  },
  {
    name: "wget-external",
    pattern: /\bwget\s+.*https?:\/\//g,
    description: "Hook fetches from external URL via wget",
  },
  {
    name: "netcat",
    pattern: /\bnc\b|\bnetcat\b/g,
    description: "Hook uses netcat — potential reverse shell or data exfiltration",
  },
  {
    name: "sendmail",
    pattern: /\bsendmail\b|\bmail\b.*-s/g,
    description: "Hook sends email — potential data exfiltration",
  },
];

function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split("\n").length;
}

// Cache safe ranges per content string to avoid re-parsing JSON for every pattern
const MAX_SAFE_RANGE_CACHE_ENTRIES = 256;
const safeRangeCache = new Map<string, ReadonlyArray<SafeRange>>();

function getSafeRanges(content: string): ReadonlyArray<SafeRange> {
  const cached = safeRangeCache.get(content);
  if (cached) return cached;

  const ranges = buildSafeRanges(content);
  safeRangeCache.set(content, ranges);

  if (safeRangeCache.size > MAX_SAFE_RANGE_CACHE_ENTRIES) {
    const oldestKey = safeRangeCache.keys().next().value;
    if (oldestKey !== undefined) safeRangeCache.delete(oldestKey);
  }

  return ranges;
}

function findAllMatches(content: string, pattern: RegExp): ReadonlyArray<RegExpMatchArray> {
  const matches = [...content.matchAll(new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g"))];
  const safeRanges = getSafeRanges(content);
  if (safeRanges.length === 0) return matches;
  return matches.filter((m) => !isInSafeRange(safeRanges, m.index ?? 0));
}

export const hookRules: ReadonlyArray<Rule> = [
  {
    id: "hooks-injection",
    name: "Hook Command Injection",
    description: "Checks hooks for command injection vulnerabilities via variable interpolation",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      for (const injPattern of INJECTION_PATTERNS) {
        const matches = findAllMatches(file.content, injPattern.pattern);

        for (const match of matches) {
          findings.push({
            id: `hooks-injection-${match.index}`,
            severity: "critical",
            category: "injection",
            title: "Potential command injection in hook",
            description: injPattern.description,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0],
            fix: {
              description:
                "Sanitize inputs before interpolation, or use a whitelist approach instead of shell interpolation",
              before: match[0],
              after: "# Use validated, sanitized input only",
              auto: false,
            },
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-exfiltration",
    name: "Hook Data Exfiltration",
    description: "Checks hooks for patterns that could exfiltrate data to external services",
    severity: "high",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      for (const exfilPattern of EXFILTRATION_PATTERNS) {
        const matches = findAllMatches(file.content, exfilPattern.pattern);

        for (const match of matches) {
          findings.push({
            id: `hooks-exfiltration-${match.index}`,
            severity: "high",
            category: "exposure",
            title: "Hook sends data to external service",
            description: `${exfilPattern.description}. If a hook is compromised or misconfigured, it could exfiltrate code, secrets, or session data.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0],
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-no-error-handling",
    name: "Hook Missing Error Handling",
    description: "Checks if hooks suppress errors silently",
    severity: "medium",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      const silentFailPatterns = [
        { pattern: /2>\/dev\/null/g, desc: "stderr silenced" },
        { pattern: /\|\|\s*true\b/g, desc: "errors suppressed with || true" },
        { pattern: /\|\|\s*:\s*(?:$|[)"'])/gm, desc: "errors suppressed with || :" },
      ];

      for (const { pattern, desc } of silentFailPatterns) {
        const matches = findAllMatches(file.content, pattern);

        for (const match of matches) {
          findings.push({
            id: `hooks-silent-fail-${match.index}`,
            severity: "medium",
            category: "hooks",
            title: `Hook silently suppresses errors: ${desc}`,
            description: `Hook uses "${match[0]}" which suppresses errors. A failing security hook that silently passes could miss real vulnerabilities.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0],
            fix: {
              description: "Remove error suppression to surface failures",
              before: match[0],
              after: "# [REMOVED: error suppression]",
              auto: true,
            },
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-missing-pretooluse",
    name: "No PreToolUse Security Hooks",
    description: "Checks if there are PreToolUse hooks for security validation",
    severity: "medium",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      try {
        const config = JSON.parse(file.content);
        const preHooks = config?.hooks?.PreToolUse ?? [];

        if (preHooks.length === 0) {
          return [
            {
              id: "hooks-no-pretooluse",
              severity: "medium",
              category: "misconfiguration",
              title: "No PreToolUse security hooks configured",
              description:
                "No PreToolUse hooks are defined. These hooks can catch dangerous operations before they run, providing an essential security layer.",
              file: file.path,
              fix: {
                description: "Add PreToolUse hooks for security-sensitive operations",
                before: '"hooks": {}',
                after:
                  '"hooks": { "PreToolUse": [{ "matcher": "Bash && command matches \'rm -rf\'", "hook": "echo \'Blocked\' >&2 && exit 1" }] }',
                auto: false,
              },
            },
          ];
        }
      } catch {
        // JSON parse errors handled elsewhere
      }

      return [];
    },
  },
  {
    id: "hooks-unthrottled-network",
    name: "Hook Unthrottled Network Requests",
    description: "Checks for PostToolUse hooks making HTTP requests on frequent tool calls without throttling",
    severity: "medium",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const postHooks = config?.hooks?.PostToolUse ?? [];

        const broadMatchers = ["Edit", "Write", "Read", "Bash", ""];
        const networkPatterns = /\b(curl|wget|fetch|http|nc|netcat)\b/i;

        for (const hook of postHooks) {
          const hookConfig = hook as { matcher?: string; hook?: string };
          const matcher = hookConfig.matcher ?? "";
          const command = hookConfig.hook ?? "";

          const isBroadMatcher =
            matcher === "" ||
            broadMatchers.some((m) => m !== "" && matcher === m);

          if (isBroadMatcher && networkPatterns.test(command)) {
            findings.push({
              id: `hooks-unthrottled-network-${findings.length}`,
              severity: "medium",
              category: "hooks",
              title: `PostToolUse hook makes network request on broad matcher "${matcher || "*"}"`,
              description: `A PostToolUse hook fires on "${matcher || "every tool call"}" and runs a network command (${command.substring(0, 60)}...). Without throttling, this fires on every matching tool call — potentially hundreds per session — causing performance degradation and potential data exposure.`,
              file: file.path,
              evidence: `matcher: "${matcher}", hook: "${command.substring(0, 80)}"`,
              fix: {
                description: "Add rate limiting or narrow the matcher",
                before: `"matcher": "${matcher}"`,
                after: `"matcher": "Bash(npm publish)" or add throttle logic`,
                auto: false,
              },
            });
          }
        }
      } catch {
        // JSON parse errors handled elsewhere
      }

      return findings;
    },
  },
  {
    id: "hooks-sensitive-file-access",
    name: "Hook Accesses Sensitive Files",
    description: "Checks for hooks that read or write to sensitive system files",
    severity: "high",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const sensitivePathPatterns = [
        {
          pattern: /\/etc\/(?:passwd|shadow|sudoers|hosts)/g,
          desc: "system authentication/configuration file",
        },
        {
          pattern: /~\/\.ssh\/|\/\.ssh\//g,
          desc: "SSH directory (may contain private keys)",
        },
        {
          pattern: /~\/\.aws\/|\/\.aws\//g,
          desc: "AWS credentials directory",
        },
        {
          pattern: /~\/\.gnupg\/|\/\.gnupg\//g,
          desc: "GPG keyring directory",
        },
        {
          pattern: /~\/\.env|\/\.env\b/g,
          desc: "environment file (likely contains secrets)",
        },
        {
          pattern: /\/etc\/ssl\/|\/etc\/pki\//g,
          desc: "SSL/TLS certificate directory",
        },
      ];

      for (const { pattern, desc } of sensitivePathPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-sensitive-file-${match.index}`,
            severity: "high",
            category: "exposure",
            title: `Hook accesses sensitive path: ${match[0]}`,
            description: `A hook references "${match[0]}" — ${desc}. Hooks should not access sensitive system files. This could expose credentials, keys, or system configuration.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0],
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-no-stop-hooks",
    name: "No Stop Hooks for Session Verification",
    description: "Checks if there are Stop hooks for end-of-session verification",
    severity: "low",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      try {
        const config = JSON.parse(file.content);
        const hooks = config?.hooks ?? {};

        // Only flag if hooks object exists but no Stop hooks
        if (Object.keys(hooks).length > 0 && !hooks.Stop?.length) {
          return [
            {
              id: "hooks-no-stop-hooks",
              severity: "low",
              category: "misconfiguration",
              title: "No Stop hooks for session-end verification",
              description:
                "Hooks are configured but no Stop hooks exist. Stop hooks run when a session ends and are useful for final verification — checking for uncommitted secrets, ensuring console.log statements were removed, or auditing file changes.",
              file: file.path,
              fix: {
                description: "Add a Stop hook for session-end checks",
                before: '"hooks": { ... }',
                after:
                  '"hooks": { ..., "Stop": [{ "hook": "check-for-secrets.sh" }] }',
                auto: false,
              },
            },
          ];
        }
      } catch {
        // JSON parse errors handled elsewhere
      }

      return [];
    },
  },
  {
    id: "hooks-session-start-download",
    name: "Hook SessionStart Downloads Remote Content",
    description: "Checks for SessionStart hooks that download or execute remote scripts",
    severity: "high",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const sessionHooks = config?.hooks?.SessionStart ?? [];

        const remoteExecutionPatterns = [
          {
            pattern: /\b(curl|wget)\b.*\|\s*(sh|bash|zsh|node|python)/i,
            desc: "Downloads and pipes to shell — classic remote code execution vector",
            severity: "critical" as const,
          },
          {
            pattern: /\b(curl|wget)\b.*https?:\/\//i,
            desc: "Downloads remote content on every session start",
            severity: "high" as const,
          },
          {
            pattern: /\bgit\s+clone\b/i,
            desc: "Clones a repository on session start — could pull malicious code",
            severity: "medium" as const,
          },
        ];

        for (const hook of sessionHooks) {
          const hookConfig = hook as { hook?: string };
          const command = hookConfig.hook ?? "";

          for (const { pattern, desc, severity } of remoteExecutionPatterns) {
            if (pattern.test(command)) {
              findings.push({
                id: `hooks-session-start-download-${findings.length}`,
                severity,
                category: "hooks",
                title: `SessionStart hook downloads remote content`,
                description: `A SessionStart hook runs "${command.substring(0, 80)}". ${desc}. SessionStart hooks run automatically at the beginning of every session without user confirmation.`,
                file: file.path,
                evidence: command.substring(0, 100),
                fix: {
                  description: "Remove remote downloads from SessionStart or use a local script",
                  before: command.substring(0, 60),
                  after: "# Use pre-installed local tools instead",
                  auto: false,
                },
              });
              break;
            }
          }
        }
      } catch {
        // JSON parse errors handled elsewhere
      }

      return findings;
    },
  },
  {
    id: "hooks-background-process",
    name: "Hook Spawns Background Process",
    description: "Checks for hooks that spawn background processes which persist beyond the hook's execution",
    severity: "high",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const bgPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bnohup\b/g,
          description: "nohup keeps a process running after the hook exits — potential persistence mechanism",
        },
        {
          pattern: /\bdisown\b/g,
          description: "disown detaches a process from the shell — hides background activity",
        },
        {
          pattern: /&\s*(?:$|[;)]|&&)/gm,
          description: "Background process via & — may run indefinitely after hook completes",
        },
        {
          pattern: /\bscreen\s+-[dS]/g,
          description: "screen session — creates persistent hidden shell sessions",
        },
        {
          pattern: /\btmux\s+(?:new|send)/g,
          description: "tmux session — creates persistent hidden shell sessions",
        },
      ];

      for (const { pattern, description } of bgPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-bg-process-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook spawns background process: ${match[0].trim()}`,
            description: `${description}. Background processes in hooks can be used for persistent backdoors or data exfiltration that outlives the session.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-env-exfiltration",
    name: "Hook Env Var Exfiltration",
    description: "Checks for hooks that access environment variables and send them to external services",
    severity: "critical",
    category: "exposure",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      // Pattern: accessing env vars AND sending data externally in the same command
      const envAccessPatterns = /\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|PASS|CRED|AUTH)\w*\}?/gi;
      const networkPatterns = /\b(curl|wget|nc|netcat|sendmail|mail\s+-s)\b/gi;

      // Check if content has BOTH env access and network patterns
      const hasEnvAccess = envAccessPatterns.test(file.content);
      const envAccessRegex = new RegExp(envAccessPatterns.source, envAccessPatterns.flags);
      envAccessPatterns.lastIndex = 0;
      const hasNetwork = networkPatterns.test(file.content);
      networkPatterns.lastIndex = 0;

      if (hasEnvAccess && hasNetwork) {
        const matches = findAllMatches(file.content, envAccessRegex);
        for (const match of matches) {
          // Check if there's a network command in the surrounding context (same line or nearby)
          const lineStart = file.content.lastIndexOf("\n", match.index ?? 0) + 1;
          const lineEnd = file.content.indexOf("\n", (match.index ?? 0) + match[0].length);
          const line = file.content.substring(lineStart, lineEnd === -1 ? undefined : lineEnd);

          const networkCheck = new RegExp(networkPatterns.source, "i");
          if (networkCheck.test(line)) {
            findings.push({
              id: `hooks-env-exfil-${match.index}`,
              severity: "critical",
              category: "exposure",
              title: `Hook combines env var access with network call`,
              description: `A hook accesses an environment variable (${match[0]}) and sends data over the network in the same command. This pattern can exfiltrate secrets from the environment to external services.`,
              file: file.path,
              line: findLineNumber(file.content, match.index ?? 0),
              evidence: line.trim().substring(0, 100),
            });
            break; // One finding per file for this pattern
          }
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-chained-commands",
    name: "Hook Chained Shell Commands",
    description: "Checks for hooks that chain multiple commands, which may execute beyond the matcher's intended scope",
    severity: "medium",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const allHooks = [
          ...(config?.hooks?.PreToolUse ?? []),
          ...(config?.hooks?.PostToolUse ?? []),
          ...(config?.hooks?.SessionStart ?? []),
          ...(config?.hooks?.Stop ?? []),
        ];

        const chainPatterns = [
          { pattern: /&&/, desc: "AND chain (&&)" },
          { pattern: /;\s*[a-zA-Z]/, desc: "semicolon chain" },
          { pattern: /\|\s*[a-zA-Z]/, desc: "pipe chain" },
        ];

        for (const hook of allHooks) {
          const hookConfig = hook as { hook?: string; matcher?: string };
          const command = hookConfig.hook ?? "";

          // Only flag if there are 3+ chained commands (2 is common/normal)
          let chainCount = 0;
          for (const { pattern } of chainPatterns) {
            const matches = [...command.matchAll(new RegExp(pattern.source, "g"))];
            chainCount += matches.length;
          }

          if (chainCount >= 3) {
            findings.push({
              id: `hooks-chained-commands-${findings.length}`,
              severity: "medium",
              category: "hooks",
              title: `Hook has ${chainCount + 1} chained commands`,
              description: `A hook chains ${chainCount + 1} commands together: "${command.substring(0, 80)}...". Complex chained commands in hooks are harder to audit and may perform operations beyond the hook's stated purpose. Consider breaking into a dedicated script file.`,
              file: file.path,
              evidence: command.substring(0, 100),
              fix: {
                description: "Move complex logic to a script file",
                before: command.substring(0, 50),
                after: '"hook": "./scripts/hook-check.sh"',
                auto: false,
              },
            });
          }
        }
      } catch {
        // JSON parse errors handled elsewhere
      }

      return findings;
    },
  },
  {
    id: "hooks-expensive-unscoped",
    name: "Hook Expensive Unscoped Command",
    description: "Checks for PostToolUse hooks running expensive build/lint commands with broad matchers",
    severity: "low",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const postHooks = config?.hooks?.PostToolUse ?? [];

        const expensiveCommands =
          /\b(tsc|eslint|prettier|webpack|jest|vitest|mocha|esbuild|rollup|turbo)\b/;
        const broadMatchers = ["Edit", "Write", ""];

        for (const hook of postHooks) {
          const hookConfig = hook as { matcher?: string; hook?: string };
          const matcher = hookConfig.matcher ?? "";
          const command = hookConfig.hook ?? "";

          const isBroadMatcher =
            matcher === "" ||
            broadMatchers.some((m) => m !== "" && matcher === m);

          const expensiveMatch = command.match(expensiveCommands);
          if (isBroadMatcher && expensiveMatch) {
            findings.push({
              id: `hooks-expensive-unscoped-${findings.length}`,
              severity: "low",
              category: "hooks",
              title: `PostToolUse runs "${expensiveMatch[0]}" on broad matcher "${matcher || "*"}"`,
              description: `A PostToolUse hook runs "${expensiveMatch[0]}" on every "${matcher || "tool call"}" event. Build tools and linters can take seconds to run — firing on every edit wastes resources and slows down the agent. Scope the matcher to specific file types or add conditional checks.`,
              file: file.path,
              evidence: `matcher: "${matcher}", hook: "${command.substring(0, 80)}"`,
              fix: {
                description: "Scope the matcher to reduce unnecessary runs",
                before: `"matcher": "${matcher}"`,
                after: `"matcher": "Edit(*.ts)" or add file-extension check in the hook script`,
                auto: false,
              },
            });
          }
        }
      } catch {
        // JSON parse errors handled elsewhere
      }

      return findings;
    },
  },
  {
    id: "hooks-output-to-world-readable",
    name: "Hook Writes to World-Readable Path",
    description: "Checks for hooks that redirect output to world-readable directories like /tmp",
    severity: "high",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const worldReadablePatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: />\s*\/tmp\//g,
          description: "Redirects output to /tmp — readable by all users on the system",
        },
        {
          pattern: /\btee\s+\/tmp\//g,
          description: "Uses tee to write to /tmp — creates world-readable file",
        },
        {
          pattern: />\s*\/var\/tmp\//g,
          description: "Redirects output to /var/tmp — persistent and world-readable",
        },
        {
          pattern: /\bmktemp\b/g,
          description: "Creates temporary file — ensure secure permissions (mktemp is generally safe but verify cleanup)",
        },
      ];

      for (const { pattern, description } of worldReadablePatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          // mktemp is generally safe — only flag if combined with risky patterns
          if (pattern.source.includes("mktemp")) continue;

          findings.push({
            id: `hooks-world-readable-${match.index}`,
            severity: "high",
            category: "exposure",
            title: `Hook writes to world-readable path: ${match[0].trim()}`,
            description: `${description}. Other users or processes on the system can read the output, which may contain secrets, code, or session data.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-source-from-env",
    name: "Hook Sources Script from Environment Path",
    description: "Checks for hooks that source scripts from environment variable paths",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const sourcePatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bsource\s+\$\{?\w+\}?\//g,
          description: "Sources a script from an environment variable path",
        },
        {
          pattern: /\.\s+\$\{?\w+\}?\//g,
          description: "Dot-sources a script from an environment variable path",
        },
        {
          pattern: /\beval\s+\$\{?\w+/g,
          description: "Evaluates content from an environment variable",
        },
      ];

      for (const { pattern, description } of sourcePatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-source-env-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Hook sources script from environment path: ${match[0].trim()}`,
            description: `${description}. If the environment variable is attacker-controlled, this enables arbitrary code execution through the sourced script.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-file-deletion",
    name: "Hook Deletes Files",
    description: "Checks for hooks that delete files, which could destroy work or cover tracks",
    severity: "high",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const deletePatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\b/g,
          description: "Recursive file deletion (rm -rf) — can destroy entire directories",
        },
        {
          pattern: /\brm\s+-[a-zA-Z]*f\b/g,
          description: "Force file deletion (rm -f) — deletes without confirmation",
        },
        {
          pattern: /\bshred\b/g,
          description: "Secure file erasure (shred) — irrecoverable deletion used to cover tracks",
        },
        {
          pattern: /\bunlink\b/g,
          description: "File deletion via unlink",
        },
      ];

      for (const { pattern, description } of deletePatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-file-delete-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook deletes files: ${match[0].trim()}`,
            description: `${description}. A hook that deletes files could destroy source code, logs, or evidence of compromise.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-cron-persistence",
    name: "Hook Installs Cron Job",
    description: "Checks for hooks that install cron jobs for persistent access",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const cronPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bcrontab\b/g,
          description: "Modifies crontab — installs persistent scheduled tasks",
        },
        {
          pattern: /\/etc\/cron/g,
          description: "Writes to system cron directory — installs persistent scheduled tasks",
        },
        {
          pattern: /\bat\s+-[a-z]/g,
          description: "Schedules deferred command execution via at",
        },
        {
          pattern: /\bsystemctl\s+(?:enable|start)/g,
          description: "Enables/starts a systemd service — potential persistence mechanism",
        },
        {
          pattern: /\blaunchctl\s+load/g,
          description: "Loads a macOS launch agent — persistent background process",
        },
      ];

      for (const { pattern, description } of cronPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-cron-persist-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook installs persistence mechanism: ${match[0].trim()}`,
            description: `${description}. Hooks should not install persistence mechanisms. This could allow a compromised hook to maintain access even after the session ends.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-env-mutation",
    name: "Hook Mutates Environment Variables",
    description: "Checks for hooks that set or export environment variables, which can alter subsequent command behavior",
    severity: "medium",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const envMutationPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
        readonly severity: "high" | "medium";
      }> = [
        {
          pattern: /\bexport\s+PATH=/g,
          description: "Modifies PATH — can redirect which binaries are executed",
          severity: "high",
        },
        {
          pattern: /\bexport\s+(?:LD_PRELOAD|LD_LIBRARY_PATH|DYLD_)=/gi,
          description: "Modifies dynamic linker variables — can inject shared libraries",
          severity: "high",
        },
        {
          pattern: /\bexport\s+(?:NODE_OPTIONS|PYTHONPATH|RUBYLIB)=/gi,
          description: "Modifies runtime import paths — can load malicious modules",
          severity: "high",
        },
        {
          pattern: /\bexport\s+(?:http_proxy|https_proxy|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY)=/gi,
          description: "Sets proxy variables — can redirect all network traffic through attacker-controlled proxy",
          severity: "high",
        },
      ];

      for (const { pattern, description, severity } of envMutationPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-env-mutation-${match.index}`,
            severity,
            category: "hooks",
            title: `Hook mutates environment: ${match[0].trim()}`,
            description: `${description}. Hooks that modify environment variables can silently alter the behavior of all subsequent commands in the session.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-git-config-modification",
    name: "Hook Modifies Git Configuration",
    description: "Checks for hooks that modify git config, which can alter commit authorship, disable signing, or change hooks",
    severity: "high",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const gitConfigPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bgit\s+config\s+--global/g,
          description: "Modifies global git config — affects all repositories on the system",
        },
        {
          pattern: /\bgit\s+config\s+(?:--system)/g,
          description: "Modifies system-level git config — affects all users",
        },
        {
          pattern: /\bgit\s+config\s+(?:.*\s+)?(?:user\.email|user\.name)/g,
          description: "Changes git commit author identity — could attribute commits to someone else",
        },
        {
          pattern: /\bgit\s+config\s+(?:.*\s+)?(?:commit\.gpgsign|tag\.gpgsign)\s+false/g,
          description: "Disables GPG commit signing — weakens commit verification",
        },
        {
          pattern: /\bgit\s+config\s+(?:.*\s+)?core\.hooksPath/g,
          description: "Changes git hooks directory — could redirect to malicious hooks",
        },
      ];

      for (const { pattern, description } of gitConfigPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-git-config-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook modifies git config: ${match[0].trim()}`,
            description: `${description}. Hooks should not modify git configuration as this can undermine version control integrity.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-user-account-modification",
    name: "Hook Creates or Modifies User Accounts",
    description: "Checks for hooks that create, modify, or delete user accounts",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const userModPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\buseradd\b/g,
          description: "Creates a new user account (useradd)",
        },
        {
          pattern: /\badduser\b/g,
          description: "Creates a new user account (adduser)",
        },
        {
          pattern: /\busermod\b/g,
          description: "Modifies an existing user account (usermod)",
        },
        {
          pattern: /\buserdel\b/g,
          description: "Deletes a user account (userdel)",
        },
        {
          pattern: /\bpasswd\b/g,
          description: "Changes a user password (passwd)",
        },
      ];

      for (const { pattern, description } of userModPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-user-mod-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook modifies user accounts: ${match[0].trim()}`,
            description: `${description}. Hooks should never create, modify, or delete user accounts. A compromised hook with this capability can create backdoor accounts for persistent access.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-privilege-escalation",
    name: "Hook Uses Privilege Escalation",
    description: "Checks for hooks that use sudo, su, or other privilege escalation commands",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const privEscPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bsudo\b/g,
          description: "Runs commands as root via sudo",
        },
        {
          pattern: /\bsu\s+-?\s*\w/g,
          description: "Switches to another user via su",
        },
        {
          pattern: /\bdoas\b/g,
          description: "Runs commands as another user via doas (OpenBSD sudo alternative)",
        },
        {
          pattern: /\bpkexec\b/g,
          description: "Runs commands as another user via polkit (pkexec)",
        },
        {
          pattern: /\brunas\b/gi,
          description: "Runs commands as another user via runas (Windows)",
        },
      ];

      for (const { pattern, description } of privEscPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-priv-esc-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook uses privilege escalation: ${match[0].trim()}`,
            description: `${description}. Hooks should never escalate privileges. A compromised hook with root access can take over the entire system.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-network-listener",
    name: "Hook Opens Network Listener",
    description: "Checks for hooks that bind to network ports, which could create reverse shells or backdoors",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const listenerPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bnc\s+.*-l/g,
          description: "Opens a netcat listener — classic reverse shell vector",
        },
        {
          pattern: /\bsocat\b/g,
          description: "Uses socat for bidirectional data transfer — can create tunnels and reverse shells",
        },
        {
          pattern: /\bpython3?\s+.*-m\s+http\.server/g,
          description: "Starts a Python HTTP server — exposes local files over the network",
        },
        {
          pattern: /\bpython3?\s+.*SimpleHTTPServer/g,
          description: "Starts a Python 2 HTTP server — exposes local files over the network",
        },
        {
          pattern: /\bphp\s+-S\b/g,
          description: "Starts a PHP built-in server — serves files and executes PHP code",
        },
      ];

      for (const { pattern, description } of listenerPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-network-listener-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook opens network listener: ${match[0].trim()}`,
            description: `${description}. Hooks should not open network listeners. This could create a backdoor accessible from the network.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-disk-wipe",
    name: "Hook Uses Disk Wiping Commands",
    description: "Checks for hooks that use destructive disk operations",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const wipePatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bdd\s+if=\/dev\/(?:zero|urandom)/g,
          description: "Overwrites disk with zeros/random data via dd",
        },
        {
          pattern: /\bmkfs\b/g,
          description: "Formats a filesystem — destroys all data on the target device",
        },
        {
          pattern: /\bwipefs\b/g,
          description: "Wipes filesystem signatures — makes data unrecoverable",
        },
      ];

      for (const { pattern, description } of wipePatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-disk-wipe-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook uses disk wiping command: ${match[0].trim()}`,
            description: `${description}. Hooks should never perform destructive disk operations. This could permanently destroy data.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-shell-profile-modification",
    name: "Hook Modifies Shell Profile",
    description: "Checks for hooks that modify shell init files (.bashrc, .zshrc, .profile) for persistence",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const profilePatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\.bashrc/g,
          description: "Modifies .bashrc — commands here run on every new bash shell",
        },
        {
          pattern: /\.zshrc/g,
          description: "Modifies .zshrc — commands here run on every new zsh shell",
        },
        {
          pattern: /\.bash_profile/g,
          description: "Modifies .bash_profile — commands here run on every login shell",
        },
        {
          pattern: /\.profile/g,
          description: "Modifies .profile — commands here run on every login shell",
        },
        {
          pattern: /\/etc\/environment/g,
          description: "Modifies /etc/environment — affects all users on the system",
        },
      ];

      for (const { pattern, description } of profilePatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          // Check if the context suggests writing/appending (not just reading)
          const idx = match.index ?? 0;
          const contextStart = Math.max(0, idx - 50);
          const context = file.content.substring(contextStart, idx + match[0].length + 50);
          const isWrite = />>|>|tee|echo\s+.*>|sed\s+-i|append/.test(context);

          if (isWrite) {
            findings.push({
              id: `hooks-shell-profile-${match.index}`,
              severity: "critical",
              category: "hooks",
              title: `Hook modifies shell profile: ${match[0].trim()}`,
              description: `${description}. Writing to shell profile files is a classic persistence technique — malicious code injected here survives across reboots and terminal sessions.`,
              file: file.path,
              line: findLineNumber(file.content, match.index ?? 0),
              evidence: context.trim().substring(0, 80),
            });
          }
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-logging-disabled",
    name: "Hook Disables Logging or Audit Trail",
    description: "Checks for hooks that clear logs or disable audit mechanisms",
    severity: "high",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const logPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: />\s*\/dev\/null\s+2>&1|&>\s*\/dev\/null/g,
          description: "Redirects all output to /dev/null — hides both stdout and stderr",
        },
        {
          pattern: /\bhistory\s+-[cwd]/g,
          description: "Clears or disables shell history — covers tracks",
        },
        {
          pattern: /\bunset\s+HISTFILE/g,
          description: "Unsets HISTFILE — prevents command history from being saved",
        },
        {
          pattern: /\btruncate\s+.*\/var\/log/g,
          description: "Truncates system log files — destroys audit trail",
        },
      ];

      for (const { pattern, description } of logPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-logging-disabled-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook disables logging: ${match[0].trim()}`,
            description: `${description}. Disabling logging or clearing audit trails in hooks is a defense evasion technique that makes it harder to detect and investigate compromises.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-ssh-key-operations",
    name: "Hook Manipulates SSH Keys",
    description: "Checks for hooks that generate, copy, or modify SSH keys — enables lateral movement",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const sshKeyPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bssh-keygen\b/g,
          description: "Generates SSH keys — could create unauthorized keys for persistent access",
        },
        {
          pattern: /\bssh-copy-id\b/g,
          description: "Copies SSH keys to remote hosts — enables passwordless lateral movement",
        },
        {
          pattern: />>?\s*~\/\.ssh\/authorized_keys/g,
          description: "Appends to authorized_keys — installs backdoor SSH access",
        },
      ];

      for (const { pattern, description } of sshKeyPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-ssh-key-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook manipulates SSH keys: ${match[0].trim()}`,
            description: `${description}. Hooks should not create or distribute SSH keys as this enables unauthorized remote access.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-background-process",
    name: "Hook Runs Background Process",
    description: "Checks for hooks that start persistent background processes that outlive the session",
    severity: "high",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const bgPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bnohup\b/g,
          description: "Runs process immune to hangup signals — survives session end",
        },
        {
          pattern: /\bdisown\b/g,
          description: "Detaches process from shell — survives session end",
        },
        {
          pattern: /\bscreen\s+-[dD]m/g,
          description: "Starts detached screen session — hidden persistent process",
        },
        {
          pattern: /\btmux\s+new-session\s+-d/g,
          description: "Starts detached tmux session — hidden persistent process",
        },
      ];

      for (const { pattern, description } of bgPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-bg-process-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook starts background process: ${match[0].trim()}`,
            description: `${description}. Hooks that start persistent background processes can maintain execution even after the agent session ends — a common persistence technique.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-dns-exfiltration",
    name: "Hook Uses DNS for Data Exfiltration",
    description: "Checks for hooks that use DNS queries with variable interpolation to exfiltrate data",
    severity: "critical",
    category: "exfiltration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const dnsPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bdig\s+.*\$\{?\w+/g,
          description: "Uses dig with variable interpolation — DNS exfiltration encodes data in DNS queries",
        },
        {
          pattern: /\bnslookup\s+.*\$\{?\w+/g,
          description: "Uses nslookup with variable interpolation — DNS exfiltration vector",
        },
        {
          pattern: /\bhost\s+.*\$\{?\w+/g,
          description: "Uses host command with variable interpolation — DNS exfiltration vector",
        },
      ];

      for (const { pattern, description } of dnsPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-dns-exfil-${match.index}`,
            severity: "critical",
            category: "exfiltration",
            title: `Hook uses DNS for exfiltration: ${match[0].trim().substring(0, 60)}`,
            description: `${description}. DNS queries bypass most firewalls and proxy filters, making this a common out-of-band exfiltration technique.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-firewall-modification",
    name: "Hook Modifies Firewall Rules",
    description: "Checks for hooks that modify iptables, ufw, or firewall rules",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const fwPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\biptables\b/g,
          description: "Modifies iptables firewall rules — can open ports or disable filtering",
        },
        {
          pattern: /\bufw\s+(?:allow|delete|disable)/g,
          description: "Modifies UFW firewall — can open ports or disable the firewall entirely",
        },
        {
          pattern: /\bfirewall-cmd\b/g,
          description: "Modifies firewalld rules — can change network access policies",
        },
      ];

      for (const { pattern, description } of fwPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-fw-modify-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook modifies firewall: ${match[0].trim()}`,
            description: `${description}. Hooks should not modify firewall rules — this could expose the system to network attacks.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-global-package-install",
    name: "Hook Installs Global Packages",
    description: "Checks for hooks that install packages globally, which can modify system-wide binaries",
    severity: "high",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const installPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bnpm\s+install\s+-g\b|\bnpm\s+i\s+-g\b/g,
          description: "Installs npm package globally — modifies system-wide PATH binaries",
        },
        {
          pattern: /\bpip\s+install\s+(?:--user\s+)?(?!-r\b)/g,
          description: "Installs Python package — may modify system Python packages",
        },
        {
          pattern: /\bgem\s+install\b/g,
          description: "Installs Ruby gem — modifies system Ruby packages",
        },
        {
          pattern: /\bcargo\s+install\b/g,
          description: "Installs Rust package globally via cargo",
        },
      ];

      for (const { pattern, description } of installPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-global-install-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook installs packages: ${match[0].trim()}`,
            description: `${description}. Hooks that install packages can introduce supply chain risks and modify the system's behavior for all future commands.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-container-escape",
    name: "Hook Uses Container Escape Techniques",
    description: "Checks for hooks that use Docker flags that enable container escape",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const containerEscapePatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /--privileged/g,
          description: "Docker --privileged flag — container has full host access",
        },
        {
          pattern: /--pid=host/g,
          description: "Docker --pid=host — container can see/signal all host processes",
        },
        {
          pattern: /--network=host/g,
          description: "Docker --network=host — container shares host network stack",
        },
        {
          pattern: /-v\s+\/:/g,
          description: "Mounts host root filesystem into container — full filesystem access",
        },
      ];

      for (const { pattern, description } of containerEscapePatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-container-escape-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook uses container escape technique: ${match[0].trim()}`,
            description: `${description}. These Docker flags break container isolation and allow full host access from within the container.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-credential-access",
    name: "Hook Accesses Credential Stores",
    description: "Checks for hooks that read password files, keychains, or credential managers",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const credPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bsecurity\s+find-generic-password\b/g,
          description: "Reads macOS Keychain passwords via security command",
        },
        {
          pattern: /\bsecurity\s+find-internet-password\b/g,
          description: "Reads macOS Keychain internet passwords",
        },
        {
          pattern: /\bsecret-tool\s+lookup\b/g,
          description: "Reads GNOME Keyring / Linux secret store",
        },
        {
          pattern: /\bkeyctl\s+read\b/g,
          description: "Reads Linux kernel keyring",
        },
        {
          pattern: /\/etc\/shadow/g,
          description: "Accesses /etc/shadow — contains password hashes",
        },
      ];

      for (const { pattern, description } of credPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-cred-access-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook accesses credential store: ${match[0].trim()}`,
            description: `${description}. Hooks should never access credential stores — this enables credential theft for lateral movement.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-reverse-shell",
    name: "Hook Opens Reverse Shell",
    description: "Checks for hooks that establish reverse shell connections back to an attacker",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const reverseShellPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bbash\s+-i\s+[>&]+.*\/dev\/tcp\//g,
          description: "Bash reverse shell via /dev/tcp — connects back to attacker",
        },
        {
          pattern: /\/dev\/tcp\/[0-9.]+\/\d+/g,
          description: "Uses /dev/tcp for network connection — common reverse shell technique",
        },
        {
          pattern: /\bpython3?\s+.*-c\s+.*socket.*connect/g,
          description: "Python reverse shell via socket.connect",
        },
        {
          pattern: /\bperl\s+.*-e\s+.*socket.*INET/g,
          description: "Perl reverse shell via Socket::INET",
        },
        {
          pattern: /\bmkfifo\b.*\bnc\b/g,
          description: "Named pipe reverse shell using mkfifo and netcat",
        },
      ];

      for (const { pattern, description } of reverseShellPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-reverse-shell-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook establishes reverse shell: ${match[0].trim().substring(0, 60)}`,
            description: `${description}. Reverse shells give attackers interactive command execution on the target system.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim().substring(0, 80),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-clipboard-access",
    name: "Hook Accesses System Clipboard",
    description: "Checks for hooks that read or write the system clipboard, which can be used for data exfiltration",
    severity: "high",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const clipboardPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bpbcopy\b/g,
          description: "Uses macOS pbcopy to write to clipboard — can silently exfiltrate data",
        },
        {
          pattern: /\bpbpaste\b/g,
          description: "Uses macOS pbpaste to read clipboard — may capture sensitive copied content",
        },
        {
          pattern: /\bxclip\b/g,
          description: "Uses xclip to access X11 clipboard — can read or write clipboard data",
        },
        {
          pattern: /\bxsel\b/g,
          description: "Uses xsel to access X11 selection — can read or write clipboard data",
        },
        {
          pattern: /\bwl-copy\b/g,
          description: "Uses wl-copy to write to Wayland clipboard",
        },
        {
          pattern: /\bwl-paste\b/g,
          description: "Uses wl-paste to read from Wayland clipboard",
        },
      ];

      for (const { pattern, description } of clipboardPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-clipboard-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook accesses clipboard: ${match[0].trim()}`,
            description: `${description}. Clipboard access in hooks can be used to steal passwords, tokens, and other sensitive data that users copy.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "hooks-log-tampering",
    name: "Hook Tampers with System Logs",
    description: "Checks for hooks that delete, truncate, or modify system log files to cover tracks",
    severity: "critical",
    category: "hooks",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];

      const findings: Finding[] = [];

      const logTamperPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\bjournalctl\s+--vacuum/g,
          description: "Purges systemd journal logs — destroys audit trail",
        },
        {
          pattern: /\brm\s+(?:-[rf]+\s+)?\/var\/log\b/g,
          description: "Deletes system log files — destroys audit evidence",
        },
        {
          pattern: /\btruncate\s+.*\/var\/log\b/g,
          description: "Truncates system log files — erases log contents",
        },
        {
          pattern: />\s*\/var\/log\/(?:syslog|auth\.log|messages|secure)/g,
          description: "Overwrites system log file with redirection — clears log contents",
        },
        {
          pattern: /\bhistory\s+-c\b/g,
          description: "Clears shell command history — covers tracks of executed commands",
        },
        {
          pattern: /\bunset\s+HISTFILE\b/g,
          description: "Disables shell history recording — prevents command audit trail",
        },
      ];

      for (const { pattern, description } of logTamperPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-log-tamper-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook tampers with logs: ${match[0].trim()}`,
            description: `${description}. Log tampering is a strong indicator of malicious intent — attackers erase evidence of their actions.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].trim(),
          });
        }
      }

      return findings;
    },
  },
];
