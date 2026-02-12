import type { ConfigFile, Finding, Rule } from "../types.js";

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

function findAllMatches(content: string, pattern: RegExp): Array<RegExpMatchArray> {
  return [...content.matchAll(new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g"))];
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
];
