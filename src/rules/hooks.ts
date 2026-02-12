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
];
