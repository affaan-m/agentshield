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
        { pattern: /\|\|\s*:\s*$/gm, desc: "errors suppressed with || :" },
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
];
