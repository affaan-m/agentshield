import type { ConfigFile, Finding, Rule } from "../types.js";

/**
 * Secret detection patterns.
 */
const SECRET_PATTERNS: ReadonlyArray<{
  readonly name: string;
  readonly pattern: RegExp;
  readonly description: string;
}> = [
  {
    name: "anthropic-api-key",
    pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g,
    description: "Anthropic API key",
  },
  {
    name: "openai-api-key",
    pattern: /sk-proj-[a-zA-Z0-9_-]{20,}/g,
    description: "OpenAI API key",
  },
  {
    name: "github-pat",
    pattern: /ghp_[a-zA-Z0-9]{36,}/g,
    description: "GitHub personal access token",
  },
  {
    name: "github-fine-grained",
    pattern: /github_pat_[a-zA-Z0-9_]{20,}/g,
    description: "GitHub fine-grained token",
  },
  {
    name: "aws-access-key",
    pattern: /AKIA[0-9A-Z]{16}/g,
    description: "AWS access key ID",
  },
  {
    name: "aws-secret-key",
    pattern: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi,
    description: "AWS secret access key",
  },
  {
    name: "private-key",
    pattern: /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g,
    description: "Private key material",
  },
  {
    name: "hardcoded-password",
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/gi,
    description: "Hardcoded password",
  },
  {
    name: "bearer-token",
    pattern: /["']Bearer\s+[a-zA-Z0-9._\-]{20,}["']/g,
    description: "Hardcoded bearer token",
  },
  {
    name: "connection-string",
    pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+:[^\s"']+@/gi,
    description: "Database connection string with credentials",
  },
  {
    name: "slack-token",
    pattern: /xox[bprs]-[a-zA-Z0-9-]{10,}/g,
    description: "Slack API token",
  },
];

function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split("\n").length;
}

function findAllMatches(content: string, pattern: RegExp): Array<RegExpMatchArray> {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return [...content.matchAll(new RegExp(pattern.source, flags))];
}

export const secretRules: ReadonlyArray<Rule> = [
  {
    id: "secrets-hardcoded",
    name: "Hardcoded Secrets Detection",
    description: "Scans for hardcoded API keys, tokens, passwords, and credentials",
    severity: "critical",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const findings: Finding[] = [];

      for (const secretPattern of SECRET_PATTERNS) {
        const matches = findAllMatches(file.content, secretPattern.pattern);

        for (const match of matches) {
          // Skip if it's inside an env var reference like ${VAR_NAME}
          const idx = match.index ?? 0;
          const context = file.content.substring(
            Math.max(0, idx - 10),
            idx + match[0].length + 10
          );
          if (context.includes("${") || context.includes("process.env")) {
            continue;
          }

          const maskedValue =
            match[0].substring(0, 8) + "..." + match[0].substring(match[0].length - 4);

          findings.push({
            id: `secrets-${secretPattern.name}-${idx}`,
            severity: "critical",
            category: "secrets",
            title: `Hardcoded ${secretPattern.description}`,
            description: `Found ${secretPattern.description} in ${file.path}. Secrets must never be hardcoded in configuration files.`,
            file: file.path,
            line: findLineNumber(file.content, idx),
            evidence: maskedValue,
            fix: {
              description: `Replace with environment variable reference`,
              before: match[0],
              after: `\${${secretPattern.name.toUpperCase().replace(/-/g, "_")}}`,
              auto: false,
            },
          });
        }
      }

      return findings;
    },
  },
  {
    id: "secrets-env-in-config",
    name: "Environment Variable Exposure",
    description: "Checks for env var values being logged or exposed in config",
    severity: "high",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const findings: Finding[] = [];

      const echoEnvPattern = /echo\s+.*\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|PASS|CRED)\w*\}?/gi;
      const matches = findAllMatches(file.content, echoEnvPattern);

      for (const match of matches) {
        findings.push({
          id: `secrets-echo-env-${match.index}`,
          severity: "high",
          category: "secrets",
          title: "Environment variable echoed to terminal",
          description: `Hook or script echoes sensitive environment variable. This exposes secrets in terminal output and session logs.`,
          file: file.path,
          line: findLineNumber(file.content, match.index ?? 0),
          evidence: match[0],
          fix: {
            description: "Remove echo of sensitive environment variables",
            before: match[0],
            after: "# [REMOVED: secret was being echoed]",
            auto: true,
          },
        });
      }

      return findings;
    },
  },
];
