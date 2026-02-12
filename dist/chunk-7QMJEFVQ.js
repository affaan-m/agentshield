// src/scanner/discovery.ts
import { readFileSync, existsSync, readdirSync, statSync } from "fs";
import { join, basename, extname, relative } from "path";
function discoverConfigFiles(rootPath) {
  const files = [];
  const directFiles = [
    ["CLAUDE.md", "claude-md"],
    [".claude/CLAUDE.md", "claude-md"],
    ["settings.json", "settings-json"],
    [".claude/settings.json", "settings-json"],
    ["mcp.json", "mcp-json"],
    [".claude/mcp.json", "mcp-json"],
    [".claude.json", "mcp-json"]
  ];
  for (const [relativePath, type] of directFiles) {
    const fullPath = join(rootPath, relativePath);
    if (existsSync(fullPath)) {
      const content = readFileSync(fullPath, "utf-8");
      files.push({ path: relative(rootPath, fullPath), type, content });
    }
  }
  const subdirs = [
    ["agents", "agent-md"],
    [".claude/agents", "agent-md"],
    ["skills", "skill-md"],
    [".claude/skills", "skill-md"],
    ["hooks", "hook-script"],
    [".claude/hooks", "hook-script"],
    ["rules", "rule-md"],
    [".claude/rules", "rule-md"],
    ["contexts", "context-md"],
    [".claude/contexts", "context-md"],
    ["commands", "skill-md"],
    [".claude/commands", "skill-md"]
  ];
  for (const [subdir, type] of subdirs) {
    const dirPath = join(rootPath, subdir);
    if (existsSync(dirPath) && statSync(dirPath).isDirectory()) {
      const entries = readdirSync(dirPath);
      for (const entry of entries) {
        const entryPath = join(dirPath, entry);
        if (statSync(entryPath).isFile()) {
          const content = readFileSync(entryPath, "utf-8");
          files.push({
            path: relative(rootPath, entryPath),
            type: inferType(entry, type),
            content
          });
        }
      }
    }
  }
  return { path: rootPath, files };
}
function inferType(filename, defaultType) {
  const ext = extname(filename).toLowerCase();
  const name = basename(filename).toLowerCase();
  if (name === "claude.md") return "claude-md";
  if (name === "settings.json") return "settings-json";
  if (name === "mcp.json" || name === ".claude.json") return "mcp-json";
  if (ext === ".sh" || ext === ".bash" || ext === ".zsh") return "hook-script";
  if (ext === ".json") return "settings-json";
  if (ext === ".md" || ext === ".markdown") return defaultType;
  return "unknown";
}

// src/rules/secrets.ts
var SECRET_PATTERNS = [
  {
    name: "anthropic-api-key",
    pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g,
    description: "Anthropic API key"
  },
  {
    name: "openai-api-key",
    pattern: /sk-proj-[a-zA-Z0-9_-]{20,}/g,
    description: "OpenAI API key"
  },
  {
    name: "github-pat",
    pattern: /ghp_[a-zA-Z0-9]{36,}/g,
    description: "GitHub personal access token"
  },
  {
    name: "github-fine-grained",
    pattern: /github_pat_[a-zA-Z0-9_]{20,}/g,
    description: "GitHub fine-grained token"
  },
  {
    name: "aws-access-key",
    pattern: /AKIA[0-9A-Z]{16}/g,
    description: "AWS access key ID"
  },
  {
    name: "aws-secret-key",
    pattern: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi,
    description: "AWS secret access key"
  },
  {
    name: "private-key",
    pattern: /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g,
    description: "Private key material"
  },
  {
    name: "hardcoded-password",
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/gi,
    description: "Hardcoded password"
  },
  {
    name: "bearer-token",
    pattern: /["']Bearer\s+[a-zA-Z0-9._\-]{20,}["']/g,
    description: "Hardcoded bearer token"
  },
  {
    name: "connection-string",
    pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+:[^\s"']+@/gi,
    description: "Database connection string with credentials"
  },
  {
    name: "slack-token",
    pattern: /xox[bprs]-[a-zA-Z0-9-]{10,}/g,
    description: "Slack API token"
  },
  {
    name: "jwt-token",
    pattern: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
    description: "JWT token"
  },
  {
    name: "google-api-key",
    pattern: /AIza[a-zA-Z0-9_\\-]{35}/g,
    description: "Google API key"
  },
  {
    name: "stripe-key",
    pattern: /(?:sk|pk)_(?:test|live)_[a-zA-Z0-9]{24,}/g,
    description: "Stripe API key"
  }
];
function findLineNumber(content, matchIndex) {
  return content.substring(0, matchIndex).split("\n").length;
}
function findAllMatches(content, pattern) {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return [...content.matchAll(new RegExp(pattern.source, flags))];
}
var secretRules = [
  {
    id: "secrets-hardcoded",
    name: "Hardcoded Secrets Detection",
    description: "Scans for hardcoded API keys, tokens, passwords, and credentials",
    severity: "critical",
    category: "secrets",
    check(file) {
      const findings = [];
      for (const secretPattern of SECRET_PATTERNS) {
        const matches = findAllMatches(file.content, secretPattern.pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;
          const context = file.content.substring(
            Math.max(0, idx - 10),
            idx + match[0].length + 10
          );
          if (context.includes("${") || context.includes("process.env")) {
            continue;
          }
          const maskedValue = match[0].substring(0, 8) + "..." + match[0].substring(match[0].length - 4);
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
              auto: false
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "secrets-env-in-config",
    name: "Environment Variable Exposure",
    description: "Checks for env var values being logged or exposed in config",
    severity: "high",
    category: "secrets",
    check(file) {
      const findings = [];
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
            auto: true
          }
        });
      }
      return findings;
    }
  },
  {
    id: "secrets-env-in-claude-md",
    name: "Secrets in CLAUDE.md",
    description: "Checks for sensitive env var assignments in CLAUDE.md files which are often committed to repos",
    severity: "high",
    category: "secrets",
    check(file) {
      if (file.type !== "claude-md") return [];
      const findings = [];
      const envAssignmentPattern = /(?:export\s+)?\b(\w*(?:API_KEY|SECRET_KEY|AUTH_TOKEN|ACCESS_TOKEN|PRIVATE_KEY|PASSWORD|CREDENTIAL|API_SECRET)\w*)\s*[=:]\s*["']?([^\s"']{4,})["']?/gi;
      const matches = findAllMatches(file.content, envAssignmentPattern);
      for (const match of matches) {
        const varName = match[1];
        const idx = match.index ?? 0;
        const value = match[2];
        if (value.startsWith("${") || value.startsWith("$")) continue;
        findings.push({
          id: `secrets-claude-md-env-${idx}`,
          severity: "high",
          category: "secrets",
          title: `Sensitive env var in CLAUDE.md: ${varName}`,
          description: `CLAUDE.md contains an assignment for "${varName}". CLAUDE.md files are typically committed to version control, exposing secrets to anyone who clones the repository.`,
          file: file.path,
          line: findLineNumber(file.content, idx),
          evidence: `${varName}=<redacted>`,
          fix: {
            description: "Move to .env file and reference via environment variable",
            before: match[0],
            after: `# Set ${varName} in your .env file`,
            auto: false
          }
        });
      }
      return findings;
    }
  },
  {
    id: "secrets-sensitive-env-passthrough",
    name: "Sensitive Env Var Passthrough",
    description: "Checks for MCP servers passing through excessive sensitive environment variables",
    severity: "medium",
    category: "secrets",
    check(file) {
      if (file.type !== "mcp-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const sensitivePatterns = /KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH/i;
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const env = serverConfig.env ?? {};
          const sensitiveVars = Object.keys(env).filter(
            (key) => sensitivePatterns.test(key)
          );
          if (sensitiveVars.length > 5) {
            findings.push({
              id: `secrets-env-passthrough-${name}`,
              severity: "medium",
              category: "secrets",
              title: `MCP server "${name}" receives ${sensitiveVars.length} sensitive env vars`,
              description: `The MCP server "${name}" has ${sensitiveVars.length} sensitive environment variables passed through (${sensitiveVars.slice(0, 3).join(", ")}...). Over-sharing secrets increases the blast radius if the server is compromised. Only pass env vars that the server actually needs.`,
              file: file.path,
              evidence: `Sensitive vars: ${sensitiveVars.join(", ")}`,
              fix: {
                description: "Remove env vars that the server does not need",
                before: `${sensitiveVars.length} sensitive env vars`,
                after: "Only the required env vars for this server",
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  }
];

// src/rules/permissions.ts
var OVERLY_PERMISSIVE = [
  {
    pattern: /^Bash\(\*\)$/,
    description: "Unrestricted Bash access \u2014 any command can run",
    severity: "critical",
    suggestion: "Bash(git *), Bash(npm *), Bash(node *)"
  },
  {
    pattern: /^Bash\(sudo\s/,
    description: "Sudo access allowed \u2014 agent can escalate privileges",
    severity: "critical",
    suggestion: "Remove sudo permissions entirely"
  },
  {
    pattern: /^Write\(\*\)$/,
    description: "Unrestricted Write access \u2014 agent can write to any file",
    severity: "high",
    suggestion: "Write(src/*), Write(tests/*)"
  },
  {
    pattern: /^Edit\(\*\)$/,
    description: "Unrestricted Edit access \u2014 agent can edit any file",
    severity: "high",
    suggestion: "Edit(src/*), Edit(tests/*)"
  },
  {
    pattern: /^Bash\(rm\s/,
    description: "Delete operations explicitly allowed in Bash",
    severity: "high",
    suggestion: "Move rm commands to deny list instead"
  },
  {
    pattern: /^Bash\(curl\s/,
    description: "Unrestricted curl access \u2014 agent can make arbitrary HTTP requests",
    severity: "medium",
    suggestion: "Restrict to specific domains or move to deny list"
  },
  {
    pattern: /^Bash\(wget\s/,
    description: "Unrestricted wget access \u2014 agent can download arbitrary files",
    severity: "medium",
    suggestion: "Restrict to specific domains or move to deny list"
  }
];
var MISSING_DENIALS = [
  { pattern: "rm -rf", description: "Recursive force delete" },
  { pattern: "sudo", description: "Privilege escalation" },
  { pattern: "chmod 777", description: "World-writable permissions" },
  { pattern: "ssh", description: "SSH connections from agent" },
  { pattern: "> /dev/", description: "Writing to device files" }
];
function parsePermissionLists(content) {
  try {
    const config = JSON.parse(content);
    return {
      allow: config?.permissions?.allow ?? [],
      deny: config?.permissions?.deny ?? []
    };
  } catch {
    return null;
  }
}
var DESTRUCTIVE_GIT_PATTERNS = [
  {
    pattern: /push\s+--force|push\s+-f\b/,
    description: "Force push can overwrite remote history, destroying teammates' work",
    suggestion: "Use --force-with-lease instead, or move to deny list"
  },
  {
    pattern: /reset\s+--hard/,
    description: "Hard reset destroys uncommitted changes without recovery",
    suggestion: "Move to deny list; use 'git stash' or 'git reset --soft' instead"
  },
  {
    pattern: /clean\s+-[a-z]*f/,
    description: "Git clean with force flag permanently deletes untracked files",
    suggestion: "Move to deny list; use 'git clean -n' (dry-run) first"
  },
  {
    pattern: /branch\s+-D\b/,
    description: "Force-delete branch regardless of merge status can lose work",
    suggestion: "Use 'branch -d' (lowercase) which checks merge status first"
  },
  {
    pattern: /checkout\s+\.\s*$/,
    description: "Discards all unstaged changes in working directory",
    suggestion: "Move to deny list to prevent accidental loss of work"
  }
];
var permissionRules = [
  {
    id: "permissions-overly-permissive",
    name: "Overly Permissive Access",
    description: "Checks the ALLOW list for permission rules that grant excessive access",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      for (const entry of perms.allow) {
        for (const check of OVERLY_PERMISSIVE) {
          if (check.pattern.test(entry)) {
            findings.push({
              id: `permissions-permissive-${entry}`,
              severity: check.severity,
              category: "permissions",
              title: `Overly permissive allow rule: ${entry}`,
              description: check.description,
              file: file.path,
              evidence: entry,
              fix: {
                description: `Restrict to specific commands: ${check.suggestion}`,
                before: entry,
                after: check.suggestion,
                auto: false
              }
            });
            break;
          }
        }
      }
      for (const denyEntry of perms.deny) {
        for (const allowEntry of perms.allow) {
          if (allowEntry === denyEntry) {
            findings.push({
              id: `permissions-contradiction-${denyEntry}`,
              severity: "medium",
              category: "misconfiguration",
              title: `Contradictory permission: "${denyEntry}" in both allow and deny`,
              description: `The permission "${denyEntry}" appears in both the allow and deny lists. Deny takes precedence, but this is confusing and should be cleaned up.`,
              file: file.path,
              evidence: denyEntry
            });
          }
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-no-deny-list",
    name: "Missing Deny List",
    description: "Checks if the settings.json has a deny list for dangerous operations",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      if (perms.deny.length === 0) {
        findings.push({
          id: "permissions-no-deny-list",
          severity: "high",
          category: "permissions",
          title: "No deny list configured",
          description: "settings.json has no deny list. Without explicit denials, the agent may run dangerous operations if the allow list is too broad.",
          file: file.path,
          fix: {
            description: "Add a deny list for dangerous operations",
            before: '"permissions": { "allow": [...] }',
            after: '"permissions": { "allow": [...], "deny": ["Bash(rm -rf *)", "Bash(sudo *)", "Bash(chmod 777 *)"] }',
            auto: false
          }
        });
      }
      for (const denial of MISSING_DENIALS) {
        const hasDenial = perms.deny.some((d) => d.includes(denial.pattern));
        if (!hasDenial && perms.deny.length > 0) {
          findings.push({
            id: `permissions-missing-deny-${denial.pattern.replace(/\s/g, "-")}`,
            severity: "medium",
            category: "permissions",
            title: `Missing deny rule: ${denial.description}`,
            description: `The deny list does not block "${denial.pattern}". Consider adding it to prevent ${denial.description.toLowerCase()}.`,
            file: file.path
          });
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-dangerous-skip",
    name: "Dangerous Permission Bypass",
    description: "Checks for dangerously-skip-permissions or no-verify flags used affirmatively",
    severity: "critical",
    category: "permissions",
    check(file) {
      const findings = [];
      const dangerousPatterns = [
        {
          pattern: /dangerously-?skip-?permissions/gi,
          desc: "Permission system bypass"
        },
        {
          pattern: /--no-verify/g,
          desc: "Git hook verification bypass"
        }
      ];
      const negationPatterns = [
        /\bnever\b/i,
        /\bdon'?t\b/i,
        /\bdo\s+not\b/i,
        /\bnot\b/i,
        /\bavoid\b/i,
        /\bprohibit/i,
        /\bforbid/i,
        /\bdisable/i,
        /\bban/i,
        /\bblock/i
      ];
      for (const { pattern, desc } of dangerousPatterns) {
        const matches = [...file.content.matchAll(
          new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g")
        )];
        for (const match of matches) {
          const idx = match.index ?? 0;
          const contextStart = Math.max(0, idx - 100);
          const context = file.content.substring(contextStart, idx).toLowerCase();
          const isNegated = negationPatterns.some((neg) => neg.test(context));
          if (isNegated) {
            findings.push({
              id: `permissions-negated-${idx}`,
              severity: "info",
              category: "permissions",
              title: `Prohibition of ${match[0]} (good practice)`,
              description: `Found "${match[0]}" in a negated/prohibitive context. This is correct \u2014 the config is telling the agent NOT to use this flag.`,
              file: file.path,
              line: findLineNumber2(file.content, idx),
              evidence: match[0]
            });
            continue;
          }
          findings.push({
            id: `permissions-dangerous-${idx}`,
            severity: "critical",
            category: "permissions",
            title: `Dangerous flag: ${match[0]}`,
            description: `${desc}. The flag "${match[0]}" disables safety mechanisms.`,
            file: file.path,
            line: findLineNumber2(file.content, idx),
            evidence: match[0],
            fix: {
              description: "Remove dangerous bypass flag",
              before: match[0],
              after: "# [REMOVED: dangerous bypass flag]",
              auto: false
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-all-mutable-tools",
    name: "All Mutable Tools Allowed",
    description: "Checks if the allow list grants access to all three mutable tool categories simultaneously",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const allowStr = perms.allow.join(" ");
      const hasBash = perms.allow.some((e) => e.startsWith("Bash"));
      const hasWrite = perms.allow.some((e) => e.startsWith("Write"));
      const hasEdit = perms.allow.some((e) => e.startsWith("Edit"));
      if (hasBash && hasWrite && hasEdit) {
        const allUnrestricted = allowStr.includes("Bash(*)") && allowStr.includes("Write(*)") && allowStr.includes("Edit(*)");
        if (!allUnrestricted) {
          return [
            {
              id: "permissions-all-mutable-tools",
              severity: "high",
              category: "permissions",
              title: "All mutable tool categories allowed simultaneously",
              description: "The allow list grants Bash, Write, and Edit access. Even with scoped patterns, having all three categories means the agent can run commands, create files, and modify files \u2014 effectively unrestricted write access to the system. Consider whether all three are truly needed.",
              file: file.path,
              fix: {
                description: "Remove one or more mutable tool categories if not needed",
                before: "Bash(...) + Write(...) + Edit(...)",
                after: "Consider if the agent really needs all three",
                auto: false
              }
            }
          ];
        }
      }
      return [];
    }
  },
  {
    id: "permissions-destructive-git",
    name: "Destructive Git Commands Allowed",
    description: "Checks if the allow list permits destructive git operations",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      for (const entry of perms.allow) {
        for (const gitPattern of DESTRUCTIVE_GIT_PATTERNS) {
          if (gitPattern.pattern.test(entry)) {
            findings.push({
              id: `permissions-destructive-git-${findings.length}`,
              severity: "high",
              category: "permissions",
              title: `Destructive git command allowed: ${entry}`,
              description: gitPattern.description,
              file: file.path,
              evidence: entry,
              fix: {
                description: gitPattern.suggestion,
                before: entry,
                after: `# Move to deny list: ${entry}`,
                auto: false
              }
            });
            break;
          }
        }
      }
      return findings;
    }
  }
];
function findLineNumber2(content, matchIndex) {
  return content.substring(0, matchIndex).split("\n").length;
}

// src/rules/hooks.ts
var INJECTION_PATTERNS = [
  {
    name: "var-interpolation",
    pattern: /\$\{(?:file|command|content|input|args?)\}/gi,
    description: "Hook uses variable interpolation that could be influenced by file content or command arguments. An attacker could craft filenames or content to inject commands.",
    severity: "critical"
  },
  {
    name: "shell-interpolation",
    pattern: /\bsh\s+-c\s+["'].*\$\{/g,
    description: "Shell invocation with variable interpolation \u2014 classic command injection vector.",
    severity: "critical"
  },
  {
    name: "curl-interpolation",
    pattern: /\bcurl\b.*\$\{/g,
    description: "HTTP request with variable interpolation \u2014 could be used for data exfiltration.",
    severity: "high"
  },
  {
    name: "wget-interpolation",
    pattern: /\bwget\b.*\$\{/g,
    description: "Download with variable interpolation \u2014 could fetch malicious payloads.",
    severity: "high"
  }
];
var EXFILTRATION_PATTERNS = [
  {
    name: "curl-external",
    pattern: /\bcurl\s+(-X\s+POST\s+)?https?:\/\//g,
    description: "Hook sends data to external URL via curl"
  },
  {
    name: "wget-external",
    pattern: /\bwget\s+.*https?:\/\//g,
    description: "Hook fetches from external URL via wget"
  },
  {
    name: "netcat",
    pattern: /\bnc\b|\bnetcat\b/g,
    description: "Hook uses netcat \u2014 potential reverse shell or data exfiltration"
  },
  {
    name: "sendmail",
    pattern: /\bsendmail\b|\bmail\b.*-s/g,
    description: "Hook sends email \u2014 potential data exfiltration"
  }
];
function findLineNumber3(content, matchIndex) {
  return content.substring(0, matchIndex).split("\n").length;
}
function findAllMatches2(content, pattern) {
  return [...content.matchAll(new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g"))];
}
var hookRules = [
  {
    id: "hooks-injection",
    name: "Hook Command Injection",
    description: "Checks hooks for command injection vulnerabilities via variable interpolation",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      for (const injPattern of INJECTION_PATTERNS) {
        const matches = findAllMatches2(file.content, injPattern.pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-injection-${match.index}`,
            severity: "critical",
            category: "injection",
            title: "Potential command injection in hook",
            description: injPattern.description,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0],
            fix: {
              description: "Sanitize inputs before interpolation, or use a whitelist approach instead of shell interpolation",
              before: match[0],
              after: "# Use validated, sanitized input only",
              auto: false
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-exfiltration",
    name: "Hook Data Exfiltration",
    description: "Checks hooks for patterns that could exfiltrate data to external services",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      for (const exfilPattern of EXFILTRATION_PATTERNS) {
        const matches = findAllMatches2(file.content, exfilPattern.pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-exfiltration-${match.index}`,
            severity: "high",
            category: "exposure",
            title: "Hook sends data to external service",
            description: `${exfilPattern.description}. If a hook is compromised or misconfigured, it could exfiltrate code, secrets, or session data.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0]
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-no-error-handling",
    name: "Hook Missing Error Handling",
    description: "Checks if hooks suppress errors silently",
    severity: "medium",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json") return [];
      const findings = [];
      const silentFailPatterns = [
        { pattern: /2>\/dev\/null/g, desc: "stderr silenced" },
        { pattern: /\|\|\s*true\b/g, desc: "errors suppressed with || true" },
        { pattern: /\|\|\s*:\s*$/gm, desc: "errors suppressed with || :" }
      ];
      for (const { pattern, desc } of silentFailPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-silent-fail-${match.index}`,
            severity: "medium",
            category: "hooks",
            title: `Hook silently suppresses errors: ${desc}`,
            description: `Hook uses "${match[0]}" which suppresses errors. A failing security hook that silently passes could miss real vulnerabilities.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0]
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-missing-pretooluse",
    name: "No PreToolUse Security Hooks",
    description: "Checks if there are PreToolUse hooks for security validation",
    severity: "medium",
    category: "misconfiguration",
    check(file) {
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
              description: "No PreToolUse hooks are defined. These hooks can catch dangerous operations before they run, providing an essential security layer.",
              file: file.path,
              fix: {
                description: "Add PreToolUse hooks for security-sensitive operations",
                before: '"hooks": {}',
                after: `"hooks": { "PreToolUse": [{ "matcher": "Bash && command matches 'rm -rf'", "hook": "echo 'Blocked' >&2 && exit 1" }] }`,
                auto: false
              }
            }
          ];
        }
      } catch {
      }
      return [];
    }
  },
  {
    id: "hooks-unthrottled-network",
    name: "Hook Unthrottled Network Requests",
    description: "Checks for PostToolUse hooks making HTTP requests on frequent tool calls without throttling",
    severity: "medium",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const postHooks = config?.hooks?.PostToolUse ?? [];
        const broadMatchers = ["Edit", "Write", "Read", "Bash", ""];
        const networkPatterns = /\b(curl|wget|fetch|http|nc|netcat)\b/i;
        for (const hook of postHooks) {
          const hookConfig = hook;
          const matcher = hookConfig.matcher ?? "";
          const command = hookConfig.hook ?? "";
          const isBroadMatcher = matcher === "" || broadMatchers.some((m) => m !== "" && matcher === m);
          if (isBroadMatcher && networkPatterns.test(command)) {
            findings.push({
              id: `hooks-unthrottled-network-${findings.length}`,
              severity: "medium",
              category: "hooks",
              title: `PostToolUse hook makes network request on broad matcher "${matcher || "*"}"`,
              description: `A PostToolUse hook fires on "${matcher || "every tool call"}" and runs a network command (${command.substring(0, 60)}...). Without throttling, this fires on every matching tool call \u2014 potentially hundreds per session \u2014 causing performance degradation and potential data exposure.`,
              file: file.path,
              evidence: `matcher: "${matcher}", hook: "${command.substring(0, 80)}"`,
              fix: {
                description: "Add rate limiting or narrow the matcher",
                before: `"matcher": "${matcher}"`,
                after: `"matcher": "Bash(npm publish)" or add throttle logic`,
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "hooks-sensitive-file-access",
    name: "Hook Accesses Sensitive Files",
    description: "Checks for hooks that read or write to sensitive system files",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const sensitivePathPatterns = [
        {
          pattern: /\/etc\/(?:passwd|shadow|sudoers|hosts)/g,
          desc: "system authentication/configuration file"
        },
        {
          pattern: /~\/\.ssh\/|\/\.ssh\//g,
          desc: "SSH directory (may contain private keys)"
        },
        {
          pattern: /~\/\.aws\/|\/\.aws\//g,
          desc: "AWS credentials directory"
        },
        {
          pattern: /~\/\.gnupg\/|\/\.gnupg\//g,
          desc: "GPG keyring directory"
        },
        {
          pattern: /~\/\.env|\/\.env\b/g,
          desc: "environment file (likely contains secrets)"
        },
        {
          pattern: /\/etc\/ssl\/|\/etc\/pki\//g,
          desc: "SSL/TLS certificate directory"
        }
      ];
      for (const { pattern, desc } of sensitivePathPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-sensitive-file-${match.index}`,
            severity: "high",
            category: "exposure",
            title: `Hook accesses sensitive path: ${match[0]}`,
            description: `A hook references "${match[0]}" \u2014 ${desc}. Hooks should not access sensitive system files. This could expose credentials, keys, or system configuration.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0]
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-no-stop-hooks",
    name: "No Stop Hooks for Session Verification",
    description: "Checks if there are Stop hooks for end-of-session verification",
    severity: "low",
    category: "misconfiguration",
    check(file) {
      if (file.type !== "settings-json") return [];
      try {
        const config = JSON.parse(file.content);
        const hooks = config?.hooks ?? {};
        if (Object.keys(hooks).length > 0 && !hooks.Stop?.length) {
          return [
            {
              id: "hooks-no-stop-hooks",
              severity: "low",
              category: "misconfiguration",
              title: "No Stop hooks for session-end verification",
              description: "Hooks are configured but no Stop hooks exist. Stop hooks run when a session ends and are useful for final verification \u2014 checking for uncommitted secrets, ensuring console.log statements were removed, or auditing file changes.",
              file: file.path,
              fix: {
                description: "Add a Stop hook for session-end checks",
                before: '"hooks": { ... }',
                after: '"hooks": { ..., "Stop": [{ "hook": "check-for-secrets.sh" }] }',
                auto: false
              }
            }
          ];
        }
      } catch {
      }
      return [];
    }
  },
  {
    id: "hooks-session-start-download",
    name: "Hook SessionStart Downloads Remote Content",
    description: "Checks for SessionStart hooks that download or execute remote scripts",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const sessionHooks = config?.hooks?.SessionStart ?? [];
        const remoteExecutionPatterns = [
          {
            pattern: /\b(curl|wget)\b.*\|\s*(sh|bash|zsh|node|python)/i,
            desc: "Downloads and pipes to shell \u2014 classic remote code execution vector",
            severity: "critical"
          },
          {
            pattern: /\b(curl|wget)\b.*https?:\/\//i,
            desc: "Downloads remote content on every session start",
            severity: "high"
          },
          {
            pattern: /\bgit\s+clone\b/i,
            desc: "Clones a repository on session start \u2014 could pull malicious code",
            severity: "medium"
          }
        ];
        for (const hook of sessionHooks) {
          const hookConfig = hook;
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
                  auto: false
                }
              });
              break;
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "hooks-expensive-unscoped",
    name: "Hook Expensive Unscoped Command",
    description: "Checks for PostToolUse hooks running expensive build/lint commands with broad matchers",
    severity: "low",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const postHooks = config?.hooks?.PostToolUse ?? [];
        const expensiveCommands = /\b(tsc|eslint|prettier|webpack|jest|vitest|mocha|esbuild|rollup|turbo)\b/;
        const broadMatchers = ["Edit", "Write", ""];
        for (const hook of postHooks) {
          const hookConfig = hook;
          const matcher = hookConfig.matcher ?? "";
          const command = hookConfig.hook ?? "";
          const isBroadMatcher = matcher === "" || broadMatchers.some((m) => m !== "" && matcher === m);
          const expensiveMatch = command.match(expensiveCommands);
          if (isBroadMatcher && expensiveMatch) {
            findings.push({
              id: `hooks-expensive-unscoped-${findings.length}`,
              severity: "low",
              category: "hooks",
              title: `PostToolUse runs "${expensiveMatch[0]}" on broad matcher "${matcher || "*"}"`,
              description: `A PostToolUse hook runs "${expensiveMatch[0]}" on every "${matcher || "tool call"}" event. Build tools and linters can take seconds to run \u2014 firing on every edit wastes resources and slows down the agent. Scope the matcher to specific file types or add conditional checks.`,
              file: file.path,
              evidence: `matcher: "${matcher}", hook: "${command.substring(0, 80)}"`,
              fix: {
                description: "Scope the matcher to reduce unnecessary runs",
                before: `"matcher": "${matcher}"`,
                after: `"matcher": "Edit(*.ts)" or add file-extension check in the hook script`,
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  }
];

// src/rules/mcp.ts
var MCP_RISK_PROFILES = [
  {
    namePattern: /filesystem/i,
    risk: "high",
    description: "Filesystem MCP grants read/write access to the file system",
    recommendation: "Restrict to specific directories using allowedDirectories config"
  },
  {
    namePattern: /puppeteer|playwright|browser/i,
    risk: "high",
    description: "Browser automation MCP can navigate to arbitrary URLs and run JavaScript",
    recommendation: "Restrict to specific domains and disable script running where possible"
  },
  {
    namePattern: /shell|terminal|command/i,
    risk: "critical",
    description: "Shell/command MCP grants arbitrary command running",
    recommendation: "Use allowlist of specific commands instead of unrestricted shell access"
  },
  {
    namePattern: /database|postgres|mysql|sqlite|mongo/i,
    risk: "high",
    description: "Database MCP can read/write database contents",
    recommendation: "Use read-only connection and restrict to specific tables/schemas"
  },
  {
    namePattern: /slack|discord|email|sendgrid/i,
    risk: "medium",
    description: "Messaging MCP can send messages to external services",
    recommendation: "Restrict to specific channels and require confirmation for sends"
  }
];
var mcpRules = [
  {
    id: "mcp-risky-servers",
    name: "Risky MCP Server Configuration",
    description: "Checks MCP server configs for servers that grant excessive capabilities",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, _server] of Object.entries(servers)) {
          for (const profile of MCP_RISK_PROFILES) {
            if (profile.namePattern.test(name)) {
              findings.push({
                id: `mcp-risky-${name}`,
                severity: profile.risk,
                category: "mcp",
                title: `${profile.risk.toUpperCase()} risk MCP server: ${name}`,
                description: `${profile.description}. ${profile.recommendation}.`,
                file: file.path
              });
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-hardcoded-env",
    name: "MCP Hardcoded Environment Variables",
    description: "Checks if MCP configs have hardcoded secrets instead of env var references",
    severity: "critical",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const env = serverConfig.env ?? {};
          for (const [key, value] of Object.entries(env)) {
            if (value && !value.startsWith("${") && !value.startsWith("$")) {
              const isSecret = /key|token|secret|password|credential|auth/i.test(key);
              if (isSecret) {
                findings.push({
                  id: `mcp-hardcoded-env-${name}-${key}`,
                  severity: "critical",
                  category: "secrets",
                  title: `Hardcoded secret in MCP server "${name}": ${key}`,
                  description: `The environment variable "${key}" for MCP server "${name}" appears to contain a hardcoded secret instead of an environment variable reference.`,
                  file: file.path,
                  evidence: `${key}: "${value.substring(0, 4)}..."`,
                  fix: {
                    description: "Use environment variable reference",
                    before: `"${key}": "${value}"`,
                    after: `"${key}": "\${${key}}"`,
                    auto: true
                  }
                });
              }
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-npx-supply-chain",
    name: "MCP npx Supply Chain Risk",
    description: "Checks for MCP servers using npx -y which auto-installs packages without confirmation",
    severity: "medium",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const command = serverConfig.command;
          const args = serverConfig.args ?? [];
          if (command === "npx" && args.includes("-y")) {
            findings.push({
              id: `mcp-npx-y-${name}`,
              severity: "medium",
              category: "mcp",
              title: `MCP server "${name}" uses npx -y (auto-install)`,
              description: `The MCP server "${name}" uses "npx -y" which automatically installs packages without confirmation. A typosquatting or supply chain attack could run malicious code.`,
              file: file.path,
              fix: {
                description: "Install the package explicitly and reference it directly, or pin a specific version",
                before: `"command": "npx", "args": ["-y", "${args[1] ?? "package"}"]`,
                after: `Install with: npm install ${args[1] ?? "package"}, then reference directly`,
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-no-description",
    name: "MCP Server Missing Description",
    description: "MCP servers without descriptions make auditing harder",
    severity: "info",
    category: "misconfiguration",
    check(file) {
      if (file.type !== "mcp-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          if (!serverConfig.description) {
            findings.push({
              id: `mcp-no-desc-${name}`,
              severity: "info",
              category: "misconfiguration",
              title: `MCP server "${name}" has no description`,
              description: `Add a description to make security auditing easier: what does this server do and why is it needed?`,
              file: file.path
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-unrestricted-root-path",
    name: "MCP Unrestricted Root Path",
    description: "Checks for MCP servers with filesystem access to root or home directory",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const rootPaths = ["/", "~", "C:\\", "C:/"];
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const args = serverConfig.args ?? [];
          for (const arg of args) {
            if (rootPaths.includes(arg)) {
              findings.push({
                id: `mcp-root-path-${name}`,
                severity: "high",
                category: "mcp",
                title: `MCP server "${name}" has unrestricted path: ${arg}`,
                description: `The MCP server "${name}" is configured with path "${arg}" which grants access to the entire filesystem. This allows an agent to read, write, or delete any file on the system.`,
                file: file.path,
                evidence: `args: ${JSON.stringify(args)}`,
                fix: {
                  description: "Restrict to project-specific directories",
                  before: `"${arg}"`,
                  after: `"./src", "./docs"`,
                  auto: false
                }
              });
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-no-version-pin",
    name: "MCP No Version Pin",
    description: "Checks for MCP servers using npx with unversioned packages",
    severity: "medium",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const command = serverConfig.command;
          const args = serverConfig.args ?? [];
          if (command !== "npx") continue;
          const packageArg = args.find(
            (a) => !a.startsWith("-") && a.includes("/")
          );
          if (!packageArg) continue;
          const afterScope = packageArg.startsWith("@") ? packageArg.substring(packageArg.indexOf("/")) : packageArg;
          const hasVersion = afterScope.includes("@");
          if (!hasVersion) {
            findings.push({
              id: `mcp-no-version-${name}`,
              severity: "medium",
              category: "mcp",
              title: `MCP server "${name}" uses unversioned package: ${packageArg}`,
              description: `The MCP server "${name}" uses "${packageArg}" without a pinned version. A compromised package update would run automatically via npx.`,
              file: file.path,
              evidence: `command: npx, package: ${packageArg}`,
              fix: {
                description: "Pin to a specific version",
                before: `"${packageArg}"`,
                after: `"${packageArg}@1.0.0"`,
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-url-transport",
    name: "MCP External URL Transport",
    description: "Checks for MCP servers using URL-based transport connecting to external hosts",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const url = serverConfig.url;
          if (!url) continue;
          const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/i.test(url);
          if (!isLocal) {
            findings.push({
              id: `mcp-url-transport-${name}`,
              severity: "high",
              category: "mcp",
              title: `MCP server "${name}" connects to external URL`,
              description: `The MCP server "${name}" uses URL transport connecting to "${url}". External MCP connections send all tool calls and results over the network, potentially exposing code, secrets, and session data to a remote server. Prefer local stdio-based MCP servers.`,
              file: file.path,
              evidence: url.substring(0, 100),
              fix: {
                description: "Use a local stdio-based MCP server instead",
                before: `"url": "${url.substring(0, 40)}"`,
                after: '"command": "node", "args": ["./local-server.js"]',
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-remote-command",
    name: "MCP Remote Command Execution",
    description: "Checks for MCP servers that download and execute remote code",
    severity: "critical",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const command = serverConfig.command ?? "";
          const args = serverConfig.args ?? [];
          const fullCommand = `${command} ${args.join(" ")}`;
          if (/\b(curl|wget)\b.*\|\s*(sh|bash|zsh|node|python)/i.test(fullCommand)) {
            findings.push({
              id: `mcp-remote-exec-${name}`,
              severity: "critical",
              category: "mcp",
              title: `MCP server "${name}" pipes remote download to shell`,
              description: `The MCP server "${name}" downloads remote code and pipes it directly to a shell interpreter. This is a critical remote code execution vulnerability \u2014 a compromised URL silently runs arbitrary commands.`,
              file: file.path,
              evidence: fullCommand.substring(0, 100),
              fix: {
                description: "Download, verify, then execute separately",
                before: fullCommand.substring(0, 60),
                after: "Install the package locally with npm/pip and reference it directly",
                auto: false
              }
            });
            continue;
          }
          const hasRemoteUrl = args.some(
            (a) => /^https?:\/\/.+\.(sh|py|js|ts|exe|bin)$/i.test(a)
          );
          if (hasRemoteUrl && /^(sh|bash|zsh|node|python|ruby)$/.test(command)) {
            findings.push({
              id: `mcp-remote-script-${name}`,
              severity: "high",
              category: "mcp",
              title: `MCP server "${name}" executes remote script URL`,
              description: `The MCP server "${name}" runs a shell interpreter with a remote script URL as an argument. The remote script could be changed at any time, making this a supply chain risk.`,
              file: file.path,
              evidence: fullCommand.substring(0, 100),
              fix: {
                description: "Download the script locally and reference the local copy",
                before: fullCommand.substring(0, 60),
                after: "Use a locally installed package or script",
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-shell-metacharacters",
    name: "MCP Shell Metacharacters in Args",
    description: "Checks for shell metacharacters in MCP server arguments that could enable command injection",
    severity: "medium",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const shellMetachars = /[;|&`$(){}]/;
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const command = serverConfig.command ?? "";
          const args = serverConfig.args ?? [];
          if (/^(sh|bash|zsh|cmd)$/.test(command)) continue;
          for (const arg of args) {
            if (arg.startsWith("-")) continue;
            if (shellMetachars.test(arg)) {
              findings.push({
                id: `mcp-shell-metachar-${name}`,
                severity: "medium",
                category: "mcp",
                title: `MCP server "${name}" has shell metacharacters in args`,
                description: `The argument "${arg.substring(0, 60)}" for MCP server "${name}" contains shell metacharacters (;|&\`$). If the command spawns a shell, these could enable command injection. Use separate args instead of shell syntax.`,
                file: file.path,
                evidence: arg.substring(0, 80),
                fix: {
                  description: "Split into separate arguments without shell metacharacters",
                  before: `"${arg.substring(0, 40)}"`,
                  after: "Split into separate args array elements",
                  auto: false
                }
              });
              break;
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-excessive-server-count",
    name: "MCP Excessive Server Count",
    description: "Flags configurations with too many MCP servers",
    severity: "low",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const count = Object.keys(servers).length;
        if (count > 10) {
          return [
            {
              id: "mcp-excessive-servers",
              severity: "low",
              category: "mcp",
              title: `${count} MCP servers configured \u2014 large attack surface`,
              description: `This configuration has ${count} MCP servers. Each server expands the attack surface through supply chain risk, environment variable exposure, and additional capabilities granted to the agent. Consider removing servers that are not actively needed.`,
              file: file.path
            }
          ];
        }
      } catch {
      }
      return [];
    }
  }
];

// src/rules/agents.ts
function findLineNumber4(content, matchIndex) {
  return content.substring(0, matchIndex).split("\n").length;
}
function findAllMatches3(content, pattern) {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return [...content.matchAll(new RegExp(pattern.source, flags))];
}
var agentRules = [
  {
    id: "agents-unrestricted-tools",
    name: "Agent with Unrestricted Tool Access",
    description: "Checks if agent definitions grant excessive tool access",
    severity: "high",
    category: "agents",
    check(file) {
      if (file.type !== "agent-md") return [];
      const findings = [];
      const toolsMatch = file.content.match(/tools:\s*\[([^\]]*)\]/);
      if (toolsMatch) {
        const tools = toolsMatch[1].split(",").map((t) => t.trim().replace(/["']/g, ""));
        if (tools.includes("Bash")) {
          findings.push({
            id: `agents-bash-access-${file.path}`,
            severity: "high",
            category: "agents",
            title: `Agent has Bash access: ${file.path}`,
            description: "This agent has Bash tool access, allowing arbitrary command running. Consider if this agent truly needs shell access, or if Read/Write/Edit would suffice.",
            file: file.path
          });
        }
        const hasWrite = tools.some((t) => ["Write", "Edit"].includes(t));
        const descriptionLower = file.content.toLowerCase();
        const isExplorer = descriptionLower.includes("explorer") || descriptionLower.includes("search") || descriptionLower.includes("read-only") || descriptionLower.includes("readonly");
        if (hasWrite && isExplorer) {
          findings.push({
            id: `agents-explorer-write-${file.path}`,
            severity: "medium",
            category: "agents",
            title: `Explorer/search agent has write access: ${file.path}`,
            description: "This agent appears to be an explorer or search agent but has Write/Edit access. Read-only agents should only have Read, Grep, and Glob tools.",
            file: file.path
          });
        }
      }
      const modelMatch = file.content.match(/model:\s*(\w+)/);
      if (!modelMatch) {
        findings.push({
          id: `agents-no-model-${file.path}`,
          severity: "low",
          category: "misconfiguration",
          title: `Agent has no model specified: ${file.path}`,
          description: "No model is specified in the agent frontmatter. This will use the default model, which may be more expensive than needed. Specify 'haiku' for lightweight tasks.",
          file: file.path
        });
      }
      return findings;
    }
  },
  {
    id: "agents-no-tools-restriction",
    name: "Agent Without Tools Restriction",
    description: "Checks if agent definitions omit the tools array entirely, inheriting all tools by default",
    severity: "high",
    category: "agents",
    check(file) {
      if (file.type !== "agent-md") return [];
      const hasFrontmatter = file.content.startsWith("---");
      if (!hasFrontmatter) return [];
      const frontmatterEnd = file.content.indexOf("---", 3);
      if (frontmatterEnd === -1) return [];
      const frontmatter = file.content.substring(0, frontmatterEnd);
      const hasToolsField = /\btools\s*:/i.test(frontmatter);
      if (!hasToolsField) {
        return [
          {
            id: `agents-no-tools-${file.path}`,
            severity: "high",
            category: "agents",
            title: `Agent has no tools restriction: ${file.path}`,
            description: "This agent definition has frontmatter but does not specify a tools array. Without an explicit tools list, the agent may inherit all available tools by default, including Bash, Write, and Edit. Always specify the minimum set of tools needed.",
            file: file.path,
            fix: {
              description: "Add an explicit tools array to the frontmatter",
              before: "---\nname: agent\n---",
              after: '---\nname: agent\ntools: ["Read", "Grep", "Glob"]\n---',
              auto: false
            }
          }
        ];
      }
      return [];
    }
  },
  {
    id: "agents-claude-md-url-execution",
    name: "CLAUDE.md URL Execution",
    description: "Checks CLAUDE.md files for instructions to download and execute remote content",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "claude-md") return [];
      const findings = [];
      const urlExecPatterns = [
        {
          pattern: /\b(curl|wget)\s+.*https?:\/\/[^\s]+.*\|\s*(sh|bash|zsh|node|python)/gi,
          desc: "Pipe-to-shell instruction \u2014 downloading and executing remote code",
          severity: "critical"
        },
        {
          pattern: /\b(curl|wget)\s+(-[a-zA-Z]*\s+)*https?:\/\/[^\s]+/gi,
          desc: "Download instruction in CLAUDE.md \u2014 if the agent follows this, it will fetch remote content",
          severity: "high"
        },
        {
          pattern: /\bgit\s+clone\s+https?:\/\/[^\s]+/gi,
          desc: "Git clone instruction \u2014 could pull malicious repository content",
          severity: "medium"
        },
        {
          pattern: /\bnpm\s+install\s+https?:\/\/[^\s]+/gi,
          desc: "npm install from URL \u2014 could install unvetted package",
          severity: "high"
        }
      ];
      for (const { pattern, desc, severity } of urlExecPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-claude-md-url-exec-${match.index}`,
            severity,
            category: "injection",
            title: "CLAUDE.md contains URL execution instruction",
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. A malicious repository could include a CLAUDE.md with instructions to download and run arbitrary code.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-prompt-injection-patterns",
    name: "Agent Prompt Injection Patterns",
    description: "Checks agent definitions for patterns commonly used in prompt injection attacks",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md") return [];
      const findings = [];
      const injectionPatterns = [
        {
          pattern: /ignore\s+(?:all\s+)?previous\s+(?:instructions|rules|constraints)/gi,
          desc: "Instruction override attempt"
        },
        {
          pattern: /disregard\s+(?:all\s+)?(?:safety|security|restrictions|guidelines)/gi,
          desc: "Safety bypass attempt"
        },
        {
          pattern: /you\s+are\s+now\s+(?:a|an|in)\s/gi,
          desc: "Role reassignment attempt"
        },
        {
          pattern: /bypass\s+(?:security|safety|permissions|restrictions|authentication)/gi,
          desc: "Security bypass instruction"
        },
        {
          pattern: /(?:do\s+not|don'?t)\s+(?:follow|obey|respect)\s+(?:the\s+)?(?:rules|instructions|guidelines)/gi,
          desc: "Rule override instruction"
        }
      ];
      for (const { pattern, desc } of injectionPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-injection-pattern-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Prompt injection pattern in agent definition`,
            description: `Found "${match[0]}" \u2014 ${desc}. If this agent definition is contributed by an external source, this could be an attempt to override the agent's safety constraints.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0]
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-hidden-instructions",
    name: "Hidden Instructions via Unicode",
    description: "Checks for invisible Unicode characters that could hide malicious instructions in agent definitions or CLAUDE.md",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const unicodeTricks = [
        {
          pattern: /[\u200B\u200C\u200D\uFEFF]/g,
          name: "zero-width character",
          description: "Zero-width characters (U+200B/200C/200D/FEFF) can hide text from visual inspection while still being processed by the model"
        },
        {
          pattern: /[\u202A-\u202E\u2066-\u2069]/g,
          name: "bidirectional override",
          description: "Bidirectional text override characters (U+202A-202E, U+2066-2069) can reverse displayed text direction, making malicious instructions appear differently than they actually read"
        },
        {
          pattern: /[\u00AD]/g,
          name: "soft hyphen",
          description: "Soft hyphens (U+00AD) are invisible but can break up keywords to evade pattern matching while preserving the original meaning for the model"
        },
        {
          pattern: /[\uE000-\uF8FF]/g,
          name: "private use area character",
          description: "Private Use Area characters (U+E000-F8FF) have no standard meaning and could carry hidden payloads or encode instructions"
        },
        {
          pattern: /[\u2028\u2029]/g,
          name: "line/paragraph separator",
          description: "Unicode line/paragraph separators (U+2028/2029) create invisible line breaks that can inject hidden instructions between visible lines"
        }
      ];
      for (const { pattern, name, description } of unicodeTricks) {
        const matches = findAllMatches3(file.content, pattern);
        if (matches.length > 0) {
          findings.push({
            id: `agents-hidden-unicode-${name.replace(/\s/g, "-")}`,
            severity: "critical",
            category: "injection",
            title: `Hidden ${name} detected (${matches.length} occurrences)`,
            description: `${description}. Found ${matches.length} instance(s) in ${file.path}. This is a prompt injection technique \u2014 review the file in a hex editor.`,
            file: file.path,
            line: findLineNumber4(file.content, matches[0].index ?? 0),
            evidence: `${matches.length}x ${name}`,
            fix: {
              description: `Remove all ${name}s from the file`,
              before: `File contains ${matches.length} hidden characters`,
              after: "Clean text with no invisible Unicode characters",
              auto: false
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-prompt-injection-surface",
    name: "Agent Prompt Injection Surface",
    description: "Checks agent definitions for patterns that increase prompt injection risk",
    severity: "medium",
    category: "agents",
    check(file) {
      if (file.type !== "agent-md") return [];
      const findings = [];
      const externalContentPatterns = [
        /fetch.*url/i,
        /read.*user.*input/i,
        /process.*external/i,
        /parse.*html/i,
        /web.*content/i
      ];
      for (const pattern of externalContentPatterns) {
        if (pattern.test(file.content)) {
          findings.push({
            id: `agents-injection-surface-${file.path}`,
            severity: "medium",
            category: "agents",
            title: `Agent processes external content: ${file.path}`,
            description: "This agent appears to process external or user-provided content. Ensure prompt injection defenses are in place: validate inputs, use system prompts to anchor behavior, and never trust content from external sources.",
            file: file.path
          });
          break;
        }
      }
      return findings;
    }
  },
  {
    id: "agents-claude-md-instructions",
    name: "CLAUDE.md Instruction Injection",
    description: "Checks CLAUDE.md for patterns that could be exploited by malicious repos",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "claude-md") return [];
      const findings = [];
      const autoRunPatterns = [
        {
          pattern: /always\s+(?:run|install|download)/gi,
          desc: "Auto-run instructions"
        },
        {
          pattern: /automatically\s+(?:run|install|clone)/gi,
          desc: "Automatic running"
        },
        {
          pattern: /without\s+(?:asking|confirmation|prompting)/gi,
          desc: "Bypasses confirmation"
        }
      ];
      for (const { pattern, desc } of autoRunPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-claude-md-autorun-${match.index}`,
            severity: "high",
            category: "injection",
            title: `CLAUDE.md contains auto-run instruction`,
            description: `Found "${match[0]}" \u2014 ${desc}. If this CLAUDE.md is in a cloned repository, a malicious repo could use this to run arbitrary commands when a developer opens it with Claude Code.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0]
          });
        }
      }
      return findings;
    }
  }
];

// src/rules/index.ts
function getBuiltinRules() {
  return [
    ...secretRules,
    ...permissionRules,
    ...hookRules,
    ...mcpRules,
    ...agentRules
  ];
}

// src/scanner/index.ts
function scan(targetPath) {
  const target = discoverConfigFiles(targetPath);
  const rules = getBuiltinRules();
  const findings = runRules(target.files, rules);
  return { target, findings };
}
function runRules(files, rules) {
  const findings = [];
  for (const file of files) {
    for (const rule of rules) {
      const ruleFindings = rule.check(file);
      findings.push(...ruleFindings);
    }
  }
  return [...findings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return order[a.severity] - order[b.severity];
  });
}

// src/reporter/score.ts
function calculateScore(result) {
  const { findings, target } = result;
  const summary = summarizeFindings(findings, target.files.length);
  const score = computeScore(findings);
  return {
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    targetPath: target.path,
    findings,
    score,
    summary
  };
}
function summarizeFindings(findings, filesScanned) {
  const autoFixable = findings.filter((f) => f.fix?.auto).length;
  return {
    totalFindings: findings.length,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
    filesScanned,
    autoFixable
  };
}
function computeScore(findings) {
  const deductions = {
    critical: 25,
    high: 15,
    medium: 5,
    low: 2,
    info: 0
  };
  let totalDeduction = 0;
  const categoryDeductions = {
    secrets: 0,
    permissions: 0,
    hooks: 0,
    mcp: 0,
    agents: 0
  };
  for (const finding of findings) {
    const deduction = deductions[finding.severity] ?? 0;
    totalDeduction += deduction;
    const scoreCategory = mapToScoreCategory(finding.category);
    categoryDeductions[scoreCategory] = (categoryDeductions[scoreCategory] ?? 0) + deduction;
  }
  const numericScore = Math.max(0, 100 - totalDeduction);
  const grade = scoreToGrade(numericScore);
  const maxCategoryScore = 100;
  const breakdown = {
    secrets: Math.max(0, maxCategoryScore - categoryDeductions.secrets),
    permissions: Math.max(0, maxCategoryScore - categoryDeductions.permissions),
    hooks: Math.max(0, maxCategoryScore - categoryDeductions.hooks),
    mcp: Math.max(0, maxCategoryScore - categoryDeductions.mcp),
    agents: Math.max(0, maxCategoryScore - categoryDeductions.agents)
  };
  return { grade, numericScore, breakdown };
}
function mapToScoreCategory(category) {
  const mapping = {
    secrets: "secrets",
    permissions: "permissions",
    hooks: "hooks",
    injection: "hooks",
    mcp: "mcp",
    agents: "agents",
    exposure: "hooks",
    misconfiguration: "permissions"
  };
  return mapping[category] ?? "permissions";
}
function scoreToGrade(score) {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

// src/reporter/json.ts
function renderJsonReport(report) {
  return JSON.stringify(report, null, 2);
}
function renderMarkdownReport(report) {
  const lines = [];
  const s = report.summary;
  lines.push("# AgentShield Security Report");
  lines.push("");
  lines.push(`**Date:** ${report.timestamp}`);
  lines.push(`**Target:** ${report.targetPath}`);
  lines.push(`**Grade:** ${report.score.grade} (${report.score.numericScore}/100)`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("|--------|-------|");
  lines.push(`| Files scanned | ${s.filesScanned} |`);
  lines.push(`| Total findings | ${s.totalFindings} |`);
  lines.push(`| Critical | ${s.critical} |`);
  lines.push(`| High | ${s.high} |`);
  lines.push(`| Medium | ${s.medium} |`);
  lines.push(`| Low | ${s.low} |`);
  lines.push(`| Info | ${s.info} |`);
  lines.push(`| Auto-fixable | ${s.autoFixable} |`);
  lines.push("");
  lines.push("## Score Breakdown");
  lines.push("");
  lines.push("| Category | Score |");
  lines.push("|----------|-------|");
  lines.push(`| Secrets | ${report.score.breakdown.secrets}/100 |`);
  lines.push(`| Permissions | ${report.score.breakdown.permissions}/100 |`);
  lines.push(`| Hooks | ${report.score.breakdown.hooks}/100 |`);
  lines.push(`| MCP Servers | ${report.score.breakdown.mcp}/100 |`);
  lines.push(`| Agents | ${report.score.breakdown.agents}/100 |`);
  lines.push("");
  if (report.findings.length > 0) {
    lines.push("## Findings");
    lines.push("");
    for (const finding of report.findings) {
      const emoji = finding.severity === "critical" ? "\u{1F534}" : finding.severity === "high" ? "\u{1F7E1}" : finding.severity === "medium" ? "\u{1F535}" : "\u26AA";
      lines.push(`### ${emoji} ${finding.title}`);
      lines.push("");
      lines.push(`- **Severity:** ${finding.severity}`);
      lines.push(`- **Category:** ${finding.category}`);
      lines.push(`- **File:** \`${finding.file}${finding.line ? `:${finding.line}` : ""}\``);
      lines.push(`- **Description:** ${finding.description}`);
      if (finding.evidence) {
        lines.push(`- **Evidence:** \`${finding.evidence}\``);
      }
      if (finding.fix) {
        lines.push(`- **Fix:** ${finding.fix.description}`);
        if (finding.fix.auto) {
          lines.push("- **Auto-fixable:** Yes");
        }
      }
      lines.push("");
    }
  } else {
    lines.push("## No Issues Found");
    lines.push("");
    lines.push("No security issues were detected in the scanned configuration.");
  }
  return lines.join("\n");
}

export {
  scan,
  calculateScore,
  renderJsonReport,
  renderMarkdownReport
};
