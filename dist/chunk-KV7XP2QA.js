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
