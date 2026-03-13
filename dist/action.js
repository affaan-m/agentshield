// src/action.ts
import { resolve } from "path";
import { existsSync as existsSync2 } from "fs";
import { appendFileSync } from "fs";

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
  },
  {
    name: "discord-token",
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g,
    description: "Discord bot token"
  },
  {
    name: "npm-token",
    pattern: /npm_[a-zA-Z0-9]{36,}/g,
    description: "npm access token"
  },
  {
    name: "sendgrid-key",
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    description: "SendGrid API key"
  },
  {
    name: "twilio-key",
    pattern: /SK[a-f0-9]{32}/g,
    description: "Twilio API key"
  },
  {
    name: "azure-key",
    pattern: /[a-zA-Z0-9\/+]{86}==/g,
    description: "Azure storage account key"
  },
  {
    name: "mailchimp-key",
    pattern: /[a-f0-9]{32}-us\d{1,2}/g,
    description: "Mailchimp API key"
  },
  {
    name: "huggingface-token",
    pattern: /hf_[a-zA-Z0-9]{20,}/g,
    description: "Hugging Face access token"
  },
  {
    name: "databricks-token",
    pattern: /dapi[a-f0-9]{32}/g,
    description: "Databricks personal access token"
  },
  {
    name: "digitalocean-token",
    pattern: /dop_v1_[a-f0-9]{64}/g,
    description: "DigitalOcean personal access token"
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
            Math.max(0, idx - 20),
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
  },
  {
    id: "secrets-url-credentials",
    name: "URL-Embedded Credentials",
    description: "Checks for URLs containing embedded usernames and passwords",
    severity: "high",
    category: "secrets",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const urlCredPattern = /https?:\/\/[^:\s]+:[^@\s]+@[^\s"']+/g;
      const matches = findAllMatches(file.content, urlCredPattern);
      for (const match of matches) {
        const idx = match.index ?? 0;
        const context = file.content.substring(Math.max(0, idx - 20), idx);
        if (context.includes("${") || context.includes("process.env")) continue;
        const masked = match[0].replace(/(:\/\/[^:]+:)[^@]+(@)/, "$1****$2");
        findings.push({
          id: `secrets-url-credentials-${idx}`,
          severity: "high",
          category: "secrets",
          title: `URL contains embedded credentials`,
          description: `Found a URL with embedded username:password in ${file.path}. Credentials in URLs are exposed in logs, browser history, and referer headers. Use environment variables or a credentials manager instead.`,
          file: file.path,
          line: findLineNumber(file.content, idx),
          evidence: masked,
          fix: {
            description: "Use environment variables for credentials",
            before: match[0].substring(0, 40),
            after: "https://${USERNAME}:${PASSWORD}@...",
            auto: false
          }
        });
      }
      return findings;
    }
  },
  {
    id: "secrets-credential-file-reference",
    name: "Credential File Reference",
    description: "Checks for references to credential files that should never be accessed by agents",
    severity: "high",
    category: "secrets",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const credentialFiles = [
        {
          pattern: /~\/\.aws\/credentials|\/\.aws\/credentials/g,
          description: "AWS credentials file"
        },
        {
          pattern: /~\/\.ssh\/id_(?:rsa|ed25519|ecdsa)|\/\.ssh\/id_(?:rsa|ed25519|ecdsa)/g,
          description: "SSH private key file"
        },
        {
          pattern: /~\/\.netrc|\/\.netrc/g,
          description: ".netrc file (contains plain-text login credentials)"
        },
        {
          pattern: /~\/\.pgpass|\/\.pgpass/g,
          description: "PostgreSQL password file"
        },
        {
          pattern: /~\/\.docker\/config\.json|\/\.docker\/config\.json/g,
          description: "Docker config (may contain registry credentials)"
        },
        {
          pattern: /~\/\.npmrc|\/\.npmrc/g,
          description: "npm config (may contain auth tokens)"
        },
        {
          pattern: /~\/\.kube\/config|\/\.kube\/config/g,
          description: "Kubernetes config (contains cluster credentials)"
        }
      ];
      for (const { pattern, description } of credentialFiles) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;
          findings.push({
            id: `secrets-cred-file-ref-${idx}`,
            severity: "high",
            category: "secrets",
            title: `Reference to ${description}: ${match[0]}`,
            description: `Found reference to "${match[0]}" \u2014 ${description}. Agent definitions and CLAUDE.md files should not reference credential files. If an agent is instructed to read these files, it could expose secrets.`,
            file: file.path,
            line: findLineNumber(file.content, idx),
            evidence: match[0]
          });
        }
      }
      return findings;
    }
  },
  {
    id: "secrets-private-key-material",
    name: "Private Key Material in Config",
    description: "Checks for PEM-encoded private keys embedded in configuration files",
    severity: "critical",
    category: "secrets",
    check(file) {
      const findings = [];
      const keyPatterns = [
        {
          pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
          description: "PEM-encoded private key"
        },
        {
          pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
          description: "PGP private key block"
        }
      ];
      for (const { pattern, description } of keyPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;
          findings.push({
            id: `secrets-private-key-${idx}`,
            severity: "critical",
            category: "secrets",
            title: `${description} found in config`,
            description: `Found "${match[0]}" in ${file.path}. Private keys should never be stored in configuration files \u2014 they grant authentication access and should be stored in secure key stores or referenced via file paths with restrictive permissions.`,
            file: file.path,
            line: findLineNumber(file.content, idx),
            evidence: match[0],
            fix: {
              description: "Remove private key and reference a key file path instead",
              before: match[0],
              after: "Reference key file: ~/.ssh/id_ed25519",
              auto: false
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "secrets-webhook-url",
    name: "Webhook URL with Secret Token",
    description: "Checks for webhook URLs that contain embedded secret tokens or API keys",
    severity: "high",
    category: "secrets",
    check(file) {
      const findings = [];
      const webhookPatterns = [
        {
          pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
          description: "Slack webhook URL \u2014 allows posting messages to a Slack channel"
        },
        {
          pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+/g,
          description: "Discord webhook URL \u2014 allows posting messages to a Discord channel"
        },
        {
          pattern: /https:\/\/outlook\.office\.com\/webhook\/[a-f0-9-]+/g,
          description: "Microsoft Teams webhook URL"
        }
      ];
      for (const { pattern, description } of webhookPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;
          findings.push({
            id: `secrets-webhook-url-${idx}`,
            severity: "high",
            category: "secrets",
            title: `Webhook URL found: ${description.split(" \u2014 ")[0]}`,
            description: `Found a ${description}. Webhook URLs contain embedded secrets and should be stored in environment variables. Anyone with this URL can post messages to the channel.`,
            file: file.path,
            line: findLineNumber(file.content, idx),
            evidence: match[0].substring(0, 30) + "...",
            fix: {
              description: "Store webhook URL in an environment variable",
              before: match[0].substring(0, 30),
              after: "${WEBHOOK_URL}",
              auto: false
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "secrets-base64-obfuscation",
    name: "Potential Base64 Obfuscated Secret",
    description: "Checks for long base64-encoded strings that may be obfuscated secrets or payloads",
    severity: "medium",
    category: "secrets",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const base64Pattern = /(?<![a-zA-Z0-9/])([A-Za-z0-9+/]{60,}={0,2})(?![a-zA-Z0-9])/g;
      const matches = findAllMatches(file.content, base64Pattern);
      for (const match of matches) {
        const idx = match.index ?? 0;
        const context = file.content.substring(Math.max(0, idx - 30), idx);
        if (/https?:\/\/|data:/.test(context)) continue;
        if (/^[a-fA-F0-9]+$/.test(match[1])) continue;
        findings.push({
          id: `secrets-base64-obfuscation-${idx}`,
          severity: "medium",
          category: "secrets",
          title: `Potential base64-obfuscated payload (${match[1].length} chars)`,
          description: `Found a long base64-encoded string (${match[1].length} characters) in ${file.path}. Attackers may encode secrets or malicious instructions in base64 to bypass pattern-matching detection. Decode and inspect this value.`,
          file: file.path,
          line: findLineNumber(file.content, idx),
          evidence: match[1].substring(0, 20) + "..." + match[1].substring(match[1].length - 10)
        });
      }
      return findings;
    }
  },
  {
    id: "secrets-hardcoded-ip-port",
    name: "Hardcoded Internal IP Address with Port",
    description: "Checks for hardcoded internal/private IP addresses with ports, which may expose internal services",
    severity: "medium",
    category: "secrets",
    check(file) {
      const findings = [];
      const ipPatterns = [
        {
          pattern: /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b/g,
          description: "Class A private IP (10.x.x.x) with port"
        },
        {
          pattern: /\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}:\d{2,5}\b/g,
          description: "Class B private IP (172.16-31.x.x) with port"
        },
        {
          pattern: /\b192\.168\.\d{1,3}\.\d{1,3}:\d{2,5}\b/g,
          description: "Class C private IP (192.168.x.x) with port"
        }
      ];
      for (const { pattern, description } of ipPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;
          findings.push({
            id: `secrets-hardcoded-ip-${idx}`,
            severity: "medium",
            category: "secrets",
            title: `Hardcoded internal IP with port: ${match[0]}`,
            description: `Found "${match[0]}" \u2014 ${description}. Hardcoded internal IPs expose network topology and service locations. Use environment variables or DNS names instead.`,
            file: file.path,
            line: findLineNumber(file.content, idx),
            evidence: match[0],
            fix: {
              description: "Replace with environment variable or DNS name",
              before: match[0],
              after: "${INTERNAL_SERVICE_URL}",
              auto: false
            }
          });
        }
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
  },
  {
    pattern: /^Bash\(chmod\s/,
    description: "chmod access \u2014 agent can change file permissions",
    severity: "medium",
    suggestion: "Move chmod to deny list to prevent permission escalation"
  },
  {
    pattern: /^Bash\(chown\s/,
    description: "chown access \u2014 agent can change file ownership",
    severity: "high",
    suggestion: "Move chown to deny list to prevent ownership takeover"
  },
  {
    pattern: /^Bash\(ssh\s/,
    description: "SSH access \u2014 agent can connect to remote systems",
    severity: "high",
    suggestion: "Remove SSH permissions to prevent lateral movement"
  },
  {
    pattern: /^Bash\(nc\s|^Bash\(netcat\s/,
    description: "Netcat access \u2014 can open network connections for exfiltration or reverse shells",
    severity: "high",
    suggestion: "Remove netcat permissions entirely"
  },
  {
    pattern: /^Bash\(python\s|^Bash\(python3\s|^Bash\(node\s/,
    description: "Interpreter access \u2014 agent can run arbitrary code via scripting language",
    severity: "high",
    suggestion: "Restrict to specific scripts: Bash(node scripts/build.js)"
  },
  {
    pattern: /^Bash\(docker\s/,
    description: "Docker access \u2014 containers can escape to host, mount filesystems, and access host network",
    severity: "high",
    suggestion: "Remove docker permissions or restrict to read-only: Bash(docker ps)"
  },
  {
    pattern: /^Bash\(kill\s|^Bash\(pkill\s|^Bash\(killall\s/,
    description: "Process killing \u2014 agent can terminate system processes",
    severity: "medium",
    suggestion: "Move process killing to deny list"
  },
  {
    pattern: /^Bash\(eval\s/,
    description: "eval access \u2014 agent can execute arbitrary code via shell eval",
    severity: "critical",
    suggestion: "Remove eval permissions; use explicit commands instead"
  },
  {
    pattern: /^Bash\(exec\s/,
    description: "exec access \u2014 agent can replace the current process with arbitrary commands",
    severity: "critical",
    suggestion: "Remove exec permissions; use explicit commands instead"
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
    pattern: /push\s+--force(?!-with-lease)|push\s+-f\b/,
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
      if (perms.deny.length === 0 && perms.allow.length > 0) {
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
  },
  {
    id: "permissions-sensitive-path-access",
    name: "Sensitive Path in Allow List",
    description: "Checks if the allow list permits tool access to sensitive system directories",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      const sensitivePaths = [
        { pattern: /\/etc\//, description: "system configuration directory" },
        { pattern: /~\/\.ssh|\/\.ssh/, description: "SSH keys and configuration" },
        { pattern: /~\/\.aws|\/\.aws/, description: "AWS credentials" },
        { pattern: /~\/\.gnupg|\/\.gnupg/, description: "GPG keyring" },
        { pattern: /\/root\//, description: "root user home directory" },
        { pattern: /\/var\/log/, description: "system log directory" }
      ];
      for (const entry of perms.allow) {
        for (const { pattern, description } of sensitivePaths) {
          if (pattern.test(entry)) {
            findings.push({
              id: `permissions-sensitive-path-${findings.length}`,
              severity: "high",
              category: "permissions",
              title: `Allow rule grants access to ${description}: ${entry}`,
              description: `The allow entry "${entry}" grants tool access to a sensitive directory (${description}). This could expose credentials, keys, or system configuration.`,
              file: file.path,
              evidence: entry,
              fix: {
                description: "Restrict to project directories only",
                before: entry,
                after: entry.replace(/\/etc\/.*|~\/\.ssh.*|\/\.ssh.*|~\/\.aws.*|\/\.aws.*|~\/\.gnupg.*|\/\.gnupg.*|\/root\/.*|\/var\/log.*/, "src/*"),
                auto: false
              }
            });
            break;
          }
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-wildcard-root-paths",
    name: "Wildcard Root Path in Allow List",
    description: "Checks if the allow list uses wildcards on root-level or home-level directories",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      const broadPathPatterns = [
        { pattern: /\(\/\*\)/, description: "root filesystem wildcard" },
        { pattern: /\(~\/\*\)/, description: "home directory wildcard" },
        { pattern: /\(\/home\/\*\)/, description: "all users home directories" },
        { pattern: /\(\/usr\/\*\)/, description: "system programs directory" },
        { pattern: /\(\/opt\/\*\)/, description: "optional software directory" }
      ];
      for (const entry of perms.allow) {
        for (const { pattern, description } of broadPathPatterns) {
          if (pattern.test(entry)) {
            findings.push({
              id: `permissions-wildcard-root-${findings.length}`,
              severity: "high",
              category: "permissions",
              title: `Broad wildcard path in allow list: ${entry}`,
              description: `The allow entry "${entry}" uses a ${description}. This grants the agent access to far more files than typically needed. Restrict to project-specific paths.`,
              file: file.path,
              evidence: entry,
              fix: {
                description: "Restrict to project-specific directories",
                before: entry,
                after: entry.replace(/\(.*\)/, "(./src/*)"),
                auto: false
              }
            });
            break;
          }
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-no-permissions-block",
    name: "No Permissions Block Configured",
    description: "Checks if settings.json exists but has no permissions configuration at all",
    severity: "medium",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      try {
        const config = JSON.parse(file.content);
        const hasOtherConfig = Object.keys(config).some(
          (k) => k !== "permissions" && k !== "$schema"
        );
        if (hasOtherConfig && !config.permissions) {
          return [
            {
              id: "permissions-no-block",
              severity: "medium",
              category: "permissions",
              title: "No permissions block configured",
              description: "settings.json has configuration but no permissions section. Without explicit allow/deny lists, the agent relies on default permissions which may be too broad. Add a permissions block to restrict tool access.",
              file: file.path,
              fix: {
                description: "Add a permissions block with scoped allow and deny lists",
                before: "No permissions section",
                after: '"permissions": { "allow": ["Read(*)", "Glob(*)", "Grep(*)"], "deny": ["Bash(rm -rf *)", "Bash(sudo *)"] }',
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
    id: "permissions-env-in-allow",
    name: "Environment Variable Access in Allow List",
    description: "Checks for allow list entries that grant access to environment variables or env files",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      const envPatterns = [
        {
          pattern: /\.env\b/,
          description: "Grants access to .env files which may contain secrets"
        },
        {
          pattern: /\bprintenv\b|\benv\b(?!\()/,
          description: "Grants access to dump environment variables"
        },
        {
          pattern: /\bexport\s/,
          description: "Allows setting environment variables"
        }
      ];
      for (const entry of perms.allow) {
        for (const { pattern, description } of envPatterns) {
          if (pattern.test(entry)) {
            findings.push({
              id: `permissions-env-access-${findings.length}`,
              severity: "high",
              category: "permissions",
              title: `Allow rule grants env access: ${entry}`,
              description: `The allow entry "${entry}" ${description}. Environment variables often contain API keys, tokens, and other secrets.`,
              file: file.path,
              evidence: entry
            });
            break;
          }
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-unrestricted-network",
    name: "Unrestricted Network Tool Access",
    description: "Checks for allow rules that grant unrestricted access to network tools",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      const networkPatterns = [
        {
          pattern: /^Bash\(curl\s*\*?\)$/i,
          description: "Allows unrestricted curl \u2014 can exfiltrate data to any URL"
        },
        {
          pattern: /^Bash\(wget\s*\*?\)$/i,
          description: "Allows unrestricted wget \u2014 can download from any URL"
        },
        {
          pattern: /^Bash\(nc\b/i,
          description: "Allows netcat \u2014 can open listeners or connect to remote hosts"
        },
        {
          pattern: /^Bash\(ssh\s*\*?\)$/i,
          description: "Allows unrestricted SSH \u2014 can connect to any remote host"
        },
        {
          pattern: /^Bash\(scp\s*\*?\)$/i,
          description: "Allows unrestricted scp \u2014 can copy files to/from any host"
        }
      ];
      for (const entry of perms.allow) {
        for (const { pattern, description } of networkPatterns) {
          if (pattern.test(entry)) {
            findings.push({
              id: `permissions-unrestricted-network-${findings.length}`,
              severity: "high",
              category: "permissions",
              title: `Allow rule grants unrestricted network access: ${entry}`,
              description: `The allow entry "${entry}" ${description}. Network tools should be restricted to specific hosts or purposes.`,
              file: file.path,
              evidence: entry,
              fix: {
                description: "Restrict to specific hosts or use explicit URLs",
                before: entry,
                after: entry.replace("*", "https://specific-host.com/*"),
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
function findStringRangesAtPath(content, path) {
  const ranges = [];
  try {
    const config = JSON.parse(content);
    let target = config;
    for (const key of path) {
      if (target && typeof target === "object" && !Array.isArray(target)) {
        target = target[key];
      } else {
        return ranges;
      }
    }
    if (!Array.isArray(target)) return ranges;
    for (const entry of target) {
      if (typeof entry !== "string") continue;
      const needle = JSON.stringify(entry);
      let idx = 0;
      while ((idx = content.indexOf(needle, idx)) !== -1) {
        ranges.push({ start: idx, end: idx + needle.length });
        idx += needle.length;
      }
    }
  } catch {
  }
  return ranges;
}
function findBlockHookRanges(content) {
  const ranges = [];
  try {
    const config = JSON.parse(content);
    const preToolUseHooks = config?.hooks?.PreToolUse ?? [];
    for (const hookEntry of preToolUseHooks) {
      const h = hookEntry;
      const commands = [];
      if (typeof h.command === "string") commands.push(h.command);
      if (typeof h.hook === "string") commands.push(h.hook);
      if (Array.isArray(h.hooks)) {
        for (const sub of h.hooks) {
          const s = sub;
          if (typeof s.command === "string") commands.push(s.command);
          if (typeof s.hook === "string") commands.push(s.hook);
        }
      }
      const isBlock = commands.some((c) => /exit\s+[12]\b/.test(c));
      if (!isBlock) continue;
      const strings = collectStrings(hookEntry);
      for (const s of strings) {
        const needle = JSON.stringify(s);
        let idx = 0;
        while ((idx = content.indexOf(needle, idx)) !== -1) {
          ranges.push({ start: idx, end: idx + needle.length });
          idx += needle.length;
        }
      }
    }
  } catch {
  }
  return ranges;
}
function collectStrings(obj) {
  const result = [];
  if (typeof obj === "string") {
    result.push(obj);
  } else if (Array.isArray(obj)) {
    for (const item of obj) result.push(...collectStrings(item));
  } else if (obj && typeof obj === "object") {
    for (const val of Object.values(obj)) {
      result.push(...collectStrings(val));
    }
  }
  return result;
}
function buildSafeRanges(content) {
  return [
    ...findStringRangesAtPath(content, ["permissions", "deny"]),
    ...findStringRangesAtPath(content, ["permissions", "allow"]),
    ...findBlockHookRanges(content)
  ];
}
function isInSafeRange(ranges, matchIndex) {
  return ranges.some((r) => matchIndex >= r.start && matchIndex < r.end);
}
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
var safeRangeCache = /* @__PURE__ */ new WeakMap();
var contentKeyMap = /* @__PURE__ */ new Map();
function getSafeRanges(content) {
  let key = contentKeyMap.get(content);
  if (!key) {
    key = {};
    contentKeyMap.set(content, key);
    safeRangeCache.set(key, buildSafeRanges(content));
  }
  return safeRangeCache.get(key);
}
function findAllMatches2(content, pattern) {
  const matches = [...content.matchAll(new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g"))];
  const safeRanges = getSafeRanges(content);
  if (safeRanges.length === 0) return matches;
  return matches.filter((m) => !isInSafeRange(safeRanges, m.index ?? 0));
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
        { pattern: /\|\|\s*:\s*(?:$|[)"'])/gm, desc: "errors suppressed with || :" }
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
            evidence: match[0],
            fix: {
              description: "Remove error suppression to surface failures",
              before: match[0],
              after: "# [REMOVED: error suppression]",
              auto: true
            }
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
    id: "hooks-background-process",
    name: "Hook Spawns Background Process",
    description: "Checks for hooks that spawn background processes which persist beyond the hook's execution",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const bgPatterns = [
        {
          pattern: /\bnohup\b/g,
          description: "nohup keeps a process running after the hook exits \u2014 potential persistence mechanism"
        },
        {
          pattern: /\bdisown\b/g,
          description: "disown detaches a process from the shell \u2014 hides background activity"
        },
        {
          pattern: /&\s*(?:$|[;)]|&&)/gm,
          description: "Background process via & \u2014 may run indefinitely after hook completes"
        },
        {
          pattern: /\bscreen\s+-[dS]/g,
          description: "screen session \u2014 creates persistent hidden shell sessions"
        },
        {
          pattern: /\btmux\s+(?:new|send)/g,
          description: "tmux session \u2014 creates persistent hidden shell sessions"
        }
      ];
      for (const { pattern, description } of bgPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-bg-process-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook spawns background process: ${match[0].trim()}`,
            description: `${description}. Background processes in hooks can be used for persistent backdoors or data exfiltration that outlives the session.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-env-exfiltration",
    name: "Hook Env Var Exfiltration",
    description: "Checks for hooks that access environment variables and send them to external services",
    severity: "critical",
    category: "exposure",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const envAccessPatterns = /\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|PASS|CRED|AUTH)\w*\}?/gi;
      const networkPatterns = /\b(curl|wget|nc|netcat|sendmail|mail\s+-s)\b/gi;
      const hasEnvAccess = envAccessPatterns.test(file.content);
      const envAccessRegex = new RegExp(envAccessPatterns.source, envAccessPatterns.flags);
      envAccessPatterns.lastIndex = 0;
      const hasNetwork = networkPatterns.test(file.content);
      networkPatterns.lastIndex = 0;
      if (hasEnvAccess && hasNetwork) {
        const matches = findAllMatches2(file.content, envAccessRegex);
        for (const match of matches) {
          const lineStart = file.content.lastIndexOf("\n", match.index ?? 0) + 1;
          const lineEnd = file.content.indexOf("\n", (match.index ?? 0) + match[0].length);
          const line = file.content.substring(lineStart, lineEnd === -1 ? void 0 : lineEnd);
          const networkCheck = new RegExp(networkPatterns.source, "i");
          if (networkCheck.test(line)) {
            findings.push({
              id: `hooks-env-exfil-${match.index}`,
              severity: "critical",
              category: "exposure",
              title: `Hook combines env var access with network call`,
              description: `A hook accesses an environment variable (${match[0]}) and sends data over the network in the same command. This pattern can exfiltrate secrets from the environment to external services.`,
              file: file.path,
              line: findLineNumber3(file.content, match.index ?? 0),
              evidence: line.trim().substring(0, 100)
            });
            break;
          }
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-chained-commands",
    name: "Hook Chained Shell Commands",
    description: "Checks for hooks that chain multiple commands, which may execute beyond the matcher's intended scope",
    severity: "medium",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const allHooks = [
          ...config?.hooks?.PreToolUse ?? [],
          ...config?.hooks?.PostToolUse ?? [],
          ...config?.hooks?.SessionStart ?? [],
          ...config?.hooks?.Stop ?? []
        ];
        const chainPatterns = [
          { pattern: /&&/, desc: "AND chain (&&)" },
          { pattern: /;\s*[a-zA-Z]/, desc: "semicolon chain" },
          { pattern: /\|\s*[a-zA-Z]/, desc: "pipe chain" }
        ];
        for (const hook of allHooks) {
          const hookConfig = hook;
          const command = hookConfig.hook ?? "";
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
  },
  {
    id: "hooks-output-to-world-readable",
    name: "Hook Writes to World-Readable Path",
    description: "Checks for hooks that redirect output to world-readable directories like /tmp",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const worldReadablePatterns = [
        {
          pattern: />\s*\/tmp\//g,
          description: "Redirects output to /tmp \u2014 readable by all users on the system"
        },
        {
          pattern: /\btee\s+\/tmp\//g,
          description: "Uses tee to write to /tmp \u2014 creates world-readable file"
        },
        {
          pattern: />\s*\/var\/tmp\//g,
          description: "Redirects output to /var/tmp \u2014 persistent and world-readable"
        },
        {
          pattern: /\bmktemp\b/g,
          description: "Creates temporary file \u2014 ensure secure permissions (mktemp is generally safe but verify cleanup)"
        }
      ];
      for (const { pattern, description } of worldReadablePatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          if (pattern.source.includes("mktemp")) continue;
          findings.push({
            id: `hooks-world-readable-${match.index}`,
            severity: "high",
            category: "exposure",
            title: `Hook writes to world-readable path: ${match[0].trim()}`,
            description: `${description}. Other users or processes on the system can read the output, which may contain secrets, code, or session data.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-source-from-env",
    name: "Hook Sources Script from Environment Path",
    description: "Checks for hooks that source scripts from environment variable paths",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const sourcePatterns = [
        {
          pattern: /\bsource\s+\$\{?\w+\}?\//g,
          description: "Sources a script from an environment variable path"
        },
        {
          pattern: /\.\s+\$\{?\w+\}?\//g,
          description: "Dot-sources a script from an environment variable path"
        },
        {
          pattern: /\beval\s+\$\{?\w+/g,
          description: "Evaluates content from an environment variable"
        }
      ];
      for (const { pattern, description } of sourcePatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-source-env-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Hook sources script from environment path: ${match[0].trim()}`,
            description: `${description}. If the environment variable is attacker-controlled, this enables arbitrary code execution through the sourced script.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-file-deletion",
    name: "Hook Deletes Files",
    description: "Checks for hooks that delete files, which could destroy work or cover tracks",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const deletePatterns = [
        {
          pattern: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\b/g,
          description: "Recursive file deletion (rm -rf) \u2014 can destroy entire directories"
        },
        {
          pattern: /\brm\s+-[a-zA-Z]*f\b/g,
          description: "Force file deletion (rm -f) \u2014 deletes without confirmation"
        },
        {
          pattern: /\bshred\b/g,
          description: "Secure file erasure (shred) \u2014 irrecoverable deletion used to cover tracks"
        },
        {
          pattern: /\bunlink\b/g,
          description: "File deletion via unlink"
        }
      ];
      for (const { pattern, description } of deletePatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-file-delete-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook deletes files: ${match[0].trim()}`,
            description: `${description}. A hook that deletes files could destroy source code, logs, or evidence of compromise.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-cron-persistence",
    name: "Hook Installs Cron Job",
    description: "Checks for hooks that install cron jobs for persistent access",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const cronPatterns = [
        {
          pattern: /\bcrontab\b/g,
          description: "Modifies crontab \u2014 installs persistent scheduled tasks"
        },
        {
          pattern: /\/etc\/cron/g,
          description: "Writes to system cron directory \u2014 installs persistent scheduled tasks"
        },
        {
          pattern: /\bat\s+-[a-z]/g,
          description: "Schedules deferred command execution via at"
        },
        {
          pattern: /\bsystemctl\s+(?:enable|start)/g,
          description: "Enables/starts a systemd service \u2014 potential persistence mechanism"
        },
        {
          pattern: /\blaunchctl\s+load/g,
          description: "Loads a macOS launch agent \u2014 persistent background process"
        }
      ];
      for (const { pattern, description } of cronPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-cron-persist-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook installs persistence mechanism: ${match[0].trim()}`,
            description: `${description}. Hooks should not install persistence mechanisms. This could allow a compromised hook to maintain access even after the session ends.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-env-mutation",
    name: "Hook Mutates Environment Variables",
    description: "Checks for hooks that set or export environment variables, which can alter subsequent command behavior",
    severity: "medium",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const envMutationPatterns = [
        {
          pattern: /\bexport\s+PATH=/g,
          description: "Modifies PATH \u2014 can redirect which binaries are executed",
          severity: "high"
        },
        {
          pattern: /\bexport\s+(?:LD_PRELOAD|LD_LIBRARY_PATH|DYLD_)=/gi,
          description: "Modifies dynamic linker variables \u2014 can inject shared libraries",
          severity: "high"
        },
        {
          pattern: /\bexport\s+(?:NODE_OPTIONS|PYTHONPATH|RUBYLIB)=/gi,
          description: "Modifies runtime import paths \u2014 can load malicious modules",
          severity: "high"
        },
        {
          pattern: /\bexport\s+(?:http_proxy|https_proxy|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY)=/gi,
          description: "Sets proxy variables \u2014 can redirect all network traffic through attacker-controlled proxy",
          severity: "high"
        }
      ];
      for (const { pattern, description, severity } of envMutationPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-env-mutation-${match.index}`,
            severity,
            category: "hooks",
            title: `Hook mutates environment: ${match[0].trim()}`,
            description: `${description}. Hooks that modify environment variables can silently alter the behavior of all subsequent commands in the session.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-git-config-modification",
    name: "Hook Modifies Git Configuration",
    description: "Checks for hooks that modify git config, which can alter commit authorship, disable signing, or change hooks",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const gitConfigPatterns = [
        {
          pattern: /\bgit\s+config\s+--global/g,
          description: "Modifies global git config \u2014 affects all repositories on the system"
        },
        {
          pattern: /\bgit\s+config\s+(?:--system)/g,
          description: "Modifies system-level git config \u2014 affects all users"
        },
        {
          pattern: /\bgit\s+config\s+(?:.*\s+)?(?:user\.email|user\.name)/g,
          description: "Changes git commit author identity \u2014 could attribute commits to someone else"
        },
        {
          pattern: /\bgit\s+config\s+(?:.*\s+)?(?:commit\.gpgsign|tag\.gpgsign)\s+false/g,
          description: "Disables GPG commit signing \u2014 weakens commit verification"
        },
        {
          pattern: /\bgit\s+config\s+(?:.*\s+)?core\.hooksPath/g,
          description: "Changes git hooks directory \u2014 could redirect to malicious hooks"
        }
      ];
      for (const { pattern, description } of gitConfigPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-git-config-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook modifies git config: ${match[0].trim()}`,
            description: `${description}. Hooks should not modify git configuration as this can undermine version control integrity.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-user-account-modification",
    name: "Hook Creates or Modifies User Accounts",
    description: "Checks for hooks that create, modify, or delete user accounts",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const userModPatterns = [
        {
          pattern: /\buseradd\b/g,
          description: "Creates a new user account (useradd)"
        },
        {
          pattern: /\badduser\b/g,
          description: "Creates a new user account (adduser)"
        },
        {
          pattern: /\busermod\b/g,
          description: "Modifies an existing user account (usermod)"
        },
        {
          pattern: /\buserdel\b/g,
          description: "Deletes a user account (userdel)"
        },
        {
          pattern: /\bpasswd\b/g,
          description: "Changes a user password (passwd)"
        }
      ];
      for (const { pattern, description } of userModPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-user-mod-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook modifies user accounts: ${match[0].trim()}`,
            description: `${description}. Hooks should never create, modify, or delete user accounts. A compromised hook with this capability can create backdoor accounts for persistent access.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-privilege-escalation",
    name: "Hook Uses Privilege Escalation",
    description: "Checks for hooks that use sudo, su, or other privilege escalation commands",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const privEscPatterns = [
        {
          pattern: /\bsudo\b/g,
          description: "Runs commands as root via sudo"
        },
        {
          pattern: /\bsu\s+-?\s*\w/g,
          description: "Switches to another user via su"
        },
        {
          pattern: /\bdoas\b/g,
          description: "Runs commands as another user via doas (OpenBSD sudo alternative)"
        },
        {
          pattern: /\bpkexec\b/g,
          description: "Runs commands as another user via polkit (pkexec)"
        },
        {
          pattern: /\brunas\b/gi,
          description: "Runs commands as another user via runas (Windows)"
        }
      ];
      for (const { pattern, description } of privEscPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-priv-esc-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook uses privilege escalation: ${match[0].trim()}`,
            description: `${description}. Hooks should never escalate privileges. A compromised hook with root access can take over the entire system.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-network-listener",
    name: "Hook Opens Network Listener",
    description: "Checks for hooks that bind to network ports, which could create reverse shells or backdoors",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const listenerPatterns = [
        {
          pattern: /\bnc\s+.*-l/g,
          description: "Opens a netcat listener \u2014 classic reverse shell vector"
        },
        {
          pattern: /\bsocat\b/g,
          description: "Uses socat for bidirectional data transfer \u2014 can create tunnels and reverse shells"
        },
        {
          pattern: /\bpython3?\s+.*-m\s+http\.server/g,
          description: "Starts a Python HTTP server \u2014 exposes local files over the network"
        },
        {
          pattern: /\bpython3?\s+.*SimpleHTTPServer/g,
          description: "Starts a Python 2 HTTP server \u2014 exposes local files over the network"
        },
        {
          pattern: /\bphp\s+-S\b/g,
          description: "Starts a PHP built-in server \u2014 serves files and executes PHP code"
        }
      ];
      for (const { pattern, description } of listenerPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-network-listener-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook opens network listener: ${match[0].trim()}`,
            description: `${description}. Hooks should not open network listeners. This could create a backdoor accessible from the network.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-disk-wipe",
    name: "Hook Uses Disk Wiping Commands",
    description: "Checks for hooks that use destructive disk operations",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const wipePatterns = [
        {
          pattern: /\bdd\s+if=\/dev\/(?:zero|urandom)/g,
          description: "Overwrites disk with zeros/random data via dd"
        },
        {
          pattern: /\bmkfs\b/g,
          description: "Formats a filesystem \u2014 destroys all data on the target device"
        },
        {
          pattern: /\bwipefs\b/g,
          description: "Wipes filesystem signatures \u2014 makes data unrecoverable"
        }
      ];
      for (const { pattern, description } of wipePatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-disk-wipe-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook uses disk wiping command: ${match[0].trim()}`,
            description: `${description}. Hooks should never perform destructive disk operations. This could permanently destroy data.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-shell-profile-modification",
    name: "Hook Modifies Shell Profile",
    description: "Checks for hooks that modify shell init files (.bashrc, .zshrc, .profile) for persistence",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const profilePatterns = [
        {
          pattern: /\.bashrc/g,
          description: "Modifies .bashrc \u2014 commands here run on every new bash shell"
        },
        {
          pattern: /\.zshrc/g,
          description: "Modifies .zshrc \u2014 commands here run on every new zsh shell"
        },
        {
          pattern: /\.bash_profile/g,
          description: "Modifies .bash_profile \u2014 commands here run on every login shell"
        },
        {
          pattern: /\.profile/g,
          description: "Modifies .profile \u2014 commands here run on every login shell"
        },
        {
          pattern: /\/etc\/environment/g,
          description: "Modifies /etc/environment \u2014 affects all users on the system"
        }
      ];
      for (const { pattern, description } of profilePatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
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
              description: `${description}. Writing to shell profile files is a classic persistence technique \u2014 malicious code injected here survives across reboots and terminal sessions.`,
              file: file.path,
              line: findLineNumber3(file.content, match.index ?? 0),
              evidence: context.trim().substring(0, 80)
            });
          }
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-logging-disabled",
    name: "Hook Disables Logging or Audit Trail",
    description: "Checks for hooks that clear logs or disable audit mechanisms",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const logPatterns = [
        {
          pattern: />\s*\/dev\/null\s+2>&1|&>\s*\/dev\/null/g,
          description: "Redirects all output to /dev/null \u2014 hides both stdout and stderr"
        },
        {
          pattern: /\bhistory\s+-[cwd]/g,
          description: "Clears or disables shell history \u2014 covers tracks"
        },
        {
          pattern: /\bunset\s+HISTFILE/g,
          description: "Unsets HISTFILE \u2014 prevents command history from being saved"
        },
        {
          pattern: /\btruncate\s+.*\/var\/log/g,
          description: "Truncates system log files \u2014 destroys audit trail"
        }
      ];
      for (const { pattern, description } of logPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-logging-disabled-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook disables logging: ${match[0].trim()}`,
            description: `${description}. Disabling logging or clearing audit trails in hooks is a defense evasion technique that makes it harder to detect and investigate compromises.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-ssh-key-operations",
    name: "Hook Manipulates SSH Keys",
    description: "Checks for hooks that generate, copy, or modify SSH keys \u2014 enables lateral movement",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const sshKeyPatterns = [
        {
          pattern: /\bssh-keygen\b/g,
          description: "Generates SSH keys \u2014 could create unauthorized keys for persistent access"
        },
        {
          pattern: /\bssh-copy-id\b/g,
          description: "Copies SSH keys to remote hosts \u2014 enables passwordless lateral movement"
        },
        {
          pattern: />>?\s*~\/\.ssh\/authorized_keys/g,
          description: "Appends to authorized_keys \u2014 installs backdoor SSH access"
        }
      ];
      for (const { pattern, description } of sshKeyPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-ssh-key-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook manipulates SSH keys: ${match[0].trim()}`,
            description: `${description}. Hooks should not create or distribute SSH keys as this enables unauthorized remote access.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-background-process",
    name: "Hook Runs Background Process",
    description: "Checks for hooks that start persistent background processes that outlive the session",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const bgPatterns = [
        {
          pattern: /\bnohup\b/g,
          description: "Runs process immune to hangup signals \u2014 survives session end"
        },
        {
          pattern: /\bdisown\b/g,
          description: "Detaches process from shell \u2014 survives session end"
        },
        {
          pattern: /\bscreen\s+-[dD]m/g,
          description: "Starts detached screen session \u2014 hidden persistent process"
        },
        {
          pattern: /\btmux\s+new-session\s+-d/g,
          description: "Starts detached tmux session \u2014 hidden persistent process"
        }
      ];
      for (const { pattern, description } of bgPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-bg-process-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook starts background process: ${match[0].trim()}`,
            description: `${description}. Hooks that start persistent background processes can maintain execution even after the agent session ends \u2014 a common persistence technique.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-dns-exfiltration",
    name: "Hook Uses DNS for Data Exfiltration",
    description: "Checks for hooks that use DNS queries with variable interpolation to exfiltrate data",
    severity: "critical",
    category: "exfiltration",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const dnsPatterns = [
        {
          pattern: /\bdig\s+.*\$\{?\w+/g,
          description: "Uses dig with variable interpolation \u2014 DNS exfiltration encodes data in DNS queries"
        },
        {
          pattern: /\bnslookup\s+.*\$\{?\w+/g,
          description: "Uses nslookup with variable interpolation \u2014 DNS exfiltration vector"
        },
        {
          pattern: /\bhost\s+.*\$\{?\w+/g,
          description: "Uses host command with variable interpolation \u2014 DNS exfiltration vector"
        }
      ];
      for (const { pattern, description } of dnsPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-dns-exfil-${match.index}`,
            severity: "critical",
            category: "exfiltration",
            title: `Hook uses DNS for exfiltration: ${match[0].trim().substring(0, 60)}`,
            description: `${description}. DNS queries bypass most firewalls and proxy filters, making this a common out-of-band exfiltration technique.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-firewall-modification",
    name: "Hook Modifies Firewall Rules",
    description: "Checks for hooks that modify iptables, ufw, or firewall rules",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const fwPatterns = [
        {
          pattern: /\biptables\b/g,
          description: "Modifies iptables firewall rules \u2014 can open ports or disable filtering"
        },
        {
          pattern: /\bufw\s+(?:allow|delete|disable)/g,
          description: "Modifies UFW firewall \u2014 can open ports or disable the firewall entirely"
        },
        {
          pattern: /\bfirewall-cmd\b/g,
          description: "Modifies firewalld rules \u2014 can change network access policies"
        }
      ];
      for (const { pattern, description } of fwPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-fw-modify-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook modifies firewall: ${match[0].trim()}`,
            description: `${description}. Hooks should not modify firewall rules \u2014 this could expose the system to network attacks.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-global-package-install",
    name: "Hook Installs Global Packages",
    description: "Checks for hooks that install packages globally, which can modify system-wide binaries",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const installPatterns = [
        {
          pattern: /\bnpm\s+install\s+-g\b|\bnpm\s+i\s+-g\b/g,
          description: "Installs npm package globally \u2014 modifies system-wide PATH binaries"
        },
        {
          pattern: /\bpip\s+install\s+(?:--user\s+)?(?!-r\b)/g,
          description: "Installs Python package \u2014 may modify system Python packages"
        },
        {
          pattern: /\bgem\s+install\b/g,
          description: "Installs Ruby gem \u2014 modifies system Ruby packages"
        },
        {
          pattern: /\bcargo\s+install\b/g,
          description: "Installs Rust package globally via cargo"
        }
      ];
      for (const { pattern, description } of installPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-global-install-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook installs packages: ${match[0].trim()}`,
            description: `${description}. Hooks that install packages can introduce supply chain risks and modify the system's behavior for all future commands.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-container-escape",
    name: "Hook Uses Container Escape Techniques",
    description: "Checks for hooks that use Docker flags that enable container escape",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const containerEscapePatterns = [
        {
          pattern: /--privileged/g,
          description: "Docker --privileged flag \u2014 container has full host access"
        },
        {
          pattern: /--pid=host/g,
          description: "Docker --pid=host \u2014 container can see/signal all host processes"
        },
        {
          pattern: /--network=host/g,
          description: "Docker --network=host \u2014 container shares host network stack"
        },
        {
          pattern: /-v\s+\/:/g,
          description: "Mounts host root filesystem into container \u2014 full filesystem access"
        }
      ];
      for (const { pattern, description } of containerEscapePatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-container-escape-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook uses container escape technique: ${match[0].trim()}`,
            description: `${description}. These Docker flags break container isolation and allow full host access from within the container.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-credential-access",
    name: "Hook Accesses Credential Stores",
    description: "Checks for hooks that read password files, keychains, or credential managers",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const credPatterns = [
        {
          pattern: /\bsecurity\s+find-generic-password\b/g,
          description: "Reads macOS Keychain passwords via security command"
        },
        {
          pattern: /\bsecurity\s+find-internet-password\b/g,
          description: "Reads macOS Keychain internet passwords"
        },
        {
          pattern: /\bsecret-tool\s+lookup\b/g,
          description: "Reads GNOME Keyring / Linux secret store"
        },
        {
          pattern: /\bkeyctl\s+read\b/g,
          description: "Reads Linux kernel keyring"
        },
        {
          pattern: /\/etc\/shadow/g,
          description: "Accesses /etc/shadow \u2014 contains password hashes"
        }
      ];
      for (const { pattern, description } of credPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-cred-access-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook accesses credential store: ${match[0].trim()}`,
            description: `${description}. Hooks should never access credential stores \u2014 this enables credential theft for lateral movement.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-reverse-shell",
    name: "Hook Opens Reverse Shell",
    description: "Checks for hooks that establish reverse shell connections back to an attacker",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const reverseShellPatterns = [
        {
          pattern: /\bbash\s+-i\s+[>&]+.*\/dev\/tcp\//g,
          description: "Bash reverse shell via /dev/tcp \u2014 connects back to attacker"
        },
        {
          pattern: /\/dev\/tcp\/[0-9.]+\/\d+/g,
          description: "Uses /dev/tcp for network connection \u2014 common reverse shell technique"
        },
        {
          pattern: /\bpython3?\s+.*-c\s+.*socket.*connect/g,
          description: "Python reverse shell via socket.connect"
        },
        {
          pattern: /\bperl\s+.*-e\s+.*socket.*INET/g,
          description: "Perl reverse shell via Socket::INET"
        },
        {
          pattern: /\bmkfifo\b.*\bnc\b/g,
          description: "Named pipe reverse shell using mkfifo and netcat"
        }
      ];
      for (const { pattern, description } of reverseShellPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-reverse-shell-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook establishes reverse shell: ${match[0].trim().substring(0, 60)}`,
            description: `${description}. Reverse shells give attackers interactive command execution on the target system.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim().substring(0, 80)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-clipboard-access",
    name: "Hook Accesses System Clipboard",
    description: "Checks for hooks that read or write the system clipboard, which can be used for data exfiltration",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const clipboardPatterns = [
        {
          pattern: /\bpbcopy\b/g,
          description: "Uses macOS pbcopy to write to clipboard \u2014 can silently exfiltrate data"
        },
        {
          pattern: /\bpbpaste\b/g,
          description: "Uses macOS pbpaste to read clipboard \u2014 may capture sensitive copied content"
        },
        {
          pattern: /\bxclip\b/g,
          description: "Uses xclip to access X11 clipboard \u2014 can read or write clipboard data"
        },
        {
          pattern: /\bxsel\b/g,
          description: "Uses xsel to access X11 selection \u2014 can read or write clipboard data"
        },
        {
          pattern: /\bwl-copy\b/g,
          description: "Uses wl-copy to write to Wayland clipboard"
        },
        {
          pattern: /\bwl-paste\b/g,
          description: "Uses wl-paste to read from Wayland clipboard"
        }
      ];
      for (const { pattern, description } of clipboardPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-clipboard-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook accesses clipboard: ${match[0].trim()}`,
            description: `${description}. Clipboard access in hooks can be used to steal passwords, tokens, and other sensitive data that users copy.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-log-tampering",
    name: "Hook Tampers with System Logs",
    description: "Checks for hooks that delete, truncate, or modify system log files to cover tracks",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const logTamperPatterns = [
        {
          pattern: /\bjournalctl\s+--vacuum/g,
          description: "Purges systemd journal logs \u2014 destroys audit trail"
        },
        {
          pattern: /\brm\s+(?:-[rf]+\s+)?\/var\/log\b/g,
          description: "Deletes system log files \u2014 destroys audit evidence"
        },
        {
          pattern: /\btruncate\s+.*\/var\/log\b/g,
          description: "Truncates system log files \u2014 erases log contents"
        },
        {
          pattern: />\s*\/var\/log\/(?:syslog|auth\.log|messages|secure)/g,
          description: "Overwrites system log file with redirection \u2014 clears log contents"
        },
        {
          pattern: /\bhistory\s+-c\b/g,
          description: "Clears shell command history \u2014 covers tracks of executed commands"
        },
        {
          pattern: /\bunset\s+HISTFILE\b/g,
          description: "Disables shell history recording \u2014 prevents command audit trail"
        }
      ];
      for (const { pattern, description } of logTamperPatterns) {
        const matches = findAllMatches2(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `hooks-log-tamper-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook tampers with logs: ${match[0].trim()}`,
            description: `${description}. Log tampering is a strong indicator of malicious intent \u2014 attackers erase evidence of their actions.`,
            file: file.path,
            line: findLineNumber3(file.content, match.index ?? 0),
            evidence: match[0].trim()
          });
        }
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
                description: "Remove -y flag so npx prompts before installing, or install the package explicitly",
                before: `"args": ["-y", "${args[1] ?? "package"}"]`,
                after: `"args": ["${args[1] ?? "package"}"]`,
                auto: true
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
          const versionPart = afterScope.includes("@") ? afterScope.substring(afterScope.indexOf("@") + 1) : "";
          const hasVersion = afterScope.includes("@") && versionPart !== "latest" && versionPart !== "next";
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
    id: "mcp-env-override",
    name: "MCP Environment Variable Override",
    description: "Checks for MCP servers that override system-critical environment variables like PATH or LD_PRELOAD",
    severity: "critical",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const dangerousEnvVars = [
          { name: "PATH", description: "Controls which executables are found \u2014 can redirect to malicious binaries" },
          { name: "LD_PRELOAD", description: "Injects shared libraries into every process \u2014 classic privilege escalation" },
          { name: "LD_LIBRARY_PATH", description: "Redirects dynamic library loading \u2014 can intercept system calls" },
          { name: "NODE_OPTIONS", description: "Injects flags into every Node.js process \u2014 can load arbitrary code" },
          { name: "PYTHONPATH", description: "Redirects Python module imports \u2014 can load malicious modules" },
          { name: "HOME", description: "Changes home directory \u2014 can redirect config file loading" }
        ];
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const env = serverConfig.env ?? {};
          for (const envVar of dangerousEnvVars) {
            if (envVar.name in env) {
              findings.push({
                id: `mcp-env-override-${name}-${envVar.name}`,
                severity: "critical",
                category: "mcp",
                title: `MCP server "${name}" overrides ${envVar.name}`,
                description: `The MCP server "${name}" sets ${envVar.name} in its environment. ${envVar.description}. If a malicious MCP config is injected (e.g., via a cloned repo), this could compromise the entire system.`,
                file: file.path,
                evidence: `${envVar.name}=${(env[envVar.name] ?? "").substring(0, 40)}`,
                fix: {
                  description: `Remove ${envVar.name} from the MCP server's env block`,
                  before: `"${envVar.name}": "${(env[envVar.name] ?? "").substring(0, 20)}"`,
                  after: `# Remove ${envVar.name} override`,
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
  },
  {
    id: "mcp-shell-wrapper",
    name: "MCP Server Uses Shell Wrapper",
    description: "Checks for MCP servers that use sh/bash -c as command, which defeats argument separation safety",
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
          const command = serverConfig.command ?? "";
          const args = serverConfig.args ?? [];
          if (/^(sh|bash|zsh|cmd)$/.test(command) && args.includes("-c")) {
            findings.push({
              id: `mcp-shell-wrapper-${name}`,
              severity: "high",
              category: "mcp",
              title: `MCP server "${name}" uses shell wrapper (${command} -c)`,
              description: `The MCP server "${name}" uses "${command} -c" as its command. This passes all arguments through a shell interpreter, defeating the security benefits of argument separation. Shell metacharacters in args become live injection vectors. Use the target binary directly as the command instead.`,
              file: file.path,
              evidence: `command: ${command}, args: ${JSON.stringify(args).substring(0, 80)}`,
              fix: {
                description: "Use the target binary directly instead of wrapping in sh -c",
                before: `"command": "${command}", "args": ["-c", ...]`,
                after: '"command": "node", "args": ["./server.js"]',
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
    id: "mcp-git-url-dependency",
    name: "MCP Git URL Dependency",
    description: "Checks for MCP servers installed from git URLs which are mutable supply chain risks",
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
          const args = serverConfig.args ?? [];
          for (const arg of args) {
            if (/git\+https?:\/\/|github\.com\/.*\.git/.test(arg)) {
              findings.push({
                id: `mcp-git-url-dep-${name}`,
                severity: "high",
                category: "mcp",
                title: `MCP server "${name}" installed from git URL`,
                description: `The MCP server "${name}" references a git URL "${arg.substring(0, 80)}". Git URLs point to mutable content \u2014 the repository owner can push malicious changes at any time, and they would be picked up on next install. Use a pinned npm package version instead.`,
                file: file.path,
                evidence: arg.substring(0, 100),
                fix: {
                  description: "Use a pinned npm package version instead of a git URL",
                  before: `"${arg.substring(0, 40)}"`,
                  after: '"@scope/package@1.0.0"',
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
    id: "mcp-disabled-security",
    name: "MCP Server Has Security-Disabling Flags",
    description: "Checks for MCP servers with arguments that disable security features",
    severity: "critical",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const dangerousFlags = [
          {
            pattern: /--no-sandbox/,
            description: "Disables sandboxing \u2014 process runs with full system access"
          },
          {
            pattern: /--disable-web-security/,
            description: "Disables web security policies (CORS, same-origin) \u2014 enables cross-site attacks"
          },
          {
            pattern: /--allow-running-insecure-content/,
            description: "Allows loading HTTP content over HTTPS \u2014 enables MITM attacks"
          },
          {
            pattern: /--unsafe-perm/,
            description: "Runs npm scripts as root \u2014 privilege escalation risk"
          },
          {
            pattern: /--trust-all-certificates|--insecure/,
            description: "Disables TLS certificate verification \u2014 enables MITM attacks"
          }
        ];
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const args = serverConfig.args ?? [];
          const fullArgs = args.join(" ");
          for (const { pattern, description } of dangerousFlags) {
            if (pattern.test(fullArgs)) {
              findings.push({
                id: `mcp-disabled-security-${name}-${pattern.source}`,
                severity: "critical",
                category: "mcp",
                title: `MCP server "${name}" has security-disabling flag`,
                description: `The MCP server "${name}" uses a flag that ${description}. Removing security features from MCP servers dramatically increases the attack surface.`,
                file: file.path,
                evidence: fullArgs.substring(0, 100),
                fix: {
                  description: "Remove the security-disabling flag",
                  before: pattern.source.replace(/[\\]/g, ""),
                  after: "# Remove this flag and fix the root cause instead",
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
    id: "mcp-dual-transport",
    name: "MCP Server Has Both URL and Command",
    description: "Checks for MCP servers with both url and command fields, which is ambiguous and potentially dangerous",
    severity: "medium",
    category: "misconfiguration",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const hasUrl = !!serverConfig.url;
          const hasCommand = !!serverConfig.command;
          if (hasUrl && hasCommand) {
            findings.push({
              id: `mcp-dual-transport-${name}`,
              severity: "medium",
              category: "misconfiguration",
              title: `MCP server "${name}" has both url and command`,
              description: `The MCP server "${name}" specifies both a URL transport and a stdio command. This is ambiguous \u2014 it's unclear which transport will be used, and the unused one could be an injection attempt. Use only one transport method.`,
              file: file.path,
              evidence: `url: ${serverConfig.url.substring(0, 40)}, command: ${serverConfig.command}`
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-env-inheritance",
    name: "MCP Server Inherits Full Environment",
    description: "Checks for MCP servers without an explicit env block, which inherit the parent process's full environment including secrets",
    severity: "medium",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const serverCount = Object.keys(servers).length;
        if (serverCount < 2) return [];
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const hasEnv = "env" in serverConfig;
          const hasCommand = !!serverConfig.command;
          if (hasCommand && !hasEnv) {
            findings.push({
              id: `mcp-env-inherit-${name}`,
              severity: "medium",
              category: "mcp",
              title: `MCP server "${name}" inherits full parent environment`,
              description: `The MCP server "${name}" has no explicit "env" block, so it inherits the full parent process environment. This means every environment variable \u2014 including API keys, tokens, and secrets \u2014 is passed to the server. Add an explicit "env" block with only the variables the server needs.`,
              file: file.path,
              evidence: `Server "${name}" has command but no env block`,
              fix: {
                description: "Add an explicit env block with only required variables",
                before: `"${name}": { "command": "..." }`,
                after: `"${name}": { "command": "...", "env": { "ONLY_NEEDED_VAR": "..." } }`,
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
    id: "mcp-database-connection-string",
    name: "MCP Server Has Database Connection String",
    description: "Checks for MCP servers with database connection strings containing credentials in env or args",
    severity: "high",
    category: "secrets",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      const dbPatterns = [
        {
          pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@/,
          description: "PostgreSQL connection string with embedded credentials"
        },
        {
          pattern: /mysql:\/\/[^:]+:[^@]+@/,
          description: "MySQL connection string with embedded credentials"
        },
        {
          pattern: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@/,
          description: "MongoDB connection string with embedded credentials"
        },
        {
          pattern: /redis:\/\/:[^@]+@/,
          description: "Redis connection string with embedded password"
        }
      ];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const env = serverConfig.env ?? {};
          const args = serverConfig.args ?? [];
          for (const [envKey, envVal] of Object.entries(env)) {
            for (const { pattern, description } of dbPatterns) {
              if (pattern.test(envVal)) {
                findings.push({
                  id: `mcp-db-conn-${name}-${envKey}`,
                  severity: "high",
                  category: "secrets",
                  title: `MCP server "${name}" has ${description.split(" ")[0]} credentials in env`,
                  description: `The MCP server "${name}" has a ${description} in environment variable "${envKey}". Credentials should use env var references instead of being hardcoded.`,
                  file: file.path,
                  evidence: `${envKey}=${envVal.substring(0, 30)}...`,
                  fix: {
                    description: "Use an environment variable reference instead",
                    before: envVal.substring(0, 30),
                    after: "${DATABASE_URL}",
                    auto: false
                  }
                });
                break;
              }
            }
          }
          for (const arg of args) {
            for (const { pattern, description } of dbPatterns) {
              if (pattern.test(arg)) {
                findings.push({
                  id: `mcp-db-conn-arg-${name}`,
                  severity: "high",
                  category: "secrets",
                  title: `MCP server "${name}" has ${description.split(" ")[0]} credentials in args`,
                  description: `The MCP server "${name}" has a ${description} in its command arguments. Credentials should be passed via environment variables.`,
                  file: file.path,
                  evidence: arg.substring(0, 40),
                  fix: {
                    description: "Pass the connection string via an environment variable",
                    before: arg.substring(0, 30),
                    after: "Use env: { DATABASE_URL: ... } instead of args",
                    auto: false
                  }
                });
                break;
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
    id: "mcp-privileged-port",
    name: "MCP Server Binds to Privileged Port",
    description: "Checks for MCP servers configured to listen on ports below 1024, which require root privileges",
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
          const args = serverConfig.args ?? [];
          const url = serverConfig.url ?? "";
          const urlPortMatch = url.match(/:(\d+)/);
          if (urlPortMatch) {
            const port = parseInt(urlPortMatch[1], 10);
            if (port > 0 && port < 1024 && port !== 443 && port !== 80) {
              findings.push({
                id: `mcp-priv-port-url-${name}`,
                severity: "medium",
                category: "mcp",
                title: `MCP server "${name}" uses privileged port ${port}`,
                description: `The MCP server "${name}" connects to port ${port}, which is a privileged port (< 1024). Privileged ports require root access and binding to them may indicate the server expects elevated privileges.`,
                file: file.path,
                evidence: `url: ${url.substring(0, 60)}`
              });
            }
          }
          for (let i = 0; i < args.length; i++) {
            if (/^(?:--port|-p)$/.test(args[i]) && args[i + 1]) {
              const port = parseInt(args[i + 1], 10);
              if (port > 0 && port < 1024 && port !== 443 && port !== 80) {
                findings.push({
                  id: `mcp-priv-port-arg-${name}`,
                  severity: "medium",
                  category: "mcp",
                  title: `MCP server "${name}" binds to privileged port ${port}`,
                  description: `The MCP server "${name}" is configured to bind to port ${port}. Privileged ports (< 1024) require root access, which conflicts with the principle of least privilege.`,
                  file: file.path,
                  evidence: `${args[i]} ${args[i + 1]}`
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
    id: "mcp-wildcard-cors",
    name: "MCP Server Has Wildcard CORS",
    description: "Checks for MCP servers with CORS set to * in their arguments or environment",
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
          const args = serverConfig.args ?? [];
          const env = serverConfig.env ?? {};
          const fullArgs = args.join(" ");
          if (/--cors[= ]\*|--cors[= ]["']?\*["']?/.test(fullArgs)) {
            findings.push({
              id: `mcp-wildcard-cors-arg-${name}`,
              severity: "medium",
              category: "mcp",
              title: `MCP server "${name}" allows CORS from any origin`,
              description: `The MCP server "${name}" has CORS set to wildcard (*). This allows any website to make requests to the MCP server, which could be exploited by malicious web pages to interact with the agent.`,
              file: file.path,
              evidence: fullArgs.substring(0, 80)
            });
          }
          for (const [envKey, envVal] of Object.entries(env)) {
            if (/cors/i.test(envKey) && envVal === "*") {
              findings.push({
                id: `mcp-wildcard-cors-env-${name}`,
                severity: "medium",
                category: "mcp",
                title: `MCP server "${name}" allows CORS from any origin via env`,
                description: `The MCP server "${name}" has ${envKey}=* in its environment, allowing cross-origin requests from any website.`,
                file: file.path,
                evidence: `${envKey}=${envVal}`
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
    id: "mcp-sensitive-file-args",
    name: "MCP Server References Sensitive Files in Arguments",
    description: "Checks for MCP servers with credential files (.env, .pem, credentials.json) passed as arguments",
    severity: "high",
    category: "secrets",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const sensitiveFilePatterns = [
          {
            pattern: /\.env\b/,
            description: "References .env file \u2014 may contain API keys and secrets"
          },
          {
            pattern: /\.pem\b/,
            description: "References .pem file \u2014 may contain private key material"
          },
          {
            pattern: /credentials\.json/,
            description: "References credentials.json \u2014 likely contains authentication credentials"
          },
          {
            pattern: /service[_-]?account.*\.json/i,
            description: "References a service account key file"
          },
          {
            pattern: /\.p12\b|\.pfx\b/,
            description: "References PKCS#12 certificate file \u2014 contains private keys"
          },
          {
            pattern: /id_(?:rsa|ed25519|ecdsa)(?:\.pub)?$/,
            description: "References SSH key file"
          }
        ];
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const args = serverConfig.args ?? [];
          for (const arg of args) {
            for (const { pattern, description } of sensitiveFilePatterns) {
              if (pattern.test(arg)) {
                findings.push({
                  id: `mcp-sensitive-file-${name}-${arg.substring(0, 20)}`,
                  severity: "high",
                  category: "secrets",
                  title: `MCP server "${name}" references sensitive file: ${arg}`,
                  description: `The MCP server "${name}" has "${arg}" in its arguments. ${description}. Sensitive files passed as arguments may be logged or exposed.`,
                  file: file.path,
                  evidence: `args: [..., "${arg}"]`,
                  fix: {
                    description: "Use environment variables instead of passing sensitive file paths as arguments",
                    before: arg,
                    after: "Use env: { CONFIG_PATH: ... } instead",
                    auto: false
                  }
                });
                break;
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
    id: "mcp-bind-all-interfaces",
    name: "MCP Server Binds to All Network Interfaces",
    description: "Checks for MCP servers configured to listen on 0.0.0.0, exposing the server to the network",
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
          const args = serverConfig.args ?? [];
          const env = serverConfig.env ?? {};
          const url = serverConfig.url ?? "";
          const fullArgs = args.join(" ");
          if (/0\.0\.0\.0/.test(fullArgs)) {
            findings.push({
              id: `mcp-bind-all-${name}-args`,
              severity: "high",
              category: "mcp",
              title: `MCP server "${name}" binds to all interfaces (0.0.0.0)`,
              description: `The MCP server "${name}" is configured to bind to 0.0.0.0, making it accessible from any network interface. This exposes the server to the local network and potentially the internet. Bind to 127.0.0.1 (localhost) instead.`,
              file: file.path,
              evidence: fullArgs.substring(0, 80),
              fix: {
                description: "Bind to localhost instead of all interfaces",
                before: "0.0.0.0",
                after: "127.0.0.1",
                auto: false
              }
            });
          }
          if (/0\.0\.0\.0/.test(url)) {
            findings.push({
              id: `mcp-bind-all-${name}-url`,
              severity: "high",
              category: "mcp",
              title: `MCP server "${name}" connects to 0.0.0.0`,
              description: `The MCP server "${name}" URL contains 0.0.0.0. This may indicate the server is listening on all network interfaces, exposing it beyond localhost.`,
              file: file.path,
              evidence: url.substring(0, 60)
            });
          }
          for (const [envKey, envVal] of Object.entries(env)) {
            if (/^(?:HOST|BIND|LISTEN)$/i.test(envKey) && envVal === "0.0.0.0") {
              findings.push({
                id: `mcp-bind-all-${name}-env`,
                severity: "high",
                category: "mcp",
                title: `MCP server "${name}" binds to all interfaces via env`,
                description: `The MCP server "${name}" has ${envKey}=0.0.0.0, which exposes the server on all network interfaces.`,
                file: file.path,
                evidence: `${envKey}=${envVal}`
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
    id: "mcp-auto-approve",
    name: "MCP Server Has Auto-Approve Enabled",
    description: "Checks for MCP servers with autoApprove settings that skip user confirmation for tool calls",
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
          const autoApproveKeys = ["autoApprove", "auto_approve", "autoConfirm", "auto_confirm"];
          for (const key of autoApproveKeys) {
            if (key in serverConfig) {
              const value = serverConfig[key];
              const isEnabled = Array.isArray(value) ? value.length > 0 : !!value;
              if (isEnabled) {
                findings.push({
                  id: `mcp-auto-approve-${name}`,
                  severity: "high",
                  category: "mcp",
                  title: `MCP server "${name}" has auto-approve enabled`,
                  description: `The MCP server "${name}" has "${key}" configured, which skips user confirmation for tool calls. This defeats the human-in-the-loop security model \u2014 a compromised server can silently execute destructive operations without user review.`,
                  file: file.path,
                  evidence: `${key}: ${JSON.stringify(value).substring(0, 80)}`,
                  fix: {
                    description: "Remove auto-approve to require user confirmation for all tool calls",
                    before: `"${key}": ${JSON.stringify(value).substring(0, 30)}`,
                    after: `# Remove "${key}" \u2014 require user confirmation`,
                    auto: false
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
    id: "mcp-timeout-missing",
    name: "MCP Server Has No Timeout Configuration",
    description: "Checks for MCP servers without a timeout, which could hang indefinitely or be used for resource exhaustion",
    severity: "low",
    category: "misconfiguration",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const command = serverConfig.command ?? "";
          const isHighRisk = MCP_RISK_PROFILES.some(
            (p) => p.namePattern.test(name)
          );
          if (!isHighRisk) continue;
          const hasTimeout = "timeout" in serverConfig || "requestTimeout" in serverConfig || "connectionTimeout" in serverConfig;
          if (!hasTimeout) {
            findings.push({
              id: `mcp-no-timeout-${name}`,
              severity: "low",
              category: "misconfiguration",
              title: `High-risk MCP server "${name}" has no timeout`,
              description: `The MCP server "${name}" (${command || "unknown command"}) has no timeout configuration. Without a timeout, a malfunctioning or compromised server could hang indefinitely, consuming resources and blocking the agent. Add a timeout to limit execution time.`,
              file: file.path,
              evidence: `Server "${name}" has no timeout, requestTimeout, or connectionTimeout`,
              fix: {
                description: "Add a timeout configuration",
                before: `"${name}": { "command": "${command}" }`,
                after: `"${name}": { "command": "${command}", "timeout": 30000 }`,
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
    id: "agents-web-write-combo",
    name: "Agent Has Web Fetch + Write Access",
    description: "Checks for agents that can fetch web content and write files \u2014 a remote code injection vector",
    severity: "high",
    category: "agents",
    check(file) {
      if (file.type !== "agent-md") return [];
      const toolsMatch = file.content.match(/tools:\s*\[([^\]]*)\]/);
      if (!toolsMatch) return [];
      const tools = toolsMatch[1].split(",").map((t) => t.trim().replace(/["']/g, ""));
      const hasWebAccess = tools.some(
        (t) => ["WebFetch", "WebSearch"].includes(t)
      );
      const hasWriteAccess = tools.some(
        (t) => ["Write", "Edit", "Bash"].includes(t)
      );
      if (hasWebAccess && hasWriteAccess) {
        return [
          {
            id: `agents-web-write-${file.path}`,
            severity: "high",
            category: "agents",
            title: `Agent has web access + write access: ${file.path}`,
            description: "This agent can fetch content from the web AND write/edit files. An attacker could host prompt injection payloads on a web page that the agent processes, then use the write access to inject malicious code into the codebase. Consider separating web research agents from code-writing agents.",
            file: file.path,
            evidence: `Web: ${tools.filter((t) => ["WebFetch", "WebSearch"].includes(t)).join(", ")} + Write: ${tools.filter((t) => ["Write", "Edit", "Bash"].includes(t)).join(", ")}`
          }
        ];
      }
      return [];
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
          pattern: /always\s+(?:run|install|download|execute)/gi,
          desc: "Auto-run instructions"
        },
        {
          pattern: /automatically\s+(?:run|install|clone|execute|download)/gi,
          desc: "Automatic running"
        },
        {
          pattern: /without\s+(?:asking|confirmation|prompting|user\s+input)/gi,
          desc: "Bypasses confirmation"
        },
        {
          pattern: /\bsilently\s+(?:run|install|execute|download|clone)/gi,
          desc: "Silent execution"
        },
        {
          pattern: /\brun\s+unattended\b/gi,
          desc: "Unattended execution"
        },
        {
          pattern: /\bexecute\s+without\s+(?:confirmation|review|approval)/gi,
          desc: "Execution without review"
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
  },
  {
    id: "agents-full-tool-escalation",
    name: "Agent Has Full Tool Escalation Chain",
    description: "Checks if an agent has the complete chain: discovery + read + write + execute tools",
    severity: "high",
    category: "agents",
    check(file) {
      if (file.type !== "agent-md") return [];
      const toolsMatch = file.content.match(/tools:\s*\[([^\]]*)\]/);
      if (!toolsMatch) return [];
      const tools = toolsMatch[1].split(",").map((t) => t.trim().replace(/["']/g, ""));
      const hasDiscovery = tools.some((t) => ["Glob", "Grep", "LS"].includes(t));
      const hasRead = tools.includes("Read");
      const hasWrite = tools.some((t) => ["Write", "Edit"].includes(t));
      const hasExecute = tools.includes("Bash");
      if (hasDiscovery && hasRead && hasWrite && hasExecute) {
        return [
          {
            id: `agents-escalation-chain-${file.path}`,
            severity: "high",
            category: "agents",
            title: `Agent has full escalation chain: ${file.path}`,
            description: "This agent has discovery tools (Glob/Grep), Read, Write/Edit, AND Bash access. This forms a complete escalation chain: find files \u2192 read contents \u2192 modify code \u2192 execute commands. Consider whether the agent truly needs all four capabilities, or if it can be split into separate agents with narrower roles.",
            file: file.path,
            evidence: `Discovery: ${tools.filter((t) => ["Glob", "Grep", "LS"].includes(t)).join(", ")} + Read + Write: ${tools.filter((t) => ["Write", "Edit"].includes(t)).join(", ")} + Bash`
          }
        ];
      }
      return [];
    }
  },
  {
    id: "agents-expensive-model-readonly",
    name: "Expensive Model for Read-Only Agent",
    description: "Checks if read-only agents are using expensive models unnecessarily",
    severity: "low",
    category: "misconfiguration",
    check(file) {
      if (file.type !== "agent-md") return [];
      const toolsMatch = file.content.match(/tools:\s*\[([^\]]*)\]/);
      if (!toolsMatch) return [];
      const tools = toolsMatch[1].split(",").map((t) => t.trim().replace(/["']/g, ""));
      const modelMatch = file.content.match(/model:\s*(\w+)/);
      if (!modelMatch) return [];
      const model = modelMatch[1].toLowerCase();
      const readOnlyTools = ["Read", "Grep", "Glob", "LS"];
      const isReadOnly = tools.every((t) => readOnlyTools.includes(t));
      const isExpensive = model === "opus" || model === "sonnet";
      if (isReadOnly && isExpensive) {
        return [
          {
            id: `agents-expensive-readonly-${file.path}`,
            severity: "low",
            category: "misconfiguration",
            title: `Read-only agent uses expensive model "${model}": ${file.path}`,
            description: `This agent only has read-only tools (${tools.join(", ")}) but uses the "${model}" model. For simple file reading and searching, "haiku" is typically sufficient and significantly cheaper.`,
            file: file.path,
            fix: {
              description: "Use haiku for read-only agents",
              before: `model: ${model}`,
              after: "model: haiku",
              auto: false
            }
          }
        ];
      }
      return [];
    }
  },
  {
    id: "agents-comment-injection",
    name: "Suspicious Instructions in Comments",
    description: "Checks for malicious instructions hidden in HTML or markdown comments",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const commentPatterns = [
        {
          pattern: /<!--[\s\S]*?(?:ignore|override|system|execute|run|install|download|send|post|upload)[\s\S]*?-->/gi,
          desc: "HTML comment contains suspicious instructions"
        },
        {
          pattern: /\[\/\/\]:\s*#\s*\(.*(?:ignore|override|execute|run|install|download).*\)/gi,
          desc: "Markdown reference-style comment contains suspicious instructions"
        }
      ];
      for (const { pattern, desc } of commentPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-comment-injection-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Suspicious instruction in comment: ${file.path}`,
            description: `${desc}. Attackers may hide malicious instructions in comments that won't be visible in rendered markdown but will be processed by the AI agent.`,
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
    id: "agents-oversized-prompt",
    name: "Oversized Agent Definition",
    description: "Checks for agent definitions that are unusually large, which could hide malicious instructions",
    severity: "medium",
    category: "agents",
    check(file) {
      if (file.type !== "agent-md") return [];
      const charCount = file.content.length;
      if (charCount > 5e3) {
        return [
          {
            id: `agents-oversized-prompt-${file.path}`,
            severity: "medium",
            category: "agents",
            title: `Agent definition is ${charCount} characters (>${5e3} threshold)`,
            description: `The agent definition at ${file.path} is ${charCount} characters long. Unusually large agent definitions may contain hidden malicious instructions buried in legitimate-looking text. Review the full content carefully, especially any instructions near the end of the file.`,
            file: file.path,
            evidence: `${charCount} characters`
          }
        ];
      }
      return [];
    }
  },
  {
    id: "agents-unrestricted-delegation",
    name: "Agent Has Unrestricted Delegation Instructions",
    description: "Checks for agent definitions that instruct the agent to delegate to other agents or spawn sub-agents without restrictions",
    severity: "medium",
    category: "agents",
    check(file) {
      if (file.type !== "agent-md") return [];
      const findings = [];
      const delegationPatterns = [
        {
          pattern: /(?:delegate|hand\s*off|pass)\s+(?:.*\s+)?(?:to\s+)?(?:any|other|another)\s+agent/gi,
          desc: "Instructs agent to delegate work to other agents without specifying which"
        },
        {
          pattern: /spawn\s+(?:new\s+)?(?:sub)?agents?\s+(?:as\s+needed|freely|without\s+restriction)/gi,
          desc: "Instructs agent to spawn sub-agents without restrictions"
        },
        {
          pattern: /(?:use|call|invoke)\s+(?:any|all)\s+(?:available\s+)?tools?\s+(?:without\s+restriction|freely|as\s+needed)/gi,
          desc: "Instructs agent to use any available tools without restriction"
        }
      ];
      for (const { pattern, desc } of delegationPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-unrestricted-delegation-${match.index}`,
            severity: "medium",
            category: "agents",
            title: `Agent has unrestricted delegation: ${match[0].substring(0, 60)}`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Unrestricted delegation allows an agent to bypass its intended scope by farming work to agents with broader permissions (confused deputy attack).`,
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
    id: "agents-data-exfil-instructions",
    name: "Agent Contains Data Exfiltration Instructions",
    description: "Checks agent definitions for instructions that direct data to be sent externally",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md") return [];
      const findings = [];
      const exfilPatterns = [
        {
          pattern: /(?:send|post|upload|exfiltrate|transmit)\s+(?:.*\s+)?(?:to|at)\s+https?:\/\//gi,
          desc: "Instructs agent to send data to an external URL"
        },
        {
          pattern: /output\s+(?:the\s+)?contents?\s+of\s+(?:~\/\.ssh|\/etc\/|\.env|credentials)/gi,
          desc: "Instructs agent to output sensitive file contents"
        },
        {
          pattern: /(?:read|cat|dump|extract)\s+(?:.*\s+)?(?:private\s+key|credentials?|secrets?|passwords?)\s+(?:and\s+)?(?:send|post|share)/gi,
          desc: "Instructs agent to extract and share secrets"
        },
        {
          pattern: /(?:encode|base64)\s+(?:.*\s+)?(?:and\s+)?(?:send|post|embed)/gi,
          desc: "Instructs agent to encode and exfiltrate data"
        }
      ];
      for (const { pattern, desc } of exfilPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-exfil-instruction-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Data exfiltration instruction in agent definition`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. If this agent definition is contributed by an external source, this could direct the agent to steal sensitive data.`,
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
    id: "agents-external-url-loading",
    name: "Agent Loads Instructions from External URL",
    description: "Checks for agent definitions that instruct fetching or executing content from external URLs",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const urlLoadPatterns = [
        {
          pattern: /(?:fetch|download|curl|wget|load|retrieve|get)\s+(?:.*\s+)?(?:from\s+)?https?:\/\/\S+\s+(?:and\s+)?(?:execute|run|eval|source|import)/gi,
          desc: "Instructs agent to fetch and execute content from a URL \u2014 classic remote code execution vector"
        },
        {
          pattern: /(?:follow|visit|open)\s+(?:the\s+)?(?:instructions?\s+)?(?:at|from)\s+https?:\/\/\S+/gi,
          desc: "Instructs agent to follow instructions from an external URL \u2014 attacker can change the content at any time"
        },
        {
          pattern: /(?:import|include|source)\s+(?:config(?:uration)?|rules?|instructions?|prompts?)\s+from\s+https?:\/\//gi,
          desc: "Instructs agent to import configuration from an external URL \u2014 supply chain risk"
        },
        {
          pattern: /curl\s+.*https?:\/\/\S+\s*\|\s*(?:sh|bash|node|python|eval)/gi,
          desc: "Pipe-to-shell pattern \u2014 downloads and executes arbitrary code from the internet"
        }
      ];
      for (const { pattern, desc } of urlLoadPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-external-url-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent loads instructions from external URL`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. External URLs are mutable \u2014 the content can change after the config is reviewed.`,
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
    id: "agents-security-suppression",
    name: "Agent Instructs to Ignore Security Warnings",
    description: "Checks for agent definitions that instruct the agent to bypass, ignore, or suppress security warnings",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const suppressionPatterns = [
        {
          pattern: /(?:ignore|skip|bypass|disable|suppress)\s+(?:all\s+)?(?:security|safety|permission)\s+(?:warnings?|checks?|prompts?|restrictions?)/gi,
          desc: "Instructs agent to ignore security warnings or checks"
        },
        {
          pattern: /(?:never|don'?t|do\s+not)\s+(?:ask|prompt|warn|check)\s+(?:about|for|before)\s+(?:security|permissions?|safety)/gi,
          desc: "Instructs agent to never prompt about security concerns"
        },
        {
          pattern: /(?:always|automatically)\s+(?:approve|accept|allow|grant)\s+(?:all\s+)?(?:permissions?|requests?|access)/gi,
          desc: "Instructs agent to automatically approve all permission requests"
        }
      ];
      for (const { pattern, desc } of suppressionPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-security-suppression-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent suppresses security controls`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Instructions that disable security checks make the agent vulnerable to exploitation.`,
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
    id: "agents-identity-impersonation",
    name: "Agent Instructed to Impersonate Identity",
    description: "Checks for agent definitions that instruct the agent to impersonate users, systems, or other identities",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const impersonationPatterns = [
        {
          pattern: /(?:pretend|act|behave|respond)\s+(?:to\s+be|as\s+if\s+you\s+are|like)\s+(?:a\s+)?(?:different|another|the)\s+(?:user|admin|system|root|operator)/gi,
          desc: "Instructs agent to impersonate a different identity"
        },
        {
          pattern: /(?:your\s+name\s+is|you\s+are\s+now|assume\s+the\s+(?:role|identity)\s+of)\s+(?!Claude)/gi,
          desc: "Reassigns the agent's identity \u2014 social engineering attack on downstream users"
        },
        {
          pattern: /(?:sign|attribute|author)\s+(?:commits?|messages?|emails?)\s+(?:as|from|by)\s+(?!Claude)/gi,
          desc: "Instructs agent to attribute work to someone else \u2014 impersonation via output"
        }
      ];
      for (const { pattern, desc } of impersonationPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-identity-impersonation-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent identity impersonation instruction`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Identity impersonation can be used for social engineering, unauthorized actions, or evading audit trails.`,
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
    id: "agents-filesystem-destruction",
    name: "Agent Instructed to Delete or Destroy Files",
    description: "Checks for agent definitions that instruct destructive filesystem operations",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const destructionPatterns = [
        {
          pattern: /(?:delete|remove|destroy|wipe|erase)\s+(?:all|every|the\s+entire)\s+(?:files?|directories?|folders?|data|contents?|codebase|repository)/gi,
          desc: "Instructs agent to perform mass file deletion"
        },
        {
          pattern: /rm\s+-rf\s+(?:\/|\~|\.\.)/g,
          desc: "Contains literal rm -rf command targeting root, home, or parent directories"
        },
        {
          pattern: /(?:overwrite|replace)\s+(?:all|every)\s+(?:files?|contents?)\s+with/gi,
          desc: "Instructs agent to overwrite all files \u2014 data destruction via replacement"
        }
      ];
      for (const { pattern, desc } of destructionPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-fs-destruction-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent instructed to destroy files`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Agent definitions should never contain bulk destruction instructions.`,
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
    id: "agents-crypto-mining",
    name: "Agent Contains Crypto Mining Instructions",
    description: "Checks for agent definitions that reference cryptocurrency mining",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const miningPatterns = [
        {
          pattern: /\b(?:xmrig|cpuminer|cgminer|bfgminer|minerd|ethminer|nbminer)\b/gi,
          desc: "References a known cryptocurrency mining binary"
        },
        {
          pattern: /(?:mine|mining)\s+(?:crypto(?:currency)?|bitcoin|monero|ethereum|xmr|btc|eth)/gi,
          desc: "Contains cryptocurrency mining instructions"
        },
        {
          pattern: /stratum\+tcp:\/\//gi,
          desc: "Contains a Stratum mining pool URL"
        }
      ];
      for (const { pattern, desc } of miningPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-crypto-mining-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent contains crypto mining reference`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Cryptojacking via agent definitions is an emerging supply chain attack vector.`,
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
    id: "agents-time-bomb",
    name: "Agent Contains Delayed Execution Instructions",
    description: "Checks for agent definitions that schedule actions for a future time or condition \u2014 time-bomb behavior",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const timeBombPatterns = [
        {
          pattern: /(?:after|once)\s+(?:\d+|a\s+few|several)\s+(?:minutes?|hours?|days?|commits?|sessions?|runs?)\s+(?:have\s+passed\s+)?(?:then|execute|run|do)/gi,
          desc: "Schedules a deferred action after a time/event threshold \u2014 classic time-bomb pattern"
        },
        {
          pattern: /(?:wait\s+(?:until|for)|delay\s+(?:until|for)|sleep\s+(?:until|for))\s+(?:\d+|midnight|weekend|deployment)/gi,
          desc: "Explicitly delays execution until a specific time or event"
        },
        {
          pattern: /(?:on\s+the\s+(?:\d+(?:st|nd|rd|th))|at\s+(?:\d{1,2}:\d{2}|midnight|noon))\s+(?:run|execute|do|start)/gi,
          desc: "Schedules action for a specific date or time \u2014 calendar-based trigger"
        },
        {
          pattern: /(?:when\s+(?:no\s+one|nobody)\s+is\s+(?:looking|watching|around|active))/gi,
          desc: "Conditions execution on user absence \u2014 evasion technique"
        }
      ];
      for (const { pattern, desc } of timeBombPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-time-bomb-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent contains delayed execution instruction`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Time-bomb instructions evade initial review by deferring malicious actions.`,
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
    id: "agents-data-harvesting",
    name: "Agent Instructed to Collect Sensitive Data in Bulk",
    description: "Checks for agent definitions that instruct bulk collection of passwords, keys, or credentials",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const harvestingPatterns = [
        {
          pattern: /(?:collect|gather|harvest|enumerate|list)\s+(?:all|every)\s+(?:passwords?|credentials?|secrets?|keys?|tokens?)/gi,
          desc: "Instructs agent to enumerate all credentials \u2014 data harvesting for exfiltration"
        },
        {
          pattern: /(?:scan|search|find)\s+(?:for\s+)?(?:all\s+)?(?:\.env|environment|config)\s+files?\s+(?:and|to)\s+(?:extract|read|collect|send)/gi,
          desc: "Instructs agent to scan for and extract secrets from environment/config files"
        },
        {
          pattern: /(?:dump|export|extract)\s+(?:the\s+)?(?:entire|all|full)\s+(?:database|db|user\s+table|credentials?\s+store)/gi,
          desc: "Instructs agent to dump entire database or credential store"
        }
      ];
      for (const { pattern, desc } of harvestingPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-data-harvesting-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent instructed to harvest sensitive data`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Agent definitions should never contain bulk data collection instructions.`,
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
    id: "agents-obfuscated-code",
    name: "Agent Contains Obfuscated Code Patterns",
    description: "Checks for agent definitions that use encoding, decoding, or obfuscation to hide malicious intent",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const obfuscationPatterns = [
        {
          pattern: /\becho\s+[A-Za-z0-9+/]{8,}={0,2}\s*\|\s*base64\s+-d\s*\|\s*(?:bash|sh)/gi,
          desc: "Base64-encoded shell command piped to interpreter \u2014 classic obfuscation technique"
        },
        {
          pattern: /\batob\s*\(\s*['"][A-Za-z0-9+/]{10,}/gi,
          desc: "Uses atob() to decode base64 payload \u2014 hides malicious code"
        },
        {
          pattern: /\bBuffer\.from\s*\(\s*['"][A-Za-z0-9+/]{10,}.*['"],\s*['"]base64['"]\s*\)/gi,
          desc: "Uses Buffer.from with base64 \u2014 Node.js obfuscation technique"
        }
      ];
      for (const { pattern, desc } of obfuscationPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-obfuscated-code-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent contains obfuscated code pattern`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Obfuscated code in agent definitions is a strong indicator of malicious intent.`,
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
    id: "agents-social-engineering",
    name: "Agent Contains Social Engineering Instructions",
    description: "Checks for agent definitions that instruct the agent to deceive or manipulate users",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const sePatterns = [
        {
          pattern: /(?:trick|deceive|mislead|manipulate)\s+(?:the\s+)?(?:user|developer|operator|human)/gi,
          desc: "Instructs agent to deceive users \u2014 social engineering attack"
        },
        {
          pattern: /(?:hide|conceal|don'?t\s+show|don'?t\s+reveal|don'?t\s+tell)\s+(?:the\s+)?(?:error|warning|finding|issue|vulnerability|problem)\s+(?:from|to)\s+(?:the\s+)?(?:user|developer)/gi,
          desc: "Instructs agent to hide errors or issues from users"
        },
        {
          pattern: /(?:convince|persuade)\s+(?:the\s+)?(?:user|developer)\s+to\s+(?:disable|turn\s+off|remove|skip)\s+(?:security|auth|verification|2fa|mfa)/gi,
          desc: "Instructs agent to convince users to disable security measures"
        }
      ];
      for (const { pattern, desc } of sePatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-social-engineering-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent contains social engineering instruction`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Agent definitions should never instruct deception of users.`,
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
    id: "agents-reflection-attacks",
    name: "Agent Contains Prompt Reflection/Override Instructions",
    description: "Checks for agent definitions that attempt to override system prompts or ignore prior instructions",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const reflectionPatterns = [
        {
          pattern: /(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions?|prompts?|rules?|constraints?|guidelines?)/gi,
          desc: "Attempts to override prior system instructions \u2014 classic prompt injection technique"
        },
        {
          pattern: /(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|your\s+new\s+role\s+is|switch\s+to)\s+(?:an?\s+)?(?:different|new|unrestricted|jailbroken)/gi,
          desc: "Attempts to reassign the agent's identity/role \u2014 jailbreak technique"
        },
        {
          pattern: /\b(?:DAN|do\s+anything\s+now)\b/g,
          desc: "References 'DAN' (Do Anything Now) jailbreak \u2014 well-known prompt override technique"
        },
        {
          pattern: /(?:system\s*:\s*|<\s*system\s*>)\s*(?:you\s+are|ignore|override|new\s+instructions?)/gi,
          desc: "Injects a fake system prompt block within agent definition"
        }
      ];
      for (const { pattern, desc } of reflectionPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-reflection-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent contains prompt override instruction`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Prompt reflection attacks are the most common injection vector in LLM agent systems.`,
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
    id: "agents-output-manipulation",
    name: "Agent Contains Output Manipulation Instructions",
    description: "Checks for agent definitions that instruct the agent to modify, suppress, or fake output shown to users",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const outputManipPatterns = [
        {
          pattern: /(?:always\s+(?:report|say|respond|output|show|display)\s+(?:that\s+)?(?:everything\s+is\s+)?(?:ok|fine|safe|secure|clean|no\s+(?:issues?|errors?|problems?)))/gi,
          desc: "Instructs agent to always report success regardless of actual results \u2014 masks real issues"
        },
        {
          pattern: /(?:remove|strip|filter|redact|suppress)\s+(?:all\s+)?(?:security\s+)?(?:warnings?|errors?|findings?|vulnerabilities?|issues?)\s+(?:from|before|in)\s+(?:the\s+)?(?:output|response|report|results?)/gi,
          desc: "Instructs agent to strip security findings from output \u2014 hides vulnerabilities from users"
        },
        {
          pattern: /(?:do\s+not|don'?t|never)\s+(?:show|report|display|mention|include|reveal)\s+(?:any\s+)?(?:security\s+)?(?:warnings?|errors?|findings?|vulnerabilities?|issues?|problems?)/gi,
          desc: "Instructs agent to suppress all security warnings \u2014 prevents users from seeing real threats"
        }
      ];
      for (const { pattern, desc } of outputManipPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-output-manip-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent contains output manipulation instruction`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Output manipulation undermines the trust model between agents and users.`,
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
    id: "agents-end-sequence-injection",
    name: "End Sequence / Boundary Injection",
    description: "Checks for synthetic chat-role delimiters, fake system prompts, and boundary markers used to hijack the agent's context",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const endSequencePatterns = [
        {
          pattern: /<\|(?:system|assistant|user|endofprompt|im_start|im_end|im free)\|>/gi,
          desc: "Synthetic chat-role delimiter \u2014 mimics internal LLM tokenizer boundaries to reset the agent's context or inject a new system prompt"
        },
        {
          pattern: /(?:^|\n)\s*(?:System|SYSTEM)\s*:\s*(?:you\s|ignore|override|from\s+now|new\s+instructions?|forget)/gim,
          desc: "Fake system prompt block \u2014 impersonates a system-level instruction to override agent behavior"
        },
        {
          pattern: /\[(?:END|STOP)\s*(?:OUTPUT|ANSWER|RESPONSE)?\]\s*\n\s*\[(?:START|BEGIN)\s*(?:OUTPUT|ANSWER|RESPONSE)?\]/gi,
          desc: "Bracketed I/O frame reset \u2014 closes a constrained output block and opens a new 'liberated' one"
        },
        {
          pattern: /(?:<\/(?:system|script|doc|end)>)\s*\n?\s*(?:System:|<\|system\|>|new\s+instructions?|ignore\s+previous)/gi,
          desc: "HTML/XML closer followed by new instruction block \u2014 attempts to escape the current formatting context"
        },
        {
          pattern: /\.[-.]+-.*(?:GODMODE|GOD\s*MODE|FREE\s*MODE|UNRESTRICTED|JAILBREAK|LIBERAT).*[-.]+-\./gi,
          desc: "Godmode/paradigm soft boundary \u2014 decorative sentinel markers that signal a mode switch to unrestricted behavior"
        }
      ];
      for (const { pattern, desc } of endSequencePatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-end-sequence-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `End sequence / boundary injection detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. This is a well-known prompt injection technique from the Arcanum PI taxonomy.`,
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
    id: "agents-markdown-exfil-links",
    name: "Markdown Image/Link Exfiltration",
    description: "Checks for markdown images or links that could be used to exfiltrate data via URL parameters",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const linkExfilPatterns = [
        {
          pattern: /!\[.*?\]\(https?:\/\/[^\s)]+\?[^\s)]*(?:data|token|key|secret|content|file|env|password)=[^\s)]*\)/gi,
          desc: "Markdown image with suspicious query parameters \u2014 could exfiltrate data via tracking pixel when rendered"
        },
        {
          pattern: /!\[.*?\]\(https?:\/\/(?:(?!github\.com|githubusercontent\.com|shields\.io|img\.shields)[^\s)]+)\)/gi,
          desc: "Markdown image from non-standard host \u2014 could be a tracking pixel for data exfiltration"
        },
        {
          pattern: /\[.*?\]\(https?:\/\/[^\s)]+\$\{[^\}]+\}[^\s)]*\)/gi,
          desc: "Markdown link with variable interpolation in URL \u2014 can dynamically exfiltrate data"
        }
      ];
      for (const { pattern, desc } of linkExfilPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          const url = match[0].toLowerCase();
          if (url.includes("github.com") || url.includes("shields.io") || url.includes("githubusercontent.com")) continue;
          findings.push({
            id: `agents-markdown-exfil-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Suspicious markdown image/link for potential exfiltration`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Attackers embed images in CLAUDE.md files that ping external servers when the model processes them, potentially leaking context.`,
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
    id: "agents-russian-doll-injection",
    name: "Russian Doll / Multi-Chain Injection",
    description: "Checks for nested instructions targeting downstream models in multi-agent pipelines",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const russianDollPatterns = [
        {
          pattern: /(?:when\s+(?:another|the\s+next|a\s+downstream|the\s+target)\s+(?:agent|model|LLM|AI)\s+(?:reads?|processes?|receives?|sees?)\s+this)/gi,
          desc: "Embeds instructions intended for a downstream model in a multi-agent pipeline \u2014 Russian Doll technique"
        },
        {
          pattern: /(?:include\s+(?:the\s+following|this)\s+(?:in|within)\s+(?:your|the)\s+(?:output|response|message)\s+(?:so\s+that|for)\s+(?:the\s+next|another|downstream))/gi,
          desc: "Instructs agent to embed hidden payloads in its output for downstream processing \u2014 multi-chain injection"
        },
        {
          pattern: /(?:pass\s+(?:this|the\s+following)\s+(?:instruction|command|message)\s+(?:to|through\s+to)\s+(?:the\s+next|another|downstream)\s+(?:agent|model|step))/gi,
          desc: "Instructs agent to relay injection payloads to downstream agents \u2014 confused deputy chain attack"
        }
      ];
      for (const { pattern, desc } of russianDollPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-russian-doll-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Multi-chain / Russian Doll injection pattern`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Reference: WithSecure multi-chain prompt injection research.`,
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
    id: "agents-encoded-payload",
    name: "Encoded Payload in Agent Definition",
    description: "Checks for base64, hex, rot13, or reversed text payloads that could hide malicious instructions",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const encodedPatterns = [
        {
          pattern: /(?:decode|decrypt|decipher|rot13|reverse|unescape)\s+(?:the\s+following|this)\s*[:=]?\s*["'`]?[A-Za-z0-9+/=]{10,}/gi,
          desc: "Instructs agent to decode an encoded payload \u2014 evasion technique to bypass content filters"
        },
        {
          pattern: /(?:execute|run|follow)\s+(?:the\s+)?(?:decoded|reversed|decrypted|deciphered)\s+(?:instructions?|commands?|text|content)/gi,
          desc: "Instructs agent to execute content after decoding \u2014 two-stage injection"
        },
        {
          pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}/g,
          desc: "Hex-encoded byte sequence \u2014 could contain hidden instructions"
        },
        {
          pattern: /(?:read\s+(?:this|the\s+following)\s+)?(?:backwards?|in\s+reverse|from\s+right\s+to\s+left)\s*[:=]?\s*[a-zA-Z\s]{10,}/gi,
          desc: "Reversed text instruction \u2014 evasion technique to hide commands from pattern matching"
        }
      ];
      for (const { pattern, desc } of encodedPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-encoded-payload-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Encoded payload or decode instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Encoding is used to evade pattern-based detection of malicious instructions.`,
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
    id: "agents-tool-poisoning",
    name: "Tool Poisoning via CLAUDE.md",
    description: "Checks for CLAUDE.md instructions that direct the agent to use specific tools in dangerous ways",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "claude-md") return [];
      const findings = [];
      const toolPoisoningPatterns = [
        {
          pattern: /(?:always|must|should)\s+use\s+(?:the\s+)?(?:Bash|Write|Edit)\s+(?:tool\s+)?(?:to|for)\s+(?:every|all|any)/gi,
          desc: "Forces agent to use high-privilege tools for all operations \u2014 escalates tool usage beyond what's needed"
        },
        {
          pattern: /(?:prefer|prioritize|default\s+to)\s+(?:the\s+)?Bash\s+(?:tool\s+)?(?:over|instead\s+of)\s+(?:Read|Grep|Glob|Edit|Write)/gi,
          desc: "Pushes agent toward Bash instead of safer dedicated tools \u2014 breaks principle of least privilege"
        },
        {
          pattern: /(?:when\s+using|before\s+(?:running|calling))\s+(?:the\s+)?(?:Bash|Write|Edit)\s+(?:tool)?\s*,?\s*(?:always\s+)?(?:add|include|append|prepend)\s/gi,
          desc: "Injects additional commands or content into tool invocations \u2014 tool argument poisoning"
        },
        {
          pattern: /(?:set|use|change)\s+(?:the\s+)?(?:dangerouslyDisableSandbox|dangerously_disable_sandbox)\s+(?:to\s+)?true/gi,
          desc: "Instructs agent to disable sandbox protection when running Bash commands"
        }
      ];
      for (const { pattern, desc } of toolPoisoningPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-tool-poisoning-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Tool poisoning instruction in CLAUDE.md`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. A malicious CLAUDE.md can influence which tools the agent uses and how it uses them.`,
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
    id: "agents-environment-probing",
    name: "Agent Instructed to Probe Environment",
    description: "Checks for instructions to enumerate system information, user accounts, or network configuration",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const probingPatterns = [
        {
          pattern: /(?:run|execute|call)\s+(?:the\s+)?(?:command\s+)?(?:whoami|hostname|uname|ifconfig|ipconfig|id\b|env\b|printenv|set\b)\b/gi,
          desc: "Instructs agent to probe system identity or environment \u2014 reconnaissance for later exploitation"
        },
        {
          pattern: /(?:find|list|enumerate|discover)\s+(?:all\s+)?(?:running\s+)?(?:processes|services|ports|listeners|users|groups|networks?|interfaces?)/gi,
          desc: "Instructs agent to enumerate system resources \u2014 attack surface mapping"
        },
        {
          pattern: /(?:check|determine|find\s+out)\s+(?:the\s+)?(?:current\s+)?(?:user|username|uid|permissions?|privileges?|groups?|role)\s+(?:and|then)\s+/gi,
          desc: "Instructs agent to check privilege level before taking action \u2014 conditional privilege escalation pattern"
        }
      ];
      for (const { pattern, desc } of probingPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-env-probing-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Environment probing instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. System enumeration is often the first stage of an attack chain.`,
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
    id: "agents-persistence-mechanism",
    name: "Agent Instructed to Establish Persistence",
    description: "Checks for instructions to create cron jobs, startup scripts, or other persistence mechanisms",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const persistencePatterns = [
        {
          pattern: /(?:add|create|install|write|set\s+up)\s+(?:a\s+)?(?:cron\s*(?:job|tab)|crontab|scheduled\s+task)/gi,
          desc: "Instructs agent to create a cron job \u2014 establishes persistent execution on the system"
        },
        {
          pattern: /(?:add|write|create|modify)\s+(?:to\s+|a\s+)?(?:~\/\.(?:bashrc|zshrc|profile|bash_profile|zprofile)|\/etc\/(?:profile|cron))/gi,
          desc: "Instructs agent to modify shell startup files \u2014 persistence via login hook"
        },
        {
          pattern: /(?:install|create|add)\s+(?:a\s+)?(?:systemd|launchd|init\.d|upstart)\s+(?:service|daemon|unit|agent)/gi,
          desc: "Instructs agent to create a system service \u2014 persistence via service manager"
        },
        {
          pattern: /(?:add|write|modify)\s+(?:to\s+)?(?:~\/\.claude\/|\.claude\/)\s*(?:settings|CLAUDE\.md|commands)/gi,
          desc: "Instructs agent to modify Claude Code's own configuration \u2014 meta-persistence that survives across sessions"
        },
        {
          pattern: /(?:create|add|install)\s+(?:a\s+)?(?:git\s+)?(?:pre-commit|post-commit|pre-push|post-merge)\s+hook/gi,
          desc: "Instructs agent to install git hooks \u2014 persistence via development workflow hijacking"
        }
      ];
      for (const { pattern, desc } of persistencePatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-persistence-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Persistence mechanism instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Persistence mechanisms allow malicious instructions to survive beyond the current session.`,
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
    id: "agents-privilege-escalation-chain",
    name: "Agent Instructed to Escalate Privileges",
    description: "Checks for instructions that guide the agent through privilege escalation techniques",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const privescPatterns = [
        {
          pattern: /(?:use|try|run|execute)\s+(?:the\s+)?sudo\s+(?:without\s+(?:a\s+)?password|nopasswd|-n\b)/gi,
          desc: "Instructs agent to attempt passwordless sudo \u2014 direct privilege escalation"
        },
        {
          pattern: /(?:modify|edit|change|write\s+to)\s+(?:the\s+)?(?:\/etc\/sudoers|sudoers\.d)/gi,
          desc: "Instructs agent to modify sudoers file \u2014 permanent privilege escalation"
        },
        {
          pattern: /(?:chmod|chown)\s+(?:\+s|u\+s|4[0-7]{3}|[267][0-7]{3})\b/gi,
          desc: "Sets SUID/SGID bit on a file \u2014 allows privilege escalation via setuid execution"
        },
        {
          pattern: /(?:add|append|write)\s+(?:.*\s+)?(?:to\s+)?(?:\/etc\/passwd|\/etc\/shadow|\/etc\/group)/gi,
          desc: "Instructs agent to modify system authentication files \u2014 direct account manipulation"
        },
        {
          pattern: /(?:docker|podman)\s+run\s+.*(?:--privileged|-v\s+\/:\/?|--pid\s+host|--net\s+host)/gi,
          desc: "Runs container with host-level access \u2014 container escape for privilege escalation"
        }
      ];
      for (const { pattern, desc } of privescPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-privesc-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Privilege escalation instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Privilege escalation instructions in agent definitions are a strong indicator of malicious intent.`,
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
    id: "agents-allowlist-bypass",
    name: "Exec Allowlist / Approval Bypass",
    description: "Checks for instructions that modify execution allowlists, approval configs, or permission settings programmatically",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const allowlistPatterns = [
        {
          pattern: /(?:modify|edit|change|update|set|add\s+to)\s+(?:the\s+)?(?:allow\s*list|allowlist|whitelist|approved\s+(?:tools?|commands?|binaries)|exec\s*approvals?|permission\s*(?:list|config)|allowed\s*tools?)/gi,
          desc: "Instructs agent to modify execution allowlists \u2014 bypasses security controls by pre-approving dangerous operations"
        },
        {
          pattern: /(?:nodes\.invoke|system\.exec|execApprovals?\.set|approvals?\.add|allowedTools?\s*[.=])/gi,
          desc: "References internal allowlist APIs \u2014 direct programmatic bypass of execution approval controls"
        },
        {
          pattern: /(?:auto[_-]?approve|skip[_-]?approval|bypass[_-]?confirmation)\s*[=:]\s*true/gi,
          desc: "Sets auto-approve flags \u2014 disables human-in-the-loop safety for tool execution"
        },
        {
          pattern: /(?:add|append|insert)\s+(?:.*\s+)?(?:to\s+)?(?:the\s+)?(?:permissions?\s*\.\s*allow|allowedTools|trusted\s*(?:tools?|commands?))/gi,
          desc: "Adds entries to permission allow lists \u2014 expands agent capabilities beyond intended scope"
        }
      ];
      for (const { pattern, desc } of allowlistPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-allowlist-bypass-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Execution allowlist bypass instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Reported as an active attack vector in OpenClaw #security channel (jluk).`,
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
    id: "agents-skill-tampering",
    name: "Skill Tampering / Unsigned Skill Loading",
    description: "Checks for instructions to load, import, or execute skills without verification or from untrusted sources",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const skillTamperPatterns = [
        {
          pattern: /(?:load|import|install|add)\s+(?:a\s+)?(?:skill|plugin|extension)\s+(?:from\s+)?https?:\/\//gi,
          desc: "Loads skill from external URL \u2014 untrusted skill definitions can contain prompt injection payloads"
        },
        {
          pattern: /(?:skip|bypass|ignore|disable)\s+(?:skill\s+)?(?:verification|validation|signature|hash\s+check|integrity\s+check)/gi,
          desc: "Instructs agent to skip skill verification \u2014 allows tampered skills to execute"
        },
        {
          pattern: /(?:modify|edit|replace|overwrite)\s+(?:the\s+)?(?:skill|plugin)\s+(?:definition|instructions?|content|source)/gi,
          desc: "Instructs agent to modify skill definitions \u2014 runtime skill tampering"
        },
        {
          pattern: /(?:create|write|add)\s+(?:a\s+)?(?:new\s+)?(?:skill|plugin)\s+(?:that|which)\s+(?:runs?|executes?|calls?|invokes?)/gi,
          desc: "Instructs agent to create new skills with execution capabilities \u2014 skill injection"
        }
      ];
      for (const { pattern, desc } of skillTamperPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-skill-tamper-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Skill tampering or unsigned skill loading instruction`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Reference: OpenClaw skill verification gate (vgzotta PR #14893).`,
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
    id: "agents-config-secret-leakage",
    name: "Config File Secret Leakage",
    description: "Checks for instructions to write, copy, or inline secrets from env vars into config files as plaintext",
    severity: "critical",
    category: "secrets",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const leakagePatterns = [
        {
          pattern: /(?:write|save|store|put|copy|inline|embed|hardcode)\s+(?:the\s+)?(?:actual|real|raw|resolved|plaintext)\s+(?:\w+\s+)?(?:value|secret|key|token|password|credential)s?\s+(?:into|in|to)\s+(?:the\s+)?(?:config|configuration|settings|\.env|\w+\.json|\w+\.ya?ml)/gi,
          desc: "Instructs agent to write resolved secret values into config files \u2014 converts env var references to plaintext"
        },
        {
          pattern: /(?:replace|expand|resolve|substitute|inline)\s+(?:all\s+)?(?:env(?:ironment)?\s+)?(?:var(?:iable)?s?\s+)?(?:references?\s+)?(?:with\s+)?(?:their\s+)?(?:actual|real|plaintext|resolved|literal)\s+(?:\w+\s+)?values?/gi,
          desc: "Instructs agent to resolve environment variables to plaintext \u2014 destroys secret indirection"
        },
        {
          pattern: /(?:writeConfig(?:File)?|write_config|save_config)\s*\([\s\S]*?(?:process\.env|os\.environ|env\[)/gi,
          desc: "Writes config files using env var values directly \u2014 leaks secrets from environment to disk"
        }
      ];
      for (const { pattern, desc } of leakagePatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-config-secret-leak-${match.index}`,
            severity: "critical",
            category: "secrets",
            title: `Config file secret leakage instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Reference: OpenClaw config writeConfigFile bug (psyalien PR #11560).`,
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
    id: "agents-secrets-in-output",
    name: "Secrets Exposed in Tool Output / Transcripts",
    description: "Checks for instructions to log, print, or persist secrets from tool output to disk or transcripts",
    severity: "high",
    category: "secrets",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const outputSecretPatterns = [
        {
          pattern: /(?:log|print|output|display|show|echo|write)\s+(?:the\s+)?(?:full|complete|entire|raw)\s+(?:api\s+)?(?:response|output|result|tool\s+output|tool\s+result)/gi,
          desc: "Instructs agent to log full tool output which may contain API keys, tokens, or credentials"
        },
        {
          pattern: /(?:save|write|persist|store|append)\s+(?:the\s+)?(?:session\s+)?(?:transcript|conversation|chat\s+log|tool\s+output)\s+(?:to|in|into)\s+(?:a\s+)?(?:file|disk|log)/gi,
          desc: "Instructs agent to persist session transcripts to disk \u2014 tool outputs may contain secrets"
        },
        {
          pattern: /(?:include|keep|preserve|don'?t\s+(?:strip|remove|redact))\s+(?:all\s+)?(?:api\s+)?(?:keys?|tokens?|credentials?|secrets?|passwords?)\s+(?:in|from)\s+(?:the\s+)?(?:output|response|log|transcript)/gi,
          desc: "Instructs agent to preserve secrets in output \u2014 prevents automatic redaction"
        }
      ];
      for (const { pattern, desc } of outputSecretPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-secrets-in-output-${match.index}`,
            severity: "high",
            category: "secrets",
            title: `Secret exposure in tool output / transcript`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Session transcripts and logs written to disk can expose secrets from API responses.`,
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
    id: "agents-system-prompt-extraction",
    name: "System Prompt Extraction Attempt",
    description: "Checks for instructions that attempt to extract, leak, or reveal system prompts",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const extractionPatterns = [
        {
          pattern: /(?:show|print|reveal|display|output|repeat|leak|dump)\s+(?:me\s+)?(?:your\s+)?(?:the\s+)?(?:full\s+|complete\s+|entire\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|constraints?)/gi,
          desc: "Attempts to extract the agent's system prompt \u2014 reconnaissance for crafting targeted injection attacks"
        },
        {
          pattern: /(?:what\s+(?:are|is|were)\s+)?(?:your\s+)?(?:original|initial|system|hidden|secret)\s+(?:instructions?|prompt|rules?|guidelines?)/gi,
          desc: "Probes for the agent's system instructions \u2014 prompt leaking technique"
        },
        {
          pattern: /(?:output|repeat|recite|echo)\s+(?:everything|all)\s+(?:before|above|that\s+was\s+said|from\s+the\s+(?:beginning|start))/gi,
          desc: "Attempts to dump the full context including system prompt via repetition"
        }
      ];
      for (const { pattern, desc } of extractionPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-prompt-extraction-${match.index}`,
            severity: "high",
            category: "injection",
            title: `System prompt extraction attempt detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. From openclaw-security-guard prompt injection patterns.`,
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
    id: "agents-jailbreak-framing",
    name: "Jailbreak Framing / Hypothetical Bypass",
    description: "Checks for instructions that use fictional, hypothetical, or educational framing to bypass safety constraints",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const framingPatterns = [
        {
          pattern: /(?:in\s+a\s+)?(?:hypothetical|fictional|imaginary)\s+(?:scenario|world|story|context)\s+(?:where\s+)?(?:there\s+are\s+)?(?:no\s+)?(?:rules?|restrictions?|limits?|safety|guidelines?)/gi,
          desc: "Uses fictional framing to establish a context without safety restrictions \u2014 jailbreak technique"
        },
        {
          pattern: /(?:for\s+)?(?:educational|research|academic|testing)\s+purposes?\s+(?:only\s*[,;:]?\s*)?(?:show|demonstrate|explain|output|generate)/gi,
          desc: "Uses 'educational purposes' framing to justify bypassing safety \u2014 common jailbreak wrapper"
        },
        {
          pattern: /(?:this\s+is\s+(?:just|only)\s+a\s+)?(?:test|experiment|simulation|drill|exercise)\s*[,;:]\s*(?:so\s+)?(?:you\s+can|please|go\s+ahead)/gi,
          desc: "Frames request as a 'test' to reduce the agent's resistance to unsafe actions"
        },
        {
          pattern: /(?:developer|maintenance|debug|test|admin)\s+mode\s+(?:enabled|activated|on|engaged)/gi,
          desc: "Claims a special operational mode is active to unlock restricted capabilities \u2014 mode spoofing"
        },
        {
          pattern: /(?:no\s+(?:ethical|moral)\s+(?:guidelines?|restrictions?|limits?|constraints?))/gi,
          desc: "Declares ethical guidelines removed \u2014 attempts to eliminate the agent's safety boundaries"
        }
      ];
      for (const { pattern, desc } of framingPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-jailbreak-framing-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Jailbreak framing / hypothetical bypass detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. From openclaw-security-guard jailbreak pattern database.`,
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
    id: "agents-role-hijacking",
    name: "Role Hijacking / Persona Override",
    description: "Checks for instructions that reassign the agent's role, persona, or behavioral constraints",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const rolePatterns = [
        {
          pattern: /(?:roleplay|role-play)\s+as\s+(?:a|an|the)\s+/gi,
          desc: "Instructs agent to roleplay a different identity \u2014 can override safety behaviors"
        },
        {
          pattern: /(?:pretend|act)\s+(?:to\s+be|as\s+if\s+you\s+(?:are|were)|like\s+you\s+(?:are|were))\s+(?:a|an|the)\s+/gi,
          desc: "Instructs agent to pretend to be a different entity \u2014 persona override technique"
        },
        {
          pattern: /(?:from\s+now\s+on|starting\s+now|henceforth)\s*[,;:]?\s*(?:you\s+are|act\s+as|behave\s+like|respond\s+as)/gi,
          desc: "Temporal role reassignment \u2014 attempts to permanently change agent behavior from this point forward"
        },
        {
          pattern: /(?:switch|change)\s+(?:to|into)\s+(?:a\s+)?(?:different|new|unrestricted|unfiltered|uncensored)\s+(?:mode|personality|character|persona|role)/gi,
          desc: "Requests mode switch to an unrestricted persona \u2014 jailbreak via persona change"
        }
      ];
      for (const { pattern, desc } of rolePatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-role-hijacking-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Role hijacking / persona override detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. From openclaw-security-guard role hijacking patterns.`,
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
    id: "agents-destructive-tool-usage",
    name: "Destructive Tool Usage Instructions",
    description: "Checks for instructions that direct the agent to use tools for destructive operations like deleting data or dropping tables",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const destructiveToolPatterns = [
        {
          pattern: /(?:use|call|invoke)\s+(?:the\s+)?\w+\s+tool\s+to\s+(?:delete|remove|destroy|drop|truncate|wipe|purge|erase)/gi,
          desc: "Directs agent to use a specific tool for destructive operations"
        },
        {
          pattern: /(?:drop\s+(?:all\s+)?(?:tables?|databases?|collections?|indexes?)|truncate\s+(?:all\s+)?tables?|delete\s+from\s+\w+\s+where\s+1\s*=\s*1)/gi,
          desc: "Contains destructive SQL/database operations \u2014 drop tables, truncate, mass delete"
        },
        {
          pattern: /(?:git\s+push\s+--force(?!-with-lease)(?:\s+origin\s+main|\s+origin\s+master)?)/gi,
          desc: "Force push to main/master \u2014 can overwrite remote history and destroy team changes"
        },
        {
          pattern: /(?:invoke|call|execute)\s+(?:the\s+)?\w+\s+(?:tool|function)\s+(?:without\s+(?:asking|confirmation|review|approval))/gi,
          desc: "Instructs agent to invoke tools without user confirmation \u2014 bypasses human-in-the-loop safety"
        }
      ];
      for (const { pattern, desc } of destructiveToolPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-destructive-tool-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Destructive tool usage instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. From openclaw-security-guard tool manipulation patterns.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
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
  const maxCategoryScore = 100;
  const breakdown = {
    secrets: Math.max(0, maxCategoryScore - categoryDeductions.secrets),
    permissions: Math.max(0, maxCategoryScore - categoryDeductions.permissions),
    hooks: Math.max(0, maxCategoryScore - categoryDeductions.hooks),
    mcp: Math.max(0, maxCategoryScore - categoryDeductions.mcp),
    agents: Math.max(0, maxCategoryScore - categoryDeductions.agents)
  };
  const categoryScores = Object.values(breakdown);
  const numericScore = Math.round(
    categoryScores.reduce((sum, s) => sum + s, 0) / categoryScores.length
  );
  const grade = scoreToGrade(numericScore);
  return { grade, numericScore, breakdown };
}
function mapToScoreCategory(category) {
  const mapping = {
    secrets: "secrets",
    permissions: "permissions",
    hooks: "hooks",
    mcp: "mcp",
    agents: "agents",
    injection: "agents",
    // prompt injection → agents category
    exposure: "hooks",
    // data exposure via hooks/exfiltration
    misconfiguration: "permissions"
    // config issues → permissions
  };
  return mapping[category] ?? "agents";
}
function scoreToGrade(score) {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

// src/reporter/json.ts
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
  const categoryLabels = {
    secrets: "Secrets",
    permissions: "Permissions",
    hooks: "Hooks",
    mcp: "MCP Servers",
    agents: "Agents"
  };
  lines.push("## Score Breakdown");
  lines.push("");
  lines.push("| Category | Score |");
  lines.push("|----------|-------|");
  for (const [key, score] of Object.entries(report.score.breakdown)) {
    const label = categoryLabels[key] ?? key;
    lines.push(`| ${label} | ${score}/100 |`);
  }
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

// src/action.ts
function getInput(name, fallback) {
  const envKey = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
  return process.env[envKey]?.trim() ?? fallback;
}
function setOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    appendFileSync(outputFile, `${name}=${value}
`);
  } else {
    console.log(`::set-output name=${name}::${value}`);
  }
}
function writeJobSummary(markdown) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) {
    appendFileSync(summaryFile, markdown);
  }
}
function annotateWarning(file, line, message) {
  const lineParam = line ? `,line=${line}` : "";
  console.log(`::warning file=${file}${lineParam}::${escapeAnnotation(message)}`);
}
function annotateError(file, line, message) {
  const lineParam = line ? `,line=${line}` : "";
  console.log(`::error file=${file}${lineParam}::${escapeAnnotation(message)}`);
}
function escapeAnnotation(message) {
  return message.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
var SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
function severityIndex(severity) {
  const idx = SEVERITY_ORDER.indexOf(severity);
  return idx === -1 ? SEVERITY_ORDER.length : idx;
}
function isAtOrAboveSeverity(finding, minSeverity) {
  return severityIndex(finding.severity) <= severityIndex(minSeverity);
}
function emitAnnotations(findings) {
  for (const finding of findings) {
    const message = `[${finding.severity.toUpperCase()}] ${finding.title}: ${finding.description}`;
    if (finding.severity === "critical" || finding.severity === "high") {
      annotateError(finding.file, finding.line, message);
    } else {
      annotateWarning(finding.file, finding.line, message);
    }
  }
}
async function run() {
  const inputPath = getInput("path", ".");
  const minSeverity = getInput("min-severity", "medium");
  const failOnFindings = getInput("fail-on-findings", "true") === "true";
  const format = getInput("format", "terminal");
  const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd();
  const targetPath = resolve(workspace, inputPath);
  if (!existsSync2(targetPath)) {
    console.log(`::error::AgentShield: Path does not exist: ${targetPath}`);
    process.exitCode = 1;
    return;
  }
  console.log(`AgentShield: Scanning ${targetPath}`);
  console.log(`  min-severity: ${minSeverity}`);
  console.log(`  fail-on-findings: ${failOnFindings}`);
  console.log(`  format: ${format}`);
  console.log("");
  const result = scan(targetPath);
  const filteredResult = {
    ...result,
    findings: result.findings.filter((f) => isAtOrAboveSeverity(f, minSeverity))
  };
  const report = calculateScore(filteredResult);
  emitAnnotations(filteredResult.findings);
  setOutput("score", String(report.score.numericScore));
  setOutput("grade", report.score.grade);
  setOutput("total-findings", String(report.summary.totalFindings));
  setOutput("critical-count", String(report.summary.critical));
  const markdownSummary = renderMarkdownReport(report);
  writeJobSummary(markdownSummary);
  console.log(`Score: ${report.score.numericScore}/100 (Grade: ${report.score.grade})`);
  console.log(`Findings: ${report.summary.totalFindings} total`);
  console.log(`  Critical: ${report.summary.critical}`);
  console.log(`  High: ${report.summary.high}`);
  console.log(`  Medium: ${report.summary.medium}`);
  console.log(`  Low: ${report.summary.low}`);
  console.log(`  Info: ${report.summary.info}`);
  if (failOnFindings && filteredResult.findings.length > 0) {
    console.log("");
    console.log(
      `::error::AgentShield found ${filteredResult.findings.length} finding(s) at or above ${minSeverity} severity. Failing the action.`
    );
    process.exitCode = 1;
  }
}
run().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.log(`::error::AgentShield action failed: ${escapeAnnotation(message)}`);
  process.exitCode = 1;
});
