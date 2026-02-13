import type { ConfigFile, Finding, Rule } from "../types.js";

/**
 * Dangerous permission patterns that grant excessive access.
 * These are only dangerous when they appear in the ALLOW list.
 */
const OVERLY_PERMISSIVE: ReadonlyArray<{
  readonly pattern: RegExp;
  readonly description: string;
  readonly severity: "critical" | "high" | "medium";
  readonly suggestion: string;
}> = [
  {
    pattern: /^Bash\(\*\)$/,
    description: "Unrestricted Bash access — any command can run",
    severity: "critical",
    suggestion: "Bash(git *), Bash(npm *), Bash(node *)",
  },
  {
    pattern: /^Bash\(sudo\s/,
    description: "Sudo access allowed — agent can escalate privileges",
    severity: "critical",
    suggestion: "Remove sudo permissions entirely",
  },
  {
    pattern: /^Write\(\*\)$/,
    description: "Unrestricted Write access — agent can write to any file",
    severity: "high",
    suggestion: "Write(src/*), Write(tests/*)",
  },
  {
    pattern: /^Edit\(\*\)$/,
    description: "Unrestricted Edit access — agent can edit any file",
    severity: "high",
    suggestion: "Edit(src/*), Edit(tests/*)",
  },
  {
    pattern: /^Bash\(rm\s/,
    description: "Delete operations explicitly allowed in Bash",
    severity: "high",
    suggestion: "Move rm commands to deny list instead",
  },
  {
    pattern: /^Bash\(curl\s/,
    description: "Unrestricted curl access — agent can make arbitrary HTTP requests",
    severity: "medium",
    suggestion: "Restrict to specific domains or move to deny list",
  },
  {
    pattern: /^Bash\(wget\s/,
    description: "Unrestricted wget access — agent can download arbitrary files",
    severity: "medium",
    suggestion: "Restrict to specific domains or move to deny list",
  },
  {
    pattern: /^Bash\(chmod\s/,
    description: "chmod access — agent can change file permissions",
    severity: "medium",
    suggestion: "Move chmod to deny list to prevent permission escalation",
  },
  {
    pattern: /^Bash\(chown\s/,
    description: "chown access — agent can change file ownership",
    severity: "high",
    suggestion: "Move chown to deny list to prevent ownership takeover",
  },
  {
    pattern: /^Bash\(ssh\s/,
    description: "SSH access — agent can connect to remote systems",
    severity: "high",
    suggestion: "Remove SSH permissions to prevent lateral movement",
  },
  {
    pattern: /^Bash\(nc\s|^Bash\(netcat\s/,
    description: "Netcat access — can open network connections for exfiltration or reverse shells",
    severity: "high",
    suggestion: "Remove netcat permissions entirely",
  },
  {
    pattern: /^Bash\(python\s|^Bash\(python3\s|^Bash\(node\s/,
    description: "Interpreter access — agent can run arbitrary code via scripting language",
    severity: "high",
    suggestion: "Restrict to specific scripts: Bash(node scripts/build.js)",
  },
  {
    pattern: /^Bash\(docker\s/,
    description: "Docker access — containers can escape to host, mount filesystems, and access host network",
    severity: "high",
    suggestion: "Remove docker permissions or restrict to read-only: Bash(docker ps)",
  },
  {
    pattern: /^Bash\(kill\s|^Bash\(pkill\s|^Bash\(killall\s/,
    description: "Process killing — agent can terminate system processes",
    severity: "medium",
    suggestion: "Move process killing to deny list",
  },
  {
    pattern: /^Bash\(eval\s/,
    description: "eval access — agent can execute arbitrary code via shell eval",
    severity: "critical",
    suggestion: "Remove eval permissions; use explicit commands instead",
  },
  {
    pattern: /^Bash\(exec\s/,
    description: "exec access — agent can replace the current process with arbitrary commands",
    severity: "critical",
    suggestion: "Remove exec permissions; use explicit commands instead",
  },
];

/**
 * Permissions that should be in the deny list but are commonly missing.
 */
const MISSING_DENIALS: ReadonlyArray<{
  readonly pattern: string;
  readonly description: string;
}> = [
  { pattern: "rm -rf", description: "Recursive force delete" },
  { pattern: "sudo", description: "Privilege escalation" },
  { pattern: "chmod 777", description: "World-writable permissions" },
  { pattern: "ssh", description: "SSH connections from agent" },
  { pattern: "> /dev/", description: "Writing to device files" },
];

/**
 * Parse the allow and deny arrays from a settings.json file.
 * Returns null if the file is not valid JSON or has no permissions.
 */
function parsePermissionLists(content: string): {
  allow: ReadonlyArray<string>;
  deny: ReadonlyArray<string>;
} | null {
  try {
    const config = JSON.parse(content);
    return {
      allow: config?.permissions?.allow ?? [],
      deny: config?.permissions?.deny ?? [],
    };
  } catch {
    return null;
  }
}

/**
 * Destructive git commands that should never be in the allow list.
 */
const DESTRUCTIVE_GIT_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp;
  readonly description: string;
  readonly suggestion: string;
}> = [
  {
    pattern: /push\s+--force(?!-with-lease)|push\s+-f\b/,
    description: "Force push can overwrite remote history, destroying teammates' work",
    suggestion: "Use --force-with-lease instead, or move to deny list",
  },
  {
    pattern: /reset\s+--hard/,
    description: "Hard reset destroys uncommitted changes without recovery",
    suggestion: "Move to deny list; use 'git stash' or 'git reset --soft' instead",
  },
  {
    pattern: /clean\s+-[a-z]*f/,
    description: "Git clean with force flag permanently deletes untracked files",
    suggestion: "Move to deny list; use 'git clean -n' (dry-run) first",
  },
  {
    pattern: /branch\s+-D\b/,
    description: "Force-delete branch regardless of merge status can lose work",
    suggestion: "Use 'branch -d' (lowercase) which checks merge status first",
  },
  {
    pattern: /checkout\s+\.\s*$/,
    description: "Discards all unstaged changes in working directory",
    suggestion: "Move to deny list to prevent accidental loss of work",
  },
];

export const permissionRules: ReadonlyArray<Rule> = [
  {
    id: "permissions-overly-permissive",
    name: "Overly Permissive Access",
    description: "Checks the ALLOW list for permission rules that grant excessive access",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      const perms = parsePermissionLists(file.content);
      if (!perms) return [];

      const findings: Finding[] = [];

      // Only check patterns against the ALLOW list, not the deny list
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
                auto: false,
              },
            });
            break; // One finding per allow entry is enough
          }
        }
      }

      // Bonus: flag deny entries that also appear in allow (contradictions)
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
              evidence: denyEntry,
            });
          }
        }
      }

      return findings;
    },
  },
  {
    id: "permissions-no-deny-list",
    name: "Missing Deny List",
    description: "Checks if the settings.json has a deny list for dangerous operations",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      const perms = parsePermissionLists(file.content);
      if (!perms) return [];

      const findings: Finding[] = [];

      if (perms.deny.length === 0 && perms.allow.length > 0) {
        findings.push({
          id: "permissions-no-deny-list",
          severity: "high",
          category: "permissions",
          title: "No deny list configured",
          description:
            "settings.json has no deny list. Without explicit denials, the agent may run dangerous operations if the allow list is too broad.",
          file: file.path,
          fix: {
            description: "Add a deny list for dangerous operations",
            before: '"permissions": { "allow": [...] }',
            after:
              '"permissions": { "allow": [...], "deny": ["Bash(rm -rf *)", "Bash(sudo *)", "Bash(chmod 777 *)"] }',
            auto: false,
          },
        });
      }

      // Check for specific missing denials
      for (const denial of MISSING_DENIALS) {
        const hasDenial = perms.deny.some((d) => d.includes(denial.pattern));
        if (!hasDenial && perms.deny.length > 0) {
          findings.push({
            id: `permissions-missing-deny-${denial.pattern.replace(/\s/g, "-")}`,
            severity: "medium",
            category: "permissions",
            title: `Missing deny rule: ${denial.description}`,
            description: `The deny list does not block "${denial.pattern}". Consider adding it to prevent ${denial.description.toLowerCase()}.`,
            file: file.path,
          });
        }
      }

      return findings;
    },
  },
  {
    id: "permissions-dangerous-skip",
    name: "Dangerous Permission Bypass",
    description: "Checks for dangerously-skip-permissions or no-verify flags used affirmatively",
    severity: "critical",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const findings: Finding[] = [];

      const dangerousPatterns = [
        {
          pattern: /dangerously-?skip-?permissions/gi,
          desc: "Permission system bypass",
        },
        {
          pattern: /--no-verify/g,
          desc: "Git hook verification bypass",
        },
      ];

      // Negation words that indicate the pattern is being PROHIBITED, not used
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
        /\bblock/i,
      ];

      for (const { pattern, desc } of dangerousPatterns) {
        const matches = [...file.content.matchAll(
          new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g")
        )];

        for (const match of matches) {
          const idx = match.index ?? 0;

          // Check surrounding context (100 chars before) for negation
          const contextStart = Math.max(0, idx - 100);
          const context = file.content.substring(contextStart, idx).toLowerCase();

          const isNegated = negationPatterns.some((neg) => neg.test(context));

          if (isNegated) {
            // This is a prohibition, not a usage — skip or downgrade to info
            findings.push({
              id: `permissions-negated-${idx}`,
              severity: "info",
              category: "permissions",
              title: `Prohibition of ${match[0]} (good practice)`,
              description: `Found "${match[0]}" in a negated/prohibitive context. This is correct — the config is telling the agent NOT to use this flag.`,
              file: file.path,
              line: findLineNumber(file.content, idx),
              evidence: match[0],
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
            line: findLineNumber(file.content, idx),
            evidence: match[0],
            fix: {
              description: "Remove dangerous bypass flag",
              before: match[0],
              after: "# [REMOVED: dangerous bypass flag]",
              auto: false,
            },
          });
        }
      }

      return findings;
    },
  },
  {
    id: "permissions-all-mutable-tools",
    name: "All Mutable Tools Allowed",
    description: "Checks if the allow list grants access to all three mutable tool categories simultaneously",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      const perms = parsePermissionLists(file.content);
      if (!perms) return [];

      const allowStr = perms.allow.join(" ");

      const hasBash = perms.allow.some((e) => e.startsWith("Bash"));
      const hasWrite = perms.allow.some((e) => e.startsWith("Write"));
      const hasEdit = perms.allow.some((e) => e.startsWith("Edit"));

      if (hasBash && hasWrite && hasEdit) {
        // Check if individual entries are already flagged as overly permissive
        // This rule adds value when entries are scoped but the combination is dangerous
        const allUnrestricted =
          allowStr.includes("Bash(*)") &&
          allowStr.includes("Write(*)") &&
          allowStr.includes("Edit(*)");

        // Only flag the combination if not all three are already wildcards
        // (wildcards are individually flagged by overly-permissive rule)
        if (!allUnrestricted) {
          return [
            {
              id: "permissions-all-mutable-tools",
              severity: "high",
              category: "permissions",
              title: "All mutable tool categories allowed simultaneously",
              description:
                "The allow list grants Bash, Write, and Edit access. Even with scoped patterns, having all three categories means the agent can run commands, create files, and modify files — effectively unrestricted write access to the system. Consider whether all three are truly needed.",
              file: file.path,
              fix: {
                description:
                  "Remove one or more mutable tool categories if not needed",
                before: "Bash(...) + Write(...) + Edit(...)",
                after: "Consider if the agent really needs all three",
                auto: false,
              },
            },
          ];
        }
      }

      return [];
    },
  },
  {
    id: "permissions-destructive-git",
    name: "Destructive Git Commands Allowed",
    description: "Checks if the allow list permits destructive git operations",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      const perms = parsePermissionLists(file.content);
      if (!perms) return [];

      const findings: Finding[] = [];

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
                auto: false,
              },
            });
            break;
          }
        }
      }

      return findings;
    },
  },
  {
    id: "permissions-sensitive-path-access",
    name: "Sensitive Path in Allow List",
    description: "Checks if the allow list permits tool access to sensitive system directories",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      const perms = parsePermissionLists(file.content);
      if (!perms) return [];

      const findings: Finding[] = [];

      const sensitivePaths: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        { pattern: /\/etc\//, description: "system configuration directory" },
        { pattern: /~\/\.ssh|\/\.ssh/, description: "SSH keys and configuration" },
        { pattern: /~\/\.aws|\/\.aws/, description: "AWS credentials" },
        { pattern: /~\/\.gnupg|\/\.gnupg/, description: "GPG keyring" },
        { pattern: /\/root\//, description: "root user home directory" },
        { pattern: /\/var\/log/, description: "system log directory" },
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
                auto: false,
              },
            });
            break;
          }
        }
      }

      return findings;
    },
  },
  {
    id: "permissions-wildcard-root-paths",
    name: "Wildcard Root Path in Allow List",
    description: "Checks if the allow list uses wildcards on root-level or home-level directories",
    severity: "high",
    category: "permissions",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "settings-json") return [];

      const perms = parsePermissionLists(file.content);
      if (!perms) return [];

      const findings: Finding[] = [];

      const broadPathPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        { pattern: /\(\/\*\)/, description: "root filesystem wildcard" },
        { pattern: /\(~\/\*\)/, description: "home directory wildcard" },
        { pattern: /\(\/home\/\*\)/, description: "all users home directories" },
        { pattern: /\(\/usr\/\*\)/, description: "system programs directory" },
        { pattern: /\(\/opt\/\*\)/, description: "optional software directory" },
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
                auto: false,
              },
            });
            break;
          }
        }
      }

      return findings;
    },
  },
];

function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split("\n").length;
}
