import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

/**
 * Result of creating a single file during init.
 */
export interface InitFileResult {
  readonly path: string;
  readonly status: "created" | "skipped";
  readonly reason?: string;
}

/**
 * Overall result of the init command.
 */
export interface InitResult {
  readonly directory: string;
  readonly files: ReadonlyArray<InitFileResult>;
}

/**
 * Secure default settings.json content.
 *
 * Provides scoped permissions (restrictive allow list, explicit deny list)
 * and PreToolUse hooks for safety checks.
 */
function getDefaultSettings(): string {
  const settings = {
    permissions: {
      allow: [
        "Bash(git *)",
        "Bash(npm *)",
        "Bash(npx *)",
        "Bash(node *)",
        "Bash(pnpm *)",
        "Bash(yarn *)",
        "Bash(tsc *)",
        "Bash(eslint *)",
        "Bash(prettier *)",
        "Bash(vitest *)",
        "Bash(jest *)",
        "Read(*)",
        "Edit(src/*)",
        "Edit(tests/*)",
        "Write(src/*)",
        "Write(tests/*)",
      ],
      deny: [
        "Bash(rm -rf *)",
        "Bash(sudo *)",
        "Bash(chmod 777 *)",
        "Bash(curl * | bash)",
        "Bash(wget * | bash)",
        "Bash(ssh *)",
        "Bash(> /dev/*)",
        "Bash(dd *)",
      ],
    },
    hooks: {
      PreToolUse: [
        {
          matcher: "Bash",
          hook: "# Warn on destructive commands\nif echo \"$TOOL_INPUT\" | grep -qE '(rm -rf|sudo|chmod 777|mkfs|dd if=)'; then\n  echo 'WARN: Potentially destructive command detected'\nfi",
        },
      ],
      PostToolUse: [
        {
          matcher: "Write",
          hook: "# Check for accidentally written secrets\nif echo \"$TOOL_INPUT\" | grep -qE '(sk-ant-|sk-proj-|ghp_|AKIA)'; then\n  echo 'BLOCK: Possible secret detected in written file'\n  exit 1\nfi",
        },
      ],
    },
  };

  return JSON.stringify(settings, null, 2);
}

/**
 * Secure default CLAUDE.md content.
 *
 * Provides security best practices as instructions for the AI agent.
 */
function getDefaultClaudeMd(): string {
  return `# Security Guidelines

## Secrets

- NEVER hardcode API keys, tokens, passwords, or credentials in any file
- Always use environment variable references: \`\${VAR_NAME}\` or \`process.env.VAR_NAME\`
- Never echo, log, or print secret values to the terminal

## Permissions

- Never use \`--dangerously-skip-permissions\` or \`--no-verify\`
- Do not run \`sudo\` commands
- Do not use \`rm -rf\` without explicit user confirmation
- Do not use \`chmod 777\` on any file or directory

## Code Safety

- Validate all user inputs before processing
- Use parameterized queries for database operations
- Sanitize HTML output to prevent XSS
- Never execute dynamically constructed shell commands with user input

## MCP Servers

- Only connect to trusted, verified MCP servers
- Review MCP server permissions before enabling
- Do not pass secrets as command-line arguments to MCP servers
- Use environment variables for MCP server credentials

## Hooks

- All hooks must be reviewed before activation
- Hooks should not exfiltrate data or make external network calls
- PostToolUse hooks should validate output, not modify it silently
`;
}

/**
 * Default MCP configuration placeholder.
 *
 * Contains an empty mcpServers object with a commented example.
 */
function getDefaultMcpConfig(): string {
  const config = {
    mcpServers: {},
  };

  return JSON.stringify(config, null, 2);
}

/**
 * Safely write a file, skipping if it already exists.
 */
function safeWriteFile(filePath: string, content: string): InitFileResult {
  if (existsSync(filePath)) {
    return {
      path: filePath,
      status: "skipped",
      reason: "File already exists",
    };
  }

  writeFileSync(filePath, content, "utf-8");
  return {
    path: filePath,
    status: "created",
  };
}

/**
 * Run the init command to generate a secure baseline Claude Code configuration.
 *
 * Creates a `.claude/` directory with:
 * - `settings.json` — scoped permissions and safety hooks
 * - `CLAUDE.md` — security best practices for the agent
 * - `mcp.json` — empty MCP server config placeholder
 *
 * Existing files are never overwritten. If a file already exists,
 * it is skipped and a warning is included in the result.
 */
export function runInit(targetDir?: string): InitResult {
  const baseDir = targetDir
    ? resolve(targetDir)
    : resolve(process.cwd());
  const claudeDir = join(baseDir, ".claude");

  // Ensure .claude directory exists
  if (!existsSync(claudeDir)) {
    mkdirSync(claudeDir, { recursive: true });
  }

  const files: InitFileResult[] = [];

  // Create settings.json
  files.push(
    safeWriteFile(join(claudeDir, "settings.json"), getDefaultSettings())
  );

  // Create CLAUDE.md
  files.push(
    safeWriteFile(join(claudeDir, "CLAUDE.md"), getDefaultClaudeMd())
  );

  // Create mcp.json
  files.push(
    safeWriteFile(join(claudeDir, "mcp.json"), getDefaultMcpConfig())
  );

  return {
    directory: claudeDir,
    files,
  };
}

/**
 * Render the init result as a formatted summary string for terminal output.
 */
export function renderInitSummary(result: InitResult): string {
  const lines: string[] = [];

  lines.push("");
  lines.push("  AgentShield Init");
  lines.push("  " + "─".repeat(40));
  lines.push(`  Directory: ${result.directory}`);
  lines.push("");

  const created = result.files.filter((f) => f.status === "created");
  const skipped = result.files.filter((f) => f.status === "skipped");

  if (created.length > 0) {
    lines.push("  Created:");
    for (const file of created) {
      lines.push(`    + ${file.path}`);
    }
    lines.push("");
  }

  if (skipped.length > 0) {
    lines.push("  Skipped (already exist):");
    for (const file of skipped) {
      lines.push(`    ~ ${file.path}`);
      if (file.reason) {
        lines.push(`      ${file.reason}`);
      }
    }
    lines.push("");
  }

  if (created.length > 0) {
    lines.push("  Next steps:");
    lines.push("    1. Review the generated files in .claude/");
    lines.push("    2. Customize permissions for your project");
    lines.push("    3. Run 'agentshield scan' to verify your config");
    lines.push("");
  }

  return lines.join("\n");
}
