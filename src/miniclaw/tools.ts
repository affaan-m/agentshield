/**
 * MiniClaw Tool Whitelist and Executor
 *
 * Manages the set of tools available to the agent and ensures every tool
 * call is validated against the whitelist before execution.
 *
 * Security model:
 * - Tools are classified into three risk tiers: safe, guarded, restricted
 * - Safe tools require no confirmation and are scoped to the sandbox
 * - Guarded tools require explicit session configuration
 * - Restricted tools are disabled by default and require opt-in
 *
 * WHY a whitelist (not a blacklist): Blacklists fail open — any new tool
 * is automatically allowed. Whitelists fail closed — any new tool is
 * automatically blocked until explicitly approved.
 */

import type {
  AllowedTool,
  ToolWhitelist,
  ToolCallRequest,
  ToolValidationResult,
  SecurityEvent,
  ToolRiskLevel,
} from "./types.js";
import { validatePath, validateExtension, createSecurityEvent } from "./sandbox.js";

// ─── Default Tool Definitions ─────────────────────────────

/**
 * Safe tools: No confirmation needed, operate within sandbox only.
 *
 * WHY these are safe: They only READ data within the sandbox.
 * Reading files inside the sandbox cannot modify state or exfiltrate data
 * (assuming no network access, which is the default).
 */
const SAFE_TOOLS: ReadonlyArray<AllowedTool> = [
  {
    name: "read",
    description: "Read file contents within the sandbox. Cannot access files outside the sandbox boundary.",
    riskLevel: "safe",
  },
  {
    name: "search",
    description: "Search file contents within the sandbox using text patterns. Scoped to sandbox directory.",
    riskLevel: "safe",
  },
  {
    name: "list",
    description: "List directory contents within the sandbox. Cannot traverse above sandbox root.",
    riskLevel: "safe",
  },
];

/**
 * Guarded tools: Require explicit session-level opt-in.
 *
 * WHY these are guarded (not safe): They MODIFY data. Even within a sandbox,
 * write operations can destroy the user's work or create files that affect
 * subsequent processing. Requiring opt-in means the user consciously accepts
 * the risk of the agent modifying files.
 */
const GUARDED_TOOLS: ReadonlyArray<AllowedTool> = [
  {
    name: "write",
    description: "Write file contents within the sandbox. Requires explicit session configuration.",
    riskLevel: "guarded",
  },
  {
    name: "edit",
    description: "Edit existing files within the sandbox. Validates file exists before modification.",
    riskLevel: "guarded",
  },
  {
    name: "glob",
    description: "Pattern-match files within the sandbox. Scoped to sandbox directory only.",
    riskLevel: "guarded",
  },
];

/**
 * Restricted tools: Disabled by default, require explicit opt-in in config.
 *
 * WHY these are restricted: They have unbounded blast radius.
 * - Bash: Can execute arbitrary commands, access host system, network
 * - Network: Can exfiltrate data to external servers
 * - External API: Can make authenticated requests to third-party services
 *
 * These should ONLY be enabled when the user fully understands the risks
 * and has additional containment (e.g., Docker, VM) in place.
 */
const RESTRICTED_TOOLS: ReadonlyArray<AllowedTool> = [
  {
    name: "bash",
    description: "Execute shell commands. DANGER: Can access host system. Only enable with additional containment.",
    riskLevel: "restricted",
  },
  {
    name: "network",
    description: "Make HTTP requests. DANGER: Can exfiltrate data. Only enable with network policy allowlist.",
    riskLevel: "restricted",
  },
  {
    name: "external_api",
    description: "Call external APIs. DANGER: Can make authenticated requests to third-party services.",
    riskLevel: "restricted",
  },
];

// ─── Tool Registry ────────────────────────────────────────

/**
 * All known tools across all risk levels.
 * Used for documentation and validation — not for authorization.
 *
 * WHY a separate registry: The whitelist is per-session and determines what's
 * allowed. The registry is global and determines what EXISTS. A tool must
 * exist in the registry AND be in the session whitelist to be invoked.
 */
export const TOOL_REGISTRY: ReadonlyArray<AllowedTool> = [
  ...SAFE_TOOLS,
  ...GUARDED_TOOLS,
  ...RESTRICTED_TOOLS,
];

// ─── Whitelist Creation ───────────────────────────────────

/**
 * Creates a tool whitelist with only safe tools enabled.
 * This is the most restrictive whitelist — suitable for untrusted users.
 *
 * WHY this is the default: "Safe by default" means a misconfigured MiniClaw
 * instance still has minimal risk. Users must explicitly opt into more
 * permissive configurations.
 */
export function createSafeWhitelist(): ToolWhitelist {
  return { tools: [...SAFE_TOOLS] };
}

/**
 * Creates a whitelist that includes safe and guarded tools.
 * Suitable for trusted users who need write access to the sandbox.
 */
export function createGuardedWhitelist(): ToolWhitelist {
  return { tools: [...SAFE_TOOLS, ...GUARDED_TOOLS] };
}

/**
 * Creates a custom whitelist from a list of tool names.
 * Only tools that exist in the TOOL_REGISTRY can be included.
 *
 * WHY validate against registry: Prevents injection of arbitrary tool names
 * that could bypass the validation system.
 *
 * @returns The whitelist and any tool names that were not recognized
 */
export function createCustomWhitelist(
  toolNames: ReadonlyArray<string>
): { readonly whitelist: ToolWhitelist; readonly unrecognized: ReadonlyArray<string> } {
  const recognized: AllowedTool[] = [];
  const unrecognized: string[] = [];

  for (const name of toolNames) {
    const tool = TOOL_REGISTRY.find((t) => t.name === name);
    if (tool) {
      recognized.push(tool);
    } else {
      unrecognized.push(name);
    }
  }

  return {
    whitelist: { tools: recognized },
    unrecognized,
  };
}

// ─── Tool Call Validation ─────────────────────────────────

/**
 * Validates a tool call against the session's whitelist.
 *
 * This is the authorization checkpoint. Every tool call MUST pass through
 * this function before execution. There are no exceptions.
 *
 * WHY strict validation: A single bypassed tool call could compromise
 * the entire sandbox. Defense in depth means we validate at multiple
 * levels, but this is the primary gate.
 */
export function validateToolCall(
  call: ToolCallRequest,
  whitelist: ToolWhitelist
): ToolValidationResult {
  // Check if the tool exists in the registry at all
  // WHY: Unknown tools should be rejected with a clear message,
  // not a generic "not allowed" error that might confuse debugging
  const registeredTool = TOOL_REGISTRY.find((t) => t.name === call.tool);
  if (!registeredTool) {
    return {
      allowed: false,
      tool: call.tool,
      reason: `Unknown tool "${call.tool}" — not in the tool registry`,
    };
  }

  // Check if the tool is in the session's whitelist
  const allowedTool = whitelist.tools.find((t) => t.name === call.tool);
  if (!allowedTool) {
    return {
      allowed: false,
      tool: call.tool,
      reason: `Tool "${call.tool}" (${registeredTool.riskLevel}) is not in the session whitelist`,
    };
  }

  return {
    allowed: true,
    tool: call.tool,
    reason: `Tool "${call.tool}" is allowed (risk level: ${allowedTool.riskLevel})`,
  };
}

// ─── Tool Call Scoping ────────────────────────────────────

/**
 * Rewrites paths in a tool call to be scoped within the sandbox.
 *
 * This transforms relative and absolute paths in tool arguments to be
 * relative to the sandbox root. Combined with validatePath() in the
 * sandbox module, this provides two layers of path containment.
 *
 * WHY two layers: scopeToolCall rewrites paths proactively (before the tool runs).
 * validatePath checks reactively (the tool verifies before actual I/O).
 * Both must pass for a path to be accessed.
 */
export function scopeToolCall(
  call: ToolCallRequest,
  sandboxPath: string
): ToolCallRequest {
  const scopedArgs: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(call.args)) {
    if (isPathArgument(key) && typeof value === "string") {
      // Rewrite path arguments to be relative to sandbox
      // WHY: Even if the user passes "/etc/passwd", it becomes
      // "/tmp/miniclaw-sandboxes/<session>/etc/passwd" which doesn't exist
      scopedArgs[key] = scopePath(value, sandboxPath);
    } else {
      scopedArgs[key] = value;
    }
  }

  return {
    tool: call.tool,
    args: scopedArgs,
  };
}

/**
 * Determines if an argument key represents a filesystem path.
 *
 * WHY a dedicated function: Path arguments need special handling (scoping).
 * Other arguments (like search patterns) should be passed through unchanged.
 * Having a clear list of path-like keys prevents accidental scoping of
 * non-path arguments.
 */
function isPathArgument(key: string): boolean {
  // WHY these specific keys: These are the standard argument names used
  // by file operation tools. Additional keys should be added as new tools
  // are registered.
  const pathKeys = ["path", "file", "filePath", "file_path", "directory", "dir", "target"];
  return pathKeys.includes(key);
}

/**
 * Scopes a path to be within the sandbox root.
 *
 * Strategy:
 * - Absolute paths: Strip leading "/" and join with sandbox root
 * - Relative paths: Join directly with sandbox root
 * - Paths with "../": resolve() handles normalization, then re-scope
 *
 * WHY strip leading slash: An absolute path like "/etc/passwd" should
 * become "sandbox/etc/passwd", not escape to the real "/etc/passwd".
 */
function scopePath(requestedPath: string, sandboxPath: string): string {
  // Remove leading slashes to prevent absolute path escape
  const stripped = requestedPath.replace(/^\/+/, "");
  // Remove any ../ sequences that might escape the sandbox
  // WHY: Even though resolve() handles this, we strip them explicitly
  // as a defense-in-depth measure
  const cleaned = stripped.replace(/\.\.\//g, "");
  // Join with sandbox path
  return `${sandboxPath}/${cleaned}`;
}

// ─── Tool Execution ───────────────────────────────────────

/**
 * Executes a validated and scoped tool call.
 *
 * Prerequisites (enforced by caller, not by this function):
 * 1. Tool call has been validated against the whitelist (validateToolCall)
 * 2. Paths have been scoped to the sandbox (scopeToolCall)
 * 3. Session is still active (not timed out)
 *
 * WHY not enforce prerequisites here: This function trusts its caller
 * (routePrompt) to have done the checks. Double-checking here would
 * add latency. The security boundary is at the router level.
 *
 * However, path validation IS re-checked here as a defense-in-depth
 * measure because path access is the most critical security boundary.
 */
export async function executeToolCall(
  call: ToolCallRequest,
  sandboxPath: string,
  sessionId: string
): Promise<{
  readonly result: string;
  readonly events: ReadonlyArray<SecurityEvent>;
}> {
  const events: SecurityEvent[] = [];

  // Defense-in-depth: Re-validate path arguments against sandbox
  // WHY: Even after scoping, we validate again because scopeToolCall
  // might have a bug. Belt AND suspenders for path security.
  for (const [key, value] of Object.entries(call.args)) {
    if (isPathArgument(key) && typeof value === "string") {
      const pathCheck = await validatePath(sandboxPath, value);
      if (!pathCheck.valid) {
        events.push(
          createSecurityEvent("sandbox_violation", pathCheck.reason, sessionId)
        );
        return {
          result: `Error: ${pathCheck.reason}`,
          events,
        };
      }
    }
  }

  // Execute the tool based on its name
  // In production, this would dispatch to actual tool implementations
  // For now, we provide the execution framework
  switch (call.tool) {
    case "read":
      return { result: await executeRead(call, sandboxPath), events };
    case "write":
      return { result: await executeWrite(call, sandboxPath, events, sessionId), events };
    case "search":
      return { result: await executeSearch(call, sandboxPath), events };
    case "list":
      return { result: await executeList(call, sandboxPath), events };
    case "edit":
      return { result: await executeEdit(call, sandboxPath, events, sessionId), events };
    case "glob":
      return { result: await executeGlob(call, sandboxPath), events };
    default:
      events.push(
        createSecurityEvent(
          "tool_denied",
          `No executor found for tool "${call.tool}"`,
          sessionId
        )
      );
      return { result: `Error: No executor for tool "${call.tool}"`, events };
  }
}

// ─── Tool Implementations (Stubs) ─────────────────────────

/**
 * Read file contents within the sandbox.
 * Validates path and file size before reading.
 */
async function executeRead(
  call: ToolCallRequest,
  _sandboxPath: string
): Promise<string> {
  const filePath = call.args["path"] as string | undefined;
  if (!filePath) {
    return "Error: 'path' argument is required for read tool";
  }

  // In production: validate path, check file size, read and return contents
  // The actual fs.readFile call would go here
  return `[read] Would read file: ${filePath}`;
}

/**
 * Write file contents within the sandbox.
 * Validates path, extension, and file size before writing.
 */
async function executeWrite(
  call: ToolCallRequest,
  _sandboxPath: string,
  events: SecurityEvent[],
  sessionId: string
): Promise<string> {
  const filePath = call.args["path"] as string | undefined;
  const content = call.args["content"] as string | undefined;

  if (!filePath || content === undefined) {
    return "Error: 'path' and 'content' arguments are required for write tool";
  }

  // Validate file extension
  // WHY: Prevent creation of executable or system files
  const extCheck = validateExtension(filePath, [
    ".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".txt",
    ".css", ".html", ".yaml", ".yml", ".toml",
  ]);
  if (!extCheck.valid) {
    events.push(
      createSecurityEvent("sandbox_violation", extCheck.reason, sessionId)
    );
    return `Error: ${extCheck.reason}`;
  }

  // In production: validate path, check resulting file size, write contents
  return `[write] Would write ${content.length} bytes to: ${filePath}`;
}

/**
 * Search file contents within the sandbox.
 */
async function executeSearch(
  call: ToolCallRequest,
  _sandboxPath: string
): Promise<string> {
  const pattern = call.args["pattern"] as string | undefined;
  if (!pattern) {
    return "Error: 'pattern' argument is required for search tool";
  }

  // In production: search files in sandbox directory matching the pattern
  return `[search] Would search for pattern: ${pattern}`;
}

/**
 * List directory contents within the sandbox.
 */
async function executeList(
  call: ToolCallRequest,
  sandboxPath: string
): Promise<string> {
  const dir = (call.args["path"] as string | undefined) ?? sandboxPath;

  // In production: list directory contents, validate path first
  return `[list] Would list directory: ${dir}`;
}

/**
 * Edit existing files within the sandbox.
 * Validates that the file exists before modification.
 */
async function executeEdit(
  call: ToolCallRequest,
  _sandboxPath: string,
  _events: SecurityEvent[],
  _sessionId: string
): Promise<string> {
  const filePath = call.args["path"] as string | undefined;
  if (!filePath) {
    return "Error: 'path' argument is required for edit tool";
  }

  // In production: validate file exists, validate extension, apply edit
  return `[edit] Would edit file: ${filePath}`;
}

/**
 * Pattern-match files within the sandbox.
 */
async function executeGlob(
  call: ToolCallRequest,
  _sandboxPath: string
): Promise<string> {
  const pattern = call.args["pattern"] as string | undefined;
  if (!pattern) {
    return "Error: 'pattern' argument is required for glob tool";
  }

  // In production: glob files in sandbox directory
  return `[glob] Would glob for pattern: ${pattern}`;
}

// ─── Utility Exports ──────────────────────────────────────

/**
 * Returns all tools grouped by risk level for display in the dashboard.
 */
export function getToolsByRiskLevel(): Readonly<Record<ToolRiskLevel, ReadonlyArray<AllowedTool>>> {
  return {
    safe: SAFE_TOOLS,
    guarded: GUARDED_TOOLS,
    restricted: RESTRICTED_TOOLS,
  };
}
