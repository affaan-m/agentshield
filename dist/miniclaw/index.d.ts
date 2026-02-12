import { createServer } from 'node:http';

/**
 * MiniClaw Core Type System
 *
 * All types are immutable by design — fields are readonly and arrays use ReadonlyArray.
 * This prevents accidental mutation of security-critical configuration at the type level.
 */
/**
 * Represents an active MiniClaw session with its sandbox and permissions.
 * Sessions are ephemeral — they are created, used, and destroyed.
 * No session data should persist after destruction.
 */
interface MiniClawSession {
    /** Unique session identifier (UUIDv4) */
    readonly id: string;
    /** ISO 8601 timestamp of session creation */
    readonly createdAt: string;
    /**
     * Absolute path to the sandbox directory for this session.
     * All filesystem operations are confined to this path.
     */
    readonly sandboxPath: string;
    /**
     * Tools this session is allowed to use. Defined at session creation time
     * and cannot be expanded later — only narrowed. This prevents privilege
     * escalation during a session.
     */
    readonly allowedTools: ReadonlyArray<AllowedTool>;
    /**
     * Maximum session duration in milliseconds.
     * Sessions exceeding this duration are forcibly terminated.
     * WHY: Prevents runaway agent sessions from consuming resources indefinitely.
     */
    readonly maxDuration: number;
}
/**
 * Incoming prompt request from the client.
 * The prompt field contains raw user input that MUST be sanitized before processing.
 */
interface PromptRequest {
    /** Session ID this prompt belongs to — must reference an active session */
    readonly sessionId: string;
    /**
     * Raw prompt text from the user.
     * WARNING: This is untrusted input and must pass through sanitizePrompt()
     * before any processing occurs.
     */
    readonly prompt: string;
    /**
     * Optional key-value context passed alongside the prompt.
     * This is metadata only — it does not bypass sanitization.
     */
    readonly context?: Readonly<Record<string, string>>;
}
/**
 * Response returned to the client after processing a prompt.
 * The response field has been through filterResponse() to strip any leaked internals.
 */
interface PromptResponse {
    /** Session ID this response belongs to */
    readonly sessionId: string;
    /** Sanitized response text */
    readonly response: string;
    /** Record of tool calls made during processing */
    readonly toolCalls: ReadonlyArray<ToolCallRecord>;
    /** Total processing time in milliseconds */
    readonly duration: number;
    /** Token usage for this request-response cycle */
    readonly tokenUsage: TokenUsage;
}
/**
 * Tracks token consumption for billing and resource monitoring.
 */
interface TokenUsage {
    readonly input: number;
    readonly output: number;
}
/**
 * Records a tool call that was executed during prompt processing.
 * Used for audit trail and client-side transparency.
 */
interface ToolCallRecord {
    readonly tool: string;
    readonly args: Readonly<Record<string, unknown>>;
    readonly result: string;
    readonly duration: number;
}
/**
 * Risk levels for tools. This classification determines the default
 * availability and required authorization for each tool.
 *
 * - safe: No confirmation needed, operates within sandbox (Read, Search)
 * - guarded: Requires explicit session configuration (Edit, Write, Glob)
 * - restricted: Disabled by default, requires opt-in (Bash, Network)
 *
 * WHY three levels: Binary allow/deny is too coarse. Some tools are
 * safe for browsing but risky for modification. The guarded tier lets
 * users enable write access without opening the shell.
 */
type ToolRiskLevel = "safe" | "guarded" | "restricted";
/**
 * A tool that the agent is permitted to invoke, with its risk classification.
 */
interface AllowedTool {
    /** Tool identifier (e.g., "read", "write", "search") */
    readonly name: string;
    /** Human-readable description of what this tool does */
    readonly description: string;
    /**
     * Risk classification. Determines default behavior:
     * - safe: auto-approved
     * - guarded: requires session-level opt-in
     * - restricted: disabled unless explicitly enabled in config
     */
    readonly riskLevel: ToolRiskLevel;
}
/**
 * The complete set of tools available to a session.
 * This is set at session creation and is immutable — tools cannot be added mid-session.
 *
 * WHY ReadonlyArray: Prevents runtime mutation that could expand permissions
 * after initial validation.
 */
interface ToolWhitelist {
    readonly tools: ReadonlyArray<AllowedTool>;
}
/**
 * A validated tool call request, after checking against the whitelist.
 */
interface ToolCallRequest {
    readonly tool: string;
    readonly args: Readonly<Record<string, unknown>>;
}
/**
 * Result of validating a tool call against the whitelist.
 */
interface ToolValidationResult {
    readonly allowed: boolean;
    readonly tool: string;
    readonly reason: string;
}
/**
 * Network access policies for the sandbox.
 *
 * - none: No network access at all (default, most secure)
 * - localhost: Only localhost/127.0.0.1 connections allowed
 * - allowlist: Only connections to explicitly listed hosts
 *
 * WHY 'none' is default: Network access is the primary vector for data exfiltration.
 * An AI agent with arbitrary network access can send sensitive data to external servers.
 */
type NetworkPolicy = "none" | "localhost" | "allowlist";
/**
 * Configuration for the sandbox environment.
 * Every field has a security rationale documented.
 */
interface SandboxConfig {
    /**
     * Root directory under which all session sandboxes are created.
     * Must be an absolute path. Each session gets a subdirectory here.
     */
    readonly rootPath: string;
    /**
     * Maximum file size in bytes that can be written inside the sandbox.
     * WHY: Prevents resource exhaustion attacks where the agent fills the disk.
     * Default: 10MB (10_485_760 bytes)
     */
    readonly maxFileSize: number;
    /**
     * File extensions the agent is allowed to create or modify.
     * WHY: Prevents creation of executable files (.sh, .exe, .bat) or
     * configuration files that could affect the host system.
     */
    readonly allowedExtensions: ReadonlyArray<string>;
    /**
     * Network access policy for the sandbox.
     * WHY: Controls the blast radius of a compromised agent.
     */
    readonly networkPolicy: NetworkPolicy;
    /**
     * Maximum session duration in milliseconds.
     * WHY: Prevents infinite loops or runaway processes from consuming resources.
     * Default: 300_000 (5 minutes)
     */
    readonly maxDuration: number;
    /**
     * Optional allowlisted hosts when networkPolicy is 'allowlist'.
     * Ignored for other network policies.
     */
    readonly allowedHosts?: ReadonlyArray<string>;
}
/**
 * Types of security events that can occur during session operation.
 * These are logged for audit and surfaced in the dashboard.
 */
type SecurityEventType = "prompt_injection_detected" | "tool_denied" | "sandbox_violation" | "timeout" | "path_traversal_blocked" | "file_size_exceeded" | "rate_limit_exceeded" | "response_filtered";
/**
 * A security-relevant event that occurred during session operation.
 * All events are immutable and append-only — they cannot be modified or deleted.
 *
 * WHY: Security audit trails must be tamper-proof. If an agent could delete
 * its own security events, it could cover its tracks after a prompt injection.
 */
interface SecurityEvent {
    /** Classification of the security event */
    readonly type: SecurityEventType;
    /** Human-readable description of what happened */
    readonly details: string;
    /** ISO 8601 timestamp of when the event occurred */
    readonly timestamp: string;
    /** Session ID where the event occurred */
    readonly sessionId: string;
}
/**
 * Configuration for the MiniClaw HTTP server.
 */
interface ServerConfig {
    /** Port to listen on. Default: 3847 */
    readonly port: number;
    /** Hostname to bind to. Default: 'localhost' (not 0.0.0.0 for security) */
    readonly hostname: string;
    /**
     * Allowed CORS origins.
     * WHY default is localhost only: Prevents cross-origin requests from
     * malicious websites that could issue prompts to the agent.
     */
    readonly corsOrigins: ReadonlyArray<string>;
    /**
     * Maximum requests per minute per IP.
     * WHY: Prevents abuse and resource exhaustion from rapid-fire prompts.
     * Default: 10
     */
    readonly rateLimit: number;
    /**
     * Maximum request body size in bytes.
     * WHY: Prevents oversized payloads from consuming memory.
     * Default: 10_240 (10KB)
     */
    readonly maxRequestSize: number;
}
/**
 * Top-level configuration for starting a MiniClaw instance.
 * Combines sandbox, server, and tool configuration.
 */
interface MiniClawConfig {
    readonly sandbox: SandboxConfig;
    readonly server: ServerConfig;
    readonly tools: ToolWhitelist;
}
/**
 * Default sandbox configuration — maximum security posture.
 * Users can relax these as needed, but defaults should be safe for "normies".
 */
declare const DEFAULT_SANDBOX_CONFIG: SandboxConfig;
/**
 * Default server configuration — locked down to localhost.
 */
declare const DEFAULT_SERVER_CONFIG: ServerConfig;

/**
 * MiniClaw Sandbox Manager
 *
 * Creates, validates, and destroys isolated filesystem sandboxes for each session.
 * This is the critical security boundary — all filesystem operations MUST be
 * validated through this module before execution.
 *
 * Security invariant: No operation ever accesses a path outside the sandbox root.
 */

/**
 * Validates that a requested path is safely within the sandbox boundary.
 *
 * This is the MOST CRITICAL security function in MiniClaw.
 * A failure here means the agent can read/write arbitrary files on the host.
 *
 * Defense in depth approach:
 * 1. Resolve the path to absolute form (eliminates ../ tricks)
 * 2. Check that the resolved path starts with the sandbox root
 * 3. Resolve symlinks and re-check (prevents symlink escape)
 *
 * WHY we resolve symlinks: An attacker could create a symlink inside the
 * sandbox that points to /etc/passwd. Without symlink resolution, the
 * path check passes but the actual file access escapes the sandbox.
 *
 * @returns The validated absolute path, or null if the path is outside the sandbox
 */
declare function validatePath(sandboxPath: string, requestedPath: string): Promise<{
    readonly valid: boolean;
    readonly resolvedPath: string;
    readonly reason: string;
}>;
/**
 * Validates that a file extension is in the allowed list.
 *
 * WHY: Prevents creation of executable files (.sh, .exe, .bat, .cmd)
 * or system configuration files that could affect the host.
 * A sandboxed agent should only work with source code and text files.
 */
declare function validateExtension(filePath: string, allowedExtensions: ReadonlyArray<string>): {
    readonly valid: boolean;
    readonly reason: string;
};
/**
 * Checks if a file at the given path exceeds the maximum allowed size.
 *
 * WHY: Prevents resource exhaustion attacks where the agent writes
 * enormous files to fill the disk. Also prevents reading huge files
 * that could consume all available memory.
 *
 * @returns Object with valid status and the actual file size
 */
declare function checkFileSize(filePath: string, maxSize: number): Promise<{
    readonly valid: boolean;
    readonly size: number;
    readonly reason: string;
}>;
/**
 * Creates a new isolated sandbox directory for a session.
 *
 * The sandbox directory is created under the configured root path with a
 * unique UUID-based name. Permissions are set to owner-only (0o700) to
 * prevent other users on the system from accessing session data.
 *
 * WHY UUID for directory name: Prevents session ID guessing attacks.
 * An attacker who knows the root path cannot predict sandbox paths.
 *
 * WHY 0o700 permissions: Only the owner (the MiniClaw process user)
 * should have read/write/execute access to the sandbox.
 */
declare function createSandbox(config?: SandboxConfig, allowedTools?: ReadonlyArray<AllowedTool>, maxDuration?: number): Promise<MiniClawSession>;
/**
 * Destroys a sandbox directory and all its contents.
 *
 * This is a destructive operation — all files within the sandbox are permanently deleted.
 * Called when a session ends (either by client request or timeout).
 *
 * WHY force + recursive: The sandbox may contain nested directories and
 * read-only files. We need to ensure complete cleanup regardless.
 *
 * Security: We validate the sandbox path before deletion to prevent
 * an attacker from tricking us into deleting arbitrary directories.
 */
declare function destroySandbox(sandboxPath: string, rootPath: string): Promise<{
    readonly success: boolean;
    readonly reason: string;
}>;
/**
 * Creates an immutable SecurityEvent for audit logging.
 * These events are append-only — once created, they cannot be modified.
 *
 * WHY a dedicated factory: Ensures timestamp and structure consistency.
 * Every security event gets a precise ISO 8601 timestamp regardless of
 * where in the codebase it's created.
 */
declare function createSecurityEvent(type: SecurityEvent["type"], details: string, sessionId: string): SecurityEvent;

/**
 * MiniClaw Prompt Router
 *
 * Handles the full lifecycle of a prompt:
 * 1. Input sanitization — strip prompt injection attempts
 * 2. Routing — process the sanitized prompt through allowed tools
 * 3. Output filtering — remove any leaked system prompt content
 *
 * This is the second critical security boundary (after the sandbox).
 * The sandbox limits WHERE the agent can operate; the router limits
 * WHAT the agent can be instructed to do.
 */

/**
 * Sanitizes raw user input by detecting and neutralizing prompt injection attempts.
 *
 * Returns the sanitized prompt and any security events that were triggered.
 * The original prompt is NEVER returned — only the sanitized version.
 *
 * WHY return events alongside the sanitized prompt: The dashboard needs to
 * display blocked injections for transparency, and the audit log needs them
 * for forensics.
 */
declare function sanitizePrompt(raw: string, sessionId: string): {
    readonly sanitized: string;
    readonly events: ReadonlyArray<SecurityEvent>;
};
/**
 * Filters the agent's response to remove leaked system prompt content
 * and internal error details.
 *
 * WHY: Even with good system prompts, models sometimes leak their instructions
 * when cleverly asked. This is a defense-in-depth measure — the primary defense
 * is the system prompt itself saying "do not reveal instructions".
 */
declare function filterResponse(response: string, sessionId: string): {
    readonly filtered: string;
    readonly events: ReadonlyArray<SecurityEvent>;
};
/**
 * Routes a sanitized prompt through the agent's allowed tools.
 *
 * This is the main processing function. It:
 * 1. Sanitizes the input
 * 2. Processes tool calls against the whitelist
 * 3. Filters the output
 *
 * WHY this is a single function: The three steps (sanitize, process, filter)
 * must ALWAYS happen in sequence. Separating them risks a caller forgetting
 * to sanitize or filter.
 *
 * Note: The actual LLM processing is abstracted out. This function handles
 * the security envelope; the LLM call would be injected as a dependency
 * in a production implementation.
 */
declare function routePrompt(request: PromptRequest, session: MiniClawSession): Promise<{
    readonly response: PromptResponse;
    readonly securityEvents: ReadonlyArray<SecurityEvent>;
}>;

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

/**
 * All known tools across all risk levels.
 * Used for documentation and validation — not for authorization.
 *
 * WHY a separate registry: The whitelist is per-session and determines what's
 * allowed. The registry is global and determines what EXISTS. A tool must
 * exist in the registry AND be in the session whitelist to be invoked.
 */
declare const TOOL_REGISTRY: ReadonlyArray<AllowedTool>;
/**
 * Creates a tool whitelist with only safe tools enabled.
 * This is the most restrictive whitelist — suitable for untrusted users.
 *
 * WHY this is the default: "Safe by default" means a misconfigured MiniClaw
 * instance still has minimal risk. Users must explicitly opt into more
 * permissive configurations.
 */
declare function createSafeWhitelist(): ToolWhitelist;
/**
 * Creates a whitelist that includes safe and guarded tools.
 * Suitable for trusted users who need write access to the sandbox.
 */
declare function createGuardedWhitelist(): ToolWhitelist;
/**
 * Creates a custom whitelist from a list of tool names.
 * Only tools that exist in the TOOL_REGISTRY can be included.
 *
 * WHY validate against registry: Prevents injection of arbitrary tool names
 * that could bypass the validation system.
 *
 * @returns The whitelist and any tool names that were not recognized
 */
declare function createCustomWhitelist(toolNames: ReadonlyArray<string>): {
    readonly whitelist: ToolWhitelist;
    readonly unrecognized: ReadonlyArray<string>;
};
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
declare function validateToolCall(call: ToolCallRequest, whitelist: ToolWhitelist): ToolValidationResult;
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
declare function scopeToolCall(call: ToolCallRequest, sandboxPath: string): ToolCallRequest;
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
declare function executeToolCall(call: ToolCallRequest, sandboxPath: string, sessionId: string): Promise<{
    readonly result: string;
    readonly events: ReadonlyArray<SecurityEvent>;
}>;
/**
 * Returns all tools grouped by risk level for display in the dashboard.
 */
declare function getToolsByRiskLevel(): Readonly<Record<ToolRiskLevel, ReadonlyArray<AllowedTool>>>;

/**
 * MiniClaw HTTP Server
 *
 * A minimal HTTP server with a single primary endpoint (POST /api/prompt).
 * Built on Node.js native http module — no Express, no Koa, no dependencies.
 *
 * WHY native http: Fewer dependencies = smaller attack surface.
 * Express and similar frameworks add convenience but also add code paths
 * that an attacker can exploit. For a security-first agent, we use the
 * minimum viable server.
 *
 * Security features:
 * - CORS restricted to configured origins (default: localhost only)
 * - Rate limiting per IP (default: 10 req/min)
 * - Request size limiting (default: 10KB)
 * - No directory listing, no static files, no file uploads
 */

/**
 * Creates and starts the MiniClaw HTTP server.
 *
 * Returns a handle to the server for programmatic control (testing, embedding).
 */
declare function createMiniClawServer(config: MiniClawConfig): {
    readonly server: ReturnType<typeof createServer>;
    readonly stop: () => void;
};
/**
 * Starts the MiniClaw server and begins listening for requests.
 *
 * This is the main entry point for running MiniClaw as a standalone server.
 */
declare function startServer(config: MiniClawConfig): {
    readonly server: ReturnType<typeof createServer>;
    readonly stop: () => void;
};

/**
 * Starts a MiniClaw server with the provided (or default) configuration.
 *
 * This is the simplest way to run MiniClaw — a single function call
 * that sets up the sandbox, tool whitelist, and HTTP server.
 *
 * @param config - Optional partial configuration. Unspecified fields use secure defaults.
 * @returns A handle with the server instance and a stop function
 */
declare function startMiniClaw(config?: Partial<MiniClawConfig>): {
    readonly server: ReturnType<typeof createServer>;
    readonly stop: () => void;
};
/**
 * Creates a MiniClaw session programmatically, without starting a server.
 *
 * Use this when embedding MiniClaw into an existing application that
 * already has its own HTTP server. The session can be used directly
 * with routePrompt() for prompt processing.
 *
 * @param config - Optional partial sandbox configuration
 * @returns A new MiniClaw session with a sandbox directory
 */
declare function createMiniClawSession(config?: Partial<{
    readonly sandbox: Partial<SandboxConfig>;
    readonly tools: ToolWhitelist;
}>): Promise<MiniClawSession>;

export { type AllowedTool, DEFAULT_SANDBOX_CONFIG, DEFAULT_SERVER_CONFIG, type MiniClawConfig, type MiniClawSession, type NetworkPolicy, type PromptRequest, type PromptResponse, type SandboxConfig, type SecurityEvent, type SecurityEventType, type ServerConfig, TOOL_REGISTRY, type TokenUsage, type ToolCallRecord, type ToolCallRequest, type ToolRiskLevel, type ToolValidationResult, type ToolWhitelist, checkFileSize, createCustomWhitelist, createGuardedWhitelist, createMiniClawServer, createMiniClawSession, createSafeWhitelist, createSandbox, createSecurityEvent, destroySandbox, executeToolCall, filterResponse, getToolsByRiskLevel, routePrompt, sanitizePrompt, scopeToolCall, startMiniClaw, startServer, validateExtension, validatePath, validateToolCall };
