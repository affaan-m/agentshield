/**
 * MiniClaw Core Type System
 *
 * All types are immutable by design — fields are readonly and arrays use ReadonlyArray.
 * This prevents accidental mutation of security-critical configuration at the type level.
 */

// ─── Session Management ───────────────────────────────────

/**
 * Represents an active MiniClaw session with its sandbox and permissions.
 * Sessions are ephemeral — they are created, used, and destroyed.
 * No session data should persist after destruction.
 */
export interface MiniClawSession {
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

// ─── Prompt Handling ──────────────────────────────────────

/**
 * Incoming prompt request from the client.
 * The prompt field contains raw user input that MUST be sanitized before processing.
 */
export interface PromptRequest {
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
export interface PromptResponse {
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
export interface TokenUsage {
  readonly input: number;
  readonly output: number;
}

/**
 * Records a tool call that was executed during prompt processing.
 * Used for audit trail and client-side transparency.
 */
export interface ToolCallRecord {
  readonly tool: string;
  readonly args: Readonly<Record<string, unknown>>;
  readonly result: string;
  readonly duration: number;
}

// ─── Tool Whitelist (Security-Critical) ───────────────────

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
export type ToolRiskLevel = "safe" | "guarded" | "restricted";

/**
 * A tool that the agent is permitted to invoke, with its risk classification.
 */
export interface AllowedTool {
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
export interface ToolWhitelist {
  readonly tools: ReadonlyArray<AllowedTool>;
}

/**
 * A validated tool call request, after checking against the whitelist.
 */
export interface ToolCallRequest {
  readonly tool: string;
  readonly args: Readonly<Record<string, unknown>>;
}

/**
 * Result of validating a tool call against the whitelist.
 */
export interface ToolValidationResult {
  readonly allowed: boolean;
  readonly tool: string;
  readonly reason: string;
}

// ─── Sandbox Configuration ────────────────────────────────

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
export type NetworkPolicy = "none" | "localhost" | "allowlist";

/**
 * Configuration for the sandbox environment.
 * Every field has a security rationale documented.
 */
export interface SandboxConfig {
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

// ─── Security Events ──────────────────────────────────────

/**
 * Types of security events that can occur during session operation.
 * These are logged for audit and surfaced in the dashboard.
 */
export type SecurityEventType =
  | "prompt_injection_detected"
  | "tool_denied"
  | "sandbox_violation"
  | "timeout"
  | "path_traversal_blocked"
  | "file_size_exceeded"
  | "rate_limit_exceeded"
  | "response_filtered";

/**
 * A security-relevant event that occurred during session operation.
 * All events are immutable and append-only — they cannot be modified or deleted.
 *
 * WHY: Security audit trails must be tamper-proof. If an agent could delete
 * its own security events, it could cover its tracks after a prompt injection.
 */
export interface SecurityEvent {
  /** Classification of the security event */
  readonly type: SecurityEventType;
  /** Human-readable description of what happened */
  readonly details: string;
  /** ISO 8601 timestamp of when the event occurred */
  readonly timestamp: string;
  /** Session ID where the event occurred */
  readonly sessionId: string;
}

// ─── Server Configuration ─────────────────────────────────

/**
 * Configuration for the MiniClaw HTTP server.
 */
export interface ServerConfig {
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

// ─── MiniClaw Configuration (Top-Level) ───────────────────

/**
 * Top-level configuration for starting a MiniClaw instance.
 * Combines sandbox, server, and tool configuration.
 */
export interface MiniClawConfig {
  readonly sandbox: SandboxConfig;
  readonly server: ServerConfig;
  readonly tools: ToolWhitelist;
}

// ─── Defaults ─────────────────────────────────────────────

/**
 * Default sandbox configuration — maximum security posture.
 * Users can relax these as needed, but defaults should be safe for "normies".
 */
export const DEFAULT_SANDBOX_CONFIG: SandboxConfig = {
  rootPath: "/tmp/miniclaw-sandboxes",
  maxFileSize: 10_485_760, // 10MB
  allowedExtensions: [
    ".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".txt",
    ".css", ".html", ".yaml", ".yml", ".toml", ".xml",
    ".csv", ".svg", ".env.example",
  ],
  networkPolicy: "none", // WHY: Most secure default — no exfiltration possible
  maxDuration: 300_000, // 5 minutes
} as const;

/**
 * Default server configuration — locked down to localhost.
 */
export const DEFAULT_SERVER_CONFIG: ServerConfig = {
  port: 3847,
  hostname: "localhost", // WHY: Never bind to 0.0.0.0 by default — prevents remote access
  corsOrigins: ["http://localhost:3847", "http://localhost:3000"],
  rateLimit: 10, // WHY: 10 req/min is reasonable for interactive use, prevents scripted abuse
  maxRequestSize: 10_240, // WHY: 10KB is plenty for a prompt — prevents memory exhaustion
} as const;
