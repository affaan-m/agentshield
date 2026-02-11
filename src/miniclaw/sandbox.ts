/**
 * MiniClaw Sandbox Manager
 *
 * Creates, validates, and destroys isolated filesystem sandboxes for each session.
 * This is the critical security boundary — all filesystem operations MUST be
 * validated through this module before execution.
 *
 * Security invariant: No operation ever accesses a path outside the sandbox root.
 */

import { mkdir, rm, stat, realpath, access } from "node:fs/promises";
import { join, resolve, relative, extname } from "node:path";
import { randomUUID } from "node:crypto";
import type {
  SandboxConfig,
  MiniClawSession,
  SecurityEvent,
  AllowedTool,
} from "./types.js";
import { DEFAULT_SANDBOX_CONFIG } from "./types.js";

// ─── Path Validation ──────────────────────────────────────

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
export async function validatePath(
  sandboxPath: string,
  requestedPath: string
): Promise<{ readonly valid: boolean; readonly resolvedPath: string; readonly reason: string }> {
  // Step 1: Resolve to absolute path, normalizing any ../ sequences
  // WHY: path.resolve() collapses "../" segments, so "sandbox/../../../etc/passwd"
  // becomes "/etc/passwd" which will correctly fail the prefix check.
  const absoluteRequested = resolve(sandboxPath, requestedPath);

  // Step 2: Verify the resolved path starts with the sandbox root
  // WHY: This is the primary containment check. After resolution, any path
  // that doesn't start with the sandbox root has escaped.
  const normalizedSandbox = resolve(sandboxPath);
  if (!absoluteRequested.startsWith(normalizedSandbox + "/") && absoluteRequested !== normalizedSandbox) {
    return {
      valid: false,
      resolvedPath: absoluteRequested,
      reason: `Path traversal detected: "${requestedPath}" resolves outside sandbox`,
    };
  }

  // Step 3: If the path exists, resolve symlinks and re-check
  // WHY: A symlink at sandbox/link -> /etc/passwd would pass the string prefix
  // check above, but the real path is outside the sandbox.
  try {
    await access(absoluteRequested);
    const realPath = await realpath(absoluteRequested);
    if (!realPath.startsWith(normalizedSandbox + "/") && realPath !== normalizedSandbox) {
      return {
        valid: false,
        resolvedPath: realPath,
        reason: `Symlink escape detected: "${requestedPath}" resolves to "${realPath}" outside sandbox`,
      };
    }
    return { valid: true, resolvedPath: realPath, reason: "Path is within sandbox" };
  } catch {
    // Path doesn't exist yet — that's OK for write operations.
    // The string prefix check above is sufficient for non-existent paths
    // because there's no symlink to follow.
    return { valid: true, resolvedPath: absoluteRequested, reason: "Path is within sandbox (new file)" };
  }
}

/**
 * Validates that a file extension is in the allowed list.
 *
 * WHY: Prevents creation of executable files (.sh, .exe, .bat, .cmd)
 * or system configuration files that could affect the host.
 * A sandboxed agent should only work with source code and text files.
 */
export function validateExtension(
  filePath: string,
  allowedExtensions: ReadonlyArray<string>
): { readonly valid: boolean; readonly reason: string } {
  const ext = extname(filePath).toLowerCase();

  // Files without extensions (like "Makefile") are blocked by default
  // WHY: Many executable files have no extension on Unix systems
  if (ext === "") {
    return {
      valid: false,
      reason: `Files without extensions are not allowed (file: "${filePath}")`,
    };
  }

  if (!allowedExtensions.includes(ext)) {
    return {
      valid: false,
      reason: `Extension "${ext}" is not in the allowed list`,
    };
  }

  return { valid: true, reason: "Extension is allowed" };
}

// ─── File Size Validation ─────────────────────────────────

/**
 * Checks if a file at the given path exceeds the maximum allowed size.
 *
 * WHY: Prevents resource exhaustion attacks where the agent writes
 * enormous files to fill the disk. Also prevents reading huge files
 * that could consume all available memory.
 *
 * @returns Object with valid status and the actual file size
 */
export async function checkFileSize(
  filePath: string,
  maxSize: number
): Promise<{ readonly valid: boolean; readonly size: number; readonly reason: string }> {
  try {
    const stats = await stat(filePath);

    if (stats.size > maxSize) {
      return {
        valid: false,
        size: stats.size,
        reason: `File size ${stats.size} bytes exceeds maximum ${maxSize} bytes`,
      };
    }

    return {
      valid: true,
      size: stats.size,
      reason: "File size is within limits",
    };
  } catch {
    // File doesn't exist — size check not applicable
    // This is not an error; the file may be about to be created
    return { valid: true, size: 0, reason: "File does not exist yet" };
  }
}

// ─── Sandbox Lifecycle ────────────────────────────────────

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
export async function createSandbox(
  config: SandboxConfig = DEFAULT_SANDBOX_CONFIG,
  allowedTools: ReadonlyArray<AllowedTool> = [],
  maxDuration?: number
): Promise<MiniClawSession> {
  const sessionId = randomUUID();
  const sandboxPath = join(config.rootPath, sessionId);

  // Create the sandbox root if it doesn't exist
  // WHY recursive: The root path might not exist on first run
  await mkdir(config.rootPath, { recursive: true, mode: 0o700 });

  // Create the session-specific sandbox directory
  // WHY mode 0o700: Owner-only access prevents other system users from
  // reading or modifying sandbox contents
  await mkdir(sandboxPath, { mode: 0o700 });

  const session: MiniClawSession = {
    id: sessionId,
    createdAt: new Date().toISOString(),
    sandboxPath,
    allowedTools,
    maxDuration: maxDuration ?? config.maxDuration,
  };

  return session;
}

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
export async function destroySandbox(
  sandboxPath: string,
  rootPath: string
): Promise<{ readonly success: boolean; readonly reason: string }> {
  // CRITICAL: Validate that the sandbox path is actually under our root
  // WHY: Without this check, an attacker could pass "/etc" as sandboxPath
  // and we would recursively delete system files.
  const normalizedSandbox = resolve(sandboxPath);
  const normalizedRoot = resolve(rootPath);

  if (!normalizedSandbox.startsWith(normalizedRoot + "/")) {
    return {
      success: false,
      reason: `Sandbox path "${sandboxPath}" is not under root "${rootPath}" — refusing to delete`,
    };
  }

  // Additional safety: the sandbox path should be exactly one level deep under root
  // WHY: Prevents deletion of the root itself or deeply nested system paths
  // that happen to share the root prefix
  const relativePath = relative(normalizedRoot, normalizedSandbox);
  if (relativePath.includes("/") || relativePath === "" || relativePath === "..") {
    return {
      success: false,
      reason: `Sandbox path must be a direct child of root — got relative path "${relativePath}"`,
    };
  }

  try {
    await rm(normalizedSandbox, { recursive: true, force: true });
    return { success: true, reason: "Sandbox destroyed successfully" };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, reason: `Failed to destroy sandbox: ${message}` };
  }
}

// ─── Security Event Creation ──────────────────────────────

/**
 * Creates an immutable SecurityEvent for audit logging.
 * These events are append-only — once created, they cannot be modified.
 *
 * WHY a dedicated factory: Ensures timestamp and structure consistency.
 * Every security event gets a precise ISO 8601 timestamp regardless of
 * where in the codebase it's created.
 */
export function createSecurityEvent(
  type: SecurityEvent["type"],
  details: string,
  sessionId: string
): SecurityEvent {
  return {
    type,
    details,
    timestamp: new Date().toISOString(),
    sessionId,
  };
}
