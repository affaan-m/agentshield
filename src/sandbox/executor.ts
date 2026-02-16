import { spawn } from "node:child_process";
import { mkdtemp, readdir, stat, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

// ─── Types ────────────────────────────────────────────────

export interface SandboxOptions {
  readonly timeout: number; // ms, default 5000
  readonly networkMonitor: boolean; // capture network activity
  readonly fileMonitor: boolean; // capture file access
  readonly fakeEnv: Record<string, string>; // fake sensitive env vars
}

export interface SandboxExecution {
  readonly hookCommand: string;
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly duration: number; // ms
  readonly observations: ReadonlyArray<SandboxObservation>;
  readonly workDir: string;
}

export interface SandboxObservation {
  readonly type:
    | "network_request"
    | "file_read"
    | "file_write"
    | "env_access"
    | "process_spawn"
    | "dns_lookup"
    | "suspicious_output";
  readonly detail: string;
  readonly severity: "critical" | "high" | "medium" | "low";
  readonly timestamp: number;
}

export type HookType = "PreToolUse" | "PostToolUse" | "SessionStart" | "Stop";

export interface ParsedHook {
  readonly type: HookType;
  readonly command: string;
  readonly matcher?: string;
}

// ─── Default Options ──────────────────────────────────────

const DEFAULT_FAKE_ENV: Record<string, string> = {
  ANTHROPIC_API_KEY: "CANARY_anthropic_sk-ant-fake12345",
  OPENAI_API_KEY: "CANARY_openai_sk-fake67890",
  GITHUB_TOKEN: "CANARY_github_ghp_fake11111",
  AWS_SECRET_ACCESS_KEY: "CANARY_aws_fakesecretkey22222",
  AWS_ACCESS_KEY_ID: "CANARY_aws_fakeaccesskey33333",
  DATABASE_URL: "CANARY_db_postgres://fake:fake@localhost/fake",
  STRIPE_SECRET_KEY: "CANARY_stripe_sk_test_fake44444",
  SLACK_TOKEN: "CANARY_slack_xoxb-fake55555",
  NPM_TOKEN: "CANARY_npm_npm_fake66666",
  SUPABASE_SERVICE_ROLE_KEY: "CANARY_supabase_fake77777",
};

const DEFAULT_OPTIONS: SandboxOptions = {
  timeout: 5000,
  networkMonitor: true,
  fileMonitor: true,
  fakeEnv: DEFAULT_FAKE_ENV,
};

// ─── Hook Parser ──────────────────────────────────────────

/**
 * Parse hooks from a settings.json content string.
 */
export function parseHooks(settingsContent: string): ReadonlyArray<ParsedHook> {
  const hooks: ParsedHook[] = [];

  let config: Record<string, unknown>;
  try {
    config = JSON.parse(settingsContent) as Record<string, unknown>;
  } catch {
    return hooks;
  }

  const hooksObj = config.hooks as Record<string, unknown> | undefined;
  if (!hooksObj || typeof hooksObj !== "object") return hooks;

  const hookTypes: ReadonlyArray<HookType> = [
    "PreToolUse",
    "PostToolUse",
    "SessionStart",
    "Stop",
  ];

  for (const hookType of hookTypes) {
    const entries = hooksObj[hookType];
    if (!Array.isArray(entries)) continue;

    for (const entry of entries) {
      const hookEntry = entry as { hook?: string; matcher?: string };
      if (typeof hookEntry.hook === "string" && hookEntry.hook.length > 0) {
        hooks.push({
          type: hookType,
          command: hookEntry.hook,
          matcher: hookEntry.matcher,
        });
      }
    }
  }

  return hooks;
}

// ─── Sandbox Executor ─────────────────────────────────────

/**
 * Execute a single hook command in a sandboxed child_process.
 * Uses a temp directory as cwd, fake env vars, and timeout enforcement.
 */
export async function executeHookInSandbox(
  hookCommand: string,
  options: Partial<SandboxOptions> = {}
): Promise<SandboxExecution> {
  const opts: SandboxOptions = { ...DEFAULT_OPTIONS, ...options };
  const fakeEnv = { ...DEFAULT_FAKE_ENV, ...opts.fakeEnv };

  // Create isolated temp directory for this execution
  const workDir = await mkdtemp(join(tmpdir(), "agentshield-sandbox-"));

  // Build a minimal, controlled environment
  const sandboxEnv: Record<string, string> = {
    HOME: workDir,
    TMPDIR: workDir,
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin",
    SHELL: "/bin/bash",
    TERM: "dumb",
    ...fakeEnv,
  };

  const observations: SandboxObservation[] = [];
  const startTime = Date.now();

  const controller = new AbortController();
  const { signal } = controller;

  let timedOut = false;

  // Set up timeout
  const timeoutId = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, opts.timeout);

  try {
    const result = await new Promise<{
      exitCode: number | null;
      stdout: string;
      stderr: string;
    }>((resolve) => {
      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];

      const child = spawn(hookCommand, [], {
        shell: true,
        cwd: workDir,
        env: sandboxEnv,
        signal,
        stdio: ["ignore", "pipe", "pipe"],
      });

      child.stdout.on("data", (chunk: Buffer) => {
        stdoutChunks.push(chunk);
      });

      child.stderr.on("data", (chunk: Buffer) => {
        stderrChunks.push(chunk);
      });

      child.on("close", (code) => {
        resolve({
          exitCode: code,
          stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
          stderr: Buffer.concat(stderrChunks).toString("utf-8"),
        });
      });

      child.on("error", (err: NodeJS.ErrnoException) => {
        if (err.code === "ABORT_ERR" || err.name === "AbortError") {
          resolve({
            exitCode: null,
            stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
            stderr: Buffer.concat(stderrChunks).toString("utf-8"),
          });
        } else {
          resolve({
            exitCode: null,
            stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
            stderr:
              Buffer.concat(stderrChunks).toString("utf-8") +
              `\n[spawn error: ${err.message}]`,
          });
        }
      });
    });

    clearTimeout(timeoutId);

    const duration = Date.now() - startTime;
    const combinedOutput = result.stdout + result.stderr;

    // ── Observation: Canary env var detection ──
    detectCanaryLeaks(combinedOutput, fakeEnv, observations);

    // ── Observation: Network activity patterns ──
    if (opts.networkMonitor) {
      detectNetworkActivity(combinedOutput, hookCommand, observations);
    }

    // ── Observation: File system monitoring ──
    if (opts.fileMonitor) {
      await detectFileWrites(workDir, observations);
      detectSensitiveFileAccess(combinedOutput, observations);
    }

    // ── Observation: Process spawning ──
    detectProcessSpawns(hookCommand, combinedOutput, observations);

    // ── Observation: Suspicious output patterns ──
    detectSuspiciousOutput(combinedOutput, observations);

    // ── Observation: DNS lookups ──
    detectDnsLookups(combinedOutput, observations);

    return {
      hookCommand,
      exitCode: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr,
      timedOut,
      duration,
      observations,
      workDir,
    };
  } catch {
    clearTimeout(timeoutId);
    const duration = Date.now() - startTime;

    return {
      hookCommand,
      exitCode: null,
      stdout: "",
      stderr: "[sandbox execution failed]",
      timedOut,
      duration,
      observations,
      workDir,
    };
  }
}

/**
 * Execute all hooks from a settings.json in sandboxed environments.
 */
export async function executeAllHooks(
  settingsContent: string,
  options: Partial<SandboxOptions> = {}
): Promise<ReadonlyArray<SandboxExecution>> {
  const hooks = parseHooks(settingsContent);
  const results: SandboxExecution[] = [];

  for (const hook of hooks) {
    const execution = await executeHookInSandbox(hook.command, options);
    results.push(execution);
  }

  return results;
}

/**
 * Clean up sandbox working directories after analysis.
 */
export async function cleanupSandbox(workDir: string): Promise<void> {
  try {
    await rm(workDir, { recursive: true, force: true });
  } catch {
    // Best-effort cleanup
  }
}

// ─── Detection Functions ──────────────────────────────────

function detectCanaryLeaks(
  output: string,
  fakeEnv: Record<string, string>,
  observations: SandboxObservation[]
): void {
  for (const [envName, canaryValue] of Object.entries(fakeEnv)) {
    if (output.includes(canaryValue)) {
      observations.push({
        type: "env_access",
        detail: `Canary value for ${envName} detected in output — hook is leaking environment variables`,
        severity: "critical",
        timestamp: Date.now(),
      });
    }
  }
}

function detectNetworkActivity(
  output: string,
  command: string,
  observations: SandboxObservation[]
): void {
  const combined = command + " " + output;

  const networkPatterns: ReadonlyArray<{
    readonly pattern: RegExp;
    readonly detail: string;
    readonly severity: "critical" | "high" | "medium";
  }> = [
    {
      pattern: /\bcurl\s+(?:-[a-zA-Z]*\s+)*https?:\/\/[^\s]+/gi,
      detail: "HTTP request via curl",
      severity: "high",
    },
    {
      pattern: /\bwget\s+(?:-[a-zA-Z]*\s+)*https?:\/\/[^\s]+/gi,
      detail: "HTTP request via wget",
      severity: "high",
    },
    {
      pattern: /\bnc\s+-[a-zA-Z]*\s+[^\s]+\s+\d+/g,
      detail: "Netcat connection attempt",
      severity: "critical",
    },
    {
      pattern: /Connection refused|Could not resolve host|connect to .* port/gi,
      detail: "Network connection attempt detected in output",
      severity: "high",
    },
    {
      pattern: /\bfetch\s*\(\s*['"]https?:\/\//g,
      detail: "JavaScript fetch() call to external URL",
      severity: "high",
    },
  ];

  for (const { pattern, detail, severity } of networkPatterns) {
    if (pattern.test(combined)) {
      pattern.lastIndex = 0;
      const match = pattern.exec(combined);
      const evidence = match ? match[0].substring(0, 100) : "";
      pattern.lastIndex = 0;
      observations.push({
        type: "network_request",
        detail: `${detail}: ${evidence}`,
        severity,
        timestamp: Date.now(),
      });
    }
  }
}

async function detectFileWrites(
  workDir: string,
  observations: SandboxObservation[]
): Promise<void> {
  try {
    const entries = await readdir(workDir);
    for (const entry of entries) {
      const entryPath = join(workDir, entry);
      const entryStat = await stat(entryPath);

      if (entryStat.isFile()) {
        const content = await readFile(entryPath, "utf-8");
        observations.push({
          type: "file_write",
          detail: `Hook created file in sandbox: ${entry} (${content.length} bytes)`,
          severity: "medium",
          timestamp: Date.now(),
        });

        // Check if the file contains canary values
        if (/CANARY_/.test(content)) {
          observations.push({
            type: "env_access",
            detail: `Canary value written to file: ${entry} — potential exfiltration staging`,
            severity: "critical",
            timestamp: Date.now(),
          });
        }
      } else if (entryStat.isDirectory()) {
        observations.push({
          type: "file_write",
          detail: `Hook created directory in sandbox: ${entry}`,
          severity: "low",
          timestamp: Date.now(),
        });
      }
    }
  } catch {
    // Sandbox directory may have been removed or inaccessible
  }
}

function detectSensitiveFileAccess(
  output: string,
  observations: SandboxObservation[]
): void {
  const sensitivePaths: ReadonlyArray<{
    readonly pattern: RegExp;
    readonly detail: string;
  }> = [
    {
      pattern: /\/etc\/(?:passwd|shadow|sudoers)/g,
      detail: "Attempted to access system auth files",
    },
    {
      pattern: /~\/\.ssh\/|\/\.ssh\//g,
      detail: "Attempted to access SSH directory",
    },
    {
      pattern: /~\/\.aws\/|\/\.aws\//g,
      detail: "Attempted to access AWS credentials",
    },
    {
      pattern: /~\/\.gnupg\/|\/\.gnupg\//g,
      detail: "Attempted to access GPG keyring",
    },
    {
      pattern: /\/\.env\b/g,
      detail: "Attempted to access .env file",
    },
  ];

  for (const { pattern, detail } of sensitivePaths) {
    if (pattern.test(output)) {
      observations.push({
        type: "file_read",
        detail,
        severity: "high",
        timestamp: Date.now(),
      });
    }
  }
}

function detectProcessSpawns(
  command: string,
  output: string,
  observations: SandboxObservation[]
): void {
  const combined = command + " " + output;

  const processPatterns: ReadonlyArray<{
    readonly pattern: RegExp;
    readonly detail: string;
    readonly severity: "critical" | "high";
  }> = [
    {
      pattern: /\bnohup\b/g,
      detail: "Attempted to spawn persistent background process (nohup)",
      severity: "critical",
    },
    {
      pattern: /\bdisown\b/g,
      detail: "Attempted to detach process from shell (disown)",
      severity: "critical",
    },
    {
      pattern: /\bscreen\s+-[dD]m/g,
      detail: "Attempted to create detached screen session",
      severity: "high",
    },
    {
      pattern: /\btmux\s+new-session\s+-d/g,
      detail: "Attempted to create detached tmux session",
      severity: "high",
    },
  ];

  for (const { pattern, detail, severity } of processPatterns) {
    if (pattern.test(combined)) {
      observations.push({
        type: "process_spawn",
        detail,
        severity,
        timestamp: Date.now(),
      });
    }
  }
}

function detectSuspiciousOutput(
  output: string,
  observations: SandboxObservation[]
): void {
  // Detect base64-encoded blobs (minimum 20 chars of contiguous base64)
  const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
  const base64Matches = Array.from(output.matchAll(base64Pattern));
  if (base64Matches.length > 0) {
    observations.push({
      type: "suspicious_output",
      detail: `Output contains base64-encoded data (${base64Matches.length} block(s)) — possible encoded exfiltration`,
      severity: "medium",
      timestamp: Date.now(),
    });
  }

  // Detect IP addresses in output
  const ipPattern = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
  const ipMatches = Array.from(output.matchAll(ipPattern));
  // Filter out common local IPs
  const suspiciousIps = ipMatches.filter((m) => {
    const ip = m[0];
    return (
      !ip.startsWith("127.") &&
      !ip.startsWith("0.") &&
      ip !== "255.255.255.255"
    );
  });
  if (suspiciousIps.length > 0) {
    observations.push({
      type: "suspicious_output",
      detail: `Output contains IP address(es): ${suspiciousIps.map((m) => m[0]).join(", ")}`,
      severity: "medium",
      timestamp: Date.now(),
    });
  }

  // Detect URLs in output
  const urlPattern = /https?:\/\/[^\s"'<>]+/g;
  const urlMatches = Array.from(output.matchAll(urlPattern));
  if (urlMatches.length > 0) {
    observations.push({
      type: "suspicious_output",
      detail: `Output contains URL(s): ${urlMatches.map((m) => m[0].substring(0, 80)).join(", ")}`,
      severity: "low",
      timestamp: Date.now(),
    });
  }
}

function detectDnsLookups(
  output: string,
  observations: SandboxObservation[]
): void {
  const dnsPatterns: ReadonlyArray<{
    readonly pattern: RegExp;
    readonly detail: string;
  }> = [
    {
      pattern: /\bdig\s+/g,
      detail: "DNS lookup via dig command",
    },
    {
      pattern: /\bnslookup\s+/g,
      detail: "DNS lookup via nslookup command",
    },
    {
      pattern: /\bhost\s+[a-zA-Z]/g,
      detail: "DNS lookup via host command",
    },
    {
      pattern: /;; ANSWER SECTION|Server:\s+\d+\.\d+/g,
      detail: "DNS query response detected in output",
    },
  ];

  for (const { pattern, detail } of dnsPatterns) {
    if (pattern.test(output)) {
      observations.push({
        type: "dns_lookup",
        detail,
        severity: "medium",
        timestamp: Date.now(),
      });
    }
  }
}
