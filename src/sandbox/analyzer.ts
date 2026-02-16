import type { SandboxExecution } from "./executor.js";

// ─── Types ────────────────────────────────────────────────

export interface BehavioralAnalysis {
  readonly hookCommand: string;
  readonly execution: SandboxExecution;
  readonly findings: ReadonlyArray<BehavioralFinding>;
  readonly riskScore: number; // 0-100
  readonly verdict: "safe" | "suspicious" | "malicious";
}

export interface BehavioralFinding {
  readonly id: string;
  readonly type: string;
  readonly severity: "critical" | "high" | "medium" | "low";
  readonly title: string;
  readonly description: string;
  readonly evidence: string;
}

// ─── Severity Weights ─────────────────────────────────────

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 30,
  high: 20,
  medium: 10,
  low: 5,
};

// ─── Timing Thresholds ────────────────────────────────────

const SUSPICIOUS_DURATION_MS = 3000;
const BEACONING_DURATION_MS = 4500;

// ─── Analyzer ─────────────────────────────────────────────

/**
 * Analyze a sandboxed hook execution and produce behavioral findings.
 */
export function analyzeExecution(
  execution: SandboxExecution
): BehavioralAnalysis {
  const findings: BehavioralFinding[] = [];

  // 1. Canary detection
  analyzeCanaryLeaks(execution, findings);

  // 2. Network activity
  analyzeNetworkActivity(execution, findings);

  // 3. File system access
  analyzeFileSystemAccess(execution, findings);

  // 4. Process behavior
  analyzeProcessBehavior(execution, findings);

  // 5. Timing analysis
  analyzeTimingBehavior(execution, findings);

  // 6. Output analysis
  analyzeOutputPatterns(execution, findings);

  // 7. Timeout behavior
  analyzeTimeoutBehavior(execution, findings);

  // 8. DNS activity
  analyzeDnsActivity(execution, findings);

  // Calculate risk score
  const riskScore = calculateRiskScore(findings);

  // Determine verdict
  const verdict = determineVerdict(riskScore, findings);

  return {
    hookCommand: execution.hookCommand,
    execution,
    findings,
    riskScore,
    verdict,
  };
}

/**
 * Analyze multiple hook executions and return all analyses.
 */
export function analyzeAllExecutions(
  executions: ReadonlyArray<SandboxExecution>
): ReadonlyArray<BehavioralAnalysis> {
  return executions.map((exec) => analyzeExecution(exec));
}

// ─── Analysis Functions ───────────────────────────────────

function analyzeCanaryLeaks(
  execution: SandboxExecution,
  findings: BehavioralFinding[]
): void {
  const canaryObservations = execution.observations.filter(
    (o) => o.type === "env_access"
  );

  for (const obs of canaryObservations) {
    findings.push({
      id: `sandbox-canary-leak-${findings.length}`,
      type: "canary_exfiltration",
      severity: "critical",
      title: "Hook leaks environment variable values",
      description: obs.detail,
      evidence: truncateEvidence(
        execution.stdout + execution.stderr,
        obs.detail
      ),
    });
  }
}

function analyzeNetworkActivity(
  execution: SandboxExecution,
  findings: BehavioralFinding[]
): void {
  const networkObservations = execution.observations.filter(
    (o) => o.type === "network_request"
  );

  for (const obs of networkObservations) {
    findings.push({
      id: `sandbox-network-${findings.length}`,
      type: "network_activity",
      severity: obs.severity,
      title: "Hook makes outbound network connection",
      description: obs.detail,
      evidence: obs.detail.substring(0, 200),
    });
  }
}

function analyzeFileSystemAccess(
  execution: SandboxExecution,
  findings: BehavioralFinding[]
): void {
  const fileWriteObs = execution.observations.filter(
    (o) => o.type === "file_write"
  );
  const fileReadObs = execution.observations.filter(
    (o) => o.type === "file_read"
  );

  for (const obs of fileWriteObs) {
    findings.push({
      id: `sandbox-file-write-${findings.length}`,
      type: "file_system_write",
      severity: obs.severity,
      title: "Hook writes files during execution",
      description: obs.detail,
      evidence: obs.detail,
    });
  }

  for (const obs of fileReadObs) {
    findings.push({
      id: `sandbox-file-read-${findings.length}`,
      type: "sensitive_file_access",
      severity: obs.severity,
      title: "Hook accesses sensitive file paths",
      description: obs.detail,
      evidence: obs.detail,
    });
  }
}

function analyzeProcessBehavior(
  execution: SandboxExecution,
  findings: BehavioralFinding[]
): void {
  const processObs = execution.observations.filter(
    (o) => o.type === "process_spawn"
  );

  for (const obs of processObs) {
    findings.push({
      id: `sandbox-process-spawn-${findings.length}`,
      type: "process_spawn",
      severity: obs.severity,
      title: "Hook spawns background or persistent processes",
      description: obs.detail,
      evidence: execution.hookCommand.substring(0, 200),
    });
  }
}

function analyzeTimingBehavior(
  execution: SandboxExecution,
  findings: BehavioralFinding[]
): void {
  if (execution.duration > BEACONING_DURATION_MS) {
    findings.push({
      id: `sandbox-timing-beaconing-${findings.length}`,
      type: "timing_anomaly",
      severity: "high",
      title: "Hook execution takes suspiciously long",
      description: `Hook ran for ${execution.duration}ms, which exceeds the beaconing threshold (${BEACONING_DURATION_MS}ms). Long-running hooks may be attempting C2 beaconing, waiting for network responses, or performing brute-force operations.`,
      evidence: `Duration: ${execution.duration}ms, Command: ${execution.hookCommand.substring(0, 100)}`,
    });
  } else if (execution.duration > SUSPICIOUS_DURATION_MS) {
    findings.push({
      id: `sandbox-timing-slow-${findings.length}`,
      type: "timing_anomaly",
      severity: "medium",
      title: "Hook execution is unusually slow",
      description: `Hook ran for ${execution.duration}ms. This exceeds the suspicious threshold (${SUSPICIOUS_DURATION_MS}ms). While not necessarily malicious, slow hooks may indicate network calls, heavy computation, or intentional delays.`,
      evidence: `Duration: ${execution.duration}ms, Command: ${execution.hookCommand.substring(0, 100)}`,
    });
  }
}

function analyzeOutputPatterns(
  execution: SandboxExecution,
  findings: BehavioralFinding[]
): void {
  const suspiciousObs = execution.observations.filter(
    (o) => o.type === "suspicious_output"
  );

  for (const obs of suspiciousObs) {
    // Promote base64 findings to high severity if combined with network activity
    const hasNetwork = execution.observations.some(
      (o) => o.type === "network_request"
    );
    const effectiveSeverity =
      hasNetwork && obs.detail.includes("base64")
        ? ("high" as const)
        : obs.severity;

    findings.push({
      id: `sandbox-output-${findings.length}`,
      type: "suspicious_output",
      severity: effectiveSeverity,
      title: "Hook output contains suspicious patterns",
      description: obs.detail,
      evidence: truncateEvidence(
        execution.stdout + execution.stderr,
        obs.detail
      ),
    });
  }
}

function analyzeTimeoutBehavior(
  execution: SandboxExecution,
  findings: BehavioralFinding[]
): void {
  if (execution.timedOut) {
    findings.push({
      id: `sandbox-timeout-${findings.length}`,
      type: "timeout",
      severity: "high",
      title: "Hook exceeded timeout and was killed",
      description: `Hook was killed after exceeding the timeout. This may indicate the hook is waiting for external resources, stuck in an infinite loop, or attempting C2 beaconing. Command: "${execution.hookCommand.substring(0, 100)}"`,
      evidence: `Timed out after ${execution.duration}ms. Command: ${execution.hookCommand.substring(0, 100)}`,
    });
  }
}

function analyzeDnsActivity(
  execution: SandboxExecution,
  findings: BehavioralFinding[]
): void {
  const dnsObs = execution.observations.filter(
    (o) => o.type === "dns_lookup"
  );

  for (const obs of dnsObs) {
    findings.push({
      id: `sandbox-dns-${findings.length}`,
      type: "dns_activity",
      severity: "medium",
      title: "Hook performs DNS lookups",
      description: `${obs.detail}. DNS queries can be used for data exfiltration by encoding data in subdomain names, bypassing most network filters.`,
      evidence: obs.detail,
    });
  }
}

// ─── Scoring ──────────────────────────────────────────────

function calculateRiskScore(
  findings: ReadonlyArray<BehavioralFinding>
): number {
  if (findings.length === 0) return 0;

  let score = 0;
  for (const finding of findings) {
    score += SEVERITY_WEIGHT[finding.severity] ?? 0;
  }

  // Cap at 100
  return Math.min(100, score);
}

function determineVerdict(
  riskScore: number,
  findings: ReadonlyArray<BehavioralFinding>
): "safe" | "suspicious" | "malicious" {
  // Any critical finding = malicious
  const hasCritical = findings.some((f) => f.severity === "critical");
  if (hasCritical) return "malicious";

  // High risk score = malicious
  if (riskScore >= 60) return "malicious";

  // Medium risk score = suspicious
  if (riskScore >= 20) return "suspicious";

  // Any high finding = suspicious
  const hasHigh = findings.some((f) => f.severity === "high");
  if (hasHigh) return "suspicious";

  return "safe";
}

// ─── Utilities ────────────────────────────────────────────

function truncateEvidence(output: string, context: string): string {
  // Try to find the relevant portion of output near the context
  const trimmedOutput = output.trim();
  if (trimmedOutput.length <= 200) return trimmedOutput;

  // Extract the first meaningful line
  const lines = trimmedOutput.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) return context.substring(0, 200);

  return lines[0].substring(0, 200);
}
