import type { DriftResult } from "./types.js";
import type { AlertMode } from "./types.js";

/**
 * Dispatch a drift alert via the configured mode(s).
 */
export async function dispatchAlert(
  drift: DriftResult,
  mode: AlertMode,
  webhookUrl?: string
): Promise<void> {
  if (mode === "terminal" || mode === "both") {
    renderTerminalAlert(drift);
  }

  if ((mode === "webhook" || mode === "both") && webhookUrl) {
    await sendWebhookAlert(drift, webhookUrl);
  }
}

/**
 * Render a drift alert to the terminal with colored output.
 */
export function renderTerminalAlert(drift: DriftResult): void {
  const divider = "─".repeat(60);
  const timestamp = new Date(drift.timestamp).toLocaleTimeString();

  console.error(`\n${divider}`);
  console.error(`  AgentShield Watch — Drift Detected  [${timestamp}]`);
  console.error(divider);

  if (drift.scoreDelta !== 0) {
    const direction = drift.scoreDelta > 0 ? "+" : "";
    const label = drift.scoreDelta > 0 ? "IMPROVED" : "REGRESSED";
    console.error(
      `  Score: ${drift.previousScore} → ${drift.currentScore} (${direction}${drift.scoreDelta}) [${label}]`
    );
  }

  if (drift.newFindings.length > 0) {
    console.error(`\n  NEW findings (${drift.newFindings.length}):`);
    for (const f of drift.newFindings) {
      const sev = f.severity.toUpperCase().padEnd(8);
      console.error(`    [${sev}] ${f.title}`);
      console.error(`             ${f.file}`);
    }
  }

  if (drift.resolvedFindings.length > 0) {
    console.error(`\n  RESOLVED findings (${drift.resolvedFindings.length}):`);
    for (const f of drift.resolvedFindings) {
      console.error(`    [RESOLVED] ${f.title}`);
    }
  }

  if (drift.hasCritical) {
    console.error(`\n  *** CRITICAL findings detected ***`);
  }

  console.error(`${divider}\n`);
}

/**
 * Format a drift result as a webhook JSON payload.
 */
export function formatWebhookPayload(drift: DriftResult): string {
  return JSON.stringify({
    event: "agentshield.drift",
    timestamp: drift.timestamp,
    isRegression: drift.isRegression,
    hasCritical: drift.hasCritical,
    score: {
      previous: drift.previousScore,
      current: drift.currentScore,
      delta: drift.scoreDelta,
    },
    newFindings: drift.newFindings.map((f) => ({
      id: f.id,
      severity: f.severity,
      title: f.title,
      file: f.file,
    })),
    resolvedFindings: drift.resolvedFindings.map((f) => ({
      id: f.id,
      severity: f.severity,
      title: f.title,
      file: f.file,
    })),
  });
}

/**
 * Send a drift alert to a webhook URL.
 */
export async function sendWebhookAlert(
  drift: DriftResult,
  webhookUrl: string
): Promise<void> {
  const payload = formatWebhookPayload(drift);

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: payload,
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      console.error(
        `  Webhook alert failed: ${response.status} ${response.statusText}`
      );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`  Webhook alert failed: ${message}`);
  }
}
