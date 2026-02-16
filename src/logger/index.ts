import { randomUUID } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

// ─── Event Types ──────────────────────────────────────────

export type ScanEventType =
  | "scan_start"
  | "scan_complete"
  | "finding_detected"
  | "rule_executed"
  | "opus_phase"
  | "injection_test"
  | "sandbox_execution"
  | "error";

export interface ScanEvent {
  readonly timestamp: string;
  readonly eventType: ScanEventType;
  readonly data: Record<string, unknown>;
}

// ─── Scan Log ─────────────────────────────────────────────

export interface ScanLogSummary {
  readonly filesScanned: number;
  readonly rulesExecuted: number;
  readonly findingsCount: Record<string, number>;
  readonly duration: number;
  readonly grade: string;
  readonly score: number;
}

export interface ScanLog {
  readonly scanId: string;
  readonly startTime: string;
  readonly endTime?: string;
  readonly targetPath: string;
  readonly events: ReadonlyArray<ScanEvent>;
  readonly summary: ScanLogSummary;
}

// ─── Log Format ───────────────────────────────────────────

export type LogFormat = "ndjson" | "json";

// ─── ScanLogger ───────────────────────────────────────────

/**
 * Structured logger for AgentShield scan sessions.
 *
 * Creates a UUID-identified scan log, collects timestamped events,
 * and outputs as NDJSON (one JSON object per line) or standard JSON.
 */
export class ScanLogger {
  private readonly _scanId: string;
  private readonly _startTime: string;
  private readonly _targetPath: string;
  private readonly _events: ScanEvent[];
  private readonly _startMs: number;

  private constructor(targetPath: string) {
    this._scanId = randomUUID();
    this._startTime = new Date().toISOString();
    this._targetPath = targetPath;
    this._events = [];
    this._startMs = performance.now();
  }

  /** Creates a new scan log with a fresh UUID. */
  static create(targetPath: string): ScanLogger {
    const logger = new ScanLogger(targetPath);
    logger.log("scan_start", { targetPath });
    return logger;
  }

  /** The unique scan identifier. */
  get scanId(): string {
    return this._scanId;
  }

  /** The scan start time as ISO 8601 string. */
  get startTime(): string {
    return this._startTime;
  }

  /** Read-only snapshot of events logged so far. */
  get events(): ReadonlyArray<ScanEvent> {
    return [...this._events];
  }

  /** Log a structured event. */
  log(eventType: ScanEventType, data: Record<string, unknown>): void {
    const event: ScanEvent = {
      timestamp: new Date().toISOString(),
      eventType,
      data: { ...data, _elapsedMs: Math.round(performance.now() - this._startMs) },
    };
    this._events.push(event);
  }

  /** Finalize the scan log and return the immutable result. */
  finalize(summary: ScanLogSummary): ScanLog {
    this.log("scan_complete", {
      duration: summary.duration,
      grade: summary.grade,
      score: summary.score,
    });

    return {
      scanId: this._scanId,
      startTime: this._startTime,
      endTime: new Date().toISOString(),
      targetPath: this._targetPath,
      events: [...this._events],
      summary: { ...summary },
    };
  }

  /** Write the finalized log to a file in the specified format. */
  writeToFile(outputPath: string, log: ScanLog, format: LogFormat = "ndjson"): void {
    mkdirSync(dirname(outputPath), { recursive: true });

    const content = format === "ndjson"
      ? formatNdjson(log)
      : JSON.stringify(log, null, 2);

    writeFileSync(outputPath, content, "utf-8");
  }

  /** Write the finalized log to stdout in the specified format. */
  writeToStdout(log: ScanLog, format: LogFormat = "ndjson"): void {
    const content = format === "ndjson"
      ? formatNdjson(log)
      : JSON.stringify(log, null, 2);

    process.stdout.write(content + "\n");
  }
}

// ─── NDJSON Formatting ────────────────────────────────────

/**
 * Format a ScanLog as NDJSON (newline-delimited JSON).
 * Each line is a self-contained JSON object: metadata header, then each event.
 */
function formatNdjson(log: ScanLog): string {
  const lines: string[] = [];

  // Header line with scan metadata
  lines.push(JSON.stringify({
    type: "scan_header",
    scanId: log.scanId,
    startTime: log.startTime,
    endTime: log.endTime,
    targetPath: log.targetPath,
  }));

  // One line per event
  for (const event of log.events) {
    lines.push(JSON.stringify({
      type: "event",
      scanId: log.scanId,
      ...event,
    }));
  }

  // Summary line
  lines.push(JSON.stringify({
    type: "scan_summary",
    scanId: log.scanId,
    ...log.summary,
  }));

  return lines.join("\n");
}
