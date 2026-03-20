import type { Finding, SecurityScore, Severity } from "../types.js";

// ─── Watch Configuration ────────────────────────────────────

export interface WatchConfig {
  readonly paths: ReadonlyArray<string>;
  readonly debounceMs: number;
  readonly alertMode: AlertMode;
  readonly webhookUrl?: string;
  readonly minSeverity: Severity;
  readonly blockOnCritical: boolean;
}

export type AlertMode = "terminal" | "webhook" | "both";

// ─── Baseline & Drift ───────────────────────────────────────

export interface ScanBaseline {
  readonly timestamp: string;
  readonly score: SecurityScore;
  readonly findings: ReadonlyArray<Finding>;
  readonly findingIds: ReadonlySet<string>;
}

export interface DriftResult {
  readonly timestamp: string;
  readonly newFindings: ReadonlyArray<Finding>;
  readonly resolvedFindings: ReadonlyArray<Finding>;
  readonly scoreDelta: number;
  readonly previousScore: number;
  readonly currentScore: number;
  readonly isRegression: boolean;
  readonly hasCritical: boolean;
}

// ─── Watch Events ───────────────────────────────────────────

export interface WatchEvent {
  readonly type: "change" | "rename";
  readonly filename: string;
  readonly timestamp: string;
}

export interface WatcherState {
  readonly isRunning: boolean;
  readonly baseline: ScanBaseline | null;
  readonly lastDrift: DriftResult | null;
  readonly scanCount: number;
}
