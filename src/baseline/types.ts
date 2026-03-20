import type { Finding, SecurityScore, Severity } from "../types.js";

// ─── Serialized Baseline ────────────────────────────────────

export interface SerializedBaseline {
  readonly version: 1;
  readonly timestamp: string;
  readonly score: SecurityScore;
  readonly findings: ReadonlyArray<SerializedFinding>;
}

export interface SerializedFinding {
  readonly id: string;
  readonly severity: Severity;
  readonly category: string;
  readonly title: string;
  readonly file: string;
  readonly evidence?: string;
  readonly fingerprint: string;
}

// ─── Comparison Result ──────────────────────────────────────

export interface BaselineComparison {
  readonly timestamp: string;
  readonly baselineTimestamp: string;
  readonly newFindings: ReadonlyArray<Finding>;
  readonly resolvedFindings: ReadonlyArray<SerializedFinding>;
  readonly unchangedCount: number;
  readonly scoreDelta: number;
  readonly baselineScore: number;
  readonly currentScore: number;
  readonly isRegression: boolean;
  readonly newCriticalCount: number;
  readonly newHighCount: number;
}

// ─── Gate Configuration ─────────────────────────────────────

export interface GateConfig {
  readonly maxNewFindings: number;
  readonly maxScoreDrop: number;
  readonly failOnNewCritical: boolean;
  readonly failOnNewHigh: boolean;
}

export const DEFAULT_GATE_CONFIG: GateConfig = {
  maxNewFindings: 0,
  maxScoreDrop: 5,
  failOnNewCritical: true,
  failOnNewHigh: true,
};

// ─── Gate Result ────────────────────────────────────────────

export interface GateResult {
  readonly passed: boolean;
  readonly reasons: ReadonlyArray<string>;
  readonly comparison: BaselineComparison;
}
