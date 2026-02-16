import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

// ─── Scan History Entry ───────────────────────────────────

export interface ScanHistoryEntry {
  readonly scanId: string;
  readonly timestamp: string;
  readonly targetPath: string;
  readonly grade: string;
  readonly score: number;
  readonly findingsCritical: number;
  readonly findingsHigh: number;
  readonly findingsMedium: number;
  readonly findingsLow: number;
}

// ─── Scan Diff ────────────────────────────────────────────

export interface ScanDiff {
  readonly gradeChange: string;
  readonly scoreChange: number;
  readonly newFindings: number;
  readonly resolvedFindings: number;
  readonly trend: "improving" | "degrading" | "stable";
}

// ─── Constants ────────────────────────────────────────────

const AGENTSHIELD_DIR = ".agentshield";
const HISTORY_FILE = "history.json";

/**
 * Resolve the path to the AgentShield data directory.
 * Allows override via environment variable for testing.
 */
function getAgentShieldDir(): string {
  if (process.env.AGENTSHIELD_HOME) {
    return process.env.AGENTSHIELD_HOME;
  }
  return join(homedir(), AGENTSHIELD_DIR);
}

/**
 * Resolve the path to the history file.
 */
function getHistoryPath(): string {
  return join(getAgentShieldDir(), HISTORY_FILE);
}

/**
 * Ensure the ~/.agentshield/ directory exists.
 */
function ensureDir(): void {
  const dir = getAgentShieldDir();
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

// ─── Public API ───────────────────────────────────────────

/**
 * Reads scan history from ~/.agentshield/history.json.
 * Returns an empty array if the file does not exist or is invalid.
 */
export function loadHistory(): ReadonlyArray<ScanHistoryEntry> {
  const historyPath = getHistoryPath();

  if (!existsSync(historyPath)) {
    return [];
  }

  try {
    const raw = readFileSync(historyPath, "utf-8");
    const parsed = JSON.parse(raw);

    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed as ReadonlyArray<ScanHistoryEntry>;
  } catch {
    return [];
  }
}

/**
 * Appends a new entry to the scan history file.
 * Creates the file and directory if they do not exist.
 */
export function appendHistory(entry: ScanHistoryEntry): void {
  ensureDir();

  const existing = loadHistory();
  const updated = [...existing, entry];

  writeFileSync(getHistoryPath(), JSON.stringify(updated, null, 2), "utf-8");
}

/**
 * Compares two scan history entries and returns what changed.
 */
export function diffScans(
  previous: ScanHistoryEntry,
  current: ScanHistoryEntry
): ScanDiff {
  const scoreChange = current.score - previous.score;

  const gradeChange =
    previous.grade === current.grade
      ? "no change"
      : `${previous.grade} \u2192 ${current.grade}`;

  const previousTotal =
    previous.findingsCritical +
    previous.findingsHigh +
    previous.findingsMedium +
    previous.findingsLow;

  const currentTotal =
    current.findingsCritical +
    current.findingsHigh +
    current.findingsMedium +
    current.findingsLow;

  // New findings = how many more we have now (clamped to 0)
  const newFindings = Math.max(0, currentTotal - previousTotal);
  // Resolved findings = how many fewer we have now (clamped to 0)
  const resolvedFindings = Math.max(0, previousTotal - currentTotal);

  let trend: "improving" | "degrading" | "stable";
  if (scoreChange > 0) {
    trend = "improving";
  } else if (scoreChange < 0) {
    trend = "degrading";
  } else {
    trend = "stable";
  }

  return {
    gradeChange,
    scoreChange,
    newFindings,
    resolvedFindings,
    trend,
  };
}

/**
 * Loads history and returns the most recent entry for a given target path.
 * Returns undefined if no prior scan exists.
 */
export function findPreviousScan(
  targetPath: string
): ScanHistoryEntry | undefined {
  const history = loadHistory();

  // Walk backwards to find the most recent scan for this path
  for (let i = history.length - 1; i >= 0; i--) {
    if (history[i].targetPath === targetPath) {
      return history[i];
    }
  }

  return undefined;
}
