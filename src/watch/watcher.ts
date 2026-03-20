import { watch, existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { scan } from "../scanner/index.js";
import { calculateScore } from "../reporter/score.js";
import type { Severity } from "../types.js";
import type { WatchConfig, WatcherState, ScanBaseline, DriftResult } from "./types.js";
import { createBaseline, diffBaseline } from "./diff.js";
import { dispatchAlert } from "./alerts.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Start watching the given paths for config changes.
 * Returns a cleanup function that stops watching.
 */
export function startWatcher(config: WatchConfig): {
  readonly stop: () => void;
  readonly getState: () => WatcherState;
} {
  let baseline: ScanBaseline | null = null;
  let lastDrift: DriftResult | null = null;
  let scanCount = 0;
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  const watchers: ReturnType<typeof watch>[] = [];

  // Perform initial scan to establish baseline
  const initialBaseline = performInitialScan(config);
  if (initialBaseline) {
    baseline = initialBaseline;
    scanCount = 1;
  }

  // Set up watchers for each path
  for (const watchPath of config.paths) {
    const resolvedPath = resolve(watchPath);
    if (!existsSync(resolvedPath)) continue;

    const isDir = statSync(resolvedPath).isDirectory();
    if (!isDir) continue;

    try {
      const watcher = watch(
        resolvedPath,
        { recursive: true },
        (_eventType, _filename) => {
          // Debounce: wait for config.debounceMs of silence before rescanning
          if (debounceTimer) {
            clearTimeout(debounceTimer);
          }
          debounceTimer = setTimeout(() => {
            void handleChange(config, baseline, (result) => {
              if (result.newBaseline) {
                baseline = result.newBaseline;
              }
              if (result.drift) {
                lastDrift = result.drift;
              }
              scanCount += 1;
            });
          }, config.debounceMs);
        }
      );
      watchers.push(watcher);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`  Failed to watch ${resolvedPath}: ${message}`);
    }
  }

  function stop(): void {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    for (const w of watchers) {
      w.close();
    }
    watchers.length = 0;
  }

  function getState(): WatcherState {
    return {
      isRunning: watchers.length > 0,
      baseline,
      lastDrift,
      scanCount,
    };
  }

  return { stop, getState };
}

/**
 * Perform the initial scan to establish a baseline.
 */
function performInitialScan(config: WatchConfig): ScanBaseline | null {
  try {
    const targetPath = config.paths[0];
    if (!targetPath || !existsSync(targetPath)) return null;

    const result = scan(targetPath);
    const minIndex = SEVERITY_ORDER[config.minSeverity];
    const filteredFindings = result.findings.filter(
      (f) => SEVERITY_ORDER[f.severity] <= minIndex
    );
    const report = calculateScore({ ...result, findings: filteredFindings });
    return createBaseline(filteredFindings, report.score);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`  Initial scan failed: ${message}`);
    return null;
  }
}

interface ChangeResult {
  readonly newBaseline: ScanBaseline | null;
  readonly drift: DriftResult | null;
}

/**
 * Handle a detected file change by rescanning and diffing.
 */
async function handleChange(
  config: WatchConfig,
  currentBaseline: ScanBaseline | null,
  onResult: (result: ChangeResult) => void
): Promise<void> {
  try {
    const targetPath = config.paths[0];
    if (!targetPath || !existsSync(targetPath)) return;

    const result = scan(targetPath);
    const minIndex = SEVERITY_ORDER[config.minSeverity];
    const filteredFindings = result.findings.filter(
      (f) => SEVERITY_ORDER[f.severity] <= minIndex
    );
    const report = calculateScore({ ...result, findings: filteredFindings });
    const newBaseline = createBaseline(filteredFindings, report.score);

    if (currentBaseline) {
      const drift = diffBaseline(currentBaseline, filteredFindings, report.score);

      if (drift.newFindings.length > 0 || drift.resolvedFindings.length > 0) {
        await dispatchAlert(drift, config.alertMode, config.webhookUrl);
        onResult({ newBaseline, drift });
      } else {
        onResult({ newBaseline, drift: null });
      }
    } else {
      onResult({ newBaseline, drift: null });
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`  Re-scan failed: ${message}`);
  }
}
