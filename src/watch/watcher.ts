import { watch, existsSync, readdirSync, statSync, type FSWatcher } from "node:fs";
import { join, resolve } from "node:path";
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

const RECURSIVE_WATCH_UNSUPPORTED = "ERR_FEATURE_UNAVAILABLE_ON_PLATFORM";

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
  const watchers: FSWatcher[] = [];

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
      watchers.push(
        ...createWatchers(
          resolvedPath,
          (_eventType: string, _filename: string | Buffer | null) => {
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
        )
      );
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

function createWatchers(
  rootPath: string,
  onChange: (eventType: string, filename: string | Buffer | null) => void
): FSWatcher[] {
  try {
    return [watch(rootPath, { recursive: true }, onChange)];
  } catch (error) {
    if (!isRecursiveWatchUnsupported(error)) {
      throw error;
    }
    return createDirectoryWatchers(rootPath, onChange);
  }
}

function createDirectoryWatchers(
  rootPath: string,
  onChange: (eventType: string, filename: string | Buffer | null) => void
): FSWatcher[] {
  const createdWatchers: FSWatcher[] = [];

  try {
    for (const directory of collectDirectories(rootPath)) {
      createdWatchers.push(watch(directory, onChange));
    }
    return createdWatchers;
  } catch (error) {
    for (const watcher of createdWatchers) {
      watcher.close();
    }
    throw error;
  }
}

function collectDirectories(rootPath: string): string[] {
  const directories = [rootPath];

  for (let index = 0; index < directories.length; index += 1) {
    for (const entry of readdirSync(directories[index], { withFileTypes: true })) {
      if (entry.isDirectory()) {
        directories.push(join(directories[index], entry.name));
      }
    }
  }

  return directories;
}

function isRecursiveWatchUnsupported(error: unknown): boolean {
  if (!error || typeof error !== "object") {
    return false;
  }

  const code = "code" in error ? String((error as { code?: unknown }).code ?? "") : "";
  return code === RECURSIVE_WATCH_UNSUPPORTED;
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
