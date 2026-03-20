import { afterEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { WatchConfig } from "../../src/watch/types.js";

const TEST_DIR = join(process.cwd(), "tests", "watch", "__platform-fixtures__");
const CLAUDE_DIR = join(TEST_DIR, ".claude");

function setupTestDir(): void {
  if (existsSync(TEST_DIR)) {
    rmSync(TEST_DIR, { recursive: true, force: true });
  }
  mkdirSync(CLAUDE_DIR, { recursive: true });
  writeFileSync(
    join(CLAUDE_DIR, "settings.json"),
    JSON.stringify({
      permissions: {
        allow: ["Read", "Write"],
        deny: ["Bash"],
      },
    })
  );
  writeFileSync(join(TEST_DIR, "CLAUDE.md"), "# Test Project\nNo secrets here.");
}

function cleanupTestDir(): void {
  if (existsSync(TEST_DIR)) {
    rmSync(TEST_DIR, { recursive: true, force: true });
  }
}

function makeConfig(overrides: Partial<WatchConfig> = {}): WatchConfig {
  return {
    paths: [TEST_DIR],
    debounceMs: 50,
    alertMode: "terminal",
    minSeverity: "info",
    blockOnCritical: false,
    ...overrides,
  };
}

async function importWatcherWithRecursiveFallback() {
  vi.resetModules();
  vi.doMock("node:fs", async () => {
    const actual = await vi.importActual<typeof import("node:fs")>("node:fs");

    return {
      ...actual,
      watch: vi.fn((path: any, optionsOrListener?: any, maybeListener?: any) => {
        if (
          optionsOrListener &&
          typeof optionsOrListener === "object" &&
          optionsOrListener.recursive === true
        ) {
          const error = new Error("recursive watch unsupported") as Error & {
            code?: string;
          };
          error.code = "ERR_FEATURE_UNAVAILABLE_ON_PLATFORM";
          throw error;
        }

        if (typeof optionsOrListener === "function") {
          return actual.watch(path, optionsOrListener);
        }

        return actual.watch(path, optionsOrListener, maybeListener);
      }),
    };
  });

  return import("../../src/watch/watcher.js");
}

describe("startWatcher recursive fallback", () => {
  afterEach(() => {
    cleanupTestDir();
    vi.doUnmock("node:fs");
    vi.resetModules();
    vi.restoreAllMocks();
  });

  it("watches existing directories when recursive watch is unavailable", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    setupTestDir();

    const { startWatcher } = await importWatcherWithRecursiveFallback();
    const { stop, getState } = startWatcher(makeConfig());

    try {
      const state = getState();
      expect(state.isRunning).toBe(true);
      expect(state.baseline).not.toBeNull();
      expect(state.scanCount).toBe(1);
    } finally {
      stop();
    }
  });
});
