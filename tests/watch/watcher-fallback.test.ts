import { afterEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { WatchConfig } from "../../src/watch/types.js";

const TEST_DIR = join(process.cwd(), "tests", "watch", "__fallback-fixtures__");
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
    debounceMs: 500,
    alertMode: "terminal",
    minSeverity: "info",
    blockOnCritical: false,
    ...overrides,
  };
}

describe("startWatcher recursive fallback", () => {
  afterEach(() => {
    cleanupTestDir();
    vi.restoreAllMocks();
    vi.resetModules();
    vi.doUnmock("node:fs");
  });

  it("falls back to per-directory watches when recursive mode is unavailable", async () => {
    const closeSpies: Array<ReturnType<typeof vi.fn>> = [];
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    setupTestDir();

    vi.doMock("node:fs", async () => {
      const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
      return {
        ...actual,
        watch: vi.fn(
          (
            path: string,
            optionsOrListener?: unknown,
            maybeListener?: unknown
          ) => {
            const options =
              typeof optionsOrListener === "function"
                ? undefined
                : (optionsOrListener as { recursive?: boolean } | undefined);
            const listener =
              typeof optionsOrListener === "function"
                ? optionsOrListener
                : maybeListener;

            expect(typeof listener).toBe("function");

            if (options?.recursive) {
              const error = new Error(
                "The feature watch recursively is unavailable on the current platform"
              ) as NodeJS.ErrnoException;
              error.code = "ERR_FEATURE_UNAVAILABLE_ON_PLATFORM";
              throw error;
            }

            const close = vi.fn();
            closeSpies.push(close);
            return { close };
          }
        ),
      };
    });

    const { startWatcher } = await import("../../src/watch/watcher.js");
    const { stop, getState } = startWatcher(makeConfig());

    try {
      const state = getState();
      expect(state.isRunning).toBe(true);
      expect(state.baseline).not.toBeNull();
      expect(state.scanCount).toBe(1);
      expect(closeSpies).toHaveLength(2);
      expect(consoleError).not.toHaveBeenCalled();
    } finally {
      stop();
    }

    for (const close of closeSpies) {
      expect(close).toHaveBeenCalledOnce();
    }
  });
});
