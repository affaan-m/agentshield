import { describe, it, expect, vi, afterEach } from "vitest";
import { writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { startWatcher } from "../../src/watch/watcher.js";
import type { WatchConfig } from "../../src/watch/types.js";

const TEST_DIR = join(process.cwd(), "tests", "watch", "__fixtures__");
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

describe("startWatcher", () => {
  afterEach(() => {
    cleanupTestDir();
    vi.restoreAllMocks();
  });

  it("performs initial scan and establishes baseline", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    setupTestDir();

    const { stop, getState } = startWatcher(makeConfig());

    try {
      const state = getState();
      expect(state.isRunning).toBe(true);
      expect(state.baseline).not.toBeNull();
      expect(state.scanCount).toBe(1);
      expect(state.lastDrift).toBeNull();
    } finally {
      stop();
    }
  });

  it("stops cleanly", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    setupTestDir();

    const { stop, getState } = startWatcher(makeConfig());
    stop();

    const state = getState();
    expect(state.isRunning).toBe(false);
  });

  it("handles non-existent paths gracefully", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { stop, getState } = startWatcher(
      makeConfig({ paths: ["/tmp/nonexistent-agentshield-test-path"] })
    );

    try {
      const state = getState();
      expect(state.isRunning).toBe(false);
      expect(state.baseline).toBeNull();
    } finally {
      stop();
    }
  });

  it("baseline contains scan findings", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    setupTestDir();
    // Write a config with a known finding: no deny list
    writeFileSync(
      join(CLAUDE_DIR, "settings.json"),
      JSON.stringify({
        permissions: {
          allow: ["Read", "Write", "Bash"],
        },
      })
    );

    const { stop, getState } = startWatcher(makeConfig());

    try {
      const state = getState();
      expect(state.baseline).not.toBeNull();
      // Should have at least one finding (no deny list, Bash allowed, etc.)
      expect(state.baseline!.findings.length).toBeGreaterThan(0);
    } finally {
      stop();
    }
  });

  it("filters findings by minSeverity", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    setupTestDir();
    writeFileSync(
      join(CLAUDE_DIR, "settings.json"),
      JSON.stringify({
        permissions: {
          allow: ["Read", "Write", "Bash"],
        },
      })
    );

    const { stop: stop1, getState: getState1 } = startWatcher(
      makeConfig({ minSeverity: "info" })
    );
    const allFindings = getState1().baseline?.findings.length ?? 0;
    stop1();

    setupTestDir();
    writeFileSync(
      join(CLAUDE_DIR, "settings.json"),
      JSON.stringify({
        permissions: {
          allow: ["Read", "Write", "Bash"],
        },
      })
    );

    const { stop: stop2, getState: getState2 } = startWatcher(
      makeConfig({ minSeverity: "critical" })
    );
    const criticalOnly = getState2().baseline?.findings.length ?? 0;
    stop2();

    expect(allFindings).toBeGreaterThanOrEqual(criticalOnly);
  });
});
