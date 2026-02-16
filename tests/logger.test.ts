import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";

import { ScanLogger } from "../src/logger/index.js";
import type { ScanLog, ScanLogSummary } from "../src/logger/index.js";
import {
  loadHistory,
  appendHistory,
  diffScans,
  findPreviousScan,
} from "../src/logger/history.js";
import type { ScanHistoryEntry, ScanDiff } from "../src/logger/history.js";

// ─── Helpers ──────────────────────────────────────────────

function makeSummary(overrides?: Partial<ScanLogSummary>): ScanLogSummary {
  return {
    filesScanned: 5,
    rulesExecuted: 102,
    findingsCount: { critical: 2, high: 3, medium: 1, low: 0 },
    duration: 450,
    grade: "D",
    score: 35,
    ...overrides,
  };
}

function makeHistoryEntry(overrides?: Partial<ScanHistoryEntry>): ScanHistoryEntry {
  return {
    scanId: randomUUID(),
    timestamp: new Date().toISOString(),
    targetPath: "/home/user/.claude",
    grade: "C",
    score: 60,
    findingsCritical: 1,
    findingsHigh: 3,
    findingsMedium: 2,
    findingsLow: 1,
    ...overrides,
  };
}

// ─── ScanLogger Tests ─────────────────────────────────────

describe("ScanLogger", () => {
  describe("create", () => {
    it("creates a logger with a UUID scanId", () => {
      const logger = ScanLogger.create("/test/path");

      expect(logger.scanId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
    });

    it("records the start time as ISO 8601", () => {
      const before = new Date().toISOString();
      const logger = ScanLogger.create("/test/path");
      const after = new Date().toISOString();

      expect(logger.startTime >= before).toBe(true);
      expect(logger.startTime <= after).toBe(true);
    });

    it("automatically logs a scan_start event", () => {
      const logger = ScanLogger.create("/test/path");

      expect(logger.events).toHaveLength(1);
      expect(logger.events[0].eventType).toBe("scan_start");
      expect(logger.events[0].data.targetPath).toBe("/test/path");
    });
  });

  describe("log", () => {
    it("appends events with timestamps", () => {
      const logger = ScanLogger.create("/test");

      logger.log("rule_executed", { ruleId: "secrets-hardcoded" });
      logger.log("finding_detected", { severity: "critical" });

      expect(logger.events).toHaveLength(3); // scan_start + 2
      expect(logger.events[1].eventType).toBe("rule_executed");
      expect(logger.events[2].eventType).toBe("finding_detected");
    });

    it("includes monotonic elapsed time in each event", () => {
      const logger = ScanLogger.create("/test");

      logger.log("rule_executed", { ruleId: "test" });

      const event = logger.events[1];
      expect(typeof event.data._elapsedMs).toBe("number");
      expect(event.data._elapsedMs).toBeGreaterThanOrEqual(0);
    });

    it("preserves event data immutably", () => {
      const logger = ScanLogger.create("/test");
      const data = { ruleId: "test", count: 3 };

      logger.log("rule_executed", data);

      // Mutating the original data should not affect the logged event
      (data as Record<string, unknown>).ruleId = "mutated";
      expect(logger.events[1].data.ruleId).toBe("test");
    });
  });

  describe("finalize", () => {
    it("returns a complete ScanLog", () => {
      const logger = ScanLogger.create("/test");
      logger.log("rule_executed", { ruleId: "test-rule" });

      const summary = makeSummary();
      const log = logger.finalize(summary);

      expect(log.scanId).toBe(logger.scanId);
      expect(log.startTime).toBe(logger.startTime);
      expect(log.endTime).toBeDefined();
      expect(log.targetPath).toBe("/test");
      expect(log.summary).toEqual(summary);
    });

    it("adds a scan_complete event", () => {
      const logger = ScanLogger.create("/test");
      const log = logger.finalize(makeSummary({ grade: "B", score: 80 }));

      const lastEvents = log.events.filter(
        (e) => e.eventType === "scan_complete"
      );
      expect(lastEvents).toHaveLength(1);
      expect(lastEvents[0].data.grade).toBe("B");
      expect(lastEvents[0].data.score).toBe(80);
    });

    it("sets endTime after startTime", () => {
      const logger = ScanLogger.create("/test");
      const log = logger.finalize(makeSummary());

      expect(log.endTime).toBeDefined();
      expect(log.endTime! >= log.startTime).toBe(true);
    });
  });

  describe("writeToFile", () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = join(tmpdir(), `agentshield-test-${randomUUID()}`);
      mkdirSync(tmpDir, { recursive: true });
    });

    afterEach(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("writes NDJSON log to file", () => {
      const logger = ScanLogger.create("/test");
      logger.log("finding_detected", { severity: "critical" });
      const log = logger.finalize(makeSummary());

      const outputPath = join(tmpDir, "scan.ndjson");
      logger.writeToFile(outputPath, log, "ndjson");

      expect(existsSync(outputPath)).toBe(true);

      const content = readFileSync(outputPath, "utf-8");
      const lines = content.split("\n").filter(Boolean);

      // Header + events + summary
      expect(lines.length).toBeGreaterThanOrEqual(3);

      // Each line should be valid JSON
      for (const line of lines) {
        expect(() => JSON.parse(line)).not.toThrow();
      }

      // First line is the header
      const header = JSON.parse(lines[0]);
      expect(header.type).toBe("scan_header");
      expect(header.scanId).toBe(log.scanId);

      // Last line is the summary
      const summary = JSON.parse(lines[lines.length - 1]);
      expect(summary.type).toBe("scan_summary");
    });

    it("writes JSON log to file", () => {
      const logger = ScanLogger.create("/test");
      const log = logger.finalize(makeSummary());

      const outputPath = join(tmpDir, "scan.json");
      logger.writeToFile(outputPath, log, "json");

      const content = readFileSync(outputPath, "utf-8");
      const parsed = JSON.parse(content);

      expect(parsed.scanId).toBe(log.scanId);
      expect(parsed.events).toBeInstanceOf(Array);
      expect(parsed.summary).toBeDefined();
    });

    it("creates directories recursively", () => {
      const logger = ScanLogger.create("/test");
      const log = logger.finalize(makeSummary());

      const deep = join(tmpDir, "deep", "nested", "dir", "log.json");
      logger.writeToFile(deep, log, "json");

      expect(existsSync(deep)).toBe(true);
    });
  });
});

// ─── History Tests ────────────────────────────────────────

describe("history", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = join(tmpdir(), `agentshield-history-${randomUUID()}`);
    mkdirSync(tmpDir, { recursive: true });
    process.env.AGENTSHIELD_HOME = tmpDir;
  });

  afterEach(() => {
    delete process.env.AGENTSHIELD_HOME;
    rmSync(tmpDir, { recursive: true, force: true });
  });

  describe("loadHistory", () => {
    it("returns empty array when no history file exists", () => {
      const history = loadHistory();
      expect(history).toEqual([]);
    });

    it("returns empty array for invalid JSON", () => {
      writeFileSync(join(tmpDir, "history.json"), "not-json", "utf-8");

      const history = loadHistory();
      expect(history).toEqual([]);
    });

    it("returns empty array for non-array JSON", () => {
      writeFileSync(
        join(tmpDir, "history.json"),
        JSON.stringify({ not: "array" }),
        "utf-8"
      );

      const history = loadHistory();
      expect(history).toEqual([]);
    });

    it("loads existing history entries", () => {
      const entries = [makeHistoryEntry(), makeHistoryEntry()];
      writeFileSync(
        join(tmpDir, "history.json"),
        JSON.stringify(entries),
        "utf-8"
      );

      const history = loadHistory();
      expect(history).toHaveLength(2);
      expect(history[0].scanId).toBe(entries[0].scanId);
    });
  });

  describe("appendHistory", () => {
    it("creates history file if it does not exist", () => {
      const entry = makeHistoryEntry();
      appendHistory(entry);

      const history = loadHistory();
      expect(history).toHaveLength(1);
      expect(history[0].scanId).toBe(entry.scanId);
    });

    it("appends to existing history", () => {
      const entry1 = makeHistoryEntry({ score: 50 });
      const entry2 = makeHistoryEntry({ score: 70 });

      appendHistory(entry1);
      appendHistory(entry2);

      const history = loadHistory();
      expect(history).toHaveLength(2);
      expect(history[0].score).toBe(50);
      expect(history[1].score).toBe(70);
    });

    it("creates parent directory if needed", () => {
      // Override to a nested path
      const nestedDir = join(tmpDir, "nested", "dir");
      process.env.AGENTSHIELD_HOME = nestedDir;

      appendHistory(makeHistoryEntry());

      expect(existsSync(join(nestedDir, "history.json"))).toBe(true);
    });
  });

  describe("findPreviousScan", () => {
    it("returns undefined when no history exists", () => {
      expect(findPreviousScan("/test")).toBeUndefined();
    });

    it("returns the most recent scan for the target path", () => {
      const old = makeHistoryEntry({
        targetPath: "/test",
        score: 30,
        timestamp: "2025-01-01T00:00:00Z",
      });
      const recent = makeHistoryEntry({
        targetPath: "/test",
        score: 70,
        timestamp: "2025-06-01T00:00:00Z",
      });
      const other = makeHistoryEntry({
        targetPath: "/other",
        score: 90,
      });

      writeFileSync(
        join(tmpDir, "history.json"),
        JSON.stringify([old, other, recent]),
        "utf-8"
      );

      const result = findPreviousScan("/test");
      expect(result).toBeDefined();
      expect(result!.score).toBe(70);
    });

    it("returns undefined for unmatched path", () => {
      appendHistory(makeHistoryEntry({ targetPath: "/other" }));

      expect(findPreviousScan("/nonexistent")).toBeUndefined();
    });
  });
});

// ─── Scan Diff Tests ──────────────────────────────────────

describe("diffScans", () => {
  it("detects improving trend", () => {
    const previous = makeHistoryEntry({ score: 40, grade: "D" });
    const current = makeHistoryEntry({ score: 75, grade: "B" });

    const diff = diffScans(previous, current);

    expect(diff.scoreChange).toBe(35);
    expect(diff.gradeChange).toBe("D \u2192 B");
    expect(diff.trend).toBe("improving");
  });

  it("detects degrading trend", () => {
    const previous = makeHistoryEntry({
      score: 80,
      grade: "B",
      findingsCritical: 0,
      findingsHigh: 1,
      findingsMedium: 1,
      findingsLow: 0,
    });
    const current = makeHistoryEntry({
      score: 40,
      grade: "D",
      findingsCritical: 3,
      findingsHigh: 5,
      findingsMedium: 4,
      findingsLow: 2,
    });

    const diff = diffScans(previous, current);

    expect(diff.scoreChange).toBe(-40);
    expect(diff.trend).toBe("degrading");
    expect(diff.newFindings).toBe(12); // 14 - 2
    expect(diff.resolvedFindings).toBe(0);
  });

  it("detects stable trend", () => {
    const entry = makeHistoryEntry({ score: 60, grade: "C" });

    const diff = diffScans(entry, entry);

    expect(diff.scoreChange).toBe(0);
    expect(diff.gradeChange).toBe("no change");
    expect(diff.trend).toBe("stable");
    expect(diff.newFindings).toBe(0);
    expect(diff.resolvedFindings).toBe(0);
  });

  it("calculates resolved findings correctly", () => {
    const previous = makeHistoryEntry({
      findingsCritical: 5,
      findingsHigh: 10,
      findingsMedium: 3,
      findingsLow: 2,
      score: 20,
    });
    const current = makeHistoryEntry({
      findingsCritical: 1,
      findingsHigh: 2,
      findingsMedium: 1,
      findingsLow: 0,
      score: 75,
    });

    const diff = diffScans(previous, current);

    expect(diff.resolvedFindings).toBe(16); // 20 - 4
    expect(diff.newFindings).toBe(0);
    expect(diff.trend).toBe("improving");
  });

  it("handles grade change formatting", () => {
    const previous = makeHistoryEntry({ grade: "F" });
    const current = makeHistoryEntry({ grade: "A" });

    const diff = diffScans(previous, current);

    expect(diff.gradeChange).toBe("F \u2192 A");
  });
});
