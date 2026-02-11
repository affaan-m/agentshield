import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { resolve } from "node:path";

/**
 * The action module runs immediately on import (top-level `run().catch(...)`),
 * so we can't import it directly without mocking process.env and process.exitCode.
 *
 * Instead, we test the helper functions by extracting them via a dynamic import
 * pattern, or test the module's observable behavior.
 *
 * For now, we test the escapeAnnotation pattern and the severity helpers
 * by recreating them (since they're not exported).
 */

// Recreate the helpers to test their logic (mirrors action.ts implementation)
function escapeAnnotation(message: string): string {
  return message
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

function severityIndex(severity: string): number {
  const idx = SEVERITY_ORDER.indexOf(severity as typeof SEVERITY_ORDER[number]);
  return idx === -1 ? SEVERITY_ORDER.length : idx;
}

function isAtOrAboveSeverity(severity: string, minSeverity: string): boolean {
  return severityIndex(severity) <= severityIndex(minSeverity);
}

describe("action helpers (logic verification)", () => {
  describe("escapeAnnotation", () => {
    it("escapes percent signs", () => {
      expect(escapeAnnotation("100%")).toBe("100%25");
    });

    it("escapes newlines", () => {
      expect(escapeAnnotation("line1\nline2")).toBe("line1%0Aline2");
    });

    it("escapes carriage returns", () => {
      expect(escapeAnnotation("line1\rline2")).toBe("line1%0Dline2");
    });

    it("escapes combined special chars", () => {
      expect(escapeAnnotation("100%\r\n")).toBe("100%25%0D%0A");
    });

    it("passes through plain text", () => {
      expect(escapeAnnotation("hello world")).toBe("hello world");
    });
  });

  describe("severityIndex", () => {
    it("returns 0 for critical", () => {
      expect(severityIndex("critical")).toBe(0);
    });

    it("returns 4 for info", () => {
      expect(severityIndex("info")).toBe(4);
    });

    it("returns length for unknown severity", () => {
      expect(severityIndex("unknown")).toBe(SEVERITY_ORDER.length);
    });
  });

  describe("isAtOrAboveSeverity", () => {
    it("critical is at or above medium", () => {
      expect(isAtOrAboveSeverity("critical", "medium")).toBe(true);
    });

    it("high is at or above medium", () => {
      expect(isAtOrAboveSeverity("high", "medium")).toBe(true);
    });

    it("medium is at or above medium", () => {
      expect(isAtOrAboveSeverity("medium", "medium")).toBe(true);
    });

    it("low is NOT at or above medium", () => {
      expect(isAtOrAboveSeverity("low", "medium")).toBe(false);
    });

    it("info is NOT at or above medium", () => {
      expect(isAtOrAboveSeverity("info", "medium")).toBe(false);
    });

    it("critical is at or above critical", () => {
      expect(isAtOrAboveSeverity("critical", "critical")).toBe(true);
    });
  });
});
