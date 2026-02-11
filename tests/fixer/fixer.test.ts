import { describe, it, expect } from "vitest";
import { writeFileSync, readFileSync, mkdtempSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { applyFixes, renderFixSummary } from "../../src/fixer/index.js";
import type { ScanResult } from "../../src/scanner/index.js";

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "agentshield-fixer-"));
}

function makeScanResult(
  findings: ScanResult["findings"],
  files: ScanResult["target"]["files"] = []
): ScanResult {
  return {
    target: { path: "/tmp", files },
    findings,
  };
}

describe("applyFixes", () => {
  it("applies an auto-fixable secret replacement", () => {
    const dir = createTempDir();
    const filePath = join(dir, "CLAUDE.md");
    writeFileSync(filePath, "key: sk-ant-api03-abc123xyz");

    const result = applyFixes(
      makeScanResult([
        {
          id: "SEC-001",
          severity: "critical",
          category: "secrets",
          title: "Hardcoded Anthropic key",
          description: "Found key",
          file: filePath,
          fix: {
            description: "Use env var",
            before: "sk-ant-api03-abc123xyz",
            after: "${ANTHROPIC_API_KEY}",
            auto: true,
          },
        },
      ])
    );

    expect(result.applied).toHaveLength(1);
    expect(result.applied[0].findingId).toBe("SEC-001");
    expect(readFileSync(filePath, "utf-8")).toBe("key: ${ANTHROPIC_API_KEY}");
  });

  it("skips findings without auto flag", () => {
    const result = applyFixes(
      makeScanResult([
        {
          id: "SEC-002",
          severity: "high",
          category: "secrets",
          title: "Manual fix needed",
          description: "Review required",
          file: "/tmp/nonexistent",
          fix: {
            description: "Fix manually",
            before: "old",
            after: "new",
            auto: false,
          },
        },
      ])
    );

    expect(result.applied).toHaveLength(0);
    expect(result.skipped).toHaveLength(0);
    expect(result.totalAutoFixable).toBe(0);
  });

  it("skips findings without any fix", () => {
    const result = applyFixes(
      makeScanResult([
        {
          id: "INFO-001",
          severity: "info",
          category: "agents",
          title: "Info finding",
          description: "No fix needed",
          file: "/tmp/test",
        },
      ])
    );

    expect(result.totalAutoFixable).toBe(0);
  });

  it("skips when file cannot be read", () => {
    const result = applyFixes(
      makeScanResult([
        {
          id: "SEC-003",
          severity: "critical",
          category: "secrets",
          title: "Missing file",
          description: "File not found",
          file: "/nonexistent/path/CLAUDE.md",
          fix: {
            description: "Fix",
            before: "old",
            after: "new",
            auto: true,
          },
        },
      ])
    );

    expect(result.applied).toHaveLength(0);
    expect(result.skipped).toHaveLength(1);
    expect(result.skipped[0].reason).toContain("Could not read file");
  });

  it("skips when pattern not found in file", () => {
    const dir = createTempDir();
    const filePath = join(dir, "settings.json");
    writeFileSync(filePath, '{"permissions":{}}');

    const result = applyFixes(
      makeScanResult([
        {
          id: "PERM-001",
          severity: "high",
          category: "permissions",
          title: "Overly permissive",
          description: "Tighten",
          file: filePath,
          fix: {
            description: "Scope",
            before: "Bash(*)",
            after: "Bash(git *)",
            auto: true,
          },
        },
      ])
    );

    expect(result.skipped).toHaveLength(1);
    expect(result.skipped[0].reason).toContain("Pattern not found");
  });

  it("applies multiple fixes to the same file", () => {
    const dir = createTempDir();
    const filePath = join(dir, "CLAUDE.md");
    writeFileSync(filePath, "key1: sk-ant-abc\nkey2: sk-proj-xyz");

    const result = applyFixes(
      makeScanResult([
        {
          id: "SEC-001",
          severity: "critical",
          category: "secrets",
          title: "Anthropic key",
          description: "Found",
          file: filePath,
          fix: {
            description: "Use env",
            before: "sk-ant-abc",
            after: "${ANTHROPIC_API_KEY}",
            auto: true,
          },
        },
        {
          id: "SEC-002",
          severity: "critical",
          category: "secrets",
          title: "OpenAI key",
          description: "Found",
          file: filePath,
          fix: {
            description: "Use env",
            before: "sk-proj-xyz",
            after: "${OPENAI_API_KEY}",
            auto: true,
          },
        },
      ])
    );

    expect(result.applied).toHaveLength(2);
    const content = readFileSync(filePath, "utf-8");
    expect(content).toBe("key1: ${ANTHROPIC_API_KEY}\nkey2: ${OPENAI_API_KEY}");
  });
});

describe("renderFixSummary", () => {
  it("shows 'no fixable findings' when empty", () => {
    const output = renderFixSummary({
      applied: [],
      skipped: [],
      totalAutoFixable: 0,
    });
    expect(output).toContain("No auto-fixable findings");
  });

  it("shows applied fixes", () => {
    const output = renderFixSummary({
      applied: [
        {
          file: "CLAUDE.md",
          findingId: "SEC-001",
          title: "Hardcoded key",
          description: "Use env var",
          before: "sk-ant-xxx",
          after: "${KEY}",
        },
      ],
      skipped: [],
      totalAutoFixable: 1,
    });
    expect(output).toContain("[FIXED]");
    expect(output).toContain("Hardcoded key");
    expect(output).toContain("CLAUDE.md");
  });

  it("shows skipped fixes", () => {
    const output = renderFixSummary({
      applied: [],
      skipped: [
        {
          file: "settings.json",
          findingId: "PERM-001",
          title: "Broad permission",
          reason: "Pattern not found",
        },
      ],
      totalAutoFixable: 1,
    });
    expect(output).toContain("[SKIP]");
    expect(output).toContain("Broad permission");
    expect(output).toContain("Pattern not found");
  });

  it("shows counts summary", () => {
    const output = renderFixSummary({
      applied: [
        {
          file: "a.md",
          findingId: "A",
          title: "Fix A",
          description: "d",
          before: "b",
          after: "a",
        },
      ],
      skipped: [
        { file: "b.md", findingId: "B", title: "Fix B", reason: "Not found" },
      ],
      totalAutoFixable: 2,
    });
    expect(output).toContain("Auto-fixable: 2");
    expect(output).toContain("Applied: 1");
    expect(output).toContain("Skipped: 1");
  });
});
