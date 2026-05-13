import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { detectHarnessAdapters, adapterById } from "../../src/harness-adapters/index.js";
import { scan } from "../../src/scanner/index.js";
import { calculateScore } from "../../src/reporter/score.js";

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "agentshield-harness-"));
}

function ids(summary: ReturnType<typeof detectHarnessAdapters>): string[] {
  return summary.matched.map((adapter) => adapter.id).sort();
}

describe("harness adapter registry", () => {
  it("registers supported harness metadata", () => {
    const adapter = adapterById("claude-code");

    expect(adapter?.name).toBe("Claude Code");
    expect(adapter?.configPaths).toContain("CLAUDE.md");
    expect(adapter?.mcpConventions).toContain("mcpServers");
  });

  it("does not match an empty directory", () => {
    const dir = createTempDir();
    const summary = detectHarnessAdapters(dir);

    expect(summary.totalRegistered).toBeGreaterThanOrEqual(7);
    expect(summary.totalMatched).toBe(0);
    expect(summary.matched).toEqual([]);
  });

  it("detects multiple harnesses from explicit local markers", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, ".claude"), { recursive: true });
    mkdirSync(join(dir, ".opencode", "agents"), { recursive: true });
    mkdirSync(join(dir, ".gemini", "commands"), { recursive: true });
    mkdirSync(join(dir, ".dmux"), { recursive: true });
    mkdirSync(join(dir, "commands"), { recursive: true });

    writeFileSync(join(dir, "CLAUDE.md"), "# rules");
    writeFileSync(join(dir, "AGENTS.md"), "# codex rules");
    writeFileSync(join(dir, ".opencode", "config.json"), "{}");
    writeFileSync(join(dir, "GEMINI.md"), "# gemini rules");
    writeFileSync(join(dir, ".dmux", "config.yaml"), "agents: []\n");
    writeFileSync(join(dir, "agent.yaml"), "name: local-agent\n");

    const summary = detectHarnessAdapters(dir);

    expect(ids(summary)).toEqual([
      "claude-code",
      "codex",
      "dmux",
      "gemini",
      "generic-terminal",
      "opencode",
      "project-local-template",
    ]);
    expect(summary.matched.every((adapter) => adapter.confidence === "strong")).toBe(true);
    expect(summary.matched.find((adapter) => adapter.id === "opencode")?.evidence).toContain(
      ".opencode/config.json"
    );
  });

  it("carries harness adapter evidence into scored reports", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "AGENTS.md"), "# codex rules");

    const result = scan(dir);
    const report = calculateScore(result);

    expect(report.harnessAdapters?.totalMatched).toBe(1);
    expect(report.harnessAdapters?.matched[0]?.id).toBe("codex");
    expect(report.harnessAdapters?.matched[0]?.evidence).toEqual(["AGENTS.md"]);
  });
});
