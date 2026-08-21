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

    expect(summary.totalRegistered).toBeGreaterThanOrEqual(9);
    expect(summary.totalMatched).toBe(0);
    expect(summary.matched).toEqual([]);
  });

  it.each(["mcp.json", ".mcp.json", ".claude/mcp.json"] as ReadonlyArray<string>)(
    "treats %s as supporting Claude evidence",
    (markerPath) => {
      const dir = createTempDir();
      const pathSegments = markerPath.split("/");
      const parentSegments = pathSegments.slice(0, -1);
      if (parentSegments.length > 0) {
        mkdirSync(join(dir, ...parentSegments), { recursive: true });
      }
      writeFileSync(join(dir, ...pathSegments), '{"mcpServers":{}}');

      const summary = detectHarnessAdapters(dir);
      const claude = summary.matched.find((adapter) => adapter.id === "claude-code");

      expect(claude?.confidence).toBe("partial");
      expect(claude?.evidence).toEqual([markerPath]);
    }
  );

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

  it("detects editor-native agent and task automation surfaces", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, ".zed"), { recursive: true });
    mkdirSync(join(dir, ".vscode"), { recursive: true });

    writeFileSync(
      join(dir, ".zed", "settings.json"),
      JSON.stringify({
        agent: {
          tool_permissions: {
            default: "confirm",
          },
        },
      })
    );
    writeFileSync(
      join(dir, ".zed", "tasks.json"),
      JSON.stringify([{ label: "agent setup", command: "node scripts/setup-agent.js" }])
    );
    writeFileSync(
      join(dir, ".vscode", "tasks.json"),
      JSON.stringify({ version: "2.0.0", tasks: [{ label: "agent bootstrap" }] })
    );

    const summary = detectHarnessAdapters(dir);

    expect(ids(summary)).toEqual(["vscode", "zed"]);
    expect(summary.matched.every((adapter) => adapter.confidence === "strong")).toBe(true);
    expect(summary.matched.find((adapter) => adapter.id === "zed")?.evidence).toEqual(
      expect.arrayContaining([".zed/settings.json", ".zed/tasks.json"])
    );
    expect(summary.matched.find((adapter) => adapter.id === "vscode")?.evidence).toEqual(
      expect.arrayContaining([".vscode/tasks.json"])
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
