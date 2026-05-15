import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

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
const ACTION_PATH = resolve(process.cwd(), "dist/action.js");

function severityIndex(severity: string): number {
  const idx = SEVERITY_ORDER.indexOf(severity as typeof SEVERITY_ORDER[number]);
  return idx === -1 ? SEVERITY_ORDER.length : idx;
}

function isAtOrAboveSeverity(severity: string, minSeverity: string): boolean {
  return severityIndex(severity) <= severityIndex(minSeverity);
}

describe("action helpers (logic verification)", () => {
  it("documents organization policy inputs and outputs in action.yml", () => {
    const actionYaml = readFileSync(resolve(process.cwd(), "action.yml"), "utf-8");

    expect(actionYaml).toContain("policy:");
    expect(actionYaml).toContain("fail-on-policy:");
    expect(actionYaml).toContain("policy-status:");
    expect(actionYaml).toContain("policy-violations:");
  });

  it("documents baseline drift inputs and outputs in action.yml", () => {
    const actionYaml = readFileSync(resolve(process.cwd(), "action.yml"), "utf-8");

    expect(actionYaml).toContain("baseline:");
    expect(actionYaml).toContain("save-baseline:");
    expect(actionYaml).toContain("baseline-path:");
    expect(actionYaml).toContain("baseline-status:");
    expect(actionYaml).toContain("new-findings:");
    expect(actionYaml).toContain("resolved-findings:");
    expect(actionYaml).toContain("unchanged-findings:");
    expect(actionYaml).toContain("score-delta:");
  });

  it("documents evidence-pack inputs and outputs in action.yml", () => {
    const actionYaml = readFileSync(resolve(process.cwd(), "action.yml"), "utf-8");

    expect(actionYaml).toContain("evidence-pack:");
    expect(actionYaml).toContain("verify-evidence-pack:");
    expect(actionYaml).toContain("evidence-pack-path:");
    expect(actionYaml).toContain("evidence-pack-status:");
    expect(actionYaml).toContain("evidence-pack-digest:");
    expect(actionYaml).toContain('default: "true"');
  });

  it("documents supply-chain gate inputs and outputs in action.yml", () => {
    const actionYaml = readFileSync(resolve(process.cwd(), "action.yml"), "utf-8");

    expect(actionYaml).toContain("supply-chain:");
    expect(actionYaml).toContain("supply-chain-online:");
    expect(actionYaml).toContain("fail-on-supply-chain:");
    expect(actionYaml).toContain("supply-chain-status:");
    expect(actionYaml).toContain("supply-chain-risky-packages:");
    expect(actionYaml).toContain("supply-chain-critical-count:");
    expect(actionYaml).toContain("supply-chain-high-count:");
  });

  it("writes and verifies an evidence pack when requested", () => {
    const workspace = mkdtempSync(join(tmpdir(), "agentshield-action-workspace-"));
    const outputFile = join(workspace, "github-output.txt");
    const summaryFile = join(workspace, "github-summary.md");
    const evidencePackPath = "agentshield-evidence";

    writeFileSync(join(workspace, "README.md"), "# Fixture\n");

    const result = spawnSync(process.execPath, [ACTION_PATH], {
      cwd: workspace,
      env: {
        ...process.env,
        GITHUB_WORKSPACE: workspace,
        GITHUB_OUTPUT: outputFile,
        GITHUB_STEP_SUMMARY: summaryFile,
        INPUT_PATH: ".",
        "INPUT_FAIL-ON-FINDINGS": "false",
        "INPUT_EVIDENCE-PACK": evidencePackPath,
      },
      encoding: "utf-8",
    });

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("Evidence pack verification: PASSED");

    const evidenceDir = join(workspace, evidencePackPath);
    expect(existsSync(join(evidenceDir, "manifest.json"))).toBe(true);
    expect(existsSync(join(evidenceDir, "agentshield-report.json"))).toBe(true);

    const outputs = readFileSync(outputFile, "utf-8");
    expect(outputs).toContain(`evidence-pack-path=${evidenceDir}`);
    expect(outputs).toContain("evidence-pack-status=passed");
    expect(outputs).toMatch(/evidence-pack-digest=sha256:[a-f0-9]{64}/);
    expect(outputs).toContain("supply-chain-status=clean");
  });

  it("fails by default when MCP supply-chain verification finds a compromised package", () => {
    const workspace = mkdtempSync(join(tmpdir(), "agentshield-action-supply-chain-"));
    const outputFile = join(workspace, "github-output.txt");
    const summaryFile = join(workspace, "github-summary.md");
    const claudeDir = join(workspace, ".claude");
    const settingsPath = join(claudeDir, "settings.json");

    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(settingsPath, JSON.stringify({
      mcpServers: {
        router: {
          command: "npx",
          args: ["@tanstack/react-router@1.169.8"],
        },
      },
    }, null, 2));

    const result = spawnSync(process.execPath, [ACTION_PATH], {
      cwd: workspace,
      env: {
        ...process.env,
        GITHUB_WORKSPACE: workspace,
        GITHUB_OUTPUT: outputFile,
        GITHUB_STEP_SUMMARY: summaryFile,
        INPUT_PATH: ".",
      },
      encoding: "utf-8",
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("Supply Chain Verification Report");
    expect(result.stdout).toContain("@tanstack/react-router@1.169.8");
    expect(result.stdout).toContain("AgentShield supply-chain gate FAILED");

    const outputs = readFileSync(outputFile, "utf-8");
    expect(outputs).toContain("supply-chain-status=risky");
    expect(outputs).toContain("supply-chain-risky-packages=1");
    expect(outputs).toContain("supply-chain-critical-count=1");

    const summary = readFileSync(summaryFile, "utf-8");
    expect(summary).toContain("## AgentShield Supply Chain");
    expect(summary).toContain("@tanstack/react-router@1.169.8");
  });

  it("collects supply-chain evidence without failing when findings gate is disabled", () => {
    const workspace = mkdtempSync(join(tmpdir(), "agentshield-action-supply-chain-collect-"));
    const outputFile = join(workspace, "github-output.txt");
    const summaryFile = join(workspace, "github-summary.md");
    const claudeDir = join(workspace, ".claude");
    const settingsPath = join(claudeDir, "settings.json");

    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(settingsPath, JSON.stringify({
      mcpServers: {
        router: {
          command: "npx",
          args: ["@tanstack/react-router@1.169.8"],
        },
      },
    }, null, 2));

    const result = spawnSync(process.execPath, [ACTION_PATH], {
      cwd: workspace,
      env: {
        ...process.env,
        GITHUB_WORKSPACE: workspace,
        GITHUB_OUTPUT: outputFile,
        GITHUB_STEP_SUMMARY: summaryFile,
        INPUT_PATH: ".",
        "INPUT_FAIL-ON-FINDINGS": "false",
      },
      encoding: "utf-8",
    });

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("Supply Chain Verification Report");
    expect(result.stdout).not.toContain("AgentShield supply-chain gate FAILED");

    const outputs = readFileSync(outputFile, "utf-8");
    expect(outputs).toContain("supply-chain-status=risky");
    expect(outputs).toContain("supply-chain-critical-count=1");
  });

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
