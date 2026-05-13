import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  buildRemediationPlan,
  writeRemediationPlan,
} from "../../src/remediation/index.js";
import type { Finding, SecurityReport } from "../../src/types.js";

const CLI_PATH = resolve(import.meta.dirname, "../../dist/index.js");

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "secrets-hardcoded",
    severity: "critical",
    category: "secrets",
    title: "Hardcoded secret",
    description: "A secret is committed in config.",
    file: ".claude/settings.json",
    evidence: "sk-test-sensitive-value",
    fix: {
      description: "Replace the literal value with an environment variable reference.",
      before: "sk-test-sensitive-value",
      after: "${OPENAI_API_KEY}",
      auto: true,
    },
    ...overrides,
  };
}

function makeReport(findings: ReadonlyArray<Finding>): SecurityReport {
  return {
    timestamp: "2026-05-13T09:10:00.000Z",
    targetPath: "/repo",
    findings,
    score: {
      grade: "C",
      numericScore: 72,
      breakdown: { secrets: 70, permissions: 80, hooks: 90, mcp: 100, agents: 100 },
    },
    summary: {
      totalFindings: findings.length,
      critical: findings.filter((finding) => finding.severity === "critical").length,
      high: findings.filter((finding) => finding.severity === "high").length,
      medium: findings.filter((finding) => finding.severity === "medium").length,
      low: findings.filter((finding) => finding.severity === "low").length,
      info: findings.filter((finding) => finding.severity === "info").length,
      filesScanned: 1,
      autoFixable: findings.filter((finding) => finding.fix?.auto).length,
    },
  };
}

describe("buildRemediationPlan", () => {
  it("builds a deterministic plan with stable fingerprints and safe fix metadata", () => {
    const manual = makeFinding({
      id: "permissions-no-deny-list",
      severity: "high",
      category: "permissions",
      title: "No deny list",
      evidence: "deny: []",
      fix: {
        description: "Add explicit deny rules for destructive shell commands.",
        before: "",
        after: "",
        auto: false,
      },
    });
    const report = makeReport([manual, makeFinding()]);

    const plan = buildRemediationPlan(report, {
      generatedAt: "2026-05-13T09:11:00.000Z",
    });

    expect(plan.schemaVersion).toBe(1);
    expect(plan.generatedAt).toBe("2026-05-13T09:11:00.000Z");
    expect(plan.summary).toMatchObject({
      totalFindings: 2,
      autoFixable: 1,
      manualReview: 1,
    });
    expect(plan.summary.bySeverity).toMatchObject({ critical: 1, high: 1 });
    expect(plan.findings.map((finding) => finding.id)).toEqual([
      "secrets-hardcoded",
      "permissions-no-deny-list",
    ]);
    expect(plan.workflow.phases.map((phase) => phase.id)).toEqual([
      "auto-fix",
      "manual-review",
      "verify",
    ]);
    expect(plan.workflow.phases[0]).toMatchObject({
      id: "auto-fix",
      command: "agentshield scan --fix",
      findingCount: 1,
      blocking: false,
    });
    expect(plan.workflow.phases[0].findingFingerprints).toEqual([
      expect.stringMatching(
        /^secrets-hardcoded::\.claude\/settings\.json::sha256:[a-f0-9]{16}$/
      ),
    ]);
    expect(plan.workflow.phases[1]).toMatchObject({
      id: "manual-review",
      command: "Review finding-specific remediation notes in source control.",
      findingCount: 1,
      blocking: true,
    });
    expect(plan.workflow.phases[2]).toMatchObject({
      id: "verify",
      command: "agentshield scan --gate",
      findingCount: 2,
      blocking: true,
    });
    expect(plan.findings[0]).toMatchObject({
      fingerprint: expect.stringMatching(
        /^secrets-hardcoded::\.claude\/settings\.json::sha256:[a-f0-9]{16}$/
      ),
      action: "auto-fix",
      recommendedCommand: "agentshield scan --fix",
      hasEvidence: true,
      fix: {
        description: "Replace the literal value with an environment variable reference.",
        auto: true,
      },
    });
    expect(plan.findings[0].fix).not.toHaveProperty("before");
    expect(JSON.stringify(plan)).not.toContain("sk-test-sensitive-value");
    expect(JSON.stringify(plan)).not.toContain("${OPENAI_API_KEY}");
  });

  it("omits empty workflow phases when only manual remediation is available", () => {
    const report = makeReport([
      makeFinding({
        severity: "high",
        fix: {
          description: "Add explicit deny rules for destructive shell commands.",
          before: "",
          after: "",
          auto: false,
        },
      }),
    ]);

    const plan = buildRemediationPlan(report, {
      generatedAt: "2026-05-13T09:13:00.000Z",
    });

    expect(plan.workflow.phases.map((phase) => phase.id)).toEqual([
      "manual-review",
      "verify",
    ]);
    expect(plan.workflow.phases[0]).toMatchObject({
      findingCount: 1,
      blocking: true,
    });
    expect(plan.workflow.phases[1]).toMatchObject({
      findingCount: 1,
      blocking: true,
    });
  });
});

describe("writeRemediationPlan", () => {
  it("writes parent directories and serializes the remediation plan", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentshield-remediation-plan-"));
    mkdirSync(join(dir, "nested"));
    const outputPath = join(dir, "nested", "plan.json");

    const result = writeRemediationPlan({
      outputPath,
      report: makeReport([makeFinding({ evidence: "secret-evidence" })]),
      generatedAt: "2026-05-13T09:12:00.000Z",
    });

    expect(result.outputPath).toBe(outputPath);
    expect(existsSync(outputPath)).toBe(true);

    const parsed = JSON.parse(readFileSync(outputPath, "utf-8"));
    expect(parsed.generatedAt).toBe("2026-05-13T09:12:00.000Z");
    expect(parsed.findings[0].fingerprint).toMatch(
      /^secrets-hardcoded::\.claude\/settings\.json::sha256:[a-f0-9]{16}$/
    );
    expect(JSON.stringify(parsed)).not.toContain("secret-evidence");
  });
});

describe("remediation plan CLI", () => {
  it("writes a remediation plan without changing the scanned project", () => {
    const targetDir = mkdtempSync(join(tmpdir(), "agentshield-remediation-target-"));
    const outputPath = join(targetDir, "artifacts", "remediation-plan.json");

    const result = spawnSync(process.execPath, [
      CLI_PATH,
      "scan",
      "--path",
      targetDir,
      "--remediation-plan",
      outputPath,
    ], {
      encoding: "utf-8",
      env: {
        ...process.env,
        NODE_NO_WARNINGS: "1",
      },
    });

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("Remediation plan written to:");
    expect(existsSync(outputPath)).toBe(true);

    const parsed = JSON.parse(readFileSync(outputPath, "utf-8"));
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.summary.totalFindings).toBe(0);
  });
});
