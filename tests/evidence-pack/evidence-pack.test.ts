import { describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeEvidencePack } from "../../src/evidence-pack/index.js";
import type { BaselineComparison } from "../../src/baseline/index.js";
import type { PolicyEvaluation } from "../../src/policy/index.js";
import type { SupplyChainReport } from "../../src/supply-chain/index.js";
import type { SecurityReport } from "../../src/types.js";

function makeReport(targetPath: string): SecurityReport {
  return {
    timestamp: "2026-05-13T05:00:00.000Z",
    targetPath,
    findings: [
      {
        id: "secrets-hardcoded-api-key",
        severity: "critical",
        category: "secrets",
        title: "Hardcoded API key",
        description: "A token-shaped value was found. Contact security-owner@example.com.",
        file: join(targetPath, ".claude", "settings.json"),
        line: 12,
        evidence: "sk-1234567890abcdef",
      },
    ],
    score: {
      grade: "C",
      numericScore: 72,
      breakdown: {
        secrets: 20,
        permissions: 90,
        hooks: 90,
        mcp: 90,
        agents: 90,
      },
    },
    summary: {
      totalFindings: 1,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      filesScanned: 1,
      autoFixable: 0,
    },
  };
}

function makePolicyEvaluation(): PolicyEvaluation {
  return {
    policyName: "Enterprise Policy",
    policyPack: "enterprise",
    owners: ["security-owner@example.com"],
    passed: false,
    violations: [
      {
        rule: "max_severity",
        severity: "high",
        description: "A critical finding violates policy.",
        expected: "No findings above high",
        actual: "1 critical finding",
      },
    ],
    score: 72,
    minScore: 80,
  };
}

function makeBaselineComparison(targetPath: string): BaselineComparison {
  return {
    timestamp: "2026-05-13T05:00:00.000Z",
    baselineTimestamp: "2026-05-12T05:00:00.000Z",
    newFindings: makeReport(targetPath).findings,
    resolvedFindings: [],
    unchangedCount: 0,
    scoreDelta: -8,
    baselineScore: 80,
    currentScore: 72,
    isRegression: true,
    newCriticalCount: 1,
    newHighCount: 0,
  };
}

function makeSupplyChainReport(): SupplyChainReport {
  return {
    packages: [],
    totalPackages: 0,
    riskyPackages: 0,
    criticalCount: 0,
    highCount: 0,
    provenance: {
      npmPackages: 0,
      gitPackages: 0,
      pinnedPackages: 0,
      unpinnedPackages: 0,
      knownGoodPackages: 0,
      registryMetadataPackages: 0,
    },
  };
}

describe("writeEvidencePack", () => {
  it("writes a deterministic portable evidence bundle", () => {
    const targetPath = mkdtempSync(join(tmpdir(), "agentshield-target-"));
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-evidence-pack-"));

    const result = writeEvidencePack({
      outputDir,
      report: makeReport(targetPath),
      policyEvaluation: makePolicyEvaluation(),
      policyPath: join(targetPath, ".agentshield", "policy.json"),
      baselineComparison: makeBaselineComparison(targetPath),
      baselinePath: join(targetPath, ".agentshield", "baseline.json"),
      supplyChainReport: makeSupplyChainReport(),
      generatedAt: "2026-05-13T05:01:00.000Z",
    });

    expect(result.files).toEqual([
      "manifest.json",
      "README.md",
      "agentshield-report.json",
      "agentshield-report.html",
      "agentshield-results.sarif",
      "policy-evaluation.json",
      "baseline-comparison.json",
      "supply-chain.json",
      "remediation-plan.json",
    ]);
    expect(readdirSync(outputDir).sort()).toEqual([...result.files].sort());
    for (const file of result.files) {
      expect(existsSync(join(outputDir, file))).toBe(true);
    }

    const manifest = JSON.parse(readFileSync(join(outputDir, "manifest.json"), "utf-8"));
    expect(manifest).toMatchObject({
      schemaVersion: 1,
      generator: "agentshield",
      generatedAt: "2026-05-13T05:01:00.000Z",
      redacted: true,
      targetPath: "<target-path>",
    });
    expect(manifest.artifacts.map((artifact: { file: string }) => artifact.file)).toEqual(result.files);

    const readme = readFileSync(join(outputDir, "README.md"), "utf-8");
    expect(readme).toContain("# AgentShield Evidence Pack");
    expect(readme).toContain("Policy: failed");
    expect(readme).toContain("Baseline: regressed");
    expect(readme).toContain("Remediation plan");

    const remediationPlan = JSON.parse(readFileSync(join(outputDir, "remediation-plan.json"), "utf-8"));
    expect(remediationPlan.summary.totalFindings).toBe(1);
    expect(remediationPlan.findings[0].fingerprint).toMatch(
      /^secrets-hardcoded-api-key::<target-path>\/\.claude\/settings\.json::sha256:[a-f0-9]{16}$/
    );
    expect(JSON.stringify(remediationPlan)).not.toContain("sk-1234567890abcdef");
  });

  it("redacts local paths, emails, and token-shaped strings by default", () => {
    const targetPath = mkdtempSync(join(tmpdir(), "agentshield-sensitive-target-"));
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-evidence-pack-"));

    writeEvidencePack({
      outputDir,
      report: makeReport(targetPath),
      policyEvaluation: makePolicyEvaluation(),
      baselineComparison: makeBaselineComparison(targetPath),
      supplyChainReport: makeSupplyChainReport(),
    });

    const reportJson = readFileSync(join(outputDir, "agentshield-report.json"), "utf-8");
    const reportHtml = readFileSync(join(outputDir, "agentshield-report.html"), "utf-8");
    const policyJson = readFileSync(join(outputDir, "policy-evaluation.json"), "utf-8");
    const sarifJson = readFileSync(join(outputDir, "agentshield-results.sarif"), "utf-8");
    const remediationPlanJson = readFileSync(join(outputDir, "remediation-plan.json"), "utf-8");

    expect(reportJson).not.toContain(targetPath);
    expect(reportJson).not.toContain("sk-1234567890abcdef");
    expect(reportJson).not.toContain("security-owner@example.com");
    expect(reportJson).toContain("<target-path>");
    expect(reportJson).toContain("sk-<redacted>");
    expect(reportJson).toContain("<redacted-email>");
    expect(reportHtml).not.toContain(targetPath);
    expect(reportHtml).not.toContain("sk-1234567890abcdef");
    expect(reportHtml).not.toContain("security-owner@example.com");
    expect(reportHtml).toContain("&lt;target-path&gt;");
    expect(reportHtml).toContain("sk-&lt;redacted&gt;");
    expect(reportHtml).toContain("&lt;redacted-email&gt;");
    expect(policyJson).not.toContain("security-owner@example.com");
    expect(policyJson).toContain("<redacted-email>");
    expect(sarifJson).not.toContain(targetPath);
    expect(remediationPlanJson).not.toContain(targetPath);
    expect(remediationPlanJson).not.toContain("sk-1234567890abcdef");
  });

  it("redacts common enterprise credential families from evidence packs", () => {
    const targetPath = mkdtempSync(join(tmpdir(), "agentshield-enterprise-secrets-"));
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-evidence-pack-"));
    const report = makeReport(targetPath);
    const stripeToken = ["sk", "live", "1234567890abcdefghijklmnop"].join("_");
    const githubToken = ["github", "pat", "11AAVERYLONGTOKENVALUE", "abcdefghijklmnopqrstuvwxyz0123456789"].join("_");
    const npmToken = ["npm", "abcdefghijklmnopqrstuvwxyz1234567890"].join("_");
    const linearToken = ["lin", "api", "abcdefghijklmnopqrstuvwxyz123456"].join("_");
    const googleToken = ["AI", "zaSyA1234567890abcdefghijklmnopqr"].join("");
    const jwtToken = [
      ["eyJ", "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"].join(""),
      "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
      "signature123456789",
    ].join(".");
    report.findings = [
      {
        id: "secrets-enterprise-token",
        severity: "critical",
        category: "secrets",
        title: "Enterprise token exposure",
        description: [
          `Stripe ${stripeToken}`,
          `GitHub ${githubToken}`,
          `npm ${npmToken}`,
          `Linear ${linearToken}`,
          `Google ${googleToken}`,
          `JWT ${jwtToken}`,
        ].join(" "),
        file: join(targetPath, ".claude", "settings.json"),
        evidence: [
          stripeToken,
          githubToken,
          npmToken,
          linearToken,
          googleToken,
          jwtToken,
        ].join("\n"),
      },
    ];

    writeEvidencePack({
      outputDir,
      report,
      supplyChainReport: makeSupplyChainReport(),
    });

    const reportJson = readFileSync(join(outputDir, "agentshield-report.json"), "utf-8");
    const sarifJson = readFileSync(join(outputDir, "agentshield-results.sarif"), "utf-8");
    const remediationPlanJson = readFileSync(join(outputDir, "remediation-plan.json"), "utf-8");

    for (const artifact of [reportJson, sarifJson, remediationPlanJson]) {
      expect(artifact).not.toContain(stripeToken);
      expect(artifact).not.toContain(githubToken);
      expect(artifact).not.toContain(npmToken);
      expect(artifact).not.toContain(linearToken);
      expect(artifact).not.toContain(googleToken);
      expect(artifact).not.toContain(jwtToken.split(".")[0]);
    }
    expect(reportJson).toContain("<redacted-token>");
    expect(sarifJson).toContain("<redacted-token>");
  });

  it("writes explicit not-run markers for absent optional evidence", () => {
    const targetPath = mkdtempSync(join(tmpdir(), "agentshield-no-optional-target-"));
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-evidence-pack-"));

    writeEvidencePack({
      outputDir,
      report: makeReport(targetPath),
      supplyChainReport: makeSupplyChainReport(),
      redact: false,
    });

    const policy = JSON.parse(readFileSync(join(outputDir, "policy-evaluation.json"), "utf-8"));
    const baseline = JSON.parse(readFileSync(join(outputDir, "baseline-comparison.json"), "utf-8"));
    const report = JSON.parse(readFileSync(join(outputDir, "agentshield-report.json"), "utf-8"));

    expect(policy).toMatchObject({ status: "not-run" });
    expect(baseline).toMatchObject({ status: "not-run" });
    expect(report.targetPath).toBe(targetPath);
  });
});
