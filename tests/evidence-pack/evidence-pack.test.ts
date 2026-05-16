import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  inspectEvidencePack,
  inspectEvidencePackFleet,
  verifyEvidencePack,
  writeEvidencePack,
} from "../../src/evidence-pack/index.js";
import type { BaselineComparison } from "../../src/baseline/index.js";
import type { PolicyEvaluation } from "../../src/policy/index.js";
import type { SupplyChainReport } from "../../src/supply-chain/index.js";
import type { SecurityReport } from "../../src/types.js";

const CLI_PATH = resolve(import.meta.dirname, "../../dist/index.js");

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

function makeGitHubEnvironment(targetPath: string): Record<string, string> {
  return {
    GITHUB_ACTIONS: "true",
    GITHUB_REPOSITORY: "affaan-m/agentshield",
    GITHUB_REPOSITORY_ID: "123456789",
    GITHUB_WORKFLOW: "AgentShield",
    GITHUB_WORKFLOW_REF: "affaan-m/agentshield/.github/workflows/agentshield.yml@refs/heads/main",
    GITHUB_JOB: "security",
    GITHUB_RUN_ID: "987654321",
    GITHUB_RUN_ATTEMPT: "2",
    GITHUB_RUN_NUMBER: "42",
    GITHUB_ACTOR: "security-owner",
    GITHUB_EVENT_NAME: "pull_request",
    GITHUB_REF: "refs/pull/12/merge",
    GITHUB_SHA: "0123456789abcdef0123456789abcdef01234567",
    GITHUB_HEAD_REF: "feature/evidence-pack",
    GITHUB_BASE_REF: "main",
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_TOKEN: "ghp_should_never_enter_evidence_pack",
    RUNNER_NAME: "GitHub Actions 4",
    RUNNER_OS: "macOS",
    RUNNER_ARCH: "ARM64",
    RUNNER_TEMP: join(targetPath, "runner-temp"),
    RUNNER_TOOL_CACHE: join(targetPath, "tool-cache"),
  };
}

function makeCleanReport(targetPath: string): SecurityReport {
  const report = makeReport(targetPath);
  return {
    ...report,
    findings: [],
    score: {
      ...report.score,
      grade: "A",
      numericScore: 100,
    },
    summary: {
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      filesScanned: 1,
      autoFixable: 0,
    },
  };
}

function makePassingPolicyEvaluation(): PolicyEvaluation {
  return {
    ...makePolicyEvaluation(),
    passed: true,
    violations: [],
    score: 100,
  };
}

function makePassingBaselineComparison(targetPath: string): BaselineComparison {
  return {
    ...makeBaselineComparison(targetPath),
    newFindings: [],
    scoreDelta: 0,
    currentScore: 100,
    isRegression: false,
    newCriticalCount: 0,
  };
}

function writeFleetEvidencePack(options: {
  readonly outputDir: string;
  readonly targetPath: string;
  readonly generatedAt: string;
  readonly repository: string;
  readonly report?: SecurityReport;
  readonly policyEvaluation?: PolicyEvaluation;
  readonly baselineComparison?: BaselineComparison;
  readonly supplyChainReport?: SupplyChainReport;
}): void {
  writeEvidencePack({
    outputDir: options.outputDir,
    report: options.report ?? makeReport(options.targetPath),
    policyEvaluation: options.policyEvaluation ?? makePolicyEvaluation(),
    baselineComparison: options.baselineComparison ?? makeBaselineComparison(options.targetPath),
    supplyChainReport: options.supplyChainReport ?? makeSupplyChainReport(),
    generatedAt: options.generatedAt,
    environment: {
      ...makeGitHubEnvironment(options.targetPath),
      GITHUB_REPOSITORY: options.repository,
    },
  });
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
      environment: makeGitHubEnvironment(targetPath),
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
      "ci-context.json",
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
    expect(manifest.bundleDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(manifest.artifacts).toEqual(
      expect.arrayContaining(
        result.files
          .filter((file) => file !== "manifest.json")
          .map((file) => expect.objectContaining({
            file,
            sha256: createHash("sha256")
              .update(readFileSync(join(outputDir, file), "utf-8"))
              .digest("hex"),
            bytes: Buffer.byteLength(readFileSync(join(outputDir, file), "utf-8"), "utf8"),
          }))
      )
    );
    expect(manifest.artifacts.find((artifact: { file: string }) => artifact.file === "manifest.json")).toMatchObject({
      file: "manifest.json",
      sha256: null,
      bytes: null,
    });

    const readme = readFileSync(join(outputDir, "README.md"), "utf-8");
    expect(readme).toContain("# AgentShield Evidence Pack");
    expect(readme).toContain("Policy: failed");
    expect(readme).toContain("Baseline: regressed");
    expect(readme).toContain("Remediation plan");
    expect(readme).toContain("Bundle digest:");
    expect(readme).toContain("CI context: github-actions");

    const remediationPlan = JSON.parse(readFileSync(join(outputDir, "remediation-plan.json"), "utf-8"));
    expect(remediationPlan.summary.totalFindings).toBe(1);
    expect(remediationPlan.findings[0].fingerprint).toMatch(
      /^secrets-hardcoded-api-key::<target-path>\/\.claude\/settings\.json::sha256:[a-f0-9]{16}$/
    );
    expect(JSON.stringify(remediationPlan)).not.toContain("sk-1234567890abcdef");

    const ciContextRaw = readFileSync(join(outputDir, "ci-context.json"), "utf-8");
    const ciContext = JSON.parse(ciContextRaw);
    expect(ciContext).toMatchObject({
      schemaVersion: 1,
      generatedAt: "2026-05-13T05:01:00.000Z",
      provider: "github-actions",
      source: "process-environment",
      github: {
        repository: "affaan-m/agentshield",
        workflow: "AgentShield",
        runId: "987654321",
        runAttempt: "2",
        sha: "0123456789abcdef0123456789abcdef01234567",
      },
      runtime: {
        os: "macOS",
        archLabel: "ARM64",
      },
    });
    expect(ciContextRaw).not.toContain("GITHUB_TOKEN");
    expect(ciContextRaw).not.toContain("ghp_should_never_enter_evidence_pack");
    expect(ciContextRaw).not.toContain(targetPath);
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

  it("verifies a complete evidence pack", () => {
    const targetPath = mkdtempSync(join(tmpdir(), "agentshield-verify-target-"));
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-evidence-pack-"));

    writeEvidencePack({
      outputDir,
      report: makeReport(targetPath),
      policyEvaluation: makePolicyEvaluation(),
      baselineComparison: makeBaselineComparison(targetPath),
      supplyChainReport: makeSupplyChainReport(),
      generatedAt: "2026-05-13T05:02:00.000Z",
    });

    const result = verifyEvidencePack(outputDir);

    expect(result.ok).toBe(true);
    expect(result.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          file: "agentshield-report.json",
          ok: true,
        }),
        expect.objectContaining({
          file: "remediation-plan.json",
          ok: true,
        }),
      ])
    );
    expect(result.bundleDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(result.errors).toEqual([]);
  });

  it("inspects evidence packs as a downstream consumer summary", () => {
    const targetPath = mkdtempSync(join(tmpdir(), "agentshield-inspect-target-"));
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-evidence-pack-"));

    writeEvidencePack({
      outputDir,
      report: makeReport(targetPath),
      policyEvaluation: makePolicyEvaluation(),
      baselineComparison: makeBaselineComparison(targetPath),
      supplyChainReport: makeSupplyChainReport(),
      generatedAt: "2026-05-13T05:02:30.000Z",
      environment: makeGitHubEnvironment(targetPath),
    });

    const result = inspectEvidencePack(outputDir);

    expect(result.ok).toBe(true);
    expect(result.generatedAt).toBe("2026-05-13T05:02:30.000Z");
    expect(result.targetPath).toBe("<target-path>");
    expect(result.artifactCount).toBe(10);
    expect(result.verifiedArtifactCount).toBe(10);
    expect(result.report).toMatchObject({
      score: { grade: "C", numericScore: 72 },
      findings: { total: 1, critical: 1 },
      runtimeConfidence: { "active-runtime": 1 },
    });
    expect(result.policy).toMatchObject({
      status: "failed",
      policyName: "Enterprise Policy",
      violations: 1,
    });
    expect(result.baseline).toMatchObject({
      status: "regressed",
      newFindings: 1,
      resolvedFindings: 0,
      scoreDelta: -8,
    });
    expect(result.supplyChain).toMatchObject({
      totalPackages: 0,
      riskyPackages: 0,
    });
    expect(result.ciContext).toMatchObject({
      provider: "github-actions",
      repository: "affaan-m/agentshield",
      runId: "987654321",
    });
    expect(result.remediation).toMatchObject({
      totalFindings: 1,
      autoFixable: 0,
      manualReview: 1,
    });
  });

  it("reports malformed artifact shapes as inspection errors instead of throwing", () => {
    const targetPath = mkdtempSync(join(tmpdir(), "agentshield-malformed-inspect-target-"));
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-evidence-pack-"));

    writeEvidencePack({
      outputDir,
      report: makeReport(targetPath),
      supplyChainReport: makeSupplyChainReport(),
      generatedAt: "2026-05-13T05:02:45.000Z",
    });
    writeFileSync(join(outputDir, "agentshield-report.json"), "{}\n");

    const result = inspectEvidencePack(outputDir);

    expect(result.ok).toBe(false);
    expect(result.report).toBeNull();
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.stringContaining("agentshield-report.json digest mismatch"),
        expect.stringContaining("agentshield-report.json summary failed"),
      ])
    );
  });

  it("detects tampered evidence-pack artifacts", () => {
    const targetPath = mkdtempSync(join(tmpdir(), "agentshield-tamper-target-"));
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-evidence-pack-"));

    writeEvidencePack({
      outputDir,
      report: makeReport(targetPath),
      supplyChainReport: makeSupplyChainReport(),
      generatedAt: "2026-05-13T05:03:00.000Z",
    });
    writeFileSync(join(outputDir, "remediation-plan.json"), "{}\n");

    const result = verifyEvidencePack(outputDir);

    expect(result.ok).toBe(false);
    expect(result.artifacts.find((artifact) => artifact.file === "remediation-plan.json")).toMatchObject({
      file: "remediation-plan.json",
      ok: false,
      actualBytes: 3,
    });
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.stringContaining("remediation-plan.json"),
        expect.stringContaining("bundle digest"),
      ])
    );
  });

  it("exposes evidence-pack verification through the CLI", () => {
    const targetPath = mkdtempSync(join(tmpdir(), "agentshield-cli-verify-target-"));
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-evidence-pack-"));

    writeEvidencePack({
      outputDir,
      report: makeReport(targetPath),
      supplyChainReport: makeSupplyChainReport(),
      generatedAt: "2026-05-13T05:04:00.000Z",
    });

    const valid = spawnSync(process.execPath, [
      CLI_PATH,
      "evidence-pack",
      "verify",
      outputDir,
    ], {
      encoding: "utf-8",
      env: {
        ...process.env,
        NODE_NO_WARNINGS: "1",
      },
    });

    expect(valid.status).toBe(0);
    expect(valid.stdout).toContain("Status:    passed");

    writeFileSync(join(outputDir, "agentshield-report.json"), "{}\n");
    const invalid = spawnSync(process.execPath, [
      CLI_PATH,
      "evidence-pack",
      "verify",
      outputDir,
      "--json",
    ], {
      encoding: "utf-8",
      env: {
        ...process.env,
        NODE_NO_WARNINGS: "1",
      },
    });

    expect(invalid.status).toBe(6);
    expect(JSON.parse(invalid.stdout)).toMatchObject({
      ok: false,
      errors: expect.arrayContaining([expect.stringContaining("agentshield-report.json")]),
    });
  });

  it("exposes evidence-pack inspection through the CLI", () => {
    const targetPath = mkdtempSync(join(tmpdir(), "agentshield-cli-inspect-target-"));
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-evidence-pack-"));

    writeEvidencePack({
      outputDir,
      report: makeReport(targetPath),
      policyEvaluation: makePolicyEvaluation(),
      baselineComparison: makeBaselineComparison(targetPath),
      supplyChainReport: makeSupplyChainReport(),
      generatedAt: "2026-05-13T05:05:00.000Z",
      environment: makeGitHubEnvironment(targetPath),
    });

    const text = spawnSync(process.execPath, [
      CLI_PATH,
      "evidence-pack",
      "inspect",
      outputDir,
    ], {
      encoding: "utf-8",
      env: {
        ...process.env,
        NODE_NO_WARNINGS: "1",
      },
    });

    expect(text.status).toBe(0);
    expect(text.stdout).toContain("AgentShield Evidence Pack Inspection");
    expect(text.stdout).toContain("Score:       72/100 (C); 1 findings");
    expect(text.stdout).toContain("Policy:      failed");
    expect(text.stdout).toContain("Baseline:    regressed");

    const json = spawnSync(process.execPath, [
      CLI_PATH,
      "evidence-pack",
      "inspect",
      outputDir,
      "--json",
    ], {
      encoding: "utf-8",
      env: {
        ...process.env,
        NODE_NO_WARNINGS: "1",
      },
    });

    expect(json.status).toBe(0);
    expect(JSON.parse(json.stdout)).toMatchObject({
      ok: true,
      report: {
        score: { grade: "C", numericScore: 72 },
      },
      policy: { status: "failed" },
      baseline: { status: "regressed" },
      ciContext: { provider: "github-actions" },
    });

    writeFileSync(join(outputDir, "agentshield-report.json"), "{}\n");
    const invalidJson = spawnSync(process.execPath, [
      CLI_PATH,
      "evidence-pack",
      "inspect",
      outputDir,
      "--json",
    ], {
      encoding: "utf-8",
      env: {
        ...process.env,
        NODE_NO_WARNINGS: "1",
      },
    });

    expect(invalidJson.status).toBe(6);
    expect(JSON.parse(invalidJson.stdout)).toMatchObject({
      ok: false,
      errors: expect.arrayContaining([expect.stringContaining("agentshield-report.json")]),
    });
  });

  it("aggregates multiple evidence packs into a fleet routing summary", () => {
    const cleanTargetPath = mkdtempSync(join(tmpdir(), "agentshield-fleet-clean-target-"));
    const riskyTargetPath = mkdtempSync(join(tmpdir(), "agentshield-fleet-risky-target-"));
    const cleanOutputDir = mkdtempSync(join(tmpdir(), "agentshield-fleet-clean-pack-"));
    const riskyOutputDir = mkdtempSync(join(tmpdir(), "agentshield-fleet-risky-pack-"));

    writeFleetEvidencePack({
      outputDir: cleanOutputDir,
      targetPath: cleanTargetPath,
      report: makeCleanReport(cleanTargetPath),
      policyEvaluation: makePassingPolicyEvaluation(),
      baselineComparison: makePassingBaselineComparison(cleanTargetPath),
      generatedAt: "2026-05-13T05:10:00.000Z",
      repository: "affaan-m/clean-repo",
    });
    writeFleetEvidencePack({
      outputDir: riskyOutputDir,
      targetPath: riskyTargetPath,
      supplyChainReport: {
        ...makeSupplyChainReport(),
        totalPackages: 3,
        riskyPackages: 1,
        criticalCount: 1,
      },
      generatedAt: "2026-05-13T05:11:00.000Z",
      repository: "affaan-m/risky-repo",
    });

    const fleet = inspectEvidencePackFleet([cleanOutputDir, riskyOutputDir]);

    expect(fleet.ok).toBe(true);
    expect(fleet.requiresAttention).toBe(true);
    expect(fleet.summary).toMatchObject({
      totalPacks: 2,
      verifiedPacks: 2,
      invalidPacks: 0,
      totalFindings: 1,
      critical: 1,
      high: 0,
      policyFailures: 1,
      baselineRegressions: 1,
      riskyPackages: 1,
      autoFixable: 0,
      manualReview: 1,
    });
    expect(fleet.entries).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          outputDir: cleanOutputDir,
          repository: "affaan-m/clean-repo",
          ok: true,
          route: "ready",
        }),
        expect.objectContaining({
          outputDir: riskyOutputDir,
          repository: "affaan-m/risky-repo",
          ok: true,
          route: "security-blocker",
        }),
      ])
    );
    expect(fleet.routes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          route: "security-blocker",
          repository: "affaan-m/risky-repo",
          reason: "1 critical findings",
        }),
        expect.objectContaining({
          route: "ready",
          repository: "affaan-m/clean-repo",
        }),
      ])
    );
    expect(fleet.reviewItems).toEqual([
      expect.objectContaining({
        route: "security-blocker",
        severity: "high",
        repository: "affaan-m/risky-repo",
        outputDir: riskyOutputDir,
        targetPath: "<target-path>",
        evidencePaths: expect.arrayContaining([
          join(riskyOutputDir, "manifest.json"),
          join(riskyOutputDir, "agentshield-report.json"),
          join(riskyOutputDir, "supply-chain.json"),
        ]),
        recommendation: "Route to security owner before promotion.",
      }),
    ]);
  });

  it("routes tampered fleet entries as invalid without hiding pack errors", () => {
    const targetPath = mkdtempSync(join(tmpdir(), "agentshield-fleet-invalid-target-"));
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-fleet-invalid-pack-"));

    writeFleetEvidencePack({
      outputDir,
      targetPath,
      generatedAt: "2026-05-13T05:11:30.000Z",
      repository: "affaan-m/agentshield",
    });
    writeFileSync(join(outputDir, "agentshield-report.json"), "{}\n");

    const fleet = inspectEvidencePackFleet([outputDir]);

    expect(fleet.ok).toBe(false);
    expect(fleet.requiresAttention).toBe(true);
    expect(fleet.summary).toMatchObject({
      totalPacks: 1,
      verifiedPacks: 0,
      invalidPacks: 1,
    });
    expect(fleet.entries[0]).toMatchObject({
      outputDir,
      ok: false,
      route: "invalid",
    });
    expect(fleet.errors).toEqual(expect.arrayContaining([expect.stringContaining("agentshield-report.json")]));
  });

  it("exposes evidence-pack fleet inspection through the CLI", () => {
    const cleanTargetPath = mkdtempSync(join(tmpdir(), "agentshield-cli-fleet-clean-target-"));
    const riskyTargetPath = mkdtempSync(join(tmpdir(), "agentshield-cli-fleet-risky-target-"));
    const cleanOutputDir = mkdtempSync(join(tmpdir(), "agentshield-cli-fleet-clean-pack-"));
    const riskyOutputDir = mkdtempSync(join(tmpdir(), "agentshield-cli-fleet-risky-pack-"));

    writeFleetEvidencePack({
      outputDir: cleanOutputDir,
      targetPath: cleanTargetPath,
      report: makeCleanReport(cleanTargetPath),
      policyEvaluation: makePassingPolicyEvaluation(),
      baselineComparison: makePassingBaselineComparison(cleanTargetPath),
      generatedAt: "2026-05-13T05:12:00.000Z",
      repository: "affaan-m/clean-repo",
    });
    writeFleetEvidencePack({
      outputDir: riskyOutputDir,
      targetPath: riskyTargetPath,
      generatedAt: "2026-05-13T05:13:00.000Z",
      repository: "affaan-m/risky-repo",
    });

    const text = spawnSync(process.execPath, [
      CLI_PATH,
      "evidence-pack",
      "fleet",
      cleanOutputDir,
      riskyOutputDir,
    ], {
      encoding: "utf-8",
      env: {
        ...process.env,
        NODE_NO_WARNINGS: "1",
      },
    });

    expect(text.status).toBe(0);
    expect(text.stdout).toContain("AgentShield Evidence Pack Fleet");
    expect(text.stdout).toContain("Packs:       2 total, 2 verified, 0 invalid");
    expect(text.stdout).toContain("Findings:    critical 1, high 0, medium 0, low 0, info 0");
    expect(text.stdout).toContain("security-blocker affaan-m/risky-repo");
    expect(text.stdout).toContain("ready affaan-m/clean-repo");
    expect(text.stdout).toContain("Review items:");
    expect(text.stdout).toContain("high security-blocker affaan-m/risky-repo");

    const json = spawnSync(process.execPath, [
      CLI_PATH,
      "evidence-pack",
      "fleet",
      cleanOutputDir,
      riskyOutputDir,
      "--json",
    ], {
      encoding: "utf-8",
      env: {
        ...process.env,
        NODE_NO_WARNINGS: "1",
      },
    });

    expect(json.status).toBe(0);
    expect(JSON.parse(json.stdout)).toMatchObject({
      ok: true,
      requiresAttention: true,
      summary: {
        totalPacks: 2,
        verifiedPacks: 2,
        invalidPacks: 0,
        critical: 1,
        policyFailures: 1,
        baselineRegressions: 1,
      },
      reviewItems: [
        {
          route: "security-blocker",
          severity: "high",
          repository: "affaan-m/risky-repo",
          recommendation: "Route to security owner before promotion.",
        },
      ],
    });
  });
});
