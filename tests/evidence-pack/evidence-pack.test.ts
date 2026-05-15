import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { verifyEvidencePack, writeEvidencePack } from "../../src/evidence-pack/index.js";
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
});
