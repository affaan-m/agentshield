import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  exportPolicyPacks,
  promotePolicyPack,
  type PolicyPackPromotionResult,
} from "../../src/policy/index.js";

const CLI_PATH = resolve(import.meta.dirname, "../../dist/index.js");

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf-8")) as T;
}

describe("policy pack promotion", () => {
  it("promotes one exported policy after verifying its manifest digest", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-policy-promote-"));
    exportPolicyPacks({
      outputDir,
      packs: ["enterprise"],
      owners: ["security@example.com"],
      namePrefix: "Acme",
    });

    const activePolicyPath = join(outputDir, "active-policy.json");
    const result = promotePolicyPack({
      manifestPath: join(outputDir, "manifest.json"),
      outputPath: activePolicyPath,
    });

    expect(result).toMatchObject<Partial<PolicyPackPromotionResult>>({
      pack: "enterprise",
      policyName: "Acme Enterprise Policy",
      outputPath: activePolicyPath,
      promoted: true,
      verified: true,
    });
    expect(result.sha256).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(existsSync(activePolicyPath)).toBe(true);

    const policy = readJson<Record<string, unknown>>(activePolicyPath);
    expect(policy.policy_pack).toBe("enterprise");
    expect(policy.owners).toEqual(["security@example.com"]);
  });

  it("dry-runs a promotion without writing the active policy file", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-policy-promote-dry-"));
    exportPolicyPacks({ outputDir, packs: ["ci-enforcement"] });

    const activePolicyPath = join(outputDir, "active-policy.json");
    const result = promotePolicyPack({
      manifestPath: join(outputDir, "manifest.json"),
      outputPath: activePolicyPath,
      dryRun: true,
    });

    expect(result.pack).toBe("ci-enforcement");
    expect(result.promoted).toBe(false);
    expect(result.verified).toBe(true);
    expect(existsSync(activePolicyPath)).toBe(false);
  });

  it("rejects a tampered policy file whose digest no longer matches the manifest", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-policy-promote-tamper-"));
    exportPolicyPacks({ outputDir, packs: ["team"] });

    const policyPath = join(outputDir, "team-policy.json");
    const policy = readJson<Record<string, unknown>>(policyPath);
    writeFileSync(policyPath, `${JSON.stringify({ ...policy, min_score: 1 }, null, 2)}\n`);

    expect(() => promotePolicyPack({
      manifestPath: join(outputDir, "manifest.json"),
      outputPath: join(outputDir, "active-policy.json"),
    })).toThrow(/digest mismatch/i);
  });

  it("requires an explicit pack when the manifest contains multiple policies", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-policy-promote-many-"));
    exportPolicyPacks({ outputDir });

    expect(() => promotePolicyPack({
      manifestPath: join(outputDir, "manifest.json"),
      outputPath: join(outputDir, "active-policy.json"),
    })).toThrow(/multiple policy packs/i);
  });

  it("exposes promotion through the CLI", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-policy-promote-cli-"));
    exportPolicyPacks({ outputDir, packs: ["ci-enforcement"] });
    const activePolicyPath = join(outputDir, "active-policy.json");

    const result = spawnSync(process.execPath, [
      CLI_PATH,
      "policy",
      "promote",
      "--manifest",
      join(outputDir, "manifest.json"),
      "--output",
      activePolicyPath,
      "--json",
    ], {
      encoding: "utf-8",
      env: {
        ...process.env,
        NODE_NO_WARNINGS: "1",
      },
    });

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");

    const promotion = JSON.parse(result.stdout) as PolicyPackPromotionResult;
    expect(promotion).toMatchObject({
      pack: "ci-enforcement",
      promoted: true,
      verified: true,
    });
    expect(existsSync(activePolicyPath)).toBe(true);
  });
});
