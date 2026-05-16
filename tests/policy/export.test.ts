import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  exportPolicyPacks,
  type PolicyPackExportManifest,
} from "../../src/policy/index.js";

const CLI_PATH = resolve(import.meta.dirname, "../../dist/index.js");

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf-8")) as T;
}

describe("policy pack export", () => {
  it("writes every policy pack with a manifest and stable digests", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-policy-export-"));
    const manifest = exportPolicyPacks({
      outputDir,
      owners: ["security@example.com"],
    });

    expect(manifest.schema_version).toBe("agentshield.policy-export.v1");
    expect(manifest.packs.length).toBe(6);

    for (const entry of manifest.packs) {
      const policyPath = join(outputDir, entry.file);
      expect(existsSync(policyPath)).toBe(true);
      expect(entry.sha256).toMatch(/^sha256:[a-f0-9]{64}$/);

      const policy = readJson<Record<string, unknown>>(policyPath);
      expect(policy.policy_pack).toBe(entry.id);
      expect(policy.owners).toEqual(["security@example.com"]);
    }

    const writtenManifest = readJson<PolicyPackExportManifest>(
      join(outputDir, "manifest.json")
    );
    expect(writtenManifest).toEqual(manifest);
  });

  it("can export one selected policy pack for a branch-protection workflow", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-policy-export-one-"));
    const manifest = exportPolicyPacks({
      outputDir,
      packs: ["ci-enforcement"],
      namePrefix: "Acme",
    });

    expect(manifest.packs).toEqual([
      expect.objectContaining({
        id: "ci-enforcement",
        file: "ci-enforcement-policy.json",
      }),
    ]);

    const policy = readJson<Record<string, unknown>>(
      join(outputDir, "ci-enforcement-policy.json")
    );
    expect(policy.name).toBe("Acme CI Enforcement Policy");
    expect(policy.policy_pack).toBe("ci-enforcement");
  });

  it("exposes policy pack export through the CLI", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "agentshield-policy-export-cli-"));
    const result = spawnSync(process.execPath, [
      CLI_PATH,
      "policy",
      "export",
      "--pack",
      "ci-enforcement",
      "--owner",
      "security@example.com",
      "--name-prefix",
      "Acme",
      "--output-dir",
      outputDir,
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

    const manifest = JSON.parse(result.stdout) as PolicyPackExportManifest;
    expect(manifest.packs).toHaveLength(1);
    expect(manifest.packs[0]).toMatchObject({
      id: "ci-enforcement",
      file: "ci-enforcement-policy.json",
    });
    expect(existsSync(join(outputDir, "manifest.json"))).toBe(true);
    expect(existsSync(join(outputDir, "ci-enforcement-policy.json"))).toBe(true);
  });
});
