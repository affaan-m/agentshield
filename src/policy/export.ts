import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { generatePolicyPack, listPolicyPacks } from "./presets.js";
import type { PolicyPack } from "./types.js";

export const POLICY_EXPORT_SCHEMA_VERSION = "agentshield.policy-export.v1";

export interface ExportPolicyPacksOptions {
  readonly outputDir: string;
  readonly packs?: ReadonlyArray<PolicyPack>;
  readonly owners?: ReadonlyArray<string>;
  readonly namePrefix?: string;
}

export interface PolicyPackExportEntry {
  readonly id: PolicyPack;
  readonly label: string;
  readonly description: string;
  readonly file: string;
  readonly sha256: string;
}

export interface PolicyPackExportManifest {
  readonly schema_version: typeof POLICY_EXPORT_SCHEMA_VERSION;
  readonly packs: ReadonlyArray<PolicyPackExportEntry>;
}

export function exportPolicyPacks(options: ExportPolicyPacksOptions): PolicyPackExportManifest {
  mkdirSync(options.outputDir, { recursive: true });

  const summaries = listPolicyPacks();
  const selectedPacks = options.packs && options.packs.length > 0
    ? options.packs
    : summaries.map((summary) => summary.id);
  const entries: PolicyPackExportEntry[] = [];

  for (const packId of selectedPacks) {
    const summary = summaries.find((item) => item.id === packId);
    if (!summary) {
      throw new Error(`Unknown policy pack: ${packId}`);
    }

    const policy = generatePolicyPack(packId, {
      owners: options.owners,
      name: options.namePrefix ? `${options.namePrefix} ${titleCase(summary.label)} Policy` : undefined,
    });
    const policyJson = stableJson(policy);
    const file = `${packId}-policy.json`;

    writeFileSync(join(options.outputDir, file), policyJson);
    entries.push({
      id: summary.id,
      label: summary.label,
      description: summary.description,
      file,
      sha256: digest(policyJson),
    });
  }

  const manifest: PolicyPackExportManifest = {
    schema_version: POLICY_EXPORT_SCHEMA_VERSION,
    packs: entries,
  };
  writeFileSync(join(options.outputDir, "manifest.json"), stableJson(manifest));
  return manifest;
}

function stableJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function titleCase(label: string): string {
  return label
    .split(" ")
    .map((word) => word.toUpperCase() === word
      ? word
      : `${word.slice(0, 1).toUpperCase()}${word.slice(1)}`)
    .join(" ");
}
