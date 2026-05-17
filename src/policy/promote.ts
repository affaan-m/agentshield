import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import {
  dirname,
  isAbsolute,
  join,
} from "node:path";
import { POLICY_EXPORT_SCHEMA_VERSION } from "./export.js";
import {
  OrgPolicySchema,
  PolicyPackSchema,
} from "./types.js";
import type { PolicyPack } from "./types.js";

export interface PromotePolicyPackOptions {
  readonly manifestPath: string;
  readonly outputPath: string;
  readonly pack?: PolicyPack;
  readonly dryRun?: boolean;
}

export interface PolicyPackPromotionResult {
  readonly manifestPath: string;
  readonly sourceFile: string;
  readonly outputPath: string;
  readonly pack: PolicyPack;
  readonly policyName: string;
  readonly owners: ReadonlyArray<string>;
  readonly sha256: string;
  readonly verified: true;
  readonly promoted: boolean;
  readonly dryRun: boolean;
}

interface ExportManifestEntry {
  readonly id: PolicyPack;
  readonly file: string;
  readonly sha256: string;
}

interface ExportManifest {
  readonly schema_version: typeof POLICY_EXPORT_SCHEMA_VERSION;
  readonly packs: ReadonlyArray<ExportManifestEntry>;
}

export function promotePolicyPack(options: PromotePolicyPackOptions): PolicyPackPromotionResult {
  const manifest = readExportManifest(options.manifestPath);
  const entry = selectPolicyPack(manifest.packs, options.pack);
  const sourceFile = isAbsolute(entry.file)
    ? entry.file
    : join(dirname(options.manifestPath), entry.file);

  if (!existsSync(sourceFile)) {
    throw new Error(`Policy file not found: ${sourceFile}`);
  }

  const policyJson = readFileSync(sourceFile, "utf-8");
  const actualDigest = digest(policyJson);
  if (actualDigest !== entry.sha256) {
    throw new Error(
      `Policy digest mismatch for ${entry.id}: expected ${entry.sha256}, got ${actualDigest}`
    );
  }

  const parsed = JSON.parse(policyJson);
  const policy = OrgPolicySchema.parse(parsed);
  if (policy.policy_pack !== entry.id) {
    throw new Error(
      `Policy pack mismatch: manifest entry is ${entry.id}, policy file declares ${policy.policy_pack}`
    );
  }

  if (!options.dryRun) {
    mkdirSync(dirname(options.outputPath), { recursive: true });
    writeFileSync(options.outputPath, policyJson);
  }

  return {
    manifestPath: options.manifestPath,
    sourceFile,
    outputPath: options.outputPath,
    pack: entry.id,
    policyName: policy.name ?? "Organization Policy",
    owners: policy.owners ?? [],
    sha256: entry.sha256,
    verified: true,
    promoted: !options.dryRun,
    dryRun: Boolean(options.dryRun),
  };
}

function readExportManifest(manifestPath: string): ExportManifest {
  if (!existsSync(manifestPath)) {
    throw new Error(`Policy export manifest not found: ${manifestPath}`);
  }

  const raw = JSON.parse(readFileSync(manifestPath, "utf-8")) as {
    readonly schema_version?: unknown;
    readonly packs?: unknown;
  };

  if (raw.schema_version !== POLICY_EXPORT_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported policy export manifest schema: ${String(raw.schema_version)}`
    );
  }

  if (!Array.isArray(raw.packs)) {
    throw new Error("Policy export manifest is missing a packs array");
  }

  return {
    schema_version: POLICY_EXPORT_SCHEMA_VERSION,
    packs: raw.packs.map(readManifestEntry),
  };
}

function readManifestEntry(entry: unknown): ExportManifestEntry {
  if (!entry || typeof entry !== "object") {
    throw new Error("Invalid policy export manifest entry");
  }

  const candidate = entry as {
    readonly id?: unknown;
    readonly file?: unknown;
    readonly sha256?: unknown;
  };
  const packResult = PolicyPackSchema.safeParse(candidate.id);
  if (!packResult.success) {
    throw new Error(`Invalid policy pack id in manifest: ${String(candidate.id)}`);
  }
  if (typeof candidate.file !== "string" || candidate.file.length === 0) {
    throw new Error(`Invalid policy file for manifest pack: ${packResult.data}`);
  }
  if (typeof candidate.sha256 !== "string" || !/^sha256:[a-f0-9]{64}$/.test(candidate.sha256)) {
    throw new Error(`Invalid policy digest for manifest pack: ${packResult.data}`);
  }

  return {
    id: packResult.data,
    file: candidate.file,
    sha256: candidate.sha256,
  };
}

function selectPolicyPack(
  entries: ReadonlyArray<ExportManifestEntry>,
  requestedPack: PolicyPack | undefined
): ExportManifestEntry {
  if (requestedPack) {
    const entry = entries.find((item) => item.id === requestedPack);
    if (!entry) {
      throw new Error(`Policy pack ${requestedPack} not found in export manifest`);
    }
    return entry;
  }

  if (entries.length === 1) {
    return entries[0]!;
  }

  throw new Error("Export manifest contains multiple policy packs; pass --pack to select one");
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
