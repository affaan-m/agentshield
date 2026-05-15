import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { homedir } from "node:os";
import type { BaselineComparison } from "../baseline/index.js";
import type { PolicyEvaluation } from "../policy/index.js";
import { buildRemediationPlan } from "../remediation/index.js";
import { renderHtmlReport } from "../reporter/html.js";
import { renderJsonReport } from "../reporter/json.js";
import { renderSarifReport } from "../reporter/sarif.js";
import type { SupplyChainReport } from "../supply-chain/index.js";
import type { SecurityReport } from "../types.js";

export interface EvidencePackOptions {
  readonly outputDir: string;
  readonly report: SecurityReport;
  readonly policyEvaluation?: PolicyEvaluation;
  readonly policyPath?: string;
  readonly baselineComparison?: BaselineComparison;
  readonly baselinePath?: string;
  readonly supplyChainReport: SupplyChainReport;
  readonly redact?: boolean;
  readonly generatedAt?: string;
  readonly ciContext?: EvidencePackCiContext;
  readonly environment?: EvidencePackEnvironment;
}

export interface EvidencePackResult {
  readonly outputDir: string;
  readonly files: ReadonlyArray<string>;
}

export interface EvidencePackVerificationArtifact {
  readonly file: string;
  readonly ok: boolean;
  readonly expectedSha256: string | null;
  readonly actualSha256: string | null;
  readonly expectedBytes: number | null;
  readonly actualBytes: number | null;
}

export interface EvidencePackVerificationResult {
  readonly ok: boolean;
  readonly outputDir: string;
  readonly bundleDigest: string | null;
  readonly expectedBundleDigest: string | null;
  readonly artifacts: ReadonlyArray<EvidencePackVerificationArtifact>;
  readonly errors: ReadonlyArray<string>;
}

export interface EvidencePackCiContext {
  readonly schemaVersion: 1;
  readonly generatedAt: string;
  readonly provider: "github-actions" | "local";
  readonly source: "provided" | "process-environment";
  readonly github?: EvidencePackGitHubContext;
  readonly runtime: EvidencePackRuntimeContext;
}

export interface EvidencePackGitHubContext {
  readonly repository?: string;
  readonly repositoryId?: string;
  readonly workflow?: string;
  readonly workflowRef?: string;
  readonly job?: string;
  readonly runId?: string;
  readonly runAttempt?: string;
  readonly runNumber?: string;
  readonly actor?: string;
  readonly eventName?: string;
  readonly ref?: string;
  readonly sha?: string;
  readonly headRef?: string;
  readonly baseRef?: string;
  readonly serverUrl?: string;
}

export interface EvidencePackRuntimeContext {
  readonly nodeVersion: string;
  readonly platform: string;
  readonly arch: string;
  readonly cwd: string;
  readonly name?: string;
  readonly os?: string;
  readonly archLabel?: string;
  readonly environment?: string;
  readonly temp?: string;
  readonly toolCache?: string;
}

type EvidencePackEnvironment = Readonly<Record<string, string | undefined>>;

interface EvidencePackManifest {
  readonly schemaVersion: 1;
  readonly generatedAt: string;
  readonly generator: "agentshield";
  readonly redacted: boolean;
  readonly targetPath: string;
  readonly bundleDigest: string;
  readonly artifacts: ReadonlyArray<EvidencePackArtifactManifestEntry>;
}

const ARTIFACTS = [
  {
    file: "manifest.json",
    kind: "manifest",
    description: "Machine-readable inventory of evidence-pack artifacts.",
  },
  {
    file: "README.md",
    kind: "readme",
    description: "Human-readable guide to the bundle contents.",
  },
  {
    file: "agentshield-report.json",
    kind: "scan-json",
    description: "Primary AgentShield JSON security report.",
  },
  {
    file: "agentshield-report.html",
    kind: "scan-html",
    description: "Self-contained executive HTML report.",
  },
  {
    file: "agentshield-results.sarif",
    kind: "sarif",
    description: "SARIF 2.1.0 code-scanning report.",
  },
  {
    file: "policy-evaluation.json",
    kind: "policy",
    description: "Organization policy evaluation, or a not-run marker.",
  },
  {
    file: "baseline-comparison.json",
    kind: "baseline",
    description: "Baseline drift comparison, or a not-run marker.",
  },
  {
    file: "supply-chain.json",
    kind: "supply-chain",
    description: "MCP package provenance and supply-chain verification summary.",
  },
  {
    file: "ci-context.json",
    kind: "ci-context",
    description: "Whitelisted CI, commit, workflow, and runner provenance for the scan.",
  },
  {
    file: "remediation-plan.json",
    kind: "remediation",
    description: "Stable-fingerprint remediation queue for ticketing and CI handoffs.",
  },
] as const;

type EvidencePackArtifactDefinition = (typeof ARTIFACTS)[number];

type EvidencePackArtifactManifestEntry = EvidencePackArtifactDefinition & {
  readonly sha256: string | null;
  readonly bytes: number | null;
};

const BUNDLE_DIGEST_EXCLUDED_FILES = new Set(["manifest.json", "README.md"]);

export function writeEvidencePack(options: EvidencePackOptions): EvidencePackResult {
  const outputDir = resolve(options.outputDir);
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const redacted = options.redact ?? true;
  const redactor = createRedactor(options.report.targetPath, redacted);
  const report = redactor.value(options.report) as SecurityReport;
  const policyEvaluation = options.policyEvaluation
    ? redactor.value(options.policyEvaluation)
    : {
        status: "not-run",
        reason: "No --policy file was provided for this scan.",
      };
  const baselineComparison = options.baselineComparison
    ? redactor.value(options.baselineComparison)
    : {
        status: "not-run",
        reason: "No --baseline file was provided for this scan.",
      };
  const supplyChainReport = redactor.value(options.supplyChainReport);
  const ciContext = redactor.value(
    options.ciContext ?? buildCiContext(options.environment ?? process.env, generatedAt)
  ) as EvidencePackCiContext;
  const remediationPlan = buildRemediationPlan(report, { generatedAt });
  const artifactContents = new Map<string, string>([
    ["agentshield-report.json", normalizeText(renderJsonReport(report))],
    ["agentshield-report.html", normalizeText(renderHtmlReport(report))],
    [
      "agentshield-results.sarif",
      normalizeText(renderSarifReport(report, {
        policyEvaluation: options.policyEvaluation ? (policyEvaluation as PolicyEvaluation) : undefined,
        policyUri: options.policyPath ? redactor.string(options.policyPath) : undefined,
      })),
    ],
    ["policy-evaluation.json", normalizeText(redactor.json(policyEvaluation))],
    ["baseline-comparison.json", normalizeText(redactor.json(baselineComparison))],
    ["supply-chain.json", normalizeText(redactor.json(supplyChainReport))],
    ["ci-context.json", normalizeText(redactor.json(ciContext))],
    ["remediation-plan.json", normalizeText(redactor.json(remediationPlan))],
  ]);
  const bundleDigest = buildBundleDigest(artifactContents);
  const readmeManifest: EvidencePackManifest = {
    schemaVersion: 1,
    generatedAt,
    generator: "agentshield",
    redacted,
    targetPath: redactor.string(options.report.targetPath),
    bundleDigest,
    artifacts: buildArtifactManifestEntries(artifactContents),
  };
  artifactContents.set("README.md", normalizeText(renderReadme(readmeManifest, options, ciContext)));
  const manifest: EvidencePackManifest = {
    ...readmeManifest,
    artifacts: buildArtifactManifestEntries(artifactContents),
  };
  artifactContents.set("manifest.json", normalizeText(redactor.json(manifest)));

  mkdirSync(outputDir, { recursive: true });

  for (const artifact of ARTIFACTS) {
    writeText(outputDir, artifact.file, artifactContents.get(artifact.file) ?? "");
  }

  return {
    outputDir,
    files: ARTIFACTS.map((artifact) => artifact.file),
  };
}

export function verifyEvidencePack(outputDir: string): EvidencePackVerificationResult {
  const resolvedOutputDir = resolve(outputDir);
  const manifestPath = resolve(resolvedOutputDir, "manifest.json");
  const errors: string[] = [];

  if (!existsSync(manifestPath)) {
    return {
      ok: false,
      outputDir: resolvedOutputDir,
      bundleDigest: null,
      expectedBundleDigest: null,
      artifacts: [],
      errors: ["manifest.json is missing"],
    };
  }

  let manifest: EvidencePackManifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf-8")) as EvidencePackManifest;
  } catch (error) {
    return {
      ok: false,
      outputDir: resolvedOutputDir,
      bundleDigest: null,
      expectedBundleDigest: null,
      artifacts: [],
      errors: [`manifest.json is not valid JSON: ${error instanceof Error ? error.message : String(error)}`],
    };
  }

  const artifactContents = new Map<string, string>();
  const artifacts = manifest.artifacts.map((artifact) => {
    const artifactPath = resolve(resolvedOutputDir, artifact.file);
    if (artifact.file === "manifest.json") {
      return {
        file: artifact.file,
        ok: artifact.sha256 === null && artifact.bytes === null,
        expectedSha256: artifact.sha256,
        actualSha256: null,
        expectedBytes: artifact.bytes,
        actualBytes: null,
      };
    }

    if (!existsSync(artifactPath)) {
      errors.push(`${artifact.file} is missing`);
      return {
        file: artifact.file,
        ok: false,
        expectedSha256: artifact.sha256,
        actualSha256: null,
        expectedBytes: artifact.bytes,
        actualBytes: null,
      };
    }

    const content = readFileSync(artifactPath, "utf-8");
    artifactContents.set(artifact.file, content);
    const actual = hashContent(content);
    const ok = actual.sha256 === artifact.sha256 && actual.bytes === artifact.bytes;
    if (!ok) {
      errors.push(`${artifact.file} digest mismatch`);
    }

    return {
      file: artifact.file,
      ok,
      expectedSha256: artifact.sha256,
      actualSha256: actual.sha256,
      expectedBytes: artifact.bytes,
      actualBytes: actual.bytes,
    };
  });
  const bundleDigest = buildBundleDigest(artifactContents);

  if (bundleDigest !== manifest.bundleDigest) {
    errors.push("bundle digest mismatch");
  }

  return {
    ok: errors.length === 0 && artifacts.every((artifact) => artifact.ok),
    outputDir: resolvedOutputDir,
    bundleDigest,
    expectedBundleDigest: manifest.bundleDigest,
    artifacts,
    errors,
  };
}

function buildCiContext(
  environment: EvidencePackEnvironment,
  generatedAt: string
): EvidencePackCiContext {
  const github = compact({
    repository: environment.GITHUB_REPOSITORY,
    repositoryId: environment.GITHUB_REPOSITORY_ID,
    workflow: environment.GITHUB_WORKFLOW,
    workflowRef: environment.GITHUB_WORKFLOW_REF,
    job: environment.GITHUB_JOB,
    runId: environment.GITHUB_RUN_ID,
    runAttempt: environment.GITHUB_RUN_ATTEMPT,
    runNumber: environment.GITHUB_RUN_NUMBER,
    actor: environment.GITHUB_ACTOR,
    eventName: environment.GITHUB_EVENT_NAME,
    ref: environment.GITHUB_REF,
    sha: environment.GITHUB_SHA,
    headRef: environment.GITHUB_HEAD_REF,
    baseRef: environment.GITHUB_BASE_REF,
    serverUrl: environment.GITHUB_SERVER_URL,
  });

  const runtime: EvidencePackRuntimeContext = {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    cwd: process.cwd(),
    ...compact({
      name: environment.RUNNER_NAME,
      os: environment.RUNNER_OS,
      archLabel: environment.RUNNER_ARCH,
      environment: environment.RUNNER_ENVIRONMENT,
      temp: environment.RUNNER_TEMP,
      toolCache: environment.RUNNER_TOOL_CACHE,
    }),
  };

  return {
    schemaVersion: 1,
    generatedAt,
    provider: environment.GITHUB_ACTIONS === "true" ? "github-actions" : "local",
    source: "process-environment",
    github: Object.keys(github).length > 0 ? github : undefined,
    runtime,
  };
}

function compact<T extends Record<string, string | undefined>>(value: T): {
  readonly [K in keyof T]?: string;
} {
  const entries = Object.entries(value)
    .filter(([, entryValue]) => typeof entryValue === "string" && entryValue.length > 0);
  return Object.fromEntries(entries) as { readonly [K in keyof T]?: string };
}

function writeText(outputDir: string, fileName: string, content: string): void {
  writeFileSync(resolve(outputDir, fileName), normalizeText(content));
}

function normalizeText(content: string): string {
  return content.endsWith("\n") ? content : `${content}\n`;
}

function buildArtifactManifestEntries(
  artifactContents: ReadonlyMap<string, string>
): EvidencePackManifest["artifacts"] {
  return ARTIFACTS.map((artifact) => {
    if (artifact.file === "manifest.json") {
      return { ...artifact, sha256: null, bytes: null };
    }

    const content = artifactContents.get(artifact.file);
    return content
      ? { ...artifact, ...hashContent(content) }
      : { ...artifact, sha256: null, bytes: null };
  });
}

function buildBundleDigest(artifactContents: ReadonlyMap<string, string>): string {
  const bundleEntries = ARTIFACTS
    .filter((artifact) => !BUNDLE_DIGEST_EXCLUDED_FILES.has(artifact.file))
    .map((artifact) => {
      const content = artifactContents.get(artifact.file);
      return {
        file: artifact.file,
        ...(content ? hashContent(content) : { sha256: null, bytes: null }),
      };
    });
  return `sha256:${createHash("sha256").update(JSON.stringify(bundleEntries)).digest("hex")}`;
}

function hashContent(content: string): { readonly sha256: string; readonly bytes: number } {
  return {
    sha256: createHash("sha256").update(content).digest("hex"),
    bytes: Buffer.byteLength(content, "utf8"),
  };
}

function renderReadme(
  manifest: EvidencePackManifest,
  options: EvidencePackOptions,
  ciContext: EvidencePackCiContext
): string {
  const policyStatus = options.policyEvaluation
    ? options.policyEvaluation.passed ? "passed" : "failed"
    : "not run";
  const baselineStatus = options.baselineComparison
    ? options.baselineComparison.isRegression ? "regressed" : "passed"
    : "not run";

  return [
    "# AgentShield Evidence Pack",
    "",
    `Generated: ${manifest.generatedAt}`,
    `Target: ${manifest.targetPath}`,
    `Redacted: ${manifest.redacted ? "yes" : "no"}`,
    `Bundle digest: ${manifest.bundleDigest}`,
    "",
    "## Summary",
    "",
    `- Score: ${options.report.score.numericScore}/100 (${options.report.score.grade})`,
    `- Findings: ${options.report.summary.totalFindings}`,
    `- Critical: ${options.report.summary.critical}`,
    `- High: ${options.report.summary.high}`,
    `- Policy: ${policyStatus}`,
    `- Baseline: ${baselineStatus}`,
    `- Supply-chain packages: ${options.supplyChainReport.totalPackages}`,
    `- Risky packages: ${options.supplyChainReport.riskyPackages}`,
    `- CI context: ${ciContext.provider}`,
    "- Remediation plan: included",
    "",
    "## Artifacts",
    "",
    ...manifest.artifacts.map(
      (artifact) => `- \`${artifact.file}\` (${artifact.kind}): ${artifact.description}`
    ),
    "",
    "## Interpretation",
    "",
    "- Start with `agentshield-report.html` for an executive review.",
    "- Use `agentshield-report.json` and `agentshield-results.sarif` for automation.",
    "- Use `policy-evaluation.json` to confirm organization-policy status.",
    "- Use `baseline-comparison.json` to review drift from the accepted baseline.",
    "- Use `supply-chain.json` to review MCP package provenance and package risk.",
    "- Use `ci-context.json` to confirm workflow, commit, and runner provenance.",
    "- Use `remediation-plan.json` for stable-fingerprint fix queues and ticket handoffs.",
    "",
    "This bundle is designed for audit handoffs, buyer security reviews, and CI artifacts.",
  ].join("\n");
}

function createRedactor(
  targetPath: string,
  enabled: boolean
): {
  readonly string: (value: string) => string;
  readonly value: (value: unknown) => unknown;
  readonly json: (value: unknown) => string;
} {
  const replacements = enabled ? buildReplacements(targetPath) : [];

  const redactString = (value: string): string => {
    if (!enabled) return value;
    return replacements.reduce(
      (redacted, [pattern, replacement]) => redacted.replace(pattern, replacement),
      value
    );
  };

  const redactValue = (value: unknown): unknown => {
    if (!enabled) return value;
    return JSON.parse(redactString(JSON.stringify(value)));
  };

  return {
    string: redactString,
    value: redactValue,
    json(value: unknown): string {
      return JSON.stringify(redactValue(value), null, 2);
    },
  };
}

function buildReplacements(targetPath: string): ReadonlyArray<[RegExp, string]> {
  const home = homedir();
  const targetReplacements: ReadonlyArray<[RegExp, string]> = targetPath
    ? [
        [literalPattern(resolve(targetPath)), "<target-path>"],
        [literalPattern(targetPath), "<target-path>"],
      ]
    : [];
  const homeReplacements: ReadonlyArray<[RegExp, string]> = home && home !== "/"
    ? [[literalPattern(home), "<home>"]]
    : [];
  const userNames: ReadonlyArray<string> = [
    basename(home),
    process.env.USER,
    process.env.USERNAME,
  ]
    .filter((value): value is string => Boolean(value && value.length >= 3));
  const userReplacements: ReadonlyArray<[RegExp, string]> = [...new Set(userNames)]
    .map((userName) => [new RegExp(`\\b${escapeRegExp(userName)}\\b`, "g"), "<user>"]);
  const tokenReplacements: ReadonlyArray<[RegExp, string]> = [
    [/\bsk-[A-Za-z0-9_-]{12,}\b/g, "sk-<redacted>"],
    [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{12,}\b/g, "gh_<redacted>"],
    [/github_pat_[A-Za-z0-9_]{20,}\b/g, "<redacted-token>"],
    [/glpat-[A-Za-z0-9_-]{12,}\b/g, "<redacted-token>"],
    [/npm_[A-Za-z0-9]{20,}\b/g, "<redacted-token>"],
    [/lin_api_[A-Za-z0-9]{20,}\b/g, "<redacted-token>"],
    [/(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b/g, "<redacted-token>"],
    [/AIza[0-9A-Za-z_-]{20,}\b/g, "<redacted-token>"],
    [/hf_[A-Za-z0-9]{20,}\b/g, "<redacted-token>"],
    [/vercel_[A-Za-z0-9]{20,}\b/g, "<redacted-token>"],
    [/AKIA[0-9A-Z]{16}\b/g, "<redacted-token>"],
    [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "<redacted-token>"],
    [/\b(?:xox[baprs]|slack)-[A-Za-z0-9-]{12,}\b/g, "<redacted-token>"],
    [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "<redacted-email>"],
  ];

  return [
    ...targetReplacements,
    ...homeReplacements,
    ...userReplacements,
    ...tokenReplacements,
  ];
}

function literalPattern(value: string): RegExp {
  return new RegExp(escapeRegExp(value), "g");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
