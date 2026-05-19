import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
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

export interface EvidencePackInspectionResult {
  readonly ok: boolean;
  readonly outputDir: string;
  readonly generatedAt: string | null;
  readonly targetPath: string | null;
  readonly redacted: boolean | null;
  readonly bundleDigest: string | null;
  readonly expectedBundleDigest: string | null;
  readonly artifactCount: number;
  readonly verifiedArtifactCount: number;
  readonly report: EvidencePackReportSummary | null;
  readonly policy: EvidencePackPolicySummary;
  readonly baseline: EvidencePackBaselineSummary;
  readonly supplyChain: EvidencePackSupplyChainSummary | null;
  readonly ciContext: EvidencePackCiSummary | null;
  readonly remediation: EvidencePackRemediationSummary | null;
  readonly verification: EvidencePackVerificationResult;
  readonly errors: ReadonlyArray<string>;
}

export type EvidencePackFleetRoute =
  | "invalid"
  | "security-blocker"
  | "policy-review"
  | "baseline-regression"
  | "supply-chain-review"
  | "ready";

export interface EvidencePackFleetInspectionResult {
  readonly ok: boolean;
  readonly requiresAttention: boolean;
  readonly summary: EvidencePackFleetSummary;
  readonly operatorReadback: EvidencePackFleetOperatorReadback;
  readonly entries: ReadonlyArray<EvidencePackFleetEntry>;
  readonly routes: ReadonlyArray<EvidencePackFleetRouteEntry>;
  readonly reviewItems: ReadonlyArray<EvidencePackFleetReviewItem>;
  readonly errors: ReadonlyArray<string>;
}

export interface EvidencePackFleetOperatorReadback {
  readonly status: "ready" | "blocked" | "invalid-evidence";
  readonly ready: boolean;
  readonly requiresApproval: boolean;
  readonly digest: string;
  readonly invalidPackCount: number;
  readonly reviewItemCount: number;
  readonly blockingItemCount: number;
  readonly ownerCount: number;
  readonly owners: ReadonlyArray<string>;
  readonly routesRequiringApproval: ReadonlyArray<EvidencePackFleetRoute>;
  readonly approvalIds: ReadonlyArray<string>;
  readonly nextAction: string;
}

export interface EvidencePackFleetSummary {
  readonly totalPacks: number;
  readonly verifiedPacks: number;
  readonly invalidPacks: number;
  readonly totalFindings: number;
  readonly critical: number;
  readonly high: number;
  readonly medium: number;
  readonly low: number;
  readonly info: number;
  readonly policyFailures: number;
  readonly baselineRegressions: number;
  readonly riskyPackages: number;
  readonly autoFixable: number;
  readonly manualReview: number;
}

export interface EvidencePackFleetEntry {
  readonly outputDir: string;
  readonly ok: boolean;
  readonly route: EvidencePackFleetRoute;
  readonly reason: string;
  readonly generatedAt: string | null;
  readonly targetPath: string | null;
  readonly repository: string | null;
  readonly provider: "github-actions" | "local" | "unknown" | null;
  readonly score: number | null;
  readonly grade: string | null;
  readonly totalFindings: number;
  readonly critical: number;
  readonly high: number;
  readonly medium: number;
  readonly low: number;
  readonly info: number;
  readonly policyStatus: EvidencePackPolicySummary["status"];
  readonly baselineStatus: EvidencePackBaselineSummary["status"];
  readonly riskyPackages: number;
  readonly autoFixable: number;
  readonly manualReview: number;
  readonly errors: ReadonlyArray<string>;
}

export interface EvidencePackFleetRouteEntry {
  readonly route: EvidencePackFleetRoute;
  readonly outputDir: string;
  readonly repository: string | null;
  readonly targetPath: string | null;
  readonly reason: string;
}

export interface EvidencePackFleetReviewItem {
  readonly route: EvidencePackFleetRoute;
  readonly severity: "high" | "medium" | "low" | "info";
  readonly priority: "urgent" | "high" | "normal";
  readonly approvalId: string;
  readonly outputDir: string;
  readonly owner: string;
  readonly repository: string | null;
  readonly targetPath: string | null;
  readonly reason: string;
  readonly evidencePaths: ReadonlyArray<string>;
  readonly beforeState: string;
  readonly afterState: string;
  readonly reversibleAction: string;
  readonly actions: ReadonlyArray<string>;
  readonly recommendation: string;
  readonly ticket: EvidencePackFleetReviewTicket;
}

export interface EvidencePackFleetReviewTicket {
  readonly externalId: string;
  readonly title: string;
  readonly body: string;
  readonly labels: ReadonlyArray<string>;
  readonly priority: "urgent" | "high" | "normal";
}

export interface EvidencePackReportSummary {
  readonly score: {
    readonly grade: string;
    readonly numericScore: number;
  };
  readonly findings: {
    readonly total: number;
    readonly critical: number;
    readonly high: number;
    readonly medium: number;
    readonly low: number;
    readonly info: number;
  };
  readonly runtimeConfidence: Readonly<Record<string, number>>;
}

export interface EvidencePackPolicySummary {
  readonly status: "passed" | "failed" | "not-run" | "unknown";
  readonly policyName?: string;
  readonly policyPack?: string;
  readonly violations?: number;
}

export interface EvidencePackBaselineSummary {
  readonly status: "passed" | "regressed" | "not-run" | "unknown";
  readonly newFindings?: number;
  readonly resolvedFindings?: number;
  readonly unchangedCount?: number;
  readonly scoreDelta?: number;
}

export interface EvidencePackSupplyChainSummary {
  readonly totalPackages: number;
  readonly riskyPackages: number;
  readonly criticalCount: number;
  readonly highCount: number;
}

export interface EvidencePackCiSummary {
  readonly provider: "github-actions" | "local" | "unknown";
  readonly repository?: string;
  readonly workflow?: string;
  readonly runId?: string;
  readonly sha?: string;
}

export interface EvidencePackRemediationSummary {
  readonly totalFindings: number;
  readonly autoFixable: number;
  readonly manualReview: number;
  readonly phases: ReadonlyArray<{
    readonly id: string;
    readonly findingCount: number;
    readonly blocking: boolean;
  }>;
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

export function inspectEvidencePack(outputDir: string): EvidencePackInspectionResult {
  const resolvedOutputDir = resolve(outputDir);
  const verification = verifyEvidencePack(resolvedOutputDir);
  const errors = [...verification.errors];
  const manifest = readJsonFile<EvidencePackManifest>(resolvedOutputDir, "manifest.json", errors);
  const report = readJsonFile<SecurityReport>(resolvedOutputDir, "agentshield-report.json", errors);
  const policy = readJsonFile<Record<string, unknown>>(resolvedOutputDir, "policy-evaluation.json", errors);
  const baseline = readJsonFile<Record<string, unknown>>(resolvedOutputDir, "baseline-comparison.json", errors);
  const supplyChain = readJsonFile<SupplyChainReport>(resolvedOutputDir, "supply-chain.json", errors);
  const ciContext = readJsonFile<EvidencePackCiContext>(resolvedOutputDir, "ci-context.json", errors);
  const remediation = readJsonFile<Record<string, unknown>>(resolvedOutputDir, "remediation-plan.json", errors);
  const reportSummary = summarizeArtifact("agentshield-report.json", errors, () =>
    report ? summarizeReport(report) : null
  );
  const policySummary = summarizeArtifact("policy-evaluation.json", errors, () => summarizePolicy(policy));
  const baselineSummary = summarizeArtifact("baseline-comparison.json", errors, () => summarizeBaseline(baseline));
  const supplyChainSummary = summarizeArtifact("supply-chain.json", errors, () =>
    supplyChain ? summarizeSupplyChain(supplyChain) : null
  );
  const ciContextSummary = summarizeArtifact("ci-context.json", errors, () =>
    ciContext ? summarizeCiContext(ciContext) : null
  );
  const remediationSummary = summarizeArtifact("remediation-plan.json", errors, () =>
    remediation ? summarizeRemediation(remediation) : null
  );

  return {
    ok: verification.ok && errors.length === 0,
    outputDir: resolvedOutputDir,
    generatedAt: typeof manifest?.generatedAt === "string" ? manifest.generatedAt : null,
    targetPath: typeof manifest?.targetPath === "string" ? manifest.targetPath : null,
    redacted: typeof manifest?.redacted === "boolean" ? manifest.redacted : null,
    bundleDigest: verification.bundleDigest,
    expectedBundleDigest: verification.expectedBundleDigest,
    artifactCount: manifest?.artifacts.length ?? verification.artifacts.length,
    verifiedArtifactCount: verification.artifacts.filter((artifact) => artifact.ok).length,
    report: reportSummary,
    policy: policySummary ?? { status: "unknown" },
    baseline: baselineSummary ?? { status: "unknown" },
    supplyChain: supplyChainSummary,
    ciContext: ciContextSummary,
    remediation: remediationSummary,
    verification,
    errors,
  };
}

export function inspectEvidencePackFleet(outputDirs: ReadonlyArray<string>): EvidencePackFleetInspectionResult {
  const entries: ReadonlyArray<EvidencePackFleetEntry> = outputDirs.map((outputDir) =>
    summarizeFleetEntry(inspectEvidencePack(outputDir))
  );
  const summary = entries.reduce<EvidencePackFleetSummary>(
    (accumulator, entry) => ({
      totalPacks: accumulator.totalPacks + 1,
      verifiedPacks: accumulator.verifiedPacks + (entry.ok ? 1 : 0),
      invalidPacks: accumulator.invalidPacks + (entry.ok ? 0 : 1),
      totalFindings: accumulator.totalFindings + entry.totalFindings,
      critical: accumulator.critical + entry.critical,
      high: accumulator.high + entry.high,
      medium: accumulator.medium + entry.medium,
      low: accumulator.low + entry.low,
      info: accumulator.info + entry.info,
      policyFailures: accumulator.policyFailures + (entry.policyStatus === "failed" ? 1 : 0),
      baselineRegressions: accumulator.baselineRegressions + (entry.baselineStatus === "regressed" ? 1 : 0),
      riskyPackages: accumulator.riskyPackages + entry.riskyPackages,
      autoFixable: accumulator.autoFixable + entry.autoFixable,
      manualReview: accumulator.manualReview + entry.manualReview,
    }),
    {
      totalPacks: 0,
      verifiedPacks: 0,
      invalidPacks: 0,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      policyFailures: 0,
      baselineRegressions: 0,
      riskyPackages: 0,
      autoFixable: 0,
      manualReview: 0,
    }
  );
  const routes: ReadonlyArray<EvidencePackFleetRouteEntry> = entries.map((entry) => ({
    route: entry.route,
    outputDir: entry.outputDir,
    repository: entry.repository,
    targetPath: entry.targetPath,
    reason: entry.reason,
  }));
  const errors: ReadonlyArray<string> = entries.flatMap((entry) =>
    entry.errors.map((error) => `${entry.outputDir}: ${error}`)
  );
  const reviewItems = entries
    .filter((entry) => entry.route !== "ready")
    .map(buildFleetReviewItem);
  const operatorReadback = buildFleetOperatorReadback(summary, routes, reviewItems);

  return {
    ok: summary.invalidPacks === 0,
    requiresAttention: routes.some((route) => route.route !== "ready"),
    summary,
    operatorReadback,
    entries,
    routes,
    reviewItems,
    errors,
  };
}

function buildFleetOperatorReadback(
  summary: EvidencePackFleetSummary,
  routes: ReadonlyArray<EvidencePackFleetRouteEntry>,
  reviewItems: ReadonlyArray<EvidencePackFleetReviewItem>
): EvidencePackFleetOperatorReadback {
  const status = determineFleetOperatorStatus(summary, reviewItems);
  const owners = Array.from(new Set(reviewItems.map((item) => item.owner))).sort();
  const routesRequiringApproval = Array.from(new Set(reviewItems.map((item) => item.route))).sort();
  const approvalIds = reviewItems.map((item) => item.approvalId).sort();
  return {
    status,
    ready: status === "ready",
    requiresApproval: reviewItems.length > 0,
    digest: buildFleetOperatorDigest(summary, routes, reviewItems),
    invalidPackCount: summary.invalidPacks,
    reviewItemCount: reviewItems.length,
    blockingItemCount: reviewItems.filter((item) => item.severity === "high").length,
    ownerCount: owners.length,
    owners,
    routesRequiringApproval,
    approvalIds,
    nextAction: describeFleetOperatorNextAction(status),
  };
}

function determineFleetOperatorStatus(
  summary: EvidencePackFleetSummary,
  reviewItems: ReadonlyArray<EvidencePackFleetReviewItem>
): EvidencePackFleetOperatorReadback["status"] {
  if (summary.invalidPacks > 0) return "invalid-evidence";
  return reviewItems.length > 0 ? "blocked" : "ready";
}

function describeFleetOperatorNextAction(status: EvidencePackFleetOperatorReadback["status"]): string {
  if (status === "invalid-evidence") return "Regenerate invalid evidence packs before promotion.";
  if (status === "blocked") return "Route review items to listed owners and attach approval before promotion.";
  return "Promotion can proceed with the current evidence digest.";
}

function buildFleetOperatorDigest(
  summary: EvidencePackFleetSummary,
  routes: ReadonlyArray<EvidencePackFleetRouteEntry>,
  reviewItems: ReadonlyArray<EvidencePackFleetReviewItem>
): string {
  const payload = {
    summary,
    routes: [...routes]
      .map((route) => ({
        route: route.route,
        outputDir: route.outputDir,
        repository: route.repository,
        targetPath: route.targetPath,
        reason: route.reason,
      }))
      .sort(compareDigestRecords),
    reviewItems: [...reviewItems]
      .map((item) => ({
        route: item.route,
        severity: item.severity,
        priority: item.priority,
        approvalId: item.approvalId,
        outputDir: item.outputDir,
        owner: item.owner,
        repository: item.repository,
        targetPath: item.targetPath,
        reason: item.reason,
        evidencePaths: [...item.evidencePaths].sort(),
        beforeState: item.beforeState,
        afterState: item.afterState,
        reversibleAction: item.reversibleAction,
        actions: [...item.actions],
        recommendation: item.recommendation,
        ticket: item.ticket,
      }))
      .sort(compareDigestRecords),
  };
  return `sha256:${createHash("sha256").update(JSON.stringify(payload)).digest("hex")}`;
}

function compareDigestRecords(left: Record<string, unknown>, right: Record<string, unknown>): number {
  return JSON.stringify(left).localeCompare(JSON.stringify(right));
}

function buildFleetReviewItem(entry: EvidencePackFleetEntry): EvidencePackFleetReviewItem {
  const severity = determineFleetReviewSeverity(entry.route);
  const priority = determineFleetReviewPriority(entry.route);
  const evidencePaths = buildFleetReviewEvidencePaths(entry);
  const beforeState = buildFleetReviewBeforeState(entry);
  const afterState = buildFleetReviewAfterState(entry.route);
  const reversibleAction = buildFleetReviewReversibleAction(entry.route);
  const actions = buildFleetReviewActions(entry.route);
  const recommendation = buildFleetReviewRecommendation(entry.route);
  const owner = buildFleetReviewOwner(entry);
  const approvalId = buildFleetReviewApprovalId({
    entry,
    severity,
    priority,
    owner,
    evidencePaths,
    beforeState,
    afterState,
    reversibleAction,
    actions,
    recommendation,
  });
  return {
    route: entry.route,
    severity,
    priority,
    approvalId,
    outputDir: entry.outputDir,
    owner,
    repository: entry.repository,
    targetPath: entry.targetPath,
    reason: entry.reason,
    evidencePaths,
    beforeState,
    afterState,
    reversibleAction,
    actions,
    recommendation,
    ticket: buildFleetReviewTicket({
      entry,
      severity,
      priority,
      owner,
      approvalId,
      evidencePaths,
      beforeState,
      afterState,
      reversibleAction,
      actions,
      recommendation,
    }),
  };
}

function buildFleetReviewApprovalId(options: {
  readonly entry: EvidencePackFleetEntry;
  readonly severity: EvidencePackFleetReviewItem["severity"];
  readonly priority: EvidencePackFleetReviewItem["priority"];
  readonly owner: string;
  readonly evidencePaths: ReadonlyArray<string>;
  readonly beforeState: string;
  readonly afterState: string;
  readonly reversibleAction: string;
  readonly actions: ReadonlyArray<string>;
  readonly recommendation: string;
}): string {
  const payload = {
    route: options.entry.route,
    severity: options.severity,
    priority: options.priority,
    outputDir: options.entry.outputDir,
    repository: options.entry.repository,
    targetPath: options.entry.targetPath,
    reason: options.entry.reason,
    owner: options.owner,
    evidencePaths: [...options.evidencePaths].sort(),
    beforeState: options.beforeState,
    afterState: options.afterState,
    reversibleAction: options.reversibleAction,
    actions: [...options.actions],
    recommendation: options.recommendation,
  };
  const digest = createHash("sha256").update(JSON.stringify(payload)).digest("hex");
  return `agsr_${digest.slice(0, 16)}`;
}

function determineFleetReviewSeverity(route: EvidencePackFleetRoute): EvidencePackFleetReviewItem["severity"] {
  if (route === "invalid" || route === "security-blocker") return "high";
  if (route === "policy-review" || route === "baseline-regression" || route === "supply-chain-review") return "medium";
  return "info";
}

function determineFleetReviewPriority(route: EvidencePackFleetRoute): EvidencePackFleetReviewItem["priority"] {
  if (route === "invalid" || route === "security-blocker") return "urgent";
  if (route === "policy-review" || route === "baseline-regression" || route === "supply-chain-review") return "high";
  return "normal";
}

function buildFleetReviewEvidencePaths(entry: EvidencePackFleetEntry): ReadonlyArray<string> {
  const paths = [
    join(entry.outputDir, "manifest.json"),
    join(entry.outputDir, "agentshield-report.json"),
  ];

  if (entry.policyStatus !== "not-run" && entry.policyStatus !== "unknown") {
    paths.push(join(entry.outputDir, "policy-evaluation.json"));
  }
  if (entry.baselineStatus !== "not-run" && entry.baselineStatus !== "unknown") {
    paths.push(join(entry.outputDir, "baseline-comparison.json"));
  }
  if (entry.riskyPackages > 0 || entry.route === "supply-chain-review" || entry.route === "security-blocker") {
    paths.push(join(entry.outputDir, "supply-chain.json"));
  }
  if (entry.autoFixable > 0 || entry.manualReview > 0) {
    paths.push(join(entry.outputDir, "remediation-plan.json"));
  }

  return Array.from(new Set(paths));
}

function buildFleetReviewRecommendation(route: EvidencePackFleetRoute): string {
  if (route === "invalid") return "Regenerate or repair evidence pack before promotion.";
  if (route === "security-blocker") return "Route to security owner before promotion.";
  if (route === "policy-review") return "Route to policy owner before exception approval.";
  if (route === "baseline-regression") return "Route to baseline owner before accepting drift.";
  if (route === "supply-chain-review") return "Route to supply-chain owner before publication.";
  return "Keep evidence pack in the ready set.";
}

function buildFleetReviewOwner(entry: EvidencePackFleetEntry): string {
  if (entry.repository) return `${entry.repository} security owner`;
  if (entry.provider === "github-actions") return "repository security owner";
  return "security owner queue";
}

function buildFleetReviewBeforeState(entry: EvidencePackFleetEntry): string {
  if (entry.route === "invalid") return `Evidence pack failed verification: ${entry.reason}.`;
  if (entry.route === "security-blocker") return `Evidence pack has security blockers: ${entry.reason}.`;
  if (entry.route === "policy-review") return `Evidence pack policy status is failed for ${entry.repository ?? entry.outputDir}.`;
  if (entry.route === "baseline-regression") return `Evidence pack baseline regressed for ${entry.repository ?? entry.outputDir}.`;
  if (entry.route === "supply-chain-review") return `Evidence pack has supply-chain review findings: ${entry.reason}.`;
  return "Evidence pack is ready.";
}

function buildFleetReviewAfterState(route: EvidencePackFleetRoute): string {
  if (route === "invalid") return "Evidence pack verifies successfully and can be trusted as a routing artifact.";
  if (route === "security-blocker") return "Critical and high findings are fixed, accepted by policy, or explicitly routed with owner approval.";
  if (route === "policy-review") return "Policy violations are fixed or owner-approved exceptions are attached.";
  if (route === "baseline-regression") return "Baseline drift is fixed, rolled back, or accepted with owner approval.";
  if (route === "supply-chain-review") return "Risky packages are pinned, replaced, removed, or explicitly approved.";
  return "Evidence pack remains in the ready set.";
}

function buildFleetReviewReversibleAction(route: EvidencePackFleetRoute): string {
  if (route === "invalid") return "Discard the broken pack and rerun `agentshield scan --evidence-pack <dir>` from a clean workspace.";
  if (route === "security-blocker") return "Revert the risky config change or keep the promotion blocked until a clean evidence pack is generated.";
  if (route === "policy-review") return "Revert the policy change or keep the policy in report-only mode until exception approval lands.";
  if (route === "baseline-regression") return "Restore the previous baseline or keep the new baseline unpromoted until drift is accepted.";
  if (route === "supply-chain-review") return "Restore the prior dependency or package pin if review cannot approve the new package.";
  return "Remove the ready pack from the fleet input if it should not participate in promotion.";
}

function buildFleetReviewActions(route: EvidencePackFleetRoute): ReadonlyArray<string> {
  if (route === "invalid") {
    return [
      "Regenerate the evidence pack from the original scan target.",
      "Run `agentshield evidence-pack verify <dir>` before adding it back to fleet routing.",
    ];
  }
  if (route === "security-blocker") {
    return [
      "Assign the pack to the repository security owner.",
      "Fix or explicitly approve critical/high findings before promotion.",
      "Regenerate and verify the evidence pack after remediation.",
    ];
  }
  if (route === "policy-review") {
    return [
      "Route policy failures to the policy owner.",
      "Attach an approved exception or update the policy/finding before promotion.",
    ];
  }
  if (route === "baseline-regression") {
    return [
      "Route baseline drift to the baseline owner.",
      "Attach rollback evidence or accepted-drift approval before promotion.",
    ];
  }
  if (route === "supply-chain-review") {
    return [
      "Route risky packages to the supply-chain owner.",
      "Pin, replace, remove, or approve the package and rerun supply-chain evidence.",
    ];
  }
  return ["Keep the evidence pack in the ready set."];
}

function buildFleetReviewTicket(options: {
  readonly entry: EvidencePackFleetEntry;
  readonly severity: EvidencePackFleetReviewItem["severity"];
  readonly priority: EvidencePackFleetReviewItem["priority"];
  readonly owner: string;
  readonly approvalId: string;
  readonly evidencePaths: ReadonlyArray<string>;
  readonly beforeState: string;
  readonly afterState: string;
  readonly reversibleAction: string;
  readonly actions: ReadonlyArray<string>;
  readonly recommendation: string;
}): EvidencePackFleetReviewTicket {
  const repository = options.entry.repository ?? "unknown repository";
  const externalId = `agentshield-fleet-review:${options.approvalId}`;
  const labels = [
    "AgentShield",
    "Security",
    `route:${options.entry.route}`,
    `priority:${options.priority}`,
  ];
  const body = [
    "## AgentShield Fleet Review",
    "",
    `Route: \`${options.entry.route}\``,
    `Priority: \`${options.priority}\``,
    `Severity: \`${options.severity}\``,
    `Approval ID: \`${options.approvalId}\``,
    `External ID: \`${externalId}\``,
    `Repository: \`${repository}\``,
    `Owner: \`${options.owner}\``,
    `Reason: ${options.entry.reason}`,
    "",
    "### State",
    `- Before: ${options.beforeState}`,
    `- Target: ${options.afterState}`,
    `- Reversible action: ${options.reversibleAction}`,
    "",
    "### Evidence",
    ...options.evidencePaths.map((path) => `- \`${path}\``),
    "",
    "### Required Actions",
    ...options.actions.map((action) => `- ${action}`),
    "",
    `Recommendation: ${options.recommendation}`,
  ].join("\n");

  return {
    externalId,
    title: `AgentShield ${options.entry.route}: ${repository} (${options.entry.reason})`,
    body,
    labels,
    priority: options.priority,
  };
}

function summarizeFleetEntry(inspection: EvidencePackInspectionResult): EvidencePackFleetEntry {
  const findings = inspection.report?.findings;
  const route = determineFleetRoute(inspection);
  return {
    outputDir: inspection.outputDir,
    ok: inspection.ok,
    route,
    reason: describeFleetRoute(inspection, route),
    generatedAt: inspection.generatedAt,
    targetPath: inspection.targetPath,
    repository: inspection.ciContext?.repository ?? null,
    provider: inspection.ciContext?.provider ?? null,
    score: inspection.report?.score.numericScore ?? null,
    grade: inspection.report?.score.grade ?? null,
    totalFindings: findings?.total ?? 0,
    critical: findings?.critical ?? 0,
    high: findings?.high ?? 0,
    medium: findings?.medium ?? 0,
    low: findings?.low ?? 0,
    info: findings?.info ?? 0,
    policyStatus: inspection.policy.status,
    baselineStatus: inspection.baseline.status,
    riskyPackages: inspection.supplyChain?.riskyPackages ?? 0,
    autoFixable: inspection.remediation?.autoFixable ?? 0,
    manualReview: inspection.remediation?.manualReview ?? 0,
    errors: inspection.errors,
  };
}

function determineFleetRoute(inspection: EvidencePackInspectionResult): EvidencePackFleetRoute {
  if (!inspection.ok) return "invalid";
  if ((inspection.report?.findings.critical ?? 0) > 0 || (inspection.report?.findings.high ?? 0) > 0) {
    return "security-blocker";
  }
  if ((inspection.supplyChain?.criticalCount ?? 0) > 0 || (inspection.supplyChain?.highCount ?? 0) > 0) {
    return "security-blocker";
  }
  if (inspection.policy.status === "failed") return "policy-review";
  if (inspection.baseline.status === "regressed") return "baseline-regression";
  if ((inspection.supplyChain?.riskyPackages ?? 0) > 0) return "supply-chain-review";
  return "ready";
}

function describeFleetRoute(
  inspection: EvidencePackInspectionResult,
  route: EvidencePackFleetRoute
): string {
  if (route === "invalid") return inspection.errors[0] ?? "evidence pack failed verification";
  const findings = inspection.report?.findings;
  if (route === "security-blocker") {
    if ((findings?.critical ?? 0) > 0) return `${findings?.critical ?? 0} critical findings`;
    if ((findings?.high ?? 0) > 0) return `${findings?.high ?? 0} high findings`;
    if ((inspection.supplyChain?.criticalCount ?? 0) > 0) return `${inspection.supplyChain?.criticalCount ?? 0} critical supply-chain packages`;
    return `${inspection.supplyChain?.highCount ?? 0} high supply-chain packages`;
  }
  if (route === "policy-review") return "policy failed";
  if (route === "baseline-regression") return "baseline regressed";
  if (route === "supply-chain-review") return `${inspection.supplyChain?.riskyPackages ?? 0} risky packages`;
  return "no routing blockers";
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

function readJsonFile<T>(
  outputDir: string,
  fileName: string,
  errors: string[]
): T | null {
  const filePath = resolve(outputDir, fileName);
  if (!existsSync(filePath)) {
    errors.push(`${fileName} is missing`);
    return null;
  }

  try {
    return JSON.parse(readFileSync(filePath, "utf-8")) as T;
  } catch (error) {
    errors.push(`${fileName} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

function summarizeArtifact<T>(
  fileName: string,
  errors: string[],
  summarize: () => T
): T | null {
  try {
    return summarize();
  } catch (error) {
    errors.push(`${fileName} summary failed: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

function summarizeReport(report: SecurityReport): EvidencePackReportSummary {
  return {
    score: {
      grade: report.score.grade,
      numericScore: report.score.numericScore,
    },
    findings: {
      total: report.summary.totalFindings,
      critical: report.summary.critical,
      high: report.summary.high,
      medium: report.summary.medium,
      low: report.summary.low,
      info: report.summary.info,
    },
    runtimeConfidence: countRuntimeConfidence(report),
  };
}

function countRuntimeConfidence(report: SecurityReport): Readonly<Record<string, number>> {
  const counts = report.findings.reduce<Record<string, number>>((accumulator, finding) => {
    const key = finding.runtimeConfidence ?? "active-runtime";
    return {
      ...accumulator,
      [key]: (accumulator[key] ?? 0) + 1,
    };
  }, {});
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function summarizePolicy(policy: Record<string, unknown> | null): EvidencePackPolicySummary {
  if (!policy) return { status: "unknown" };
  if (policy.status === "not-run") return { status: "not-run" };

  const violations = Array.isArray(policy.violations) ? policy.violations.length : undefined;
  return {
    status: policy.passed === true ? "passed" : policy.passed === false ? "failed" : "unknown",
    policyName: typeof policy.policyName === "string" ? policy.policyName : undefined,
    policyPack: typeof policy.policyPack === "string" ? policy.policyPack : undefined,
    violations,
  };
}

function summarizeBaseline(baseline: Record<string, unknown> | null): EvidencePackBaselineSummary {
  if (!baseline) return { status: "unknown" };
  if (baseline.status === "not-run") return { status: "not-run" };

  return {
    status: baseline.isRegression === true ? "regressed" : baseline.isRegression === false ? "passed" : "unknown",
    newFindings: Array.isArray(baseline.newFindings) ? baseline.newFindings.length : undefined,
    resolvedFindings: Array.isArray(baseline.resolvedFindings) ? baseline.resolvedFindings.length : undefined,
    unchangedCount: typeof baseline.unchangedCount === "number" ? baseline.unchangedCount : undefined,
    scoreDelta: typeof baseline.scoreDelta === "number" ? baseline.scoreDelta : undefined,
  };
}

function summarizeSupplyChain(report: SupplyChainReport): EvidencePackSupplyChainSummary {
  return {
    totalPackages: report.totalPackages,
    riskyPackages: report.riskyPackages,
    criticalCount: report.criticalCount,
    highCount: report.highCount,
  };
}

function summarizeCiContext(context: EvidencePackCiContext): EvidencePackCiSummary {
  return {
    provider: context.provider,
    repository: context.github?.repository,
    workflow: context.github?.workflow,
    runId: context.github?.runId,
    sha: context.github?.sha,
  };
}

function summarizeRemediation(remediation: Record<string, unknown>): EvidencePackRemediationSummary | null {
  const summary = remediation.summary;
  const workflow = remediation.workflow;
  if (!summary || typeof summary !== "object") return null;

  const summaryRecord = summary as Record<string, unknown>;
  const phases = workflow && typeof workflow === "object" && Array.isArray((workflow as Record<string, unknown>).phases)
    ? ((workflow as { phases: ReadonlyArray<Record<string, unknown>> }).phases)
    : [];

  return {
    totalFindings: numberOrZero(summaryRecord.totalFindings),
    autoFixable: numberOrZero(summaryRecord.autoFixable),
    manualReview: numberOrZero(summaryRecord.manualReview),
    phases: phases.map((phase) => ({
      id: typeof phase.id === "string" ? phase.id : "unknown",
      findingCount: numberOrZero(phase.findingCount),
      blocking: phase.blocking === true,
    })),
  };
}

function numberOrZero(value: unknown): number {
  return typeof value === "number" ? value : 0;
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
    [/xai-[A-Za-z0-9_-]{20,}\b/g, "<redacted-token>"],
    [/((?:CLOUDFLARE_API_TOKEN|CLOUDFLARE_TOKEN|CF_API_TOKEN|CF_TOKEN)\s*[:=]\s*["']?)[A-Za-z0-9_-]{20,}/gi, "$1<redacted-token>"],
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
