import { mkdirSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { homedir } from "node:os";
import type { BaselineComparison } from "../baseline/index.js";
import type { PolicyEvaluation } from "../policy/index.js";
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
}

export interface EvidencePackResult {
  readonly outputDir: string;
  readonly files: ReadonlyArray<string>;
}

interface EvidencePackManifest {
  readonly schemaVersion: 1;
  readonly generatedAt: string;
  readonly generator: "agentshield";
  readonly redacted: boolean;
  readonly targetPath: string;
  readonly artifacts: ReadonlyArray<{
    readonly file: string;
    readonly kind: string;
    readonly description: string;
  }>;
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
] as const;

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
  const manifest: EvidencePackManifest = {
    schemaVersion: 1,
    generatedAt,
    generator: "agentshield",
    redacted,
    targetPath: redactor.string(options.report.targetPath),
    artifacts: ARTIFACTS,
  };

  mkdirSync(outputDir, { recursive: true });

  writeText(outputDir, "manifest.json", redactor.json(manifest));
  writeText(outputDir, "README.md", renderReadme(manifest, options));
  writeText(outputDir, "agentshield-report.json", renderJsonReport(report));
  writeText(outputDir, "agentshield-report.html", renderHtmlReport(report));
  writeText(
    outputDir,
    "agentshield-results.sarif",
    renderSarifReport(report, {
      policyEvaluation: options.policyEvaluation ? (policyEvaluation as PolicyEvaluation) : undefined,
      policyUri: options.policyPath ? redactor.string(options.policyPath) : undefined,
    })
  );
  writeText(outputDir, "policy-evaluation.json", redactor.json(policyEvaluation));
  writeText(outputDir, "baseline-comparison.json", redactor.json(baselineComparison));
  writeText(outputDir, "supply-chain.json", redactor.json(supplyChainReport));

  return {
    outputDir,
    files: ARTIFACTS.map((artifact) => artifact.file),
  };
}

function writeText(outputDir: string, fileName: string, content: string): void {
  writeFileSync(resolve(outputDir, fileName), content.endsWith("\n") ? content : `${content}\n`);
}

function renderReadme(
  manifest: EvidencePackManifest,
  options: EvidencePackOptions
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
