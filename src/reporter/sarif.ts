import type { Finding, SecurityReport, Severity } from "../types.js";
import type { PolicyEvaluation, PolicyViolation } from "../policy/index.js";

const SARIF_SCHEMA =
  "https://json.schemastore.org/sarif-2.1.0.json";

type SarifLevel = "error" | "warning" | "note";

interface SarifReportingDescriptor {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: { readonly text: string };
  readonly fullDescription: { readonly text: string };
  readonly help?: { readonly text: string };
  readonly defaultConfiguration: { readonly level: SarifLevel };
  readonly properties: Record<string, unknown>;
}

export interface SarifRenderOptions {
  readonly policyEvaluation?: PolicyEvaluation;
  readonly policyUri?: string;
}

/**
 * Render an AgentShield report as SARIF 2.1.0 for GitHub code scanning.
 */
export function renderSarifReport(
  report: SecurityReport,
  options: SarifRenderOptions = {}
): string {
  const rules = [
    ...buildFindingRules(report.findings),
    ...buildPolicyRules(options.policyEvaluation),
  ];
  const ruleIndexes = new Map(rules.map((rule, index) => [rule.id, index]));
  const policyUri = options.policyUri ?? ".agentshield/policy.json";

  return JSON.stringify(
    {
      version: "2.1.0",
      $schema: SARIF_SCHEMA,
      runs: [
        {
          tool: {
            driver: {
              name: "AgentShield",
              informationUri: "https://github.com/affaan-m/agentshield",
              rules,
            },
          },
          automationDetails: {
            id: "agentshield/security-scan",
          },
          invocations: [
            {
              executionSuccessful: true,
              endTimeUtc: report.timestamp,
              workingDirectory: {
                uri: normalizeUri(report.targetPath),
              },
            },
          ],
          properties: {
            score: report.score.numericScore,
            grade: report.score.grade,
            filesScanned: report.summary.filesScanned,
            ...(options.policyEvaluation
              ? {
                  policyStatus: options.policyEvaluation.passed
                    ? "compliant"
                    : "non-compliant",
                  policyViolations: options.policyEvaluation.violations.length,
                  policyName: options.policyEvaluation.policyName,
                  policyPack: options.policyEvaluation.policyPack,
                }
              : {}),
          },
          results: [
            ...report.findings.map((finding) =>
              renderFindingResult(finding, ruleIndexes.get(finding.id) ?? 0)
            ),
            ...renderPolicyResults(
              options.policyEvaluation,
              ruleIndexes,
              policyUri
            ),
          ],
        },
      ],
    },
    null,
    2
  );
}

function buildFindingRules(findings: ReadonlyArray<Finding>): SarifReportingDescriptor[] {
  const rules = new Map<string, SarifReportingDescriptor>();

  for (const finding of findings) {
    if (rules.has(finding.id)) continue;

    rules.set(finding.id, {
      id: finding.id,
      name: finding.title,
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.description },
      help: finding.fix
        ? { text: `${finding.description}\n\nRecommended fix: ${finding.fix.description}` }
        : { text: finding.description },
      defaultConfiguration: {
        level: severityToLevel(finding.severity),
      },
      properties: {
        category: finding.category,
        severity: finding.severity,
        "security-severity": severityToSecurityScore(finding.severity),
        tags: ["security", "agent-config", finding.category],
        precision: precisionForFinding(finding),
      },
    });
  }

  return [...rules.values()];
}

function buildPolicyRules(
  evaluation: PolicyEvaluation | undefined
): SarifReportingDescriptor[] {
  if (!evaluation) return [];

  const rules = new Map<string, SarifReportingDescriptor>();

  for (const violation of evaluation.violations) {
    const ruleId = policyRuleId(violation);
    if (rules.has(ruleId)) continue;

    rules.set(ruleId, {
      id: ruleId,
      name: `Organization policy: ${violation.rule}`,
      shortDescription: {
        text: `Organization policy: ${violation.rule}`,
      },
      fullDescription: {
        text: violation.description,
      },
      help: {
        text: [
          violation.description,
          "",
          `Expected: ${violation.expected}`,
          `Actual: ${violation.actual}`,
        ].join("\n"),
      },
      defaultConfiguration: {
        level: severityToLevel(violation.severity),
      },
      properties: {
        category: "organization-policy",
        severity: violation.severity,
        "security-severity": severityToSecurityScore(violation.severity),
        tags: ["security", "agent-config", "organization-policy"],
        precision: "high",
        policyName: evaluation.policyName,
        policyPack: evaluation.policyPack,
        owners: evaluation.owners ?? [],
      },
    });
  }

  return [...rules.values()];
}

function renderFindingResult(
  finding: Finding,
  ruleIndex: number
): Record<string, unknown> {
  return {
    ruleId: finding.id,
    ruleIndex,
    level: severityToLevel(finding.severity),
    message: {
      text: finding.description,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: normalizeUri(finding.file),
          },
          ...(finding.line
            ? {
                region: {
                  startLine: Math.max(1, finding.line),
                },
              }
            : {}),
        },
      },
    ],
    properties: {
      title: finding.title,
      category: finding.category,
      severity: finding.severity,
      runtimeConfidence: finding.runtimeConfidence,
      evidence: finding.evidence,
      fix: finding.fix?.description,
    },
  };
}

function renderPolicyResults(
  evaluation: PolicyEvaluation | undefined,
  ruleIndexes: ReadonlyMap<string, number>,
  policyUri: string
): ReadonlyArray<Record<string, unknown>> {
  if (!evaluation) return [];

  return evaluation.violations.map((violation) => {
    const ruleId = policyRuleId(violation);

    return {
      ruleId,
      ruleIndex: ruleIndexes.get(ruleId) ?? 0,
      level: severityToLevel(violation.severity),
      message: {
        text: violation.description,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: normalizeUri(policyUri),
            },
          },
        },
      ],
      properties: {
        source: "organization-policy",
        policyName: evaluation.policyName,
        policyPack: evaluation.policyPack,
        owners: evaluation.owners ?? [],
        rule: violation.rule,
        severity: violation.severity,
        expected: violation.expected,
        actual: violation.actual,
      },
    };
  });
}

function policyRuleId(violation: PolicyViolation): string {
  return `agentshield-policy/${violation.rule}`;
}

function severityToLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
  }
}

function severityToSecurityScore(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "9.5";
    case "high":
      return "8.0";
    case "medium":
      return "5.0";
    case "low":
      return "2.5";
    case "info":
      return "1.0";
  }
}

function precisionForFinding(finding: Finding): "very-high" | "high" | "medium" {
  if (finding.runtimeConfidence === "active-runtime") return "very-high";
  if (
    finding.runtimeConfidence === "template-example" ||
    finding.runtimeConfidence === "docs-example" ||
    finding.runtimeConfidence === "plugin-cache"
  ) {
    return "medium";
  }
  return "high";
}

function normalizeUri(uri: string): string {
  return uri.replace(/\\/g, "/");
}
