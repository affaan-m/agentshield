import type { Finding, SecurityReport, Severity } from "../types.js";

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

/**
 * Render an AgentShield report as SARIF 2.1.0 for GitHub code scanning.
 */
export function renderSarifReport(report: SecurityReport): string {
  const rules = buildRules(report.findings);
  const ruleIndexes = new Map(rules.map((rule, index) => [rule.id, index]));

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
          },
          results: report.findings.map((finding) =>
            renderSarifResult(finding, ruleIndexes.get(finding.id) ?? 0)
          ),
        },
      ],
    },
    null,
    2
  );
}

function buildRules(findings: ReadonlyArray<Finding>): SarifReportingDescriptor[] {
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

function renderSarifResult(
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
  if (finding.runtimeConfidence === "template-example" || finding.runtimeConfidence === "docs-example") {
    return "medium";
  }
  return "high";
}

function normalizeUri(uri: string): string {
  return uri.replace(/\\/g, "/");
}
