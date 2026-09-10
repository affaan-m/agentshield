import type { Finding, FindingCategory, Severity } from "../types.js";

/**
 * Compliance control mapping.
 *
 * Maps AgentShield findings to the control IDs of common audit frameworks
 * (SOC 2, PCI DSS, ISO/IEC 27001) so GRC teams get an auditor-ready coverage
 * artifact instead of a raw findings list. The mapping is at the finding-category
 * level (robust and explainable); it is security guidance, not a certified
 * crosswalk, and is stated as such in the rendered report.
 */

export type ComplianceFramework = "soc2" | "pci" | "iso";

export const COMPLIANCE_FRAMEWORKS: ReadonlyArray<ComplianceFramework> = ["soc2", "pci", "iso"];

export const FRAMEWORK_NAMES: Readonly<Record<ComplianceFramework, string>> = {
  soc2: "SOC 2 (Trust Services Criteria)",
  pci: "PCI DSS v4.0",
  iso: "ISO/IEC 27001:2022 Annex A",
};

interface ControlDef {
  readonly id: string;
  readonly title: string;
}

// Category -> controls, per framework. Keep entries defensible and explainable.
const CONTROL_MAP: Readonly<
  Record<ComplianceFramework, Readonly<Record<FindingCategory, ReadonlyArray<ControlDef>>>>
> = {
  soc2: {
    secrets: [{ id: "CC6.1", title: "Logical access - credentials" }, { id: "CC6.3", title: "Access credentials managed" }],
    permissions: [{ id: "CC6.1", title: "Logical access security" }, { id: "CC6.3", title: "Least-privilege access" }],
    hooks: [{ id: "CC7.1", title: "Detection of security events" }, { id: "CC8.1", title: "Change management" }],
    mcp: [{ id: "CC6.6", title: "External access boundaries" }, { id: "CC6.1", title: "Logical access security" }],
    skills: [{ id: "CC8.1", title: "Unauthorized/changed software" }],
    agents: [{ id: "CC6.1", title: "Logical access security" }, { id: "CC7.1", title: "Detection of security events" }],
    injection: [{ id: "CC7.1", title: "Detection of security events" }, { id: "CC8.1", title: "Change management" }],
    exposure: [{ id: "CC6.1", title: "Logical access security" }],
    exfiltration: [{ id: "CC6.7", title: "Restricted data transmission" }],
    misconfiguration: [{ id: "CC7.1", title: "Detection of security events" }],
  },
  pci: {
    secrets: [{ id: "Req 3", title: "Protect stored account data" }, { id: "Req 8", title: "Identify and authenticate access" }],
    permissions: [{ id: "Req 7", title: "Restrict access by need-to-know" }],
    hooks: [{ id: "Req 6", title: "Secure systems and software" }, { id: "Req 10", title: "Log and monitor access" }],
    mcp: [{ id: "Req 1", title: "Network security controls" }, { id: "Req 6", title: "Secure systems and software" }],
    skills: [{ id: "Req 6", title: "Secure systems and software" }, { id: "Req 2", title: "Secure configurations" }],
    agents: [{ id: "Req 6", title: "Secure systems and software" }],
    injection: [{ id: "Req 6.2", title: "Secure software development" }],
    exposure: [{ id: "Req 3", title: "Protect stored account data" }],
    exfiltration: [{ id: "Req 4", title: "Protect data in transmission" }, { id: "Req 1", title: "Network security controls" }],
    misconfiguration: [{ id: "Req 2", title: "Secure configurations" }],
  },
  iso: {
    secrets: [{ id: "A.5.17", title: "Authentication information" }, { id: "A.8.24", title: "Use of cryptography" }],
    permissions: [{ id: "A.5.15", title: "Access control" }, { id: "A.8.2", title: "Privileged access rights" }],
    hooks: [{ id: "A.8.16", title: "Monitoring activities" }, { id: "A.8.28", title: "Secure coding" }],
    mcp: [{ id: "A.5.21", title: "ICT supply chain security" }, { id: "A.8.21", title: "Security of network services" }],
    skills: [{ id: "A.8.19", title: "Software on operational systems" }],
    agents: [{ id: "A.8.28", title: "Secure coding" }],
    injection: [{ id: "A.8.28", title: "Secure coding" }],
    exposure: [{ id: "A.8.12", title: "Data leakage prevention" }],
    exfiltration: [{ id: "A.8.12", title: "Data leakage prevention" }],
    misconfiguration: [{ id: "A.8.9", title: "Configuration management" }],
  },
};

export interface ControlCoverage {
  readonly framework: ComplianceFramework;
  readonly controlId: string;
  readonly controlTitle: string;
  readonly findingCount: number;
  readonly severities: Readonly<Record<Severity, number>>;
  readonly highestSeverity: Severity;
  readonly exampleFindings: ReadonlyArray<string>;
}

export interface ComplianceReport {
  readonly framework: ComplianceFramework;
  readonly frameworkName: string;
  readonly totalFindings: number;
  readonly mappedFindingCount: number;
  readonly unmappedFindingCount: number;
  readonly controls: ReadonlyArray<ControlCoverage>;
}

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function emptySeverities(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/**
 * Map a set of findings to control coverage for a single framework.
 */
interface MutableCoverage {
  framework: ComplianceFramework;
  controlId: string;
  controlTitle: string;
  findingCount: number;
  severities: Record<Severity, number>;
  highestSeverity: Severity;
  exampleFindings: string[];
}

export function mapFindingsToControls(
  findings: ReadonlyArray<Finding>,
  framework: ComplianceFramework
): ComplianceReport {
  const table = CONTROL_MAP[framework];
  const byControl = new Map<string, MutableCoverage>();
  let mappedFindingCount = 0;

  for (const finding of findings) {
    const controls = table[finding.category] ?? [];
    if (controls.length > 0) mappedFindingCount += 1;

    for (const control of controls) {
      const existing = byControl.get(control.id);
      if (existing) {
        existing.findingCount += 1;
        existing.severities[finding.severity] += 1;
        if (SEVERITY_RANK[finding.severity] < SEVERITY_RANK[existing.highestSeverity]) {
          existing.highestSeverity = finding.severity;
        }
        if (existing.exampleFindings.length < 3 && !existing.exampleFindings.includes(finding.title)) {
          existing.exampleFindings.push(finding.title);
        }
      } else {
        const severities = emptySeverities();
        severities[finding.severity] += 1;
        byControl.set(control.id, {
          framework,
          controlId: control.id,
          controlTitle: control.title,
          findingCount: 1,
          severities,
          highestSeverity: finding.severity,
          exampleFindings: [finding.title],
        });
      }
    }
  }

  const controls: ReadonlyArray<ControlCoverage> = [...byControl.values()].sort(
    (a, b) =>
      SEVERITY_RANK[a.highestSeverity] - SEVERITY_RANK[b.highestSeverity] ||
      b.findingCount - a.findingCount ||
      a.controlId.localeCompare(b.controlId)
  );

  return {
    framework,
    frameworkName: FRAMEWORK_NAMES[framework],
    totalFindings: findings.length,
    mappedFindingCount,
    unmappedFindingCount: findings.length - mappedFindingCount,
    controls,
  };
}

export function parseFrameworks(value: string): ReadonlyArray<ComplianceFramework> {
  const normalized = value.trim().toLowerCase();
  if (normalized === "all") return COMPLIANCE_FRAMEWORKS;
  return normalized
    .split(",")
    .map((v) => v.trim())
    .filter((v): v is ComplianceFramework => (COMPLIANCE_FRAMEWORKS as ReadonlyArray<string>).includes(v));
}

/**
 * Render a compliance report as a markdown control-coverage table.
 */
export function renderComplianceReport(report: ComplianceReport): string {
  const lines: string[] = [];
  lines.push(`## Compliance Mapping: ${report.frameworkName}`);
  lines.push("");
  lines.push(
    `Mapped ${report.mappedFindingCount}/${report.totalFindings} findings to ${report.controls.length} control(s). ` +
      `${report.unmappedFindingCount} finding(s) had no mapped control.`
  );
  lines.push("");

  if (report.controls.length === 0) {
    lines.push("No findings mapped to controls for this framework.");
    lines.push("");
  } else {
    lines.push("| Control | Title | Highest | Findings | Examples |");
    lines.push("|---------|-------|---------|----------|----------|");
    for (const control of report.controls) {
      const examples = control.exampleFindings.join("; ") || "-";
      lines.push(
        `| ${control.controlId} | ${control.controlTitle} | ${control.highestSeverity} | ${control.findingCount} | ${examples} |`
      );
    }
    lines.push("");
  }

  lines.push(
    "_Category-level guidance mapping, not a certified crosswalk. Confirm control applicability with your auditor._"
  );
  lines.push("");
  return lines.join("\n");
}
