import type { SupplyChainReport } from "./supply-chain/index.js";

export type SupplyChainActionStatus = "not-run" | "clean" | "risky" | "error";

export interface SupplyChainGateOptions {
  readonly failOnSupplyChain: boolean;
}

export interface SupplyChainJobSummaryOptions extends SupplyChainGateOptions {
  readonly online: boolean;
}

export function statusForSupplyChainReport(
  report: SupplyChainReport
): SupplyChainActionStatus {
  return report.riskyPackages > 0 ? "risky" : "clean";
}

export function shouldFailForSupplyChain(
  report: SupplyChainReport,
  options: SupplyChainGateOptions
): boolean {
  return options.failOnSupplyChain && (report.criticalCount > 0 || report.highCount > 0);
}

export function renderSupplyChainJobSummary(
  report: SupplyChainReport,
  options: SupplyChainJobSummaryOptions
): string {
  const status = statusForSupplyChainReport(report);
  const lines = [
    "",
    "",
    "## AgentShield Supply Chain",
    "",
    `- Status: ${status}`,
    `- Mode: ${options.online ? "online registry metadata" : "offline IOC and provenance checks"}`,
    `- Gate: ${options.failOnSupplyChain ? "fail on critical/high risk" : "collect evidence only"}`,
    `- Packages: ${report.totalPackages}`,
    `- Risky packages: ${report.riskyPackages}`,
    `- Critical packages: ${report.criticalCount}`,
    `- High packages: ${report.highCount}`,
    `- Provenance: npm=${report.provenance.npmPackages}, git=${report.provenance.gitPackages}, pinned=${report.provenance.pinnedPackages}, unpinned=${report.provenance.unpinnedPackages}, known-good=${report.provenance.knownGoodPackages}, registry-backed=${report.provenance.registryMetadataPackages}`,
  ];

  const riskyPackages = report.packages.filter((pkg) => pkg.risks.length > 0);
  if (riskyPackages.length > 0) {
    lines.push("", "### Risky Packages");
    for (const verification of riskyPackages) {
      const version = verification.package.version ? `@${verification.package.version}` : "";
      const risks = verification.risks
        .map((risk) => `${risk.type}/${risk.severity}`)
        .join(", ");
      lines.push(
        `- ${verification.package.name}${version} (${verification.package.serverName}) severity=${verification.overallSeverity} risks=${risks}`
      );
    }
  }

  return `${lines.join("\n")}\n`;
}
