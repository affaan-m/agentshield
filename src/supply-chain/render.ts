import type { SupplyChainReport, PackageVerification } from "./types.js";

/**
 * Render a supply chain report to the terminal.
 */
export function renderSupplyChainReport(report: SupplyChainReport): string {
  const lines: string[] = [];
  const divider = "─".repeat(60);

  lines.push("");
  lines.push(`  ${divider}`);
  lines.push("  Supply Chain Verification Report");
  lines.push(`  ${divider}`);
  lines.push("");
  lines.push(`  Packages analyzed: ${report.totalPackages}`);
  lines.push(`  Risky packages:    ${report.riskyPackages}`);

  if (report.criticalCount > 0) {
    lines.push(`  Critical:          ${report.criticalCount}`);
  }
  if (report.highCount > 0) {
    lines.push(`  High:              ${report.highCount}`);
  }

  if (report.packages.length === 0) {
    lines.push("");
    lines.push("  No MCP packages detected in configuration.");
    lines.push("");
    return lines.join("\n");
  }

  // Show risky packages first
  const risky = report.packages.filter((p) => p.risks.length > 0);
  const clean = report.packages.filter((p) => p.risks.length === 0);

  if (risky.length > 0) {
    lines.push("");
    lines.push("  RISKY PACKAGES:");
    for (const pkg of risky) {
      lines.push(...renderPackage(pkg));
    }
  }

  if (clean.length > 0) {
    lines.push("");
    lines.push("  CLEAN PACKAGES:");
    for (const pkg of clean) {
      const version = pkg.package.version ? `@${pkg.package.version}` : "";
      lines.push(`    [OK] ${pkg.package.name}${version} (${pkg.package.serverName})`);
    }
  }

  lines.push("");
  lines.push(`  ${divider}`);
  lines.push("");

  return lines.join("\n");
}

function renderPackage(verification: PackageVerification): ReadonlyArray<string> {
  const lines: string[] = [];
  const pkg = verification.package;
  const version = pkg.version ? `@${pkg.version}` : "";
  const sev = verification.overallSeverity.toUpperCase();

  lines.push(`    [${sev}] ${pkg.name}${version} (server: ${pkg.serverName}, via: ${pkg.source})`);

  for (const risk of verification.risks) {
    lines.push(`      - [${risk.severity.toUpperCase()}] ${risk.description}`);
    if (risk.evidence) {
      lines.push(`        Evidence: ${risk.evidence}`);
    }
  }

  if (verification.registry) {
    const meta = verification.registry;
    const details: string[] = [];
    if (meta.downloadsLastWeek !== undefined) {
      details.push(`${meta.downloadsLastWeek} downloads/week`);
    }
    if (meta.maintainerCount !== undefined) {
      details.push(`${meta.maintainerCount} maintainer(s)`);
    }
    if (meta.latestVersion) {
      details.push(`latest: ${meta.latestVersion}`);
    }
    if (details.length > 0) {
      lines.push(`      Registry: ${details.join(", ")}`);
    }
  }

  return lines;
}

/**
 * Render a supply chain report as JSON.
 */
export function renderSupplyChainJson(report: SupplyChainReport): string {
  return JSON.stringify(report, null, 2);
}
