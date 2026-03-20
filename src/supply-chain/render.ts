import type { SupplyChainReport, PackageVerification } from "./types.js";

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F-\u009F]/g;

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
      const version = pkg.package.version ? `@${escapeControlChars(pkg.package.version)}` : "";
      const name = escapeControlChars(pkg.package.name);
      const serverName = escapeControlChars(pkg.package.serverName);
      lines.push(`    [OK] ${name}${version} (${serverName})`);
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
  const version = pkg.version ? `@${escapeControlChars(pkg.version)}` : "";
  const sev = verification.overallSeverity.toUpperCase();
  const name = escapeControlChars(pkg.name);
  const serverName = escapeControlChars(pkg.serverName);
  const source = escapeControlChars(pkg.source);

  lines.push(`    [${sev}] ${name}${version} (server: ${serverName}, via: ${source})`);

  for (const risk of verification.risks) {
    lines.push(`      - [${risk.severity.toUpperCase()}] ${escapeControlChars(risk.description)}`);
    if (risk.evidence) {
      lines.push(`        Evidence: ${escapeControlChars(risk.evidence)}`);
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
      details.push(`latest: ${escapeControlChars(meta.latestVersion)}`);
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

function escapeControlChars(value: string): string {
  return value.replace(CONTROL_CHAR_PATTERN, (char) => {
    const code = char.charCodeAt(0);
    return code <= 0xff
      ? `\\x${code.toString(16).padStart(2, "0")}`
      : `\\u${code.toString(16).padStart(4, "0")}`;
  });
}
