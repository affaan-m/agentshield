import type { ExtractedPackage, PackageVerification, PackageRisk, NpmRegistryMeta, SupplyChainReport } from "./types.js";
import { KNOWN_GOOD_PACKAGES } from "./types.js";
import { checkPackageName, checkServerPackage } from "../threat-intel/cve-database.js";
import type { Severity } from "../types.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};
const GIT_COMMIT_HASH = /^[0-9a-f]{7,40}$/i;

/**
 * Verify a list of extracted packages against known-bad lists and optionally the npm registry.
 */
export async function verifyPackages(
  packages: ReadonlyArray<ExtractedPackage>,
  options: { readonly online?: boolean } = {}
): Promise<SupplyChainReport> {
  const verifications: PackageVerification[] = [];

  for (const pkg of packages) {
    const risks: PackageRisk[] = [];
    let registry: NpmRegistryMeta | undefined;

    // 1. Check against known malicious packages
    const malicious = checkPackageName(pkg.name, pkg.version);
    if (malicious) {
      risks.push({
        type: "known-malicious",
        severity: "critical",
        description: malicious.description,
        evidence: `Package: ${malicious.name} (${malicious.type})`,
      });
    }

    // 2. Check against known vulnerable servers
    const vulnerable = checkServerPackage(
      pkg.name,
      pkg.version ? [`${pkg.name}@${pkg.version}`] : [pkg.name]
    );
    if (vulnerable) {
      risks.push({
        type: "known-vulnerable",
        severity: "high",
        description: vulnerable.description,
        evidence: `CVEs: ${vulnerable.cveIds.join(", ")}`,
      });
    }

    // 3. Check for typosquatting
    const typosquatRisk = checkTyposquatting(pkg.name);
    if (typosquatRisk) {
      risks.push(typosquatRisk);
    }

    // 4. Check for unpinned git URLs
    if (pkg.source === "git" && !hasPinnedGitCommit(pkg.gitRef)) {
      risks.push({
        type: "unpinned-git",
        severity: "high",
        description:
          "Git URL without a pinned commit hash. An attacker who compromises the repo can inject malicious code.",
        evidence: pkg.gitUrl,
      });
    }

    // 5. If online, query npm registry
    if (options.online && pkg.source !== "git") {
      registry = await fetchRegistryMeta(pkg.name);
      if (registry) {
        risks.push(...assessRegistryRisks(registry));
      }
    }

    const overallSeverity = risks.length > 0
      ? risks.reduce((worst, r) =>
          SEVERITY_ORDER[r.severity] < SEVERITY_ORDER[worst.severity] ? r : worst
        ).severity
      : "info";

    verifications.push({
      package: pkg,
      registry,
      risks,
      overallSeverity,
    });
  }

  const riskyPackages = verifications.filter((v) => v.risks.length > 0);
  return {
    packages: verifications,
    totalPackages: verifications.length,
    riskyPackages: riskyPackages.length,
    criticalCount: riskyPackages.filter((v) => v.overallSeverity === "critical").length,
    highCount: riskyPackages.filter((v) => v.overallSeverity === "high").length,
  };
}

/**
 * Check if a package name is suspiciously similar to a known-good package.
 */
export function checkTyposquatting(packageName: string): PackageRisk | null {
  // Skip if it's a known-good package
  if (KNOWN_GOOD_PACKAGES.includes(packageName)) return null;

  for (const goodPkg of KNOWN_GOOD_PACKAGES) {
    const distance = levenshteinDistance(packageName, goodPkg);
    const maxLen = Math.max(packageName.length, goodPkg.length);
    const similarity = 1 - distance / maxLen;

    // High similarity (>80%) but not exact match
    if (similarity > 0.8 && distance > 0 && distance <= 3) {
      return {
        type: "typosquat",
        severity: "high",
        description: `Package name "${packageName}" is suspiciously similar to known-good package "${goodPkg}" (${Math.round(similarity * 100)}% similarity, edit distance: ${distance}).`,
        evidence: `Similar to: ${goodPkg}`,
      };
    }
  }

  return null;
}

function hasPinnedGitCommit(gitRef: string | undefined): boolean {
  return !!gitRef && GIT_COMMIT_HASH.test(gitRef);
}

/**
 * Compute Levenshtein distance between two strings.
 */
export function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;

  // Use two rows instead of full matrix for O(min(m,n)) space
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array<number>(n + 1);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,      // deletion
        curr[j - 1] + 1,  // insertion
        prev[j - 1] + cost // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }

  return prev[n];
}

/**
 * Fetch metadata from the npm registry.
 */
async function fetchRegistryMeta(
  packageName: string
): Promise<NpmRegistryMeta | undefined> {
  try {
    const registryUrl = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
    const response = await fetch(registryUrl, {
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) return undefined;

    const data = (await response.json()) as Record<string, unknown>;
    const time = data.time as Record<string, string> | undefined;
    const maintainers = data.maintainers as Array<{ name: string }> | undefined;
    const distTags = data["dist-tags"] as Record<string, string> | undefined;
    const latestVersion = distTags?.latest;
    const versions = data.versions as Record<string, Record<string, unknown>> | undefined;

    let hasPostinstall = false;
    if (latestVersion && versions?.[latestVersion]) {
      const scripts = versions[latestVersion].scripts as Record<string, string> | undefined;
      hasPostinstall = !!scripts?.postinstall;
    }

    // Fetch download count
    let downloadsLastWeek: number | undefined;
    try {
      const dlResponse = await fetch(
        `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`,
        { signal: AbortSignal.timeout(3000) }
      );
      if (dlResponse.ok) {
        const dlData = (await dlResponse.json()) as { downloads?: number };
        downloadsLastWeek = dlData.downloads;
      }
    } catch {
      // Download count is optional
    }

    return {
      name: packageName,
      publishedAt: time?.created,
      downloadsLastWeek,
      maintainerCount: maintainers?.length,
      hasPostinstall,
      latestVersion,
      description: data.description as string | undefined,
      deprecated: !!data.deprecated,
    };
  } catch {
    return undefined;
  }
}

/**
 * Assess risks based on npm registry metadata.
 */
function assessRegistryRisks(
  meta: NpmRegistryMeta
): ReadonlyArray<PackageRisk> {
  const risks: PackageRisk[] = [];

  if (meta.deprecated) {
    risks.push({
      type: "deprecated",
      severity: "medium",
      description: `Package "${meta.name}" is deprecated on npm.`,
    });
  }

  if (meta.hasPostinstall) {
    risks.push({
      type: "has-postinstall",
      severity: "medium",
      description: `Package "${meta.name}" has a postinstall script that runs automatically on install.`,
    });
  }

  if (meta.maintainerCount !== undefined && meta.maintainerCount <= 1) {
    risks.push({
      type: "single-maintainer",
      severity: "low",
      description: `Package "${meta.name}" has only ${meta.maintainerCount} maintainer(s). Single-maintainer packages are higher risk for account compromise.`,
    });
  }

  if (meta.downloadsLastWeek !== undefined && meta.downloadsLastWeek < 100) {
    risks.push({
      type: "low-downloads",
      severity: "medium",
      description: `Package "${meta.name}" has very low downloads (${meta.downloadsLastWeek}/week). Low-traffic packages are more likely to be malicious.`,
    });
  }

  if (meta.publishedAt) {
    const publishDate = new Date(meta.publishedAt);
    const threeMonthsAgo = new Date();
    threeMonthsAgo.setMonth(threeMonthsAgo.getMonth() - 3);

    if (publishDate > threeMonthsAgo) {
      risks.push({
        type: "new-package",
        severity: "low",
        description: `Package "${meta.name}" was first published recently (${meta.publishedAt}). New packages have less community vetting.`,
      });
    }
  }

  return risks;
}
