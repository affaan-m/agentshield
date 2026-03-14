import type {
  ConfigFile,
  Finding,
  Rule,
  RuntimeConfidence,
  ScanTarget,
  Severity,
} from "../types.js";
import { discoverConfigFiles } from "./discovery.js";
import { getBuiltinRules } from "../rules/index.js";
import { isExampleLikePath } from "../source-context.js";

export interface ScanResult {
  readonly target: ScanTarget;
  readonly findings: ReadonlyArray<Finding>;
}

/**
 * Main scanner: discovers config files and runs all rules against them.
 */
export function scan(targetPath: string): ScanResult {
  const target = discoverConfigFiles(targetPath);
  const rules = getBuiltinRules();
  const findings = runRules(target.files, rules);

  return { target, findings };
}

/**
 * Run all rules against all config files, collecting findings.
 */
function runRules(
  files: ReadonlyArray<ConfigFile>,
  rules: ReadonlyArray<Rule>
): ReadonlyArray<Finding> {
  const findings: Finding[] = [];

  for (const file of files) {
    for (const rule of rules) {
      const ruleFindings = rule.check(file, files);
      findings.push(...ruleFindings);
    }
  }

  const filesByPath = new Map(files.map((file) => [file.path, file]));
  const annotatedFindings = findings.map((finding) => {
    const annotatedFinding = annotateFindingRuntimeConfidence(finding, filesByPath);
    return adjustFindingForSourceContext(annotatedFinding);
  });

  // Sort by severity (critical first)
  return [...annotatedFindings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return order[a.severity] - order[b.severity];
  });
}

function classifyRuntimeConfidence(file: ConfigFile): RuntimeConfidence | undefined {
  const normalizedPath = file.path.replace(/\\/g, "/").toLowerCase();
  if (normalizedPath === "settings.local.json" || normalizedPath.endsWith("/settings.local.json")) {
    return "project-local-optional";
  }

  if (file.type === "hook-code") {
    return "hook-code";
  }

  if (
    file.type === "settings-json" &&
    /(?:^|\/)(?:\.claude\/)?hooks\/hooks\.json$/i.test(normalizedPath)
  ) {
    return "plugin-manifest";
  }

  if (isExampleLikePath(normalizedPath)) {
    return "docs-example";
  }

  return undefined;
}

function annotateFindingRuntimeConfidence(
  finding: Finding,
  filesByPath: ReadonlyMap<string, ConfigFile>
): Finding {
  if (finding.runtimeConfidence) {
    return finding;
  }

  const file = filesByPath.get(finding.file);
  const runtimeConfidence = file ? classifyRuntimeConfidence(file) : undefined;
  return runtimeConfidence ? { ...finding, runtimeConfidence } : finding;
}

function adjustFindingForSourceContext(finding: Finding): Finding {
  switch (finding.runtimeConfidence) {
    case "docs-example":
      return adjustDocsExampleFinding(finding);
    case "plugin-manifest":
      return adjustPluginManifestFinding(finding);
    default:
      return finding;
  }
}

function adjustDocsExampleFinding(finding: Finding): Finding {
  if (finding.category === "secrets") {
    return withPrefixedDescription(
      {
        ...finding,
        title: prefixTitle(finding.title, "Example config"),
      },
      "This finding comes from docs or sample configuration in the repository. It indicates risky guidance or example defaults, not confirmed active runtime exposure."
    );
  }

  return withPrefixedDescription(
    {
      ...finding,
      severity: downgradeStructuralSeverity(finding.severity),
      title: prefixTitle(finding.title, "Example config"),
    },
    "This finding comes from docs or sample configuration in the repository. It indicates risky guidance or example defaults, not confirmed active runtime exposure."
  );
}

function adjustPluginManifestFinding(finding: Finding): Finding {
  return withPrefixedDescription(
    {
      ...finding,
      title: prefixTitle(finding.title, "Plugin hook manifest"),
    },
    "This finding comes from a declarative hook manifest. Review the referenced hook implementation to confirm the exact runtime behavior."
  );
}

function downgradeStructuralSeverity(severity: Severity): Severity {
  switch (severity) {
    case "critical":
      return "high";
    case "high":
      return "medium";
    case "medium":
      return "low";
    default:
      return severity;
  }
}

function prefixTitle(title: string, prefix: string): string {
  return title.startsWith(`${prefix}: `) ? title : `${prefix}: ${title}`;
}

function withPrefixedDescription(finding: Finding, prefix: string): Finding {
  return finding.description.startsWith(prefix)
    ? finding
    : { ...finding, description: `${prefix} ${finding.description}` };
}

export { discoverConfigFiles } from "./discovery.js";
