import type { ConfigFile, Finding, Rule, ScanTarget } from "../types.js";
import { discoverConfigFiles } from "./discovery.js";
import { getBuiltinRules } from "../rules/index.js";

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
      const ruleFindings = rule.check(file);
      findings.push(...ruleFindings);
    }
  }

  // Sort by severity (critical first)
  return [...findings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return order[a.severity] - order[b.severity];
  });
}

export { discoverConfigFiles } from "./discovery.js";
