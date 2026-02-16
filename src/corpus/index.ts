import type { ConfigFile, Finding, Rule } from "../types.js";
import { vulnerableConfigs } from "./vulnerable-configs.js";
import type { VulnerableConfig } from "./vulnerable-configs.js";

export { vulnerableConfigs } from "./vulnerable-configs.js";
export type { VulnerableConfig } from "./vulnerable-configs.js";

// ─── Corpus Validation Types ──────────────────────────────

export interface CorpusValidationResult {
  readonly configId: string;
  readonly configName: string;
  readonly expectedFindings: number;
  readonly actualFindings: number;
  readonly missingRules: ReadonlyArray<string>;
  readonly extraRules: ReadonlyArray<string>;
  readonly passed: boolean;
}

export interface CorpusValidation {
  readonly totalConfigs: number;
  readonly passed: number;
  readonly failed: number;
  readonly results: ReadonlyArray<CorpusValidationResult>;
}

// ─── Scan Function Types ──────────────────────────────────

/**
 * A simple scan function that takes files and returns findings.
 */
export type ScanFn = (files: ReadonlyArray<{
  readonly path: string;
  readonly content: string;
  readonly type: string;
}>) => ReadonlyArray<Finding>;

/**
 * A rule-aware scan function that takes files and rules,
 * and returns findings grouped by rule ID.
 */
export type RuleScanFn = (
  files: ReadonlyArray<ConfigFile>,
  rules: ReadonlyArray<Rule>
) => Map<string, ReadonlyArray<Finding>>;

// ─── Validation ───────────────────────────────────────────

/**
 * Validate that the scanner catches all expected findings in each corpus config.
 *
 * Uses rule-aware scanning: each rule is run separately so we can track
 * exactly which rule produced which findings.
 */
export function validateCorpus(ruleScanFn: RuleScanFn, rules: ReadonlyArray<Rule>): CorpusValidation {
  const results: CorpusValidationResult[] = [];

  for (const config of vulnerableConfigs) {
    const result = validateSingleConfig(config, ruleScanFn, rules);
    results.push(result);
  }

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;

  return {
    totalConfigs: vulnerableConfigs.length,
    passed,
    failed,
    results,
  };
}

/**
 * Validate a single vulnerable config against the scanner.
 */
function validateSingleConfig(
  config: VulnerableConfig,
  ruleScanFn: RuleScanFn,
  rules: ReadonlyArray<Rule>
): CorpusValidationResult {
  const configFiles: ConfigFile[] = config.files.map((f) => ({
    path: f.path,
    content: f.content,
    type: f.type,
  }));

  // Run each rule separately and collect findings by rule ID
  const findingsByRule = ruleScanFn(configFiles, rules);

  // Compare against expected findings
  const missingRules: string[] = [];
  let expectedTotal = 0;
  let actualTotal = 0;

  for (const [_ruleId, findings] of findingsByRule) {
    actualTotal += findings.length;
  }

  for (const expected of config.expectedFindings) {
    expectedTotal += expected.count;
    const ruleFindings = findingsByRule.get(expected.ruleId) ?? [];

    if (ruleFindings.length < expected.count) {
      missingRules.push(
        `${expected.ruleId} (expected ${expected.count}, got ${ruleFindings.length})`
      );
    }
  }

  // Find rules that fired but were not expected
  const expectedRuleIds = new Set(config.expectedFindings.map((e) => e.ruleId));
  const extraRules: string[] = [];
  for (const [ruleId, findings] of findingsByRule) {
    if (!expectedRuleIds.has(ruleId) && findings.length > 0) {
      extraRules.push(`${ruleId} (${findings.length})`);
    }
  }

  return {
    configId: config.id,
    configName: config.name,
    expectedFindings: expectedTotal,
    actualFindings: actualTotal,
    missingRules,
    extraRules,
    passed: missingRules.length === 0,
  };
}

// ─── Helpers ──────────────────────────────────────────────

/**
 * Returns all configs in the corpus.
 */
export function getCorpusConfigs(): ReadonlyArray<VulnerableConfig> {
  return vulnerableConfigs;
}

/**
 * Returns a single config by ID.
 */
export function getCorpusConfig(id: string): VulnerableConfig | undefined {
  return vulnerableConfigs.find((c) => c.id === id);
}

/**
 * Default rule-aware scan function: runs each rule against each file
 * and returns findings grouped by rule ID.
 */
export function defaultRuleScanFn(
  files: ReadonlyArray<ConfigFile>,
  rules: ReadonlyArray<Rule>
): Map<string, ReadonlyArray<Finding>> {
  const result = new Map<string, Finding[]>();

  for (const rule of rules) {
    const findings: Finding[] = [];
    for (const file of files) {
      findings.push(...rule.check(file));
    }
    if (findings.length > 0) {
      result.set(rule.id, findings);
    }
  }

  return result;
}
