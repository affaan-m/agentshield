import { describe, it, expect } from "vitest";

import {
  vulnerableConfigs,
  validateCorpus,
  getCorpusConfig,
  getCorpusConfigs,
  defaultRuleScanFn,
} from "../src/corpus/index.js";
import type { VulnerableConfig } from "../src/corpus/index.js";
import type { ConfigFile, Finding, Rule } from "../src/types.js";
import { getBuiltinRules } from "../src/rules/index.js";

// ─── Helpers ──────────────────────────────────────────────

const allRules = getBuiltinRules();

/**
 * Runs all rules against a config's files, returning findings by rule ID.
 */
function scanConfig(config: VulnerableConfig): Map<string, ReadonlyArray<Finding>> {
  const configFiles: ConfigFile[] = config.files.map((f) => ({
    path: f.path,
    content: f.content,
    type: f.type,
  }));

  return defaultRuleScanFn(configFiles, allRules);
}

// ─── Corpus Structure Tests ───────────────────────────────

describe("corpus structure", () => {
  it("has at least 10 vulnerable configs", () => {
    expect(vulnerableConfigs.length).toBeGreaterThanOrEqual(10);
  });

  it("every config has a unique ID", () => {
    const ids = vulnerableConfigs.map((c) => c.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it("every config has required fields", () => {
    for (const config of vulnerableConfigs) {
      expect(config.id).toBeTruthy();
      expect(config.name).toBeTruthy();
      expect(config.description).toBeTruthy();
      expect(config.category).toBeTruthy();
      expect(config.files.length).toBeGreaterThan(0);
      expect(config.expectedFindings.length).toBeGreaterThan(0);
    }
  });

  it("every file in every config has valid type", () => {
    const validTypes = [
      "claude-md",
      "settings-json",
      "mcp-json",
      "agent-md",
      "skill-md",
      "hook-script",
      "rule-md",
      "context-md",
      "unknown",
    ];

    for (const config of vulnerableConfigs) {
      for (const file of config.files) {
        expect(validTypes).toContain(file.type);
      }
    }
  });

  it("every expected finding has a valid severity", () => {
    const validSeverities = ["critical", "high", "medium", "low", "info"];

    for (const config of vulnerableConfigs) {
      for (const expected of config.expectedFindings) {
        expect(validSeverities).toContain(expected.severity);
        expect(expected.count).toBeGreaterThan(0);
        expect(expected.ruleId).toBeTruthy();
      }
    }
  });

  it("every expected rule ID references an actual rule", () => {
    const ruleIds = new Set(allRules.map((r) => r.id));

    for (const config of vulnerableConfigs) {
      for (const expected of config.expectedFindings) {
        expect(
          ruleIds.has(expected.ruleId),
          `Config "${config.id}" references unknown rule "${expected.ruleId}"`
        ).toBe(true);
      }
    }
  });

  it("every file has non-empty content", () => {
    for (const config of vulnerableConfigs) {
      for (const file of config.files) {
        expect(file.content.length).toBeGreaterThan(0);
        expect(file.path.length).toBeGreaterThan(0);
      }
    }
  });
});

// ─── Corpus Config Retrieval ──────────────────────────────

describe("corpus retrieval", () => {
  it("getCorpusConfigs returns all configs", () => {
    const configs = getCorpusConfigs();
    expect(configs.length).toBe(vulnerableConfigs.length);
  });

  it("getCorpusConfig returns a config by ID", () => {
    const config = getCorpusConfig("secrets-everywhere");
    expect(config).toBeDefined();
    expect(config!.name).toBe("Secrets Everywhere");
  });

  it("getCorpusConfig returns undefined for nonexistent ID", () => {
    expect(getCorpusConfig("nonexistent")).toBeUndefined();
  });
});

// ─── Individual Config Category Tests ─────────────────────

describe("corpus categories", () => {
  const configsByCategory = new Map<string, VulnerableConfig[]>();
  for (const config of vulnerableConfigs) {
    const existing = configsByCategory.get(config.category) ?? [];
    configsByCategory.set(config.category, [...existing, config]);
  }

  it("covers secrets category", () => {
    expect(configsByCategory.has("secrets")).toBe(true);
  });

  it("covers permissions category", () => {
    expect(configsByCategory.has("permissions")).toBe(true);
  });

  it("covers hooks category", () => {
    expect(configsByCategory.has("hooks")).toBe(true);
  });

  it("covers mcp category", () => {
    expect(configsByCategory.has("mcp")).toBe(true);
  });

  it("covers injection category", () => {
    expect(configsByCategory.has("injection")).toBe(true);
  });

  it("covers exfiltration category", () => {
    expect(configsByCategory.has("exfiltration")).toBe(true);
  });
});

// ─── Scanner Regression Tests ─────────────────────────────
// These validate that the scanner's built-in rules catch the
// expected findings in each corpus config, using rule-level tracking.

describe("corpus regression: scanner catches expected findings", () => {
  for (const config of vulnerableConfigs) {
    describe(`config: ${config.name} (${config.id})`, () => {
      const findingsByRule = scanConfig(config);

      for (const expected of config.expectedFindings) {
        it(`detects ${expected.ruleId} (>= ${expected.count} ${expected.severity})`, () => {
          const ruleFindings = findingsByRule.get(expected.ruleId) ?? [];

          expect(
            ruleFindings.length,
            `Expected >= ${expected.count} findings for rule "${expected.ruleId}" but got ${ruleFindings.length}. ` +
            `Actual findings from this rule: [${ruleFindings.map((f) => f.id).join(", ")}]`
          ).toBeGreaterThanOrEqual(expected.count);
        });
      }

      it("produces at least one finding overall", () => {
        let total = 0;
        for (const [, findings] of findingsByRule) {
          total += findings.length;
        }
        expect(total).toBeGreaterThan(0);
      });
    });
  }
});

// ─── Validate Corpus Function ─────────────────────────────

describe("validateCorpus", () => {
  it("returns correct totals", () => {
    const validation = validateCorpus(defaultRuleScanFn, allRules);

    expect(validation.totalConfigs).toBe(vulnerableConfigs.length);
    expect(validation.passed + validation.failed).toBe(validation.totalConfigs);
  });

  it("produces a result for each config", () => {
    const validation = validateCorpus(defaultRuleScanFn, allRules);

    expect(validation.results.length).toBe(vulnerableConfigs.length);

    const configIds = new Set(vulnerableConfigs.map((c) => c.id));
    for (const result of validation.results) {
      expect(configIds.has(result.configId)).toBe(true);
    }
  });

  it("marks configs as passed when all expected findings are detected", () => {
    const validation = validateCorpus(defaultRuleScanFn, allRules);

    // At least some configs should pass with the real scanner
    expect(validation.passed).toBeGreaterThan(0);
  });

  it("marks configs as failed when expected findings are missing", () => {
    // Use an empty scanner that returns nothing
    const emptyFn = () => new Map<string, ReadonlyArray<Finding>>();

    const validation = validateCorpus(emptyFn, allRules);

    expect(validation.failed).toBe(vulnerableConfigs.length);

    for (const result of validation.results) {
      expect(result.passed).toBe(false);
      expect(result.missingRules.length).toBeGreaterThan(0);
      expect(result.actualFindings).toBe(0);
    }
  });
});
