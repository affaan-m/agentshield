import { existsSync, readFileSync } from "node:fs";
import { z } from "zod";
import type { ConfigFile, Finding, FindingCategory, Rule, Severity } from "../types.js";

/**
 * External rule-pack loader (`--rule-pack`).
 *
 * AgentShield's built-in detectors are declarative (id/severity/category/pattern
 * rows). This loads the same shape from an external JSON pack so scans can run
 * community detection rules (e.g. the MIT Agent Threat Rules pack) without
 * recompiling the binary. Generic: anyone with a pack in this shape can plug in.
 *
 * Security note: patterns are compiled to RegExp and run against file content.
 * Packs are loaded only when the operator explicitly passes `--rule-pack`, so
 * they are trusted input, but we still fail closed on invalid JSON, bad schema,
 * or any pattern that does not compile, and we cap findings per rule per file to
 * bound pathological packs. ReDoS-hardening of arbitrary external patterns is a
 * known v1 limitation (documented for the loader, same as any regex linter).
 */

const MAX_FINDINGS_PER_RULE_PER_FILE = 200;

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);

const CategorySchema = z.enum([
  "secrets",
  "permissions",
  "hooks",
  "mcp",
  "skills",
  "agents",
  "injection",
  "exposure",
  "exfiltration",
  "misconfiguration",
]);

const RulePackEntrySchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  severity: SeveritySchema,
  category: CategorySchema,
  patterns: z.array(z.string().min(1)).min(1),
  flags: z.string().optional(),
  fileTypes: z.array(z.string()).optional(),
});

export const RulePackSchema = z.object({
  version: z.literal(1),
  name: z.string().optional(),
  description: z.string().optional(),
  rules: z.array(RulePackEntrySchema).min(1),
});

export type RulePackEntry = z.infer<typeof RulePackEntrySchema>;
export type RulePack = z.infer<typeof RulePackSchema>;

export interface LoadRulePackResult {
  readonly success: boolean;
  readonly rules?: ReadonlyArray<Rule>;
  readonly meta?: { readonly name: string; readonly ruleCount: number };
  readonly error?: string;
}

function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split("\n").length;
}

function findAllMatches(content: string, pattern: RegExp): Array<RegExpMatchArray> {
  return [...content.matchAll(pattern)];
}

/** Ensure the global flag is present (matchAll requires it) and dedupe flags. */
function normalizeFlags(flags: string | undefined): string {
  const set = new Set((flags ?? "").split(""));
  set.add("g");
  return [...set].join("");
}

function compileEntryPatterns(entry: RulePackEntry): ReadonlyArray<RegExp> {
  const flags = normalizeFlags(entry.flags);
  return entry.patterns.map((source) => new RegExp(source, flags));
}

function entryToRule(entry: RulePackEntry, compiled: ReadonlyArray<RegExp>): Rule {
  const fileTypes = entry.fileTypes ? new Set(entry.fileTypes) : null;
  return {
    id: `external-${entry.id}`,
    name: entry.name,
    description: entry.description ?? entry.name,
    severity: entry.severity as Severity,
    category: entry.category as FindingCategory,
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (fileTypes && !fileTypes.has(file.type)) return [];

      const findings: Finding[] = [];
      let seq = 0;
      for (const pattern of compiled) {
        for (const match of findAllMatches(file.content, pattern)) {
          findings.push({
            id: `external-${entry.id}-${seq}`,
            severity: entry.severity as Severity,
            category: entry.category as FindingCategory,
            title: entry.name,
            description: `${entry.description ?? entry.name} (external rule ${entry.id}).`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
          seq += 1;
          if (findings.length >= MAX_FINDINGS_PER_RULE_PER_FILE) return findings;
        }
      }
      return findings;
    },
  };
}

/**
 * Load and validate an external rule pack from a JSON file path, returning
 * ready-to-run Rule objects. Fails closed on missing file, invalid JSON, schema
 * mismatch, duplicate ids, or any pattern that does not compile.
 */
export function loadRulePack(rulePackPath: string): LoadRulePackResult {
  if (!existsSync(rulePackPath)) {
    return { success: false, error: `Rule pack not found: ${rulePackPath}` };
  }

  let pack: RulePack;
  try {
    pack = RulePackSchema.parse(JSON.parse(readFileSync(rulePackPath, "utf-8")));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, error: `Invalid rule pack ${rulePackPath}: ${message}` };
  }

  const seenIds = new Set<string>();
  const rules: Rule[] = [];
  for (const entry of pack.rules) {
    if (seenIds.has(entry.id)) {
      return { success: false, error: `Duplicate rule id in pack: ${entry.id}` };
    }
    seenIds.add(entry.id);

    let compiled: ReadonlyArray<RegExp>;
    try {
      compiled = compileEntryPatterns(entry);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: `Rule "${entry.id}" has an invalid pattern: ${message}` };
    }
    rules.push(entryToRule(entry, compiled));
  }

  return {
    success: true,
    rules,
    meta: { name: pack.name ?? rulePackPath, ruleCount: rules.length },
  };
}

/**
 * Load several rule packs and concatenate their rules. Returns the first error
 * encountered, or all rules plus per-pack metadata on success.
 */
export function loadRulePacks(paths: ReadonlyArray<string>): {
  readonly success: boolean;
  readonly rules: ReadonlyArray<Rule>;
  readonly packs: ReadonlyArray<{ name: string; ruleCount: number }>;
  readonly error?: string;
} {
  const rules: Rule[] = [];
  const packs: Array<{ name: string; ruleCount: number }> = [];
  for (const path of paths) {
    const result = loadRulePack(path);
    if (!result.success || !result.rules || !result.meta) {
      return { success: false, rules: [], packs: [], error: result.error };
    }
    rules.push(...result.rules);
    packs.push(result.meta);
  }
  return { success: true, rules, packs };
}
