#!/usr/bin/env node
// Runs one named vitest batch with an explicit file list so the batches do
// not depend on shell glob expansion (npm runs scripts through cmd.exe on
// Windows, which leaves *.test.ts untouched and vitest then finds nothing).
import { spawnSync } from "node:child_process";
import { globSync } from "glob";

const BATCHES = {
  core: ["tests/rules/*.test.ts", "tests/scanner/*.test.ts", "tests/reporter/*.test.ts"],
  analysis: [
    "tests/integration.test.ts",
    "tests/injection.test.ts",
    "tests/action.test.ts",
    "tests/action-policy.test.ts",
    "tests/action-supply-chain.test.ts",
    "tests/action-hardening.test.ts",
    "tests/action-promotion.test.ts",
    "tests/action-baseline.test.ts",
  ],
  "miniclaw-a": ["tests/miniclaw/index.test.ts", "tests/miniclaw/server.test.ts", "tests/miniclaw/integration.test.ts"],
  "miniclaw-b": ["tests/miniclaw/cli.test.ts", "tests/miniclaw/sandbox.test.ts"],
  misc: [
    "tests/corpus.test.ts",
    "tests/logger.test.ts",
    "tests/init/init.test.ts",
    "tests/taint/taint.test.ts",
    "tests/opus/*.test.ts",
    "tests/fixer/*.test.ts",
    "tests/types.test.ts",
    "tests/skills/*.test.ts",
    "tests/llm/*.test.ts",
    "tests/compliance/*.test.ts",
    "tests/miniclaw/router.test.ts",
    "tests/miniclaw/tools.test.ts",
    "tests/miniclaw/types.test.ts",
    "tests/sandbox/sandbox.test.ts",
    "tests/threat-intel/*.test.ts",
    "tests/watch/*.test.ts",
    "tests/runtime/*.test.ts",
    "tests/baseline/*.test.ts",
    "tests/evidence-pack/*.test.ts",
    "tests/supply-chain/*.test.ts",
    "tests/policy/*.test.ts",
    "tests/sponsor-surface.test.ts",
  ],
};

const name = process.argv[2];
const patterns = BATCHES[name];
if (!patterns) {
  console.error(`Unknown test batch "${name}". Known: ${Object.keys(BATCHES).join(", ")}`);
  process.exit(2);
}

const files = [...new Set(patterns.flatMap((pattern) => globSync(pattern, { posix: true })))].sort();
if (files.length === 0) {
  console.error(`Batch "${name}" matched no test files.`);
  process.exit(1);
}

const vitest = process.platform === "win32" ? "npx.cmd" : "npx";
const result = spawnSync(vitest, ["vitest", "run", ...files], { stdio: "inherit", shell: process.platform === "win32" });
process.exit(result.status ?? 1);
