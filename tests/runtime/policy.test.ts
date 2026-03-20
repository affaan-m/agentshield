import { describe, it, expect, afterEach } from "vitest";
import { loadPolicy, generateDefaultPolicy } from "../../src/runtime/policy.js";
import { writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";

const FIXTURES_DIR = join(process.cwd(), "tests", "runtime", "__policy_fixtures__");

function setupFixtures(): void {
  if (!existsSync(FIXTURES_DIR)) {
    mkdirSync(FIXTURES_DIR, { recursive: true });
  }
}

function cleanupFixtures(): void {
  if (existsSync(FIXTURES_DIR)) {
    rmSync(FIXTURES_DIR, { recursive: true, force: true });
  }
}

describe("loadPolicy", () => {
  afterEach(() => cleanupFixtures());

  it("returns default policy for non-existent file", () => {
    const policy = loadPolicy("/tmp/nonexistent-policy-test-12345.json");
    expect(policy.version).toBe(1);
    expect(policy.deny).toEqual([]);
    expect(policy.log?.enabled).toBe(true);
  });

  it("loads a valid policy file", () => {
    setupFixtures();
    const policyPath = join(FIXTURES_DIR, "policy.json");
    writeFileSync(
      policyPath,
      JSON.stringify({
        version: 1,
        deny: [
          { tool: "Bash", pattern: "rm -rf", reason: "No destructive ops" },
        ],
        log: { enabled: true, path: "test.ndjson" },
      })
    );

    const policy = loadPolicy(policyPath);
    expect(policy.version).toBe(1);
    expect(policy.deny).toHaveLength(1);
    expect(policy.deny[0].tool).toBe("Bash");
    expect(policy.deny[0].pattern).toBe("rm -rf");
  });

  it("returns default policy for invalid JSON", () => {
    setupFixtures();
    const policyPath = join(FIXTURES_DIR, "bad.json");
    writeFileSync(policyPath, "not valid json{{{");

    const policy = loadPolicy(policyPath);
    expect(policy.version).toBe(1);
    expect(policy.deny).toEqual([]);
  });

  it("returns default policy for invalid schema", () => {
    setupFixtures();
    const policyPath = join(FIXTURES_DIR, "bad-schema.json");
    writeFileSync(
      policyPath,
      JSON.stringify({ version: 99, deny: "not-an-array" })
    );

    const policy = loadPolicy(policyPath);
    expect(policy.version).toBe(1);
    expect(policy.deny).toEqual([]);
  });

  it("handles policy with defaults for optional fields", () => {
    setupFixtures();
    const policyPath = join(FIXTURES_DIR, "minimal.json");
    writeFileSync(
      policyPath,
      JSON.stringify({ version: 1 })
    );

    const policy = loadPolicy(policyPath);
    expect(policy.version).toBe(1);
    expect(policy.deny).toEqual([]);
  });
});

describe("generateDefaultPolicy", () => {
  it("generates valid JSON", () => {
    const policyStr = generateDefaultPolicy();
    const policy = JSON.parse(policyStr);
    expect(policy.version).toBe(1);
  });

  it("includes example deny rules", () => {
    const policy = JSON.parse(generateDefaultPolicy());
    expect(policy.deny.length).toBeGreaterThan(0);
    expect(policy.deny[0].tool).toBe("Bash");
  });

  it("includes rate limit config", () => {
    const policy = JSON.parse(generateDefaultPolicy());
    expect(policy.rateLimit).toBeDefined();
    expect(policy.rateLimit.maxPerMinute).toBeGreaterThan(0);
  });

  it("includes log config", () => {
    const policy = JSON.parse(generateDefaultPolicy());
    expect(policy.log.enabled).toBe(true);
    expect(policy.log.path).toContain("ndjson");
  });
});
