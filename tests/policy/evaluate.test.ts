import { describe, it, expect, afterEach } from "vitest";
import { writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  loadPolicy,
  evaluatePolicy,
  renderPolicyEvaluation,
  generateExamplePolicy,
} from "../../src/policy/evaluate.js";
import type { Finding, SecurityScore, ConfigFile } from "../../src/types.js";
import type { OrgPolicy } from "../../src/policy/types.js";

const FIXTURES_DIR = join(process.cwd(), "tests", "policy", "__fixtures__");

function setup(): void {
  if (existsSync(FIXTURES_DIR)) {
    rmSync(FIXTURES_DIR, { recursive: true, force: true });
  }
  mkdirSync(FIXTURES_DIR, { recursive: true });
}

function cleanup(): void {
  if (existsSync(FIXTURES_DIR)) {
    rmSync(FIXTURES_DIR, { recursive: true, force: true });
  }
}

afterEach(cleanup);

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "test",
    severity: "medium",
    category: "permissions",
    title: "Test",
    description: "Test",
    file: "settings.json",
    ...overrides,
  };
}

function makeScore(numericScore: number): SecurityScore {
  return {
    grade: numericScore >= 90 ? "A" : numericScore >= 75 ? "B" : "C",
    numericScore,
    breakdown: { secrets: 0, permissions: 0, hooks: 0, mcp: 0, agents: 0 },
  };
}

function makeSettings(config: Record<string, unknown>): ConfigFile {
  return {
    path: "settings.json",
    type: "settings-json",
    content: JSON.stringify(config),
  };
}

function makeMcpConfig(servers: Record<string, unknown>): ConfigFile {
  return {
    path: "mcp.json",
    type: "mcp-json",
    content: JSON.stringify({ mcpServers: servers }),
  };
}

function makePolicy(overrides: Partial<OrgPolicy> = {}): OrgPolicy {
  return {
    version: 1,
    name: "Test Policy",
    required_deny_list: [],
    banned_mcp_servers: [],
    min_score: 60,
    max_severity: "critical",
    required_hooks: [],
    banned_tools: [],
    ...overrides,
  };
}

describe("loadPolicy", () => {
  it("loads a valid policy file", () => {
    setup();
    const path = join(FIXTURES_DIR, "policy.json");
    writeFileSync(path, JSON.stringify({
      version: 1,
      name: "Test",
      min_score: 80,
    }));

    const policy = loadPolicy(path);
    expect(policy).not.toBeNull();
    expect(policy!.min_score).toBe(80);
  });

  it("returns null for non-existent file", () => {
    expect(loadPolicy("/tmp/nonexistent-policy-test-12345.json")).toBeNull();
  });

  it("returns null for invalid JSON", () => {
    setup();
    const path = join(FIXTURES_DIR, "bad.json");
    writeFileSync(path, "not json");
    expect(loadPolicy(path)).toBeNull();
  });

  it("returns null for wrong version", () => {
    setup();
    const path = join(FIXTURES_DIR, "v2.json");
    writeFileSync(path, JSON.stringify({ version: 2 }));
    expect(loadPolicy(path)).toBeNull();
  });
});

describe("evaluatePolicy", () => {
  it("passes when all checks met", () => {
    const policy = makePolicy({ min_score: 60 });
    const files = [makeSettings({ permissions: { allow: ["Read"], deny: ["Bash"] } })];
    const result = evaluatePolicy(policy, [], makeScore(80), files);

    expect(result.passed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it("fails on score below minimum", () => {
    const policy = makePolicy({ min_score: 80 });
    const result = evaluatePolicy(policy, [], makeScore(50), []);

    expect(result.passed).toBe(false);
    expect(result.violations.some((v) => v.rule === "min_score")).toBe(true);
  });

  it("fails on findings exceeding max severity", () => {
    const policy = makePolicy({ max_severity: "medium" });
    const findings = [makeFinding({ severity: "critical" })];
    const result = evaluatePolicy(policy, findings, makeScore(80), []);

    expect(result.passed).toBe(false);
    expect(result.violations.some((v) => v.rule === "max_severity")).toBe(true);
  });

  it("passes when findings are within max severity", () => {
    const policy = makePolicy({ max_severity: "high" });
    const findings = [makeFinding({ severity: "high" })];
    const result = evaluatePolicy(policy, findings, makeScore(80), []);

    // "high" findings are at the threshold, not exceeding it
    expect(result.violations.some((v) => v.rule === "max_severity")).toBe(false);
  });

  it("fails on missing required deny patterns", () => {
    const policy = makePolicy({ required_deny_list: ["Bash(rm -rf"] });
    const files = [makeSettings({ permissions: { deny: ["Bash(curl"] } })];
    const result = evaluatePolicy(policy, [], makeScore(80), files);

    expect(result.passed).toBe(false);
    expect(result.violations.some((v) => v.rule === "required_deny_list")).toBe(true);
  });

  it("passes when required deny patterns present", () => {
    const policy = makePolicy({ required_deny_list: ["Bash(rm"] });
    const files = [makeSettings({ permissions: { deny: ["Bash(rm -rf /"] } })];
    const result = evaluatePolicy(policy, [], makeScore(80), files);

    expect(result.violations.some((v) => v.rule === "required_deny_list")).toBe(false);
  });

  it("fails on banned MCP servers", () => {
    const policy = makePolicy({ banned_mcp_servers: ["shell"] });
    const files = [makeMcpConfig({ shell: { command: "sh" } })];
    const result = evaluatePolicy(policy, [], makeScore(80), files);

    expect(result.passed).toBe(false);
    expect(result.violations.some((v) => v.rule === "banned_mcp_servers")).toBe(true);
  });

  it("supports wildcard banned server patterns", () => {
    const policy = makePolicy({ banned_mcp_servers: ["shell*"] });
    const files = [makeMcpConfig({ "shell-server": { command: "sh" } })];
    const result = evaluatePolicy(policy, [], makeScore(80), files);

    expect(result.passed).toBe(false);
    expect(result.violations.some((v) => v.rule === "banned_mcp_servers")).toBe(true);
  });

  it("passes when no banned servers present", () => {
    const policy = makePolicy({ banned_mcp_servers: ["shell"] });
    const files = [makeMcpConfig({ github: { command: "npx" } })];
    const result = evaluatePolicy(policy, [], makeScore(80), files);

    expect(result.violations.some((v) => v.rule === "banned_mcp_servers")).toBe(false);
  });

  it("fails on banned tools in allow list", () => {
    const policy = makePolicy({ banned_tools: ["Bash(*)"] });
    const files = [makeSettings({ permissions: { allow: ["Bash(*)", "Read"] } })];
    const result = evaluatePolicy(policy, [], makeScore(80), files);

    expect(result.passed).toBe(false);
    expect(result.violations.some((v) => v.rule === "banned_tools")).toBe(true);
  });

  it("fails on missing required hooks", () => {
    const policy = makePolicy({
      required_hooks: [
        { event: "PreToolUse", pattern: "agentshield", description: "Runtime monitor required" },
      ],
    });
    const files = [makeSettings({ hooks: {} })];
    const result = evaluatePolicy(policy, [], makeScore(80), files);

    expect(result.passed).toBe(false);
    expect(result.violations.some((v) => v.rule === "required_hooks")).toBe(true);
  });

  it("passes when required hooks present", () => {
    const policy = makePolicy({
      required_hooks: [
        { event: "PreToolUse", pattern: "agentshield" },
      ],
    });
    const files = [makeSettings({
      hooks: {
        PreToolUse: [{ matcher: "", hook: "node agentshield-hook.js" }],
      },
    })];
    const result = evaluatePolicy(policy, [], makeScore(80), files);

    expect(result.violations.some((v) => v.rule === "required_hooks")).toBe(false);
  });

  it("reports multiple violations", () => {
    const policy = makePolicy({
      min_score: 90,
      banned_mcp_servers: ["shell"],
      required_deny_list: ["Bash(rm"],
    });
    const files = [
      makeSettings({ permissions: { deny: [] } }),
      makeMcpConfig({ shell: { command: "sh" } }),
    ];
    const result = evaluatePolicy(policy, [], makeScore(50), files);

    expect(result.passed).toBe(false);
    expect(result.violations.length).toBeGreaterThanOrEqual(3);
  });
});

describe("renderPolicyEvaluation", () => {
  it("renders compliant evaluation", () => {
    const output = renderPolicyEvaluation({
      policyName: "My Policy",
      passed: true,
      violations: [],
      score: 85,
      minScore: 60,
    });

    expect(output).toContain("My Policy");
    expect(output).toContain("COMPLIANT");
  });

  it("renders non-compliant evaluation with violations", () => {
    const output = renderPolicyEvaluation({
      policyName: "Strict Policy",
      passed: false,
      violations: [
        {
          rule: "min_score",
          severity: "high",
          description: "Score too low",
          expected: "Score >= 80",
          actual: "Score = 50",
        },
      ],
      score: 50,
      minScore: 80,
    });

    expect(output).toContain("NON-COMPLIANT");
    expect(output).toContain("min_score");
    expect(output).toContain("Score too low");
  });
});

describe("generateExamplePolicy", () => {
  it("generates valid JSON", () => {
    const json = generateExamplePolicy();
    const parsed = JSON.parse(json);
    expect(parsed.version).toBe(1);
    expect(parsed.name).toBeTruthy();
  });

  it("includes all policy fields", () => {
    const parsed = JSON.parse(generateExamplePolicy());
    expect(parsed.required_deny_list).toBeDefined();
    expect(parsed.banned_mcp_servers).toBeDefined();
    expect(parsed.min_score).toBeDefined();
    expect(parsed.max_severity).toBeDefined();
    expect(parsed.required_hooks).toBeDefined();
    expect(parsed.banned_tools).toBeDefined();
  });
});
