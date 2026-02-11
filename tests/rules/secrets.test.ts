import { describe, it, expect } from "vitest";
import { secretRules } from "../../src/rules/secrets.js";
import type { ConfigFile } from "../../src/types.js";

function makeFile(content: string, type: ConfigFile["type"] = "claude-md"): ConfigFile {
  return { path: "test.md", type, content };
}

function runAllSecretRules(file: ConfigFile) {
  return secretRules.flatMap((rule) => rule.check(file));
}

describe("secretRules", () => {
  describe("hardcoded secrets detection", () => {
    it("detects Anthropic API keys", () => {
      const file = makeFile("key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Anthropic API key"))).toBe(true);
      expect(findings[0].severity).toBe("critical");
    });

    it("detects OpenAI API keys", () => {
      const file = makeFile("key: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("OpenAI API key"))).toBe(true);
    });

    it("detects GitHub PATs", () => {
      const file = makeFile("token: ghp_abcdefghijklmnopqrstuvwxyz1234567890AB");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("GitHub personal access token"))).toBe(true);
    });

    it("detects AWS access keys", () => {
      const file = makeFile("AKIAIOSFODNN7EXAMPLE1");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("AWS access key"))).toBe(true);
    });

    it("detects private keys", () => {
      const file = makeFile("-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Private key"))).toBe(true);
    });

    it("detects hardcoded passwords", () => {
      const file = makeFile('password = "super_secret_123"');
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Hardcoded password"))).toBe(true);
    });

    it("detects database connection strings", () => {
      const file = makeFile("postgres://admin:pass123@db.example.com:5432/mydb");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("connection string"))).toBe(true);
    });

    it("detects Slack tokens", () => {
      const file = makeFile("xoxb-1234567890-abcdefghij");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Slack API token"))).toBe(true);
    });

    it("skips env var references like ${VAR}", () => {
      const file = makeFile('token: "${ANTHROPIC_API_KEY}"');
      const findings = runAllSecretRules(file);
      // Should not detect anything since it's an env var reference
      const secretFindings = findings.filter((f) => f.category === "secrets" && f.severity === "critical");
      expect(secretFindings).toHaveLength(0);
    });

    it("returns no findings for clean config", () => {
      const file = makeFile("# Clean config\nNo secrets here\nUse env vars for everything");
      const findings = runAllSecretRules(file);
      expect(findings).toHaveLength(0);
    });

    it("masks secret evidence in output", () => {
      const file = makeFile("sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890");
      const findings = runAllSecretRules(file);
      expect(findings[0].evidence).toContain("...");
      expect(findings[0].evidence).not.toContain("abcdefghijklmnopqrstuvwxyz");
    });

    it("provides fix suggestions", () => {
      const file = makeFile("sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890");
      const findings = runAllSecretRules(file);
      expect(findings[0].fix).toBeDefined();
      expect(findings[0].fix?.after).toContain("${");
    });
  });

  describe("environment variable exposure", () => {
    it("detects echoed secrets", () => {
      const file = makeFile("echo $ANTHROPIC_API_KEY");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("echoed to terminal"))).toBe(true);
    });

    it("detects echoed tokens", () => {
      const file = makeFile("echo ${GITHUB_TOKEN}");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.severity === "high")).toBe(true);
    });
  });
});
