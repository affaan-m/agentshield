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

    it("detects JWT tokens", () => {
      const file = makeFile("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("JWT token"))).toBe(true);
    });

    it("detects Google API keys", () => {
      const file = makeFile("key: AIzaSyA1234567890abcdefghijklmnopqrstuvw");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Google API key"))).toBe(true);
    });

    it("detects Stripe API keys", () => {
      const file = makeFile("sk_test_abcdefghijklmnopqrstuvwxyz1234");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Stripe API key"))).toBe(true);
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

  describe("secrets in CLAUDE.md", () => {
    it("detects API_KEY assignments in CLAUDE.md", () => {
      const file = makeFile("ANTHROPIC_API_KEY=sk-ant-real-key-here-1234", "claude-md");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("claude-md-env") && f.severity === "high")).toBe(true);
    });

    it("detects export SECRET_KEY assignments", () => {
      const file = makeFile('export SECRET_KEY="my-super-secret-value"', "claude-md");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("SECRET_KEY"))).toBe(true);
    });

    it("detects AUTH_TOKEN with colon separator", () => {
      const file = makeFile("AUTH_TOKEN: some-token-value-here", "claude-md");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("claude-md-env"))).toBe(true);
    });

    it("skips env var references like $VAR", () => {
      const file = makeFile("API_KEY=$MY_REAL_KEY", "claude-md");
      const findings = runAllSecretRules(file);
      const claudeMdFindings = findings.filter((f) => f.id.includes("claude-md-env"));
      expect(claudeMdFindings).toHaveLength(0);
    });

    it("skips non-CLAUDE.md files", () => {
      const file = makeFile("API_KEY=real-secret-here-1234", "settings-json");
      const findings = runAllSecretRules(file);
      const claudeMdFindings = findings.filter((f) => f.id.includes("claude-md-env"));
      expect(claudeMdFindings).toHaveLength(0);
    });

    it("skips non-sensitive variable names", () => {
      const file = makeFile("LOG_LEVEL=debug", "claude-md");
      const findings = runAllSecretRules(file);
      const claudeMdFindings = findings.filter((f) => f.id.includes("claude-md-env"));
      expect(claudeMdFindings).toHaveLength(0);
    });

    it("redacts evidence in findings", () => {
      const file = makeFile("API_KEY=super-secret-value-1234", "claude-md");
      const findings = runAllSecretRules(file);
      const finding = findings.find((f) => f.id.includes("claude-md-env"));
      expect(finding?.evidence).toContain("<redacted>");
      expect(finding?.evidence).not.toContain("super-secret");
    });
  });

  describe("sensitive env passthrough", () => {
    it("flags servers with more than 5 sensitive env vars", () => {
      const file: ConfigFile = {
        path: "mcp.json",
        type: "mcp-json",
        content: JSON.stringify({
          mcpServers: {
            myserver: {
              command: "node",
              env: {
                API_KEY: "$API_KEY",
                AUTH_TOKEN: "$AUTH_TOKEN",
                SECRET_VALUE: "$SECRET_VALUE",
                DB_PASSWORD: "$DB_PASSWORD",
                AWS_SECRET_KEY: "$AWS_SECRET_KEY",
                GITHUB_TOKEN: "$GITHUB_TOKEN",
              },
            },
          },
        }),
      };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("env-passthrough") && f.severity === "medium")).toBe(true);
    });

    it("does not flag servers with 5 or fewer sensitive env vars", () => {
      const file: ConfigFile = {
        path: "mcp.json",
        type: "mcp-json",
        content: JSON.stringify({
          mcpServers: {
            myserver: {
              command: "node",
              env: {
                API_KEY: "$API_KEY",
                AUTH_TOKEN: "$AUTH_TOKEN",
                NODE_ENV: "production",
              },
            },
          },
        }),
      };
      const findings = runAllSecretRules(file);
      const passthroughFindings = findings.filter((f) => f.id.includes("env-passthrough"));
      expect(passthroughFindings).toHaveLength(0);
    });

    it("skips non-mcp-json files", () => {
      const file = makeFile("some content", "settings-json");
      const findings = runAllSecretRules(file);
      const passthroughFindings = findings.filter((f) => f.id.includes("env-passthrough"));
      expect(passthroughFindings).toHaveLength(0);
    });
  });
});
