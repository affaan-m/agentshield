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

    it("detects npm access tokens", () => {
      const file = makeFile("npm_abcdefghijklmnopqrstuvwxyz1234567890AB");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("npm access token"))).toBe(true);
    });

    it("detects SendGrid API keys", () => {
      // Build the test key programmatically to avoid triggering GitHub push protection
      const prefix = "SG";
      const part1 = "FAKE_TEST_KEY_12345678";
      const part2 = "FAKE_DEMO_NOT_REAL_abcdefghijklmnopqrstuvwxyz12345";
      const file = makeFile(`${prefix}.${part1}.${part2}`);
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("SendGrid API key"))).toBe(true);
    });

    it("skips env var references like ${VAR}", () => {
      const file = makeFile('token: "${ANTHROPIC_API_KEY}"');
      const findings = runAllSecretRules(file);
      // Should not detect anything since it's an env var reference
      const secretFindings = findings.filter((f) => f.category === "secrets" && f.severity === "critical");
      expect(secretFindings).toHaveLength(0);
    });

    it("skips process.env references", () => {
      const file = makeFile("const key = process.env.sk-ant-api03-PLACEHOLDER_ONLY");
      const findings = runAllSecretRules(file);
      const secretFindings = findings.filter((f) => f.category === "secrets" && f.severity === "critical");
      expect(secretFindings).toHaveLength(0);
    });

    it("detects secrets in multiline content", () => {
      const file = makeFile("line 1\nline 2\nline 3\nkey: sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890\nline 5");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Anthropic API key"))).toBe(true);
      expect(findings[0].line).toBe(4);
    });

    it("reports correct line number", () => {
      const file = makeFile("a\nb\nc\nghp_abcdefghijklmnopqrstuvwxyz1234567890AB");
      const findings = runAllSecretRules(file);
      const finding = findings.find((f) => f.title.includes("GitHub personal access token"));
      expect(finding?.line).toBe(4);
    });

    it("detects Twilio API keys", () => {
      // Build programmatically to avoid GitHub push protection
      const key = "SK" + "0123456789abcdef".repeat(2);
      const file = makeFile(key);
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Twilio API key"))).toBe(true);
    });

    it("detects Mailchimp API keys", () => {
      // Build programmatically to avoid GitHub push protection
      const key = "0123456789abcdef".repeat(2) + "-us12";
      const file = makeFile(key);
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Mailchimp API key"))).toBe(true);
    });

    it("detects Stripe publishable keys", () => {
      const file = makeFile("pk_live_abcdefghijklmnopqrstuvwxyz1234");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Stripe API key"))).toBe(true);
    });

    it("detects multiple secrets in the same file", () => {
      const file = makeFile("key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890\ntoken: ghp_abcdefghijklmnopqrstuvwxyz1234567890AB");
      const findings = runAllSecretRules(file);
      expect(findings.length).toBeGreaterThanOrEqual(2);
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

  describe("URL-embedded credentials", () => {
    it("detects https://user:pass@host in agent files", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "Connect to https://admin:secret123@api.example.com/v1" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("url-credentials"))).toBe(true);
    });

    it("detects http://user:pass@host in CLAUDE.md", () => {
      const file: ConfigFile = { path: "CLAUDE.md", type: "claude-md", content: "Registry: http://deploy:token@registry.io:5000" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("url-credentials"))).toBe(true);
    });

    it("masks password in evidence", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "https://user:mysecretpassword@host.com/api" };
      const findings = runAllSecretRules(file);
      const finding = findings.find((f) => f.id.includes("url-credentials"));
      expect(finding?.evidence).toContain("****");
      expect(finding?.evidence).not.toContain("mysecretpassword");
    });

    it("does not flag URLs without credentials", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "Connect to https://api.example.com/v1" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("url-credentials"))).toBe(false);
    });

    it("does not flag non-agent files", () => {
      const file: ConfigFile = { path: "mcp.json", type: "mcp-json", content: "https://admin:pass@host.com" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("url-credentials"))).toBe(false);
    });

    it("skips env var references", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "${API_URL}https://user:pass@host.com" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("url-credentials"))).toBe(false);
    });
  });

  describe("credential file reference", () => {
    it("detects ~/.aws/credentials reference in agent", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "Read ~/.aws/credentials for the access key" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("cred-file-ref"))).toBe(true);
    });

    it("detects ~/.ssh/id_rsa reference in CLAUDE.md", () => {
      const file: ConfigFile = { path: "CLAUDE.md", type: "claude-md", content: "Copy ~/.ssh/id_rsa to the server" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("cred-file-ref"))).toBe(true);
    });

    it("detects ~/.ssh/id_ed25519 reference", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "Use ~/.ssh/id_ed25519 for authentication" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("cred-file-ref"))).toBe(true);
    });

    it("detects ~/.netrc reference", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "Configure ~/.netrc with credentials" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("cred-file-ref"))).toBe(true);
    });

    it("detects ~/.docker/config.json reference", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "Read ~/.docker/config.json for registry auth" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("cred-file-ref"))).toBe(true);
    });

    it("detects ~/.kube/config reference", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "Use ~/.kube/config to connect to cluster" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("cred-file-ref"))).toBe(true);
    });

    it("does not flag non-agent files", () => {
      const file: ConfigFile = { path: "mcp.json", type: "mcp-json", content: "~/.aws/credentials" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("cred-file-ref"))).toBe(false);
    });

    it("does not flag normal file paths", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "Read src/config.json for settings" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("cred-file-ref"))).toBe(false);
    });
  });

  describe("base64 obfuscation", () => {
    it("detects long base64 strings in agent files", () => {
      // 80 chars of base64 — likely an encoded secret or payload
      const base64 = "A".repeat(60) + "B".repeat(20) + "==";
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: `Run this: ${base64}` };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("base64-obfuscation"))).toBe(true);
    });

    it("detects long base64 strings in CLAUDE.md", () => {
      const base64 = "c2VjcmV0" + "A".repeat(60) + "==";
      const file: ConfigFile = { path: "CLAUDE.md", type: "claude-md", content: `Decode: ${base64}` };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("base64-obfuscation"))).toBe(true);
    });

    it("does not flag short base64 strings", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "token: c2VjcmV0" };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("base64-obfuscation"))).toBe(false);
    });

    it("does not flag base64 in URLs", () => {
      const base64 = "A".repeat(80);
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: `https://example.com/data/${base64}` };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("base64-obfuscation"))).toBe(false);
    });

    it("does not flag hex-only strings", () => {
      const hex = "a".repeat(64) + "f".repeat(20);
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: `hash: ${hex}` };
      const findings = runAllSecretRules(file);
      const base64Findings = findings.filter((f) => f.id.includes("base64-obfuscation"));
      expect(base64Findings).toHaveLength(0);
    });

    it("does not flag non-agent/claude-md files", () => {
      const base64 = "A".repeat(80);
      const file: ConfigFile = { path: "mcp.json", type: "mcp-json", content: base64 };
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.id.includes("base64-obfuscation"))).toBe(false);
    });

    it("truncates evidence in output", () => {
      const base64 = "A".repeat(60) + "Z".repeat(20) + "==";
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: base64 };
      const findings = runAllSecretRules(file);
      const finding = findings.find((f) => f.id.includes("base64-obfuscation"));
      expect(finding?.evidence).toContain("...");
      expect(finding!.evidence!.length).toBeLessThan(base64.length);
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

  describe("new secret patterns", () => {
    it("detects Hugging Face tokens", () => {
      const file = makeFile("hf_abcdefghijklmnopqrstuvwxyz1234");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Hugging Face"))).toBe(true);
    });

    it("detects Databricks tokens", () => {
      // Build programmatically to avoid GitHub push protection
      const token = "dapi" + "0123456789abcdef".repeat(2);
      const file = makeFile(token);
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Databricks"))).toBe(true);
    });

    it("detects DigitalOcean tokens", () => {
      const token = "dop_v1_" + "a".repeat(64);
      const file = makeFile(token);
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("DigitalOcean"))).toBe(true);
    });

    it("does not flag short hf_ prefixes", () => {
      const file = makeFile("hf_short");
      const findings = runAllSecretRules(file);
      expect(findings.some((f) => f.title.includes("Hugging Face"))).toBe(false);
    });
  });
});
