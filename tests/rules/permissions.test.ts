import { describe, it, expect } from "vitest";
import { permissionRules } from "../../src/rules/permissions.js";
import type { ConfigFile } from "../../src/types.js";

function makeSettings(content: string): ConfigFile {
  return { path: "settings.json", type: "settings-json", content };
}

function runAllPermRules(file: ConfigFile) {
  return permissionRules.flatMap((rule) => rule.check(file));
}

describe("permissionRules", () => {
  describe("overly permissive access", () => {
    it("flags Bash(*) in the allow list", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Bash(*)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.id.includes("permissive") && f.evidence === "Bash(*)")).toBe(true);
      expect(findings.find((f) => f.evidence === "Bash(*)")?.severity).toBe("critical");
    });

    it("flags Write(*) and Edit(*) in allow list", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Write(*)", "Edit(*)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.filter((f) => f.id.includes("permissive"))).toHaveLength(2);
    });

    it("does NOT flag Bash(sudo *) in deny list", () => {
      const file = makeSettings(JSON.stringify({
        permissions: {
          allow: ["Bash(git *)", "Read(*)"],
          deny: ["Bash(sudo *)", "Bash(rm -rf *)"],
        },
      }));
      const findings = runAllPermRules(file);
      const permissiveFindings = findings.filter((f) => f.id.includes("permissive"));
      expect(permissiveFindings).toHaveLength(0);
    });

    it("does NOT flag Bash(rm *) in deny list", () => {
      const file = makeSettings(JSON.stringify({
        permissions: {
          allow: ["Bash(git *)"],
          deny: ["Bash(rm -rf *)"],
        },
      }));
      const findings = runAllPermRules(file);
      const rmFindings = findings.filter((f) => f.evidence?.includes("rm"));
      expect(rmFindings).toHaveLength(0);
    });

    it("detects contradictory allow/deny entries", () => {
      const file = makeSettings(JSON.stringify({
        permissions: {
          allow: ["Bash(git *)", "Bash(rm -rf *)"],
          deny: ["Bash(rm -rf *)"],
        },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.title.includes("Contradictory"))).toBe(true);
    });
  });

  describe("missing deny list", () => {
    it("flags when no deny list exists", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Read(*)"] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.id === "permissions-no-deny-list")).toBe(true);
    });

    it("flags missing specific denials", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Read(*)"], deny: ["Bash(rm -rf *)"] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.title.includes("World-writable"))).toBe(true);
      expect(findings.some((f) => f.title.includes("SSH connections"))).toBe(true);
    });

    it("does not flag missing denials when deny list is empty", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Read(*)"] },
      }));
      const findings = runAllPermRules(file);
      // Should flag "no deny list" but NOT individual missing denials
      const missingDenials = findings.filter((f) => f.id.startsWith("permissions-missing-deny"));
      expect(missingDenials).toHaveLength(0);
    });
  });

  describe("dangerous bypass flags", () => {
    it("flags dangerously-skip-permissions in affirmative context", () => {
      const file = makeSettings('Use dangerously-skip-permissions for faster development');
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.severity === "critical" && f.title.includes("dangerously"))).toBe(true);
    });

    it("downgrades --no-verify when preceded by NEVER", () => {
      const file = makeSettings("Rules:\n- NEVER use --no-verify when committing");
      const findings = runAllPermRules(file);
      const noVerifyFindings = findings.filter((f) => f.evidence === "--no-verify");
      expect(noVerifyFindings).toHaveLength(1);
      expect(noVerifyFindings[0].severity).toBe("info");
      expect(noVerifyFindings[0].title).toContain("good practice");
    });

    it("downgrades when preceded by 'do not'", () => {
      const file = makeSettings("Do not use --no-verify");
      const findings = runAllPermRules(file);
      const noVerifyFindings = findings.filter((f) => f.evidence === "--no-verify");
      expect(noVerifyFindings[0].severity).toBe("info");
    });

    it("flags --no-verify in affirmative context", () => {
      const file = makeSettings("git commit --no-verify -m 'quick fix'");
      const findings = runAllPermRules(file);
      const noVerifyFindings = findings.filter((f) => f.evidence === "--no-verify");
      expect(noVerifyFindings[0].severity).toBe("critical");
    });

    it("skips non-settings files for permission rules", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "Bash(*)" };
      const findings = runAllPermRules(file);
      // Permissions rules only apply to settings-json
      // dangerous-skip rule applies to all files, but "Bash(*)" isn't a dangerous pattern
      const permissiveFindings = findings.filter((f) => f.id.includes("permissive"));
      expect(permissiveFindings).toHaveLength(0);
    });
  });
});
