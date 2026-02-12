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

  describe("invalid JSON handling", () => {
    it("handles invalid JSON gracefully in overly-permissive", () => {
      const file = makeSettings("not valid json at all");
      const findings = runAllPermRules(file);
      const permFindings = findings.filter((f) => f.id.includes("permissive"));
      expect(permFindings).toHaveLength(0);
    });

    it("handles empty JSON object", () => {
      const file = makeSettings("{}");
      const findings = runAllPermRules(file);
      const permFindings = findings.filter(
        (f) => f.id.includes("permissive") || f.id === "permissions-no-deny-list"
      );
      expect(permFindings).toHaveLength(0);
    });

    it("flags Bash(sudo *) in allow list", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Bash(sudo apt install)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.severity === "critical" && f.evidence?.includes("sudo"))).toBe(true);
    });
  });

  describe("all mutable tools allowed", () => {
    it("flags when Bash + Write + Edit are all in allow list (scoped)", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Bash(git *)", "Write(src/*)", "Edit(src/*)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.id === "permissions-all-mutable-tools")).toBe(true);
    });

    it("does not flag when only two mutable tools present", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Write(src/*)", "Edit(src/*)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.id === "permissions-all-mutable-tools")).toBe(false);
    });

    it("does not double-flag when all three are wildcards", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Bash(*)", "Write(*)", "Edit(*)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      // Wildcards are already flagged by overly-permissive rule
      expect(findings.some((f) => f.id === "permissions-all-mutable-tools")).toBe(false);
    });

    it("flags mixed scoped and unscoped", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Bash(npm *)", "Write(*)", "Edit(src/*)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.id === "permissions-all-mutable-tools")).toBe(true);
    });
  });

  describe("sensitive path access", () => {
    it("flags Read(/etc/passwd) in allow list", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Read(/etc/passwd)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.id.includes("sensitive-path"))).toBe(true);
      expect(findings.find((f) => f.id.includes("sensitive-path"))?.severity).toBe("high");
    });

    it("flags Write(~/.ssh/*) in allow list", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Write(~/.ssh/*)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.title.includes("SSH"))).toBe(true);
    });

    it("flags Bash with /var/log path", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Read(/var/log/*)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.id.includes("sensitive-path"))).toBe(true);
    });

    it("does not flag normal project paths", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Read(src/*)", "Write(tests/*)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      const pathFindings = findings.filter((f) => f.id.includes("sensitive-path"));
      expect(pathFindings).toHaveLength(0);
    });
  });

  describe("destructive git commands", () => {
    it("flags git push --force in allow list", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Bash(git push --force)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.id.includes("destructive-git"))).toBe(true);
      expect(findings.find((f) => f.id.includes("destructive-git"))?.severity).toBe("high");
    });

    it("flags git push -f in allow list", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Bash(git push -f origin main)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.id.includes("destructive-git"))).toBe(true);
    });

    it("flags git reset --hard in allow list", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Bash(git reset --hard HEAD~1)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.title.includes("reset --hard"))).toBe(true);
    });

    it("flags git clean -fd in allow list", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Bash(git clean -fd)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.id.includes("destructive-git"))).toBe(true);
    });

    it("flags git branch -D in allow list", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Bash(git branch -D feature-branch)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      expect(findings.some((f) => f.title.includes("branch -D"))).toBe(true);
    });

    it("does not flag safe git commands", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Bash(git push)", "Bash(git commit)", "Bash(git branch -d)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      const gitFindings = findings.filter((f) => f.id.includes("destructive-git"));
      expect(gitFindings).toHaveLength(0);
    });

    it("does not flag non-settings files", () => {
      const file: ConfigFile = { path: "agent.md", type: "agent-md", content: "git push --force" };
      const findings = runAllPermRules(file);
      const gitFindings = findings.filter((f) => f.id.includes("destructive-git"));
      expect(gitFindings).toHaveLength(0);
    });

    it("provides fix suggestion", () => {
      const file = makeSettings(JSON.stringify({
        permissions: { allow: ["Bash(git push --force)"], deny: [] },
      }));
      const findings = runAllPermRules(file);
      const finding = findings.find((f) => f.id.includes("destructive-git"));
      expect(finding?.fix).toBeDefined();
      expect(finding?.fix?.description).toContain("force-with-lease");
    });
  });
});
