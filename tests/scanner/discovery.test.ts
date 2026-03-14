import { describe, it, expect } from "vitest";
import { discoverConfigFiles } from "../../src/scanner/discovery.js";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "agentshield-test-"));
}

describe("discoverConfigFiles", () => {
  it("discovers CLAUDE.md at root", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "CLAUDE.md"), "# Instructions");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "claude-md")).toBe(true);
    expect(result.files.some((f) => f.content === "# Instructions")).toBe(true);
  });

  it("discovers .claude/CLAUDE.md", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, ".claude"));
    writeFileSync(join(dir, ".claude", "CLAUDE.md"), "# Project rules");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "claude-md")).toBe(true);
  });

  it("discovers settings.json", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "settings.json"), '{"permissions":{}}');

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "settings-json")).toBe(true);
  });

  it("discovers mcp.json", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "mcp.json"), '{"mcpServers":{}}');

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "mcp-json")).toBe(true);
  });

  it("discovers agent files in agents/ subdirectory", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "agents"));
    writeFileSync(join(dir, "agents", "helper.md"), "Agent prompt");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "agent-md")).toBe(true);
  });

  it("discovers .claude/agents/ subdirectory", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, ".claude"));
    mkdirSync(join(dir, ".claude", "agents"));
    writeFileSync(join(dir, ".claude", "agents", "coder.md"), "Coder agent");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "agent-md")).toBe(true);
  });

  it("discovers hook scripts", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "hooks"));
    writeFileSync(join(dir, "hooks", "pre-commit.sh"), "#!/bin/bash\necho hello");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "hook-script")).toBe(true);
  });

  it("discovers executable scripts referenced from hooks/hooks.json manifests", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "hooks"));
    mkdirSync(join(dir, "scripts"));
    mkdirSync(join(dir, "scripts", "hooks"));
    mkdirSync(join(dir, "skills"));
    mkdirSync(join(dir, "skills", "observe"));
    mkdirSync(join(dir, "skills", "observe", "hooks"));

    writeFileSync(
      join(dir, "hooks", "hooks.json"),
      JSON.stringify({
        hooks: {
          PreToolUse: [
            {
              matcher: "Bash",
              hooks: [
                {
                  command: 'node "${CLAUDE_PLUGIN_ROOT}/scripts/hooks/run-with-flags.js" "pre:observe" "skills/observe/hooks/observe.sh" "strict"',
                },
              ],
            },
          ],
          Stop: [
            {
              matcher: "*",
              hooks: [
                {
                  command: 'node "${CLAUDE_PLUGIN_ROOT}/scripts/hooks/session-end.js"',
                },
              ],
            },
          ],
        },
      })
    );

    writeFileSync(join(dir, "scripts", "hooks", "run-with-flags.js"), "console.log('wrapper');");
    writeFileSync(join(dir, "scripts", "hooks", "session-end.js"), "console.log('session end');");
    writeFileSync(join(dir, "skills", "observe", "hooks", "observe.sh"), "#!/bin/bash\necho observe");

    const result = discoverConfigFiles(dir);
    expect(
      result.files.some((f) => f.path === "scripts/hooks/run-with-flags.js" && f.type === "hook-code")
    ).toBe(true);
    expect(
      result.files.some((f) => f.path === "scripts/hooks/session-end.js" && f.type === "hook-code")
    ).toBe(true);
    expect(
      result.files.some((f) => f.path === "skills/observe/hooks/observe.sh" && f.type === "hook-script")
    ).toBe(true);
  });

  it("discovers local script arguments in hook wrapper commands without treating home-directory paths as repo files", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "hooks"));
    mkdirSync(join(dir, "scripts"));
    mkdirSync(join(dir, "scripts", "hooks"));

    writeFileSync(
      join(dir, "hooks", "hooks.json"),
      JSON.stringify({
        hooks: {
          SessionStart: [
            {
              matcher: "*",
              hooks: [
                {
                  command: `bash -lc 'if [ -f "$HOME/.claude/plugins/demo/scripts/hooks/run-with-flags.js" ]; then node "$HOME/.claude/plugins/demo/scripts/hooks/run-with-flags.js" "session:start" "scripts/hooks/session-start.js"; fi'`,
                },
              ],
            },
          ],
        },
      })
    );

    writeFileSync(join(dir, "scripts", "hooks", "session-start.js"), "console.log('session start');");

    const result = discoverConfigFiles(dir);
    expect(
      result.files.some((f) => f.path === "scripts/hooks/session-start.js" && f.type === "hook-code")
    ).toBe(true);
    expect(result.files.some((f) => f.path.includes(".claude/plugins/demo"))).toBe(false);
  });

  it("treats hook README files as documentation, not executable hooks", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "hooks"));
    writeFileSync(join(dir, "hooks", "README.md"), "Run pip install example-package");

    const result = discoverConfigFiles(dir);
    const readme = result.files.find((f) => f.path === "hooks/README.md");
    expect(readme?.type).toBe("unknown");
  });

  it("discovers .claude.json as mcp config", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".claude.json"), '{"mcpServers":{}}');

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "mcp-json")).toBe(true);
  });

  it("discovers MCP template JSON files under mcp-configs", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "mcp-configs"));
    writeFileSync(join(dir, "mcp-configs", "mcp-servers.json"), '{"mcpServers":{}}');
    writeFileSync(join(dir, "mcp-configs", "README.md"), "# MCP templates");

    const result = discoverConfigFiles(dir);
    expect(
      result.files.some((f) => f.path === "mcp-configs/mcp-servers.json" && f.type === "mcp-json")
    ).toBe(true);
    expect(
      result.files.some((f) => f.path === "mcp-configs/README.md" && f.type === "unknown")
    ).toBe(true);
  });

  it("returns empty files for empty directory", () => {
    const dir = createTempDir();
    const result = discoverConfigFiles(dir);
    expect(result.files).toHaveLength(0);
    expect(result.path).toBe(dir);
  });

  it("discovers skill files in skills/ subdirectory", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "skills"));
    writeFileSync(join(dir, "skills", "tdd.md"), "TDD workflow");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "skill-md")).toBe(true);
  });

  it("discovers command files in commands/ subdirectory", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "commands"));
    writeFileSync(join(dir, "commands", "deploy.md"), "Deploy command");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.type === "skill-md")).toBe(true);
  });

  it("discovers JSON subagents and slash commands in .claude directories", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, ".claude"));
    mkdirSync(join(dir, ".claude", "subagents"));
    mkdirSync(join(dir, ".claude", "slash-commands"));
    writeFileSync(
      join(dir, ".claude", "subagents", "reviewer.json"),
      '{"allowedTools":["Read","Bash"],"model":"claude-sonnet-4-5"}'
    );
    writeFileSync(
      join(dir, ".claude", "slash-commands", "review.json"),
      '{"prompt":"Run review","subagent":"reviewer"}'
    );

    const result = discoverConfigFiles(dir);
    expect(
      result.files.some((f) => f.path === ".claude/subagents/reviewer.json" && f.type === "agent-md")
    ).toBe(true);
    expect(
      result.files.some((f) => f.path === ".claude/slash-commands/review.json" && f.type === "skill-md")
    ).toBe(true);
  });

  it("discovers nested .claude/settings.local.json in monorepo subprojects", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "packages"));
    mkdirSync(join(dir, "packages", "launch-video"));
    mkdirSync(join(dir, "packages", "launch-video", ".claude"));
    writeFileSync(
      join(dir, "packages", "launch-video", ".claude", "settings.local.json"),
      '{"permissions":{"allow":["Bash(git status)"]}}'
    );

    const result = discoverConfigFiles(dir);
    const nestedSettings = result.files.find(
      (f) => f.path === "packages/launch-video/.claude/settings.local.json"
    );

    expect(nestedSettings?.type).toBe("settings-json");
  });

  it("ignores dependency .claude trees under node_modules", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "node_modules"));
    mkdirSync(join(dir, "node_modules", "demo-pkg"));
    mkdirSync(join(dir, "node_modules", "demo-pkg", ".claude"));
    writeFileSync(
      join(dir, "node_modules", "demo-pkg", ".claude", "settings.local.json"),
      '{"permissions":{"allow":["Bash(curl https://example.com)"]}}'
    );

    const result = discoverConfigFiles(dir);
    expect(
      result.files.some((f) => f.path === "node_modules/demo-pkg/.claude/settings.local.json")
    ).toBe(false);
  });

  it("discovers docs-only CLAUDE.md files without treating the subtree as a live root", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "docs"));
    mkdirSync(join(dir, "docs", "zh-CN"), { recursive: true });
    mkdirSync(join(dir, "docs", "zh-CN", "agents"), { recursive: true });
    writeFileSync(join(dir, "docs", "zh-CN", "CLAUDE.md"), "# translated guide");
    writeFileSync(join(dir, "docs", "zh-CN", "agents", "reviewer.md"), "tools: Bash");

    const result = discoverConfigFiles(dir);
    expect(
      result.files.some((f) => f.path === "docs/zh-CN/CLAUDE.md" && f.type === "claude-md")
    ).toBe(true);
    expect(result.files.some((f) => f.path === "docs/zh-CN/agents/reviewer.md")).toBe(false);
  });

  it("treats examples subtrees like docs-only example roots when no runtime companion exists", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "examples"));
    mkdirSync(join(dir, "examples", "demo"), { recursive: true });
    mkdirSync(join(dir, "examples", "demo", "agents"), { recursive: true });
    writeFileSync(join(dir, "examples", "demo", "CLAUDE.md"), "# sample app");
    writeFileSync(join(dir, "examples", "demo", "agents", "reviewer.md"), "tools: Bash");

    const result = discoverConfigFiles(dir);
    expect(
      result.files.some((f) => f.path === "examples/demo/CLAUDE.md" && f.type === "claude-md")
    ).toBe(true);
    expect(result.files.some((f) => f.path === "examples/demo/agents/reviewer.md")).toBe(false);
  });

  it("treats tutorial demo subtrees like docs-only example roots when no runtime companion exists", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "tutorials"));
    mkdirSync(join(dir, "tutorials", "demo-app"), { recursive: true });
    mkdirSync(join(dir, "tutorials", "demo-app", "agents"), { recursive: true });
    writeFileSync(join(dir, "tutorials", "demo-app", "CLAUDE.md"), "# tutorial walkthrough");
    writeFileSync(join(dir, "tutorials", "demo-app", "agents", "reviewer.md"), "tools: Bash");

    const result = discoverConfigFiles(dir);
    expect(
      result.files.some((f) => f.path === "tutorials/demo-app/CLAUDE.md" && f.type === "claude-md")
    ).toBe(true);
    expect(result.files.some((f) => f.path === "tutorials/demo-app/agents/reviewer.md")).toBe(
      false
    );
  });

  it("still discovers nested docs roots when runtime config companions exist", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "docs"));
    mkdirSync(join(dir, "docs", "plugin"), { recursive: true });
    mkdirSync(join(dir, "docs", "plugin", "agents"), { recursive: true });
    writeFileSync(join(dir, "docs", "plugin", "CLAUDE.md"), "# plugin docs");
    writeFileSync(join(dir, "docs", "plugin", "settings.json"), '{"permissions":{"allow":["Read(*)"]}}');
    writeFileSync(join(dir, "docs", "plugin", "agents", "reviewer.md"), "Agent prompt");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((f) => f.path === "docs/plugin/CLAUDE.md")).toBe(true);
    expect(result.files.some((f) => f.path === "docs/plugin/agents/reviewer.md")).toBe(true);
  });

  it("ignores generated .dmux worktree mirrors", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, ".dmux"));
    mkdirSync(join(dir, ".dmux", "worktrees"));
    mkdirSync(join(dir, ".dmux", "worktrees", "demo"));
    mkdirSync(join(dir, ".dmux", "worktrees", "demo", ".claude"));
    writeFileSync(
      join(dir, ".dmux", "worktrees", "demo", ".claude", "settings.local.json"),
      '{"permissions":{"allow":["Bash(curl https://example.com)"]}}'
    );

    const result = discoverConfigFiles(dir);
    expect(
      result.files.some((f) => f.path === ".dmux/worktrees/demo/.claude/settings.local.json")
    ).toBe(false);
  });
});
