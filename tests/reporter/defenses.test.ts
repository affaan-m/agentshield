import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectDefenses } from "../../src/reporter/defenses.js";
import { calculateScore } from "../../src/reporter/score.js";
import { renderTerminalReport } from "../../src/reporter/terminal.js";
import { renderJsonReport, renderMarkdownReport } from "../../src/reporter/json.js";
import { renderHtmlReport } from "../../src/reporter/html.js";
import { scan } from "../../src/scanner/index.js";
import type { ConfigFile, ConfigFileType, Defense, SecurityReport } from "../../src/types.js";

function file(path: string, content: string, type: ConfigFileType = "settings-json"): ConfigFile {
  return { path, type, content };
}

function settings(body: Record<string, unknown>, path = ".claude/settings.json"): ConfigFile {
  return file(path, JSON.stringify(body, null, 2));
}

function ids(defenses: ReadonlyArray<Defense>): ReadonlyArray<string> {
  return defenses.map((defense) => defense.id);
}

function byId(defenses: ReadonlyArray<Defense>, id: string): Defense | undefined {
  return defenses.find((defense) => defense.id === id);
}

function makeReport(defenses: ReadonlyArray<Defense>): SecurityReport {
  return {
    timestamp: "2026-09-10T00:00:00.000Z",
    targetPath: "/tmp/hardened",
    findings: [],
    defenses,
    score: {
      grade: "A",
      numericScore: 100,
      breakdown: { secrets: 100, permissions: 100, hooks: 100, mcp: 100, agents: 100 },
    },
    summary: {
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      filesScanned: 1,
      autoFixable: 0,
      defenses: defenses.length,
    },
  };
}

function makeDefense(index: number): Defense {
  return {
    id: `defense-sample-${index}`,
    title: `Sample defense ${index}`,
    file: `file-${index}.json`,
    detail: "detail",
    harness: "generic",
  };
}

describe("detectDefenses: Claude Code settings", () => {
  it("credits a non-empty deny list and reports coverage", () => {
    const defenses = detectDefenses([
      settings({
        permissions: {
          deny: ["Read(./.env)", "Read(~/.ssh/**)", "Bash(curl *)", "Bash(sudo *)", "Bash(rm -rf *)"],
        },
      }),
    ]);
    const deny = byId(defenses, "defense-deny-list");
    expect(deny).toBeDefined();
    expect(deny?.harness).toBe("claude-code");
    expect(deny?.file).toBe(".claude/settings.json");
    expect(deny?.detail).toContain("5 deny rules");
    expect(deny?.detail).toContain("covers .env, ~/.ssh, curl, sudo, rm -rf");
    expect(deny?.detail).not.toContain("not covered");
  });

  it("names the common targets a deny list misses", () => {
    const defenses = detectDefenses([settings({ permissions: { deny: ["Bash(curl *)"] } })]);
    const deny = byId(defenses, "defense-deny-list");
    expect(deny?.detail).toContain("1 deny rule;");
    expect(deny?.detail).toContain("covers curl");
    expect(deny?.detail).toContain("not covered: .env, ~/.ssh, sudo, rm -rf");
  });

  it("does not credit an empty deny list or an allow-only config", () => {
    const defenses = detectDefenses([
      settings({ permissions: { deny: [], allow: ["Bash(*)"] } }),
    ]);
    expect(ids(defenses)).not.toContain("defense-deny-list");
    expect(ids(defenses)).not.toContain("defense-ask-list");
  });

  it("credits an ask list and ignores an empty one", () => {
    expect(ids(detectDefenses([settings({ permissions: { ask: ["Bash(git push *)"] } })]))).toContain(
      "defense-ask-list"
    );
    expect(ids(detectDefenses([settings({ permissions: { ask: [] } })]))).not.toContain("defense-ask-list");
  });

  it("credits plan and default modes but not bypass or auto modes", () => {
    expect(byId(detectDefenses([settings({ permissions: { defaultMode: "plan" } })]), "defense-default-mode")?.title).toBe(
      'Permission mode "plan"'
    );
    expect(ids(detectDefenses([settings({ permissions: { defaultMode: "default" } })]))).toContain("defense-default-mode");
    expect(ids(detectDefenses([settings({ permissions: { defaultMode: "bypassPermissions" } })]))).not.toContain(
      "defense-default-mode"
    );
    expect(ids(detectDefenses([settings({ permissions: { defaultMode: "acceptEdits" } })]))).not.toContain(
      "defense-default-mode"
    );
  });

  it("credits disableBypassPermissionsMode only when set to disable", () => {
    expect(
      ids(detectDefenses([settings({ permissions: { disableBypassPermissionsMode: "disable" } })]))
    ).toContain("defense-bypass-disabled");
    expect(
      ids(detectDefenses([settings({ permissions: { disableBypassPermissionsMode: "enable" } })]))
    ).not.toContain("defense-bypass-disabled");
  });

  it("credits blockReadsOutsideWorkingDirectories only when true", () => {
    expect(
      ids(detectDefenses([settings({ permissions: { blockReadsOutsideWorkingDirectories: true } })]))
    ).toContain("defense-block-reads-outside-cwd");
    expect(
      ids(detectDefenses([settings({ permissions: { blockReadsOutsideWorkingDirectories: false } })]))
    ).not.toContain("defense-block-reads-outside-cwd");
  });

  it("credits an enabled sandbox and describes its hardening", () => {
    const defenses = detectDefenses([
      settings({
        sandbox: {
          enabled: true,
          failIfUnavailable: true,
          network: { allowedDomains: ["api.anthropic.com", "registry.npmjs.org"] },
          filesystem: { denyRead: ["~/"] },
          credentials: { files: { mode: "mask" }, envVars: { mode: "deny" } },
        },
      }),
    ]);
    const sandbox = byId(defenses, "defense-sandbox-enabled");
    expect(sandbox).toBeDefined();
    expect(sandbox?.detail).toContain("fails closed when the sandbox is unavailable");
    expect(sandbox?.detail).toContain("network allow list of 2 domains with no wildcard");
    expect(sandbox?.detail).toContain("filesystem denyRead on ~/");
    expect(sandbox?.detail).toContain("credentials masked and denied");
  });

  it("does not describe a wildcard network allow list as an allow list", () => {
    const defenses = detectDefenses([
      settings({ sandbox: { enabled: true, network: { allowedDomains: ["*"] } } }),
    ]);
    const sandbox = byId(defenses, "defense-sandbox-enabled");
    expect(sandbox?.detail).toBe("sandbox.enabled is true with default network and filesystem policy.");
  });

  it("does not credit a disabled sandbox", () => {
    expect(ids(detectDefenses([settings({ sandbox: { enabled: false, failIfUnavailable: true } })]))).not.toContain(
      "defense-sandbox-enabled"
    );
  });

  it("credits managed-only and marketplace flags only when true", () => {
    const positive = detectDefenses([
      settings({
        allowManagedPermissionRulesOnly: true,
        allowManagedHooksOnly: true,
        allowManagedMcpServersOnly: true,
        strictKnownMarketplaces: true,
        disableSkillShellExecution: true,
      }),
    ]);
    expect(ids(positive)).toEqual(
      expect.arrayContaining([
        "defense-managed-permission-rules-only",
        "defense-managed-hooks-only",
        "defense-managed-mcp-servers-only",
        "defense-strict-marketplaces",
        "defense-skill-shell-disabled",
      ])
    );

    const negative = detectDefenses([
      settings({
        allowManagedPermissionRulesOnly: false,
        allowManagedHooksOnly: "true",
        allowManagedMcpServersOnly: 1,
        strictKnownMarketplaces: false,
        disableSkillShellExecution: false,
      }),
    ]);
    expect(negative).toHaveLength(0);
  });

  it("credits an explicit MCP server list unless every project server is enabled", () => {
    expect(byId(detectDefenses([settings({ enabledMcpjsonServers: ["github"] })]), "defense-explicit-mcp-servers")?.detail).toContain(
      "github"
    );
    expect(
      ids(detectDefenses([settings({ enabledMcpjsonServers: ["github"], enableAllProjectMcpServers: true })]))
    ).not.toContain("defense-explicit-mcp-servers");
    expect(ids(detectDefenses([settings({ enabledMcpjsonServers: [] })]))).not.toContain("defense-explicit-mcp-servers");
  });

  it("returns nothing for settings that do not parse", () => {
    expect(detectDefenses([file(".claude/settings.json", '{"permissions": {"deny": ["Bash(curl *)"')])).toHaveLength(0);
  });

  it("does not read Gemini, Cursor, or editor settings as Claude Code settings", () => {
    const defenses = detectDefenses([
      file(".zed/settings.json", JSON.stringify({ permissions: { deny: ["Bash(curl *)"] } })),
      file(".vscode/settings.json", JSON.stringify({ permissions: { deny: ["Bash(curl *)"] } })),
    ]);
    expect(ids(defenses)).not.toContain("defense-deny-list");
  });
});

describe("detectDefenses: blocking hooks", () => {
  function hookSettings(event: string, command: string): ConfigFile {
    return settings({
      hooks: {
        [event]: [{ matcher: "Bash", hooks: [{ type: "command", command }] }],
      },
    });
  }

  it("credits a PreToolUse hook whose inline command exits 2", () => {
    const defenses = detectDefenses([
      hookSettings("PreToolUse", "jq -e '.tool_input.command | test(\"rm -rf\")' && exit 2 || exit 0"),
    ]);
    const hook = byId(defenses, "defense-blocking-pretooluse-hook");
    expect(hook).toBeDefined();
    expect(hook?.title).toBe("Blocking PreToolUse hook");
    expect(hook?.detail).toContain("1 PreToolUse command hook can deny a call");
  });

  it("credits PermissionRequest and UserPromptSubmit hooks that emit a deny decision", () => {
    const defenses = detectDefenses([
      settings({
        hooks: {
          PermissionRequest: [{ hooks: [{ type: "command", command: "echo '{\"decision\":\"deny\"}'" }] }],
          UserPromptSubmit: [
            {
              hooks: [
                {
                  type: "command",
                  command:
                    "grep -qE 'sk-|ghp_|AKIA' && echo '{\"hookSpecificOutput\":{\"permissionDecision\":\"deny\"}}'",
                },
              ],
            },
          ],
        },
      }),
    ]);
    expect(ids(defenses)).toEqual(
      expect.arrayContaining([
        "defense-blocking-permissionrequest-hook",
        "defense-blocking-userpromptsubmit-hook",
      ])
    );
  });

  it("follows a referenced hook script and credits it when the script denies", () => {
    const defenses = detectDefenses([
      hookSettings("PreToolUse", "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/guard.sh\""),
      file(
        ".claude/hooks/guard.sh",
        "#!/bin/bash\ninput=$(cat)\nif echo \"$input\" | grep -q 'rm -rf'; then\n  echo 'blocked' >&2\n  exit 2\nfi\nexit 0\n",
        "hook-script"
      ),
    ]);
    expect(ids(defenses)).toContain("defense-blocking-pretooluse-hook");
  });

  it("does not credit a hook that only logs or only allows", () => {
    const defenses = detectDefenses([
      hookSettings("PreToolUse", "bash ./hooks/audit.sh"),
      file("hooks/audit.sh", "#!/bin/bash\ncat >> ~/.claude/audit.log\nexit 0\n", "hook-script"),
      settings({
        hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "echo '{\"decision\":\"allow\"}'" }] }] },
      }, ".claude/settings.local.json"),
    ]);
    expect(ids(defenses)).not.toContain("defense-blocking-pretooluse-hook");
  });

  it("does not credit a PostToolUse hook even when it exits 2", () => {
    expect(ids(detectDefenses([hookSettings("PostToolUse", "exit 2")]))).not.toContain(
      "defense-blocking-posttooluse-hook"
    );
  });

  it("credits a ConfigChange hook and reads plugin hooks manifests", () => {
    const defenses = detectDefenses([
      file(
        "hooks/hooks.json",
        JSON.stringify({
          hooks: {
            ConfigChange: [{ hooks: [{ type: "command", command: "${CLAUDE_PLUGIN_ROOT}/hooks/config-guard.sh" }] }],
            PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "node hooks/block-no-verify.js" }] }],
          },
        }),
        "plugin-manifest"
      ),
      file("hooks/block-no-verify.js", "if (/--no-verify/.test(cmd)) { process.exit(2); }\n", "hook-code"),
    ]);
    expect(ids(defenses)).toEqual(
      expect.arrayContaining(["defense-configchange-hook", "defense-blocking-pretooluse-hook"])
    );
    expect(byId(defenses, "defense-configchange-hook")?.harness).toBe("claude-code");
  });

  it("does not credit ConfigChange when the hooks block is absent", () => {
    expect(detectDefenses([settings({ hooks: {} })])).toHaveLength(0);
  });
});

describe("detectDefenses: skills and agents", () => {
  it("credits disable-model-invocation and narrow allowed-tools on a skill", () => {
    const defenses = detectDefenses([
      file(
        ".claude/skills/deploy/SKILL.md",
        "---\nname: deploy\ndisable-model-invocation: true\nallowed-tools: Read, Grep, Glob, Bash(git status *)\n---\n\nDeploy.\n",
        "skill-md"
      ),
    ]);
    expect(ids(defenses)).toEqual(
      expect.arrayContaining(["defense-skill-no-model-invocation", "defense-skill-narrow-tools"])
    );
    expect(byId(defenses, "defense-skill-narrow-tools")?.detail).toContain("Bash(git status *)");
  });

  it("does not credit a skill with broad tools or model invocation enabled", () => {
    const defenses = detectDefenses([
      file(
        ".claude/skills/deploy/SKILL.md",
        "---\nname: deploy\ndisable-model-invocation: false\nallowed-tools:\n  - Read\n  - Bash(*)\n---\n\nDeploy.\n",
        "skill-md"
      ),
      file(".claude/skills/write/SKILL.md", "---\nname: write\nallowed-tools: Read Write\n---\n", "skill-md"),
      file(".claude/skills/bare/SKILL.md", "---\nname: bare\nallowed-tools: Bash\n---\n", "skill-md"),
    ]);
    expect(defenses).toHaveLength(0);
  });

  it("credits an agent tools allow list that omits Write, Edit, and Bash", () => {
    const defenses = detectDefenses([
      file(".claude/agents/reviewer.md", "---\nname: reviewer\ntools: Read, Grep, Glob\n---\n\nReview.\n", "agent-md"),
    ]);
    expect(byId(defenses, "defense-agent-tools-allowlist")?.detail).toBe("tools is limited to Read, Grep, Glob.");
  });

  it("does not credit an agent whose tools include Bash or Edit, or that has no tools list", () => {
    const defenses = detectDefenses([
      file(".claude/agents/builder.md", "---\nname: builder\ntools: Read, Edit, Bash\n---\n", "agent-md"),
      file(".claude/agents/scoped.md", "---\nname: scoped\ntools: Read, Bash(git add *)\n---\n", "agent-md"),
      file(".claude/agents/open.md", "---\nname: open\ndescription: no tools key\n---\n", "agent-md"),
    ]);
    expect(ids(defenses)).not.toContain("defense-agent-tools-allowlist");
  });

  it("credits disallowedTools on markdown and JSON agents", () => {
    const defenses = detectDefenses([
      file(".claude/agents/reader.md", "---\nname: reader\ndisallowedTools: Write, Edit, Agent\n---\n", "agent-md"),
      file(
        ".claude/subagents/planner.json",
        JSON.stringify({ name: "planner", allowedTools: ["Read", "Grep"], disallowedTools: ["Bash"] }),
        "agent-md"
      ),
    ]);
    expect(defenses.filter((defense) => defense.id === "defense-agent-disallowed-tools")).toHaveLength(2);
    expect(ids(defenses)).toContain("defense-agent-tools-allowlist");
  });

  it("does not credit an agent with an empty disallowedTools list", () => {
    expect(
      ids(detectDefenses([file(".claude/agents/x.md", "---\nname: x\ndisallowedTools: []\n---\n", "agent-md")]))
    ).not.toContain("defense-agent-disallowed-tools");
  });
});

describe("detectDefenses: Codex", () => {
  it("credits read-only sandbox, on-request approvals, and env_http_headers", () => {
    const defenses = detectDefenses([
      file(
        ".codex/config.toml",
        'sandbox_mode = "read-only"\napproval_policy = "on-request"\n\n[mcp_servers.github]\nurl = "https://api.githubcopilot.com/mcp/"\nenv_http_headers = { Authorization = "GITHUB_TOKEN" }\n',
        "codex-toml"
      ),
    ]);
    expect(ids(defenses)).toEqual(
      expect.arrayContaining([
        "defense-codex-sandbox",
        "defense-codex-approval-policy",
        "defense-codex-env-http-headers",
      ])
    );
    expect(defenses.every((defense) => defense.harness === "codex")).toBe(true);
    expect(byId(defenses, "defense-codex-sandbox")?.title).toBe("Codex sandbox read-only");
  });

  it("credits workspace-write only when network access is off", () => {
    const off = detectDefenses([
      file(
        ".codex/config.toml",
        'sandbox_mode = "workspace-write"\napproval_policy = "on-failure"\n[sandbox_workspace_write]\nnetwork_access = false\n',
        "codex-toml"
      ),
    ]);
    expect(byId(off, "defense-codex-sandbox")?.detail).toContain("network_access is false");
    expect(byId(off, "defense-codex-approval-policy")?.title).toBe('Codex approval policy "on-failure"');

    const on = detectDefenses([
      file(
        ".codex/config.toml",
        'sandbox_mode = "workspace-write"\napproval_policy = "never"\n[sandbox_workspace_write]\nnetwork_access = true\n',
        "codex-toml"
      ),
    ]);
    expect(on).toHaveLength(0);
  });

  it("does not credit danger-full-access or literal http_headers", () => {
    const defenses = detectDefenses([
      file(
        ".codex/config.toml",
        'sandbox_mode = "danger-full-access"\n[mcp_servers.github]\nhttp_headers = { Authorization = "Bearer ghp_x" }\n',
        "codex-toml"
      ),
    ]);
    expect(defenses).toHaveLength(0);
  });

  it("returns nothing for a TOML file that does not parse", () => {
    expect(detectDefenses([file(".codex/config.toml", 'sandbox_mode = "read-only\n', "codex-toml")])).toHaveLength(0);
  });

  it("credits .rules files with forbidden or prompt decisions", () => {
    const defenses = detectDefenses([
      file(
        ".codex/rules/default.rules",
        'prefix_rule(pattern=["rm"], decision="forbidden")\nprefix_rule(pattern=["git", "push"], decision="prompt")\n',
        "unknown"
      ),
    ]);
    expect(byId(defenses, "defense-codex-rules-file")?.detail).toBe("1 forbidden and 1 prompt decisions gate command prefixes.");
  });

  it("does not credit .rules files that only allow", () => {
    expect(
      detectDefenses([file(".codex/rules/default.rules", 'prefix_rule(pattern=["ls"], decision="allow")\n', "unknown")])
    ).toHaveLength(0);
  });
});

describe("detectDefenses: Hermes", () => {
  it("credits manual approvals, cron deny, container terminal, and an empty allow list", () => {
    const defenses = detectDefenses([
      file(
        ".hermes/config.yaml",
        "approvals:\n  mode: manual\n  cron_mode: deny\n  command_allowlist: []\nterminal:\n  backend: docker\n",
        "hermes-yaml"
      ),
    ]);
    expect(ids(defenses)).toEqual([
      "defense-hermes-manual-approvals",
      "defense-hermes-cron-deny",
      "defense-hermes-container-terminal",
      "defense-hermes-empty-allowlist",
    ]);
    expect(defenses.every((defense) => defense.harness === "hermes")).toBe(true);
  });

  it("does not credit auto approvals, a local terminal, or a populated allow list", () => {
    const defenses = detectDefenses([
      file(
        ".hermes/config.yaml",
        "approvals:\n  mode: auto\n  cron_mode: allow\n  command_allowlist:\n    - ls\nterminal:\n  backend: local\n",
        "hermes-yaml"
      ),
    ]);
    expect(defenses).toHaveLength(0);
  });

  it("returns nothing for YAML that does not parse", () => {
    expect(detectDefenses([file(".hermes/config.yaml", "approvals: [mode: manual", "hermes-yaml")])).toHaveLength(0);
  });
});

describe("detectDefenses: Gemini, OpenCode, Cursor", () => {
  it("credits Gemini disableYoloMode and folderTrust", () => {
    const defenses = detectDefenses([
      file(
        ".gemini/settings.json",
        JSON.stringify({ security: { disableYoloMode: true, folderTrust: { enabled: true } } }),
        "harness-json"
      ),
    ]);
    expect(ids(defenses)).toEqual(["defense-gemini-yolo-disabled", "defense-gemini-folder-trust"]);
    expect(defenses[0].harness).toBe("gemini");
  });

  it("does not credit Gemini settings with yolo allowed and trust off", () => {
    expect(
      detectDefenses([
        file(
          ".gemini/settings.json",
          JSON.stringify({ security: { disableYoloMode: false, folderTrust: { enabled: false } } }),
          "harness-json"
        ),
      ])
    ).toHaveLength(0);
  });

  it("credits OpenCode permission.bash ask, deny, or an all-gated map", () => {
    expect(
      byId(
        detectDefenses([file("opencode.json", JSON.stringify({ permission: { bash: "ask" } }), "harness-json")]),
        "defense-opencode-bash-gate"
      )?.harness
    ).toBe("opencode");
    expect(
      ids(detectDefenses([file(".opencode/opencode.jsonc", '{ "permission": { "bash": "deny" }, }', "harness-json")]))
    ).toContain("defense-opencode-bash-gate");
    expect(
      ids(
        detectDefenses([
          file("opencode.json", JSON.stringify({ permission: { bash: { "*": "ask", "git status *": "deny" } } }), "harness-json"),
        ])
      )
    ).toContain("defense-opencode-bash-gate");
  });

  it("does not credit OpenCode permission.bash allow or a partially allowed map", () => {
    expect(
      detectDefenses([file("opencode.json", JSON.stringify({ permission: { bash: "allow" } }), "harness-json")])
    ).toHaveLength(0);
    expect(
      detectDefenses([
        file("opencode.json", JSON.stringify({ permission: { bash: { "*": "allow", "rm *": "deny" } } }), "harness-json"),
      ])
    ).toHaveLength(0);
  });

  it("credits Cursor hooks with failClosed true and names the events", () => {
    const defenses = detectDefenses([
      file(
        ".cursor/hooks.json",
        JSON.stringify({
          version: 1,
          hooks: {
            beforeShellExecution: [{ command: "./hooks/guard.sh", failClosed: true }],
            beforeMCPExecution: [{ command: "./hooks/mcp-guard.sh", failClosed: true }],
            afterFileEdit: [{ command: "./hooks/format.sh" }],
          },
        }),
        "harness-json"
      ),
    ]);
    expect(defenses).toHaveLength(1);
    expect(defenses[0].id).toBe("defense-cursor-fail-closed-hook");
    expect(defenses[0].harness).toBe("cursor");
    expect(defenses[0].detail).toContain("beforeShellExecution, beforeMCPExecution");
  });

  it("does not credit Cursor hooks that fail open", () => {
    expect(
      detectDefenses([
        file(
          ".cursor/hooks.json",
          JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: "./guard.sh", failClosed: false }] } }),
          "harness-json"
        ),
      ])
    ).toHaveLength(0);
  });
});

describe("defense rendering", () => {
  it("lists up to 12 defenses in the terminal report and counts the rest", () => {
    const defenses = Array.from({ length: 15 }, (_, index) => makeDefense(index + 1));
    const output = renderTerminalReport(makeReport(defenses));
    expect(output).toContain("Recognized Defenses");
    expect(output).toContain("Sample defense 1");
    expect(output).toContain("file-12.json");
    expect(output).not.toContain("Sample defense 13");
    expect(output).toContain("3 more");
    expect(output.indexOf("Score Breakdown")).toBeLessThan(output.indexOf("Recognized Defenses"));
  });

  it("omits the terminal section and the more line when nothing is recognized", () => {
    const output = renderTerminalReport(makeReport([]));
    expect(output).not.toContain("Recognized Defenses");
    expect(output).not.toContain(" more");
  });

  it("renders a markdown table and includes the array in JSON", () => {
    const defenses = [makeDefense(1), { ...makeDefense(2), detail: "pipe | inside" }];
    const markdown = renderMarkdownReport(makeReport(defenses));
    expect(markdown).toContain("## Recognized Defenses");
    expect(markdown).toContain("| Defense | File | Harness | Detail |");
    expect(markdown).toContain("| Sample defense 1 | `file-1.json` | generic | detail |");
    expect(markdown).toContain("pipe \\| inside");
    expect(markdown).toContain("| Recognized defenses | 2 |");

    const json = JSON.parse(renderJsonReport(makeReport(defenses))) as SecurityReport;
    expect(json.defenses).toHaveLength(2);
    expect(json.defenses[0].id).toBe("defense-sample-1");
    expect(json.summary.defenses).toBe(2);
  });

  it("shows a defenses count in the HTML summary", () => {
    const html = renderHtmlReport(makeReport([makeDefense(1)]));
    expect(html).toContain("Defenses");
  });
});

describe("end to end: hardened Claude Code setup", () => {
  it("credits every defense and keeps the score at 100", () => {
    const tempDir = mkdtempSync(join(tmpdir(), "agentshield-hardened-"));
    try {
      mkdirSync(join(tempDir, ".claude", "hooks"), { recursive: true });
      writeFileSync(
        join(tempDir, ".claude", "settings.json"),
        JSON.stringify(
          {
            permissions: {
              defaultMode: "default",
              disableBypassPermissionsMode: "disable",
              deny: [
                "Read(./.env)",
                "Read(~/.ssh/**)",
                "Bash(curl *)",
                "Bash(sudo *)",
                "Bash(rm -rf *)",
                "Bash(chmod 777 *)",
                "Bash(* > /dev/*)",
              ],
              ask: ["Bash(git push *)"],
            },
            sandbox: {
              enabled: true,
              failIfUnavailable: true,
              network: { allowedDomains: ["api.anthropic.com"] },
            },
            hooks: {
              PreToolUse: [
                {
                  matcher: "Bash",
                  hooks: [{ type: "command", command: '"$CLAUDE_PROJECT_DIR/.claude/hooks/guard.sh"' }],
                },
              ],
              Stop: [{ hooks: [{ type: "command", command: "npm test" }] }],
            },
          },
          null,
          2
        )
      );
      writeFileSync(
        join(tempDir, ".claude", "hooks", "guard.sh"),
        '#!/bin/bash\ninput=$(cat)\nif printf "%s" "$input" | grep -q "rm -rf"; then\n  echo "Blocked destructive command" >&2\n  exit 2\nfi\nexit 0\n'
      );

      const result = scan(tempDir);
      const report = calculateScore(result);

      expect(ids(report.defenses)).toEqual(
        expect.arrayContaining([
          "defense-deny-list",
          "defense-ask-list",
          "defense-default-mode",
          "defense-bypass-disabled",
          "defense-sandbox-enabled",
          "defense-blocking-pretooluse-hook",
        ])
      );
      expect(report.summary.defenses).toBe(report.defenses.length);
      expect(report.findings.filter((finding) => finding.severity !== "info")).toHaveLength(0);
      expect(report.score.numericScore).toBe(100);
      expect(report.score.grade).toBe("A");

      const terminal = renderTerminalReport(report);
      expect(terminal).toContain("Recognized Defenses");
      expect(terminal).toContain("Permission deny list");
      expect(terminal).toContain("Sandbox enabled");
      expect(terminal).toContain("Blocking PreToolUse hook");

      const markdown = renderMarkdownReport(report);
      expect(markdown).toContain("## Recognized Defenses");
      expect(markdown).toContain("Blocking PreToolUse hook");

      const json = JSON.parse(renderJsonReport(report)) as SecurityReport;
      expect(json.defenses.map((defense) => defense.id)).toContain("defense-sandbox-enabled");
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
