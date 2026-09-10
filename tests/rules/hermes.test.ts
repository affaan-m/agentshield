import { describe, it, expect } from "vitest";
import { hermesRules, findLineNumber } from "../../src/rules/hermes.js";
import type { ConfigFile, Finding } from "../../src/types.js";

function yaml(content: string, path = "config.yaml"): ConfigFile {
  return { path, type: "hermes-yaml", content };
}

function run(file: ConfigFile): ReadonlyArray<Finding> {
  return hermesRules.flatMap((rule) => rule.check(file));
}

function ids(findings: ReadonlyArray<Finding>): ReadonlyArray<string> {
  return findings.map((f) => f.id);
}

const HARDENED_HERMES = `
model:
  provider: openrouter
  default: anthropic/claude-sonnet-4
toolsets:
  - core
platform_toolsets:
  cli:
    - terminal
    - file
  telegram:
    - web
    - memory
terminal:
  backend: docker
  docker_mount_cwd_to_workspace: false
  timeout: 120
approvals:
  mode: manual
  cron_mode: deny
command_allowlist: []
delegation:
  max_iterations: 20
  max_concurrent_children: 2
gateway:
  unauthorized_dm_behavior: ignore
mcp_servers:
  docs:
    url: https://mcp.example.com/mcp
    headers:
      Authorization: Bearer \${DOCS_TOKEN}
  local:
    command: npx
    args: ["-y", "@example/mcp@1.0.0"]
    env:
      API_TOKEN: \${EXAMPLE_TOKEN}
`;

const GENERIC_APP_YAML = `
server:
  host: 0.0.0.0
  port: 8080
  mode: off
database:
  url: postgres://app:app@db:5432/app
  pool: 10
logging:
  level: info
  format: json
features:
  - search
  - "*"
gateway:
  timeout: 30
approvals:
  required_reviewers: 2
`;

describe("hermesRules", () => {
  describe("fail closed", () => {
    it("returns nothing for unparseable YAML", () => {
      expect(run(yaml("approvals:\n  mode: off\n  - broken\n:::"))).toEqual([]);
    });

    it("returns nothing for a YAML list or scalar document", () => {
      expect(run(yaml("- one\n- two\n"))).toEqual([]);
      expect(run(yaml("just a string\n"))).toEqual([]);
    });

    it("ignores files that are not hermes-yaml", () => {
      const file: ConfigFile = { path: "config.yaml", type: "unknown", content: "approvals:\n  mode: off\n" };
      expect(run(file)).toEqual([]);
    });

    it("yields zero findings for a random app config.yaml", () => {
      expect(run(yaml(GENERIC_APP_YAML))).toEqual([]);
    });

    it("yields zero findings for a hardened Hermes config", () => {
      expect(run(yaml(HARDENED_HERMES))).toEqual([]);
      expect(run(yaml(HARDENED_HERMES, "profiles/ito/config.yaml"))).toEqual([]);
    });
  });

  describe("hermes-approvals-off", () => {
    it("flags approvals.mode off as critical", () => {
      const finding = run(yaml("approvals:\n  mode: off\n")).find((f) => f.id === "hermes-approvals-off");
      expect(finding?.severity).toBe("critical");
      expect(finding?.category).toBe("permissions");
      expect(finding?.evidence).toBe("approvals.mode: off");
      expect(finding?.line).toBe(2);
    });

    it("treats a YAML 1.1 style boolean false as off", () => {
      expect(ids(run(yaml("approvals:\n  mode: false\n")))).toContain("hermes-approvals-off");
    });

    it("does not flag manual", () => {
      expect(ids(run(yaml("approvals:\n  mode: manual\n")))).not.toContain("hermes-approvals-off");
    });
  });

  describe("hermes-approvals-smart", () => {
    it("flags smart mode as medium", () => {
      const finding = run(yaml("approvals:\n  mode: smart\n")).find((f) => f.id === "hermes-approvals-smart");
      expect(finding?.severity).toBe("medium");
    });

    it("does not flag manual or off as smart", () => {
      expect(ids(run(yaml("approvals:\n  mode: manual\n")))).not.toContain("hermes-approvals-smart");
      expect(ids(run(yaml("approvals:\n  mode: off\n")))).not.toContain("hermes-approvals-smart");
    });
  });

  describe("hermes-cron-auto-approve", () => {
    it("flags cron_mode approve as high", () => {
      const finding = run(yaml("approvals:\n  mode: manual\n  cron_mode: approve\n")).find(
        (f) => f.id === "hermes-cron-auto-approve",
      );
      expect(finding?.severity).toBe("high");
      expect(finding?.line).toBe(3);
    });

    it("does not flag cron_mode deny", () => {
      expect(ids(run(yaml("approvals:\n  cron_mode: deny\n")))).not.toContain("hermes-cron-auto-approve");
    });
  });

  describe("hermes-command-allowlist-broad", () => {
    it.each(["*", "rm -rf *", "sudo *", "curl *", "wget *", "bash -c *", "sh -c *", "eval *", "**", "?*"])(
      "flags allowlist entry %s",
      (entry) => {
        const content = `command_allowlist:\n  - "${entry}"\n`;
        const finding = run(yaml(content)).find((f) => f.id === "hermes-command-allowlist-broad");
        expect(finding?.severity).toBe("high");
        expect(finding?.evidence).toContain(entry);
        expect(finding?.line).toBe(1);
      },
    );

    it("does not flag specific commands", () => {
      const content = 'command_allowlist:\n  - "git status"\n  - "npm test"\n  - "rmdir build"\n  - "curlie --version"\n';
      expect(ids(run(yaml(content)))).not.toContain("hermes-command-allowlist-broad");
    });
  });

  describe("hermes-local-terminal-unattended", () => {
    it("flags local backend with approvals off", () => {
      const finding = run(yaml("terminal:\n  backend: local\napprovals:\n  mode: off\n")).find(
        (f) => f.id === "hermes-local-terminal-unattended",
      );
      expect(finding?.severity).toBe("high");
      expect(finding?.evidence).toBe("terminal.backend: local; approvals.mode: off");
    });

    it("flags ssh backend with smart approvals", () => {
      expect(ids(run(yaml("terminal:\n  backend: ssh\napprovals:\n  mode: smart\n")))).toContain(
        "hermes-local-terminal-unattended",
      );
    });

    it("does not flag local with manual approvals, local with approvals unset, or docker with off", () => {
      expect(ids(run(yaml("terminal:\n  backend: local\napprovals:\n  mode: manual\n")))).not.toContain(
        "hermes-local-terminal-unattended",
      );
      expect(ids(run(yaml("terminal:\n  backend: local\n")))).not.toContain("hermes-local-terminal-unattended");
      expect(ids(run(yaml("terminal:\n  backend: docker\napprovals:\n  mode: off\n")))).not.toContain(
        "hermes-local-terminal-unattended",
      );
    });
  });

  describe("hermes-docker-mount-cwd", () => {
    it("flags docker_mount_cwd_to_workspace true", () => {
      const finding = run(yaml("terminal:\n  backend: docker\n  docker_mount_cwd_to_workspace: true\n")).find(
        (f) => f.id === "hermes-docker-mount-cwd",
      );
      expect(finding?.severity).toBe("medium");
      expect(finding?.line).toBe(3);
    });

    it("does not flag false or unset", () => {
      expect(ids(run(yaml("terminal:\n  backend: docker\n  docker_mount_cwd_to_workspace: false\n")))).not.toContain(
        "hermes-docker-mount-cwd",
      );
      expect(ids(run(yaml("terminal:\n  backend: docker\n")))).not.toContain("hermes-docker-mount-cwd");
    });
  });

  describe("hermes-mcp-secret-inline", () => {
    it("flags a literal Authorization header and redacts it", () => {
      const content = "mcp_servers:\n  remote:\n    url: https://mcp.example.com\n    headers:\n      Authorization: Bearer sk-live-abcdef1234567890\n";
      const finding = run(yaml(content)).find((f) => f.id === "hermes-mcp-secret-inline");
      expect(finding?.severity).toBe("high");
      expect(finding?.category).toBe("secrets");
      expect(finding?.evidence).toBe('mcp_servers.remote.headers.Authorization: "Bear***"');
      expect(finding?.evidence).not.toContain("abcdef");
      expect(finding?.line).toBe(5);
    });

    it("flags a literal env secret", () => {
      const content = "mcp_servers:\n  local:\n    command: npx\n    env:\n      GITHUB_TOKEN: ghp_abcdefghijklmnopqrstuvwxyz0123\n";
      expect(ids(run(yaml(content)))).toContain("hermes-mcp-secret-inline");
    });

    it("does not flag env references, placeholders, or non-secret keys", () => {
      const content =
        "mcp_servers:\n  a:\n    headers:\n      Authorization: Bearer ${TOKEN}\n      X-Api-Key: YOUR_API_KEY\n    env:\n      REGION: us-east-1-long-region-name\n";
      expect(ids(run(yaml(content)))).not.toContain("hermes-mcp-secret-inline");
    });
  });

  describe("hermes-mcp-remote-http", () => {
    it("flags http:// to a non-loopback host", () => {
      const finding = run(yaml("mcp_servers:\n  remote:\n    url: http://mcp.example.com/sse\n    transport: sse\n")).find(
        (f) => f.id === "hermes-mcp-remote-http",
      );
      expect(finding?.severity).toBe("high");
      expect(finding?.category).toBe("mcp");
      expect(finding?.line).toBe(3);
    });

    it("does not flag https or loopback", () => {
      const content = "mcp_servers:\n  a:\n    url: https://mcp.example.com\n  b:\n    url: http://localhost:8000/sse\n  c:\n    url: http://127.0.0.1:9000\n";
      expect(ids(run(yaml(content)))).not.toContain("hermes-mcp-remote-http");
    });
  });

  describe("hermes-public-platform-shell", () => {
    it.each(["telegram", "slack", "whatsapp", "discord", "email", "sms"])("flags terminal on %s", (platform) => {
      const content = `platform_toolsets:\n  ${platform}:\n    - web\n    - terminal\n`;
      const finding = run(yaml(content)).find((f) => f.id === "hermes-public-platform-shell");
      expect(finding?.severity).toBe("high");
      expect(finding?.evidence).toBe(`platform_toolsets.${platform}: [terminal]`);
      expect(finding?.line).toBe(2);
    });

    it("matches shell, exec, file, and code_execution toolsets", () => {
      const content = "platform_toolsets:\n  slack:\n    - shell_tools\n    - code_execution\n    - file_ops\n    - exec\n";
      const finding = run(yaml(content)).find((f) => f.id === "hermes-public-platform-shell");
      expect(finding?.evidence).toBe("platform_toolsets.slack: [shell_tools, code_execution, file_ops, exec]");
    });

    it("does not flag cli or safe toolsets on public platforms", () => {
      const content = "platform_toolsets:\n  cli:\n    - terminal\n  telegram:\n    - web\n    - memory\n";
      expect(ids(run(yaml(content)))).not.toContain("hermes-public-platform-shell");
    });
  });

  describe("hermes-delegation-unbounded", () => {
    it("flags max_iterations over 50 with approvals off", () => {
      const finding = run(yaml("approvals:\n  mode: off\ndelegation:\n  max_iterations: 200\n")).find(
        (f) => f.id === "hermes-delegation-unbounded",
      );
      expect(finding?.severity).toBe("low");
      expect(finding?.line).toBe(4);
    });

    it("flags unset max_iterations with approvals off", () => {
      const finding = run(yaml("approvals:\n  mode: off\n")).find((f) => f.id === "hermes-delegation-unbounded");
      expect(finding?.evidence).toContain("(unset)");
    });

    it("does not flag a bounded delegation or approvals on", () => {
      expect(ids(run(yaml("approvals:\n  mode: off\ndelegation:\n  max_iterations: 20\n")))).not.toContain(
        "hermes-delegation-unbounded",
      );
      expect(ids(run(yaml("approvals:\n  mode: manual\ndelegation:\n  max_iterations: 500\n")))).not.toContain(
        "hermes-delegation-unbounded",
      );
    });
  });

  describe("hermes-gateway-open-dm", () => {
    it.each(["allow", "respond", "accept", "allow_all"])("flags unauthorized_dm_behavior %s", (value) => {
      const finding = run(yaml(`gateway:\n  unauthorized_dm_behavior: ${value}\n`)).find(
        (f) => f.id === "hermes-gateway-open-dm",
      );
      expect(finding?.severity).toBe("medium");
      expect(finding?.line).toBe(2);
    });

    it("does not flag ignore or block", () => {
      expect(ids(run(yaml("gateway:\n  unauthorized_dm_behavior: ignore\n")))).not.toContain("hermes-gateway-open-dm");
      expect(ids(run(yaml("gateway:\n  unauthorized_dm_behavior: block\n")))).not.toContain("hermes-gateway-open-dm");
    });
  });

  describe("helpers", () => {
    it("findLineNumber walks the key path from the deepest segment", () => {
      const content = "approvals:\n  mode: manual\n  cron_mode: deny\nterminal:\n  backend: docker\n";
      expect(findLineNumber(content, "approvals.cron_mode")).toBe(3);
      expect(findLineNumber(content, "terminal.backend")).toBe(5);
      expect(findLineNumber(content, "terminal.missing")).toBe(4);
      expect(findLineNumber(content, "nothing.here")).toBeUndefined();
    });
  });
});
