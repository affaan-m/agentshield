var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/threat-intel/cve-database.ts
function checkPackageName(packageName, version) {
  const match = MALICIOUS_PACKAGES.find((pkg) => pkg.name === packageName);
  if (!match) return void 0;
  if (match.type === "compromised" && match.affectedVersions && version) {
    const affectedVersionList = match.affectedVersions.split(",").map((v) => v.trim());
    if (!affectedVersionList.includes(version)) {
      return void 0;
    }
  }
  return match;
}
function checkServerPackage(command, args) {
  for (const server of VULNERABLE_SERVERS) {
    if (command === server.packageName || command.endsWith(`/${server.packageName}`)) {
      return server;
    }
  }
  for (const arg of args) {
    if (arg.startsWith("-")) continue;
    for (const server of VULNERABLE_SERVERS) {
      if (arg === server.packageName || arg.startsWith(`${server.packageName}@`)) {
        return server;
      }
    }
  }
  return void 0;
}
var TANSTACK_MINI_SHAI_HULUD_PACKAGES, MINI_SHAI_HULUD_ADDITIONAL_PACKAGES, MALICIOUS_PACKAGES, VULNERABLE_SERVERS;
var init_cve_database = __esm({
  "src/threat-intel/cve-database.ts"() {
    "use strict";
    TANSTACK_MINI_SHAI_HULUD_PACKAGES = [
      ["@tanstack/arktype-adapter", "1.166.12, 1.166.15"],
      ["@tanstack/eslint-plugin-router", "1.161.9, 1.161.12"],
      ["@tanstack/eslint-plugin-start", "0.0.4, 0.0.7"],
      ["@tanstack/history", "1.161.9, 1.161.12"],
      ["@tanstack/nitro-v2-vite-plugin", "1.154.12, 1.154.15"],
      ["@tanstack/react-router", "1.169.5, 1.169.8"],
      ["@tanstack/react-router-devtools", "1.166.16, 1.166.19"],
      ["@tanstack/react-router-ssr-query", "1.166.15, 1.166.18"],
      ["@tanstack/react-start", "1.167.68, 1.167.71"],
      ["@tanstack/react-start-client", "1.166.51, 1.166.54"],
      ["@tanstack/react-start-rsc", "0.0.47, 0.0.50"],
      ["@tanstack/react-start-server", "1.166.55, 1.166.58"],
      ["@tanstack/router-cli", "1.166.46, 1.166.49"],
      ["@tanstack/router-core", "1.169.5, 1.169.8"],
      ["@tanstack/router-devtools", "1.166.16, 1.166.19"],
      ["@tanstack/router-devtools-core", "1.167.6, 1.167.9"],
      ["@tanstack/router-generator", "1.166.45, 1.166.48"],
      ["@tanstack/router-plugin", "1.167.38, 1.167.41"],
      ["@tanstack/router-ssr-query-core", "1.168.3, 1.168.6"],
      ["@tanstack/router-utils", "1.161.11, 1.161.14"],
      ["@tanstack/router-vite-plugin", "1.166.53, 1.166.56"],
      ["@tanstack/solid-router", "1.169.5, 1.169.8"],
      ["@tanstack/solid-router-devtools", "1.166.16, 1.166.19"],
      ["@tanstack/solid-router-ssr-query", "1.166.15, 1.166.18"],
      ["@tanstack/solid-start", "1.167.65, 1.167.68"],
      ["@tanstack/solid-start-client", "1.166.50, 1.166.53"],
      ["@tanstack/solid-start-server", "1.166.54, 1.166.57"],
      ["@tanstack/start-client-core", "1.168.5, 1.168.8"],
      ["@tanstack/start-fn-stubs", "1.161.9, 1.161.12"],
      ["@tanstack/start-plugin-core", "1.169.23, 1.169.26"],
      ["@tanstack/start-server-core", "1.167.33, 1.167.36"],
      ["@tanstack/start-static-server-functions", "1.166.44, 1.166.47"],
      ["@tanstack/start-storage-context", "1.166.38, 1.166.41"],
      ["@tanstack/valibot-adapter", "1.166.12, 1.166.15"],
      ["@tanstack/virtual-file-routes", "1.161.10, 1.161.13"],
      ["@tanstack/vue-router", "1.169.5, 1.169.8"],
      ["@tanstack/vue-router-devtools", "1.166.16, 1.166.19"],
      ["@tanstack/vue-router-ssr-query", "1.166.15, 1.166.18"],
      ["@tanstack/vue-start", "1.167.61, 1.167.64"],
      ["@tanstack/vue-start-client", "1.166.46, 1.166.49"],
      ["@tanstack/vue-start-server", "1.166.50, 1.166.53"],
      ["@tanstack/zod-adapter", "1.166.12, 1.166.15"]
    ];
    MINI_SHAI_HULUD_ADDITIONAL_PACKAGES = [
      [
        "@beproduct/nestjs-auth",
        "0.1.2, 0.1.3, 0.1.4, 0.1.5, 0.1.6, 0.1.7, 0.1.8, 0.1.9, 0.1.10, 0.1.11, 0.1.12, 0.1.13, 0.1.14, 0.1.15, 0.1.16, 0.1.17, 0.1.18, 0.1.19"
      ],
      ["@cap-js/db-service", "2.10.1"],
      ["@cap-js/postgres", "2.2.2"],
      ["@cap-js/sqlite", "2.2.2"],
      ["@dirigible-ai/sdk", "0.6.2, 0.6.3"],
      ["@draftauth/client", "0.2.1, 0.2.2"],
      ["@draftauth/core", "0.13.1, 0.13.2"],
      ["@draftlab/auth", "0.24.1, 0.24.2"],
      ["@draftlab/auth-router", "0.5.1, 0.5.2"],
      ["@draftlab/db", "0.16.1, 0.16.2"],
      ["@mesadev/rest", "0.28.3"],
      ["@mesadev/saguaro", "0.4.22"],
      ["@mesadev/sdk", "0.28.3"],
      ["@mistralai/mistralai", "2.2.2, 2.2.3, 2.2.4"],
      ["@mistralai/mistralai-azure", "1.7.1, 1.7.2, 1.7.3"],
      ["@mistralai/mistralai-gcp", "1.7.1, 1.7.2, 1.7.3"],
      ["@ml-toolkit-ts/preprocessing", "1.0.2, 1.0.3"],
      ["@ml-toolkit-ts/xgboost", "1.0.3, 1.0.4"],
      ["@opensearch-project/opensearch", "3.5.3, 3.6.2, 3.7.0, 3.8.0"],
      ["@squawk/airport-data", "0.7.4, 0.7.5, 0.7.6, 0.7.7, 0.7.8"],
      ["@squawk/airports", "0.6.2, 0.6.3, 0.6.4, 0.6.5, 0.6.6"],
      ["@squawk/airspace", "0.8.1, 0.8.2, 0.8.3, 0.8.4, 0.8.5"],
      ["@squawk/airspace-data", "0.5.3, 0.5.4, 0.5.5, 0.5.6, 0.5.7"],
      ["@squawk/airway-data", "0.5.4, 0.5.5, 0.5.6, 0.5.7, 0.5.8"],
      ["@squawk/airways", "0.4.2, 0.4.3, 0.4.4, 0.4.5, 0.4.6"],
      ["@squawk/fix-data", "0.6.4, 0.6.5, 0.6.6, 0.6.7, 0.6.8"],
      ["@squawk/fixes", "0.3.2, 0.3.3, 0.3.4, 0.3.5, 0.3.6"],
      ["@squawk/flight-math", "0.5.4, 0.5.5, 0.5.6, 0.5.7, 0.5.8"],
      ["@squawk/flightplan", "0.5.2, 0.5.3, 0.5.4, 0.5.5, 0.5.6"],
      ["@squawk/geo", "0.4.4, 0.4.5, 0.4.6, 0.4.7, 0.4.8"],
      ["@squawk/icao-registry", "0.5.2, 0.5.3, 0.5.4, 0.5.5, 0.5.6"],
      ["@squawk/icao-registry-data", "0.8.4, 0.8.5, 0.8.6, 0.8.7, 0.8.8"],
      ["@squawk/mcp", "0.9.1, 0.9.2, 0.9.3, 0.9.4, 0.9.5"],
      ["@squawk/navaid-data", "0.6.4, 0.6.5, 0.6.6, 0.6.7, 0.6.8"],
      ["@squawk/navaids", "0.4.2, 0.4.3, 0.4.4, 0.4.5, 0.4.6"],
      ["@squawk/notams", "0.3.6, 0.3.7, 0.3.8, 0.3.9, 0.3.10"],
      ["@squawk/procedure-data", "0.7.3, 0.7.4, 0.7.5, 0.7.6, 0.7.7"],
      ["@squawk/procedures", "0.5.2, 0.5.3, 0.5.4, 0.5.5, 0.5.6"],
      ["@squawk/types", "0.8.1, 0.8.2, 0.8.3, 0.8.4, 0.8.5"],
      ["@squawk/units", "0.4.3, 0.4.4, 0.4.5, 0.4.6, 0.4.7"],
      ["@squawk/weather", "0.5.6, 0.5.7, 0.5.8, 0.5.9, 0.5.10"],
      ["@supersurkhet/cli", "0.0.2, 0.0.3, 0.0.4, 0.0.5, 0.0.6, 0.0.7"],
      ["@supersurkhet/sdk", "0.0.2, 0.0.3, 0.0.4, 0.0.5, 0.0.6, 0.0.7"],
      ["@tallyui/components", "1.0.1, 1.0.2, 1.0.3"],
      ["@tallyui/connector-medusa", "1.0.1, 1.0.2, 1.0.3"],
      ["@tallyui/connector-shopify", "1.0.1, 1.0.2, 1.0.3"],
      ["@tallyui/connector-vendure", "1.0.1, 1.0.2, 1.0.3"],
      ["@tallyui/connector-woocommerce", "1.0.1, 1.0.2, 1.0.3"],
      ["@tallyui/core", "0.2.1, 0.2.2, 0.2.3"],
      ["@tallyui/database", "1.0.1, 1.0.2, 1.0.3"],
      ["@tallyui/pos", "0.1.1, 0.1.2, 0.1.3"],
      ["@tallyui/storage-sqlite", "0.2.1, 0.2.2, 0.2.3"],
      ["@tallyui/theme", "0.2.1, 0.2.2, 0.2.3"],
      ["@taskflow-corp/cli", "0.1.24, 0.1.25, 0.1.26, 0.1.27, 0.1.28, 0.1.29"],
      ["@tolka/cli", "1.0.2, 1.0.3, 1.0.4, 1.0.5, 1.0.6"],
      ["@uipath/access-policy-sdk", "0.3.1"],
      ["@uipath/access-policy-tool", "0.3.1"],
      ["@uipath/admin-tool", "0.1.1"],
      ["@uipath/agent-sdk", "1.0.2"],
      ["@uipath/agent-tool", "1.0.1"],
      ["@uipath/agent.sdk", "0.0.18"],
      ["@uipath/aops-policy-tool", "0.3.1"],
      ["@uipath/ap-chat", "1.5.7"],
      ["@uipath/api-workflow-tool", "1.0.1"],
      ["@uipath/apollo-core", "5.9.2"],
      ["@uipath/apollo-react", "4.24.5"],
      ["@uipath/apollo-wind", "2.16.2"],
      ["@uipath/auth", "1.0.1"],
      ["@uipath/case-tool", "1.0.1"],
      ["@uipath/cli", "1.0.1"],
      ["@uipath/codedagent-tool", "1.0.1"],
      ["@uipath/codedagents-tool", "0.1.12"],
      ["@uipath/codedapp-tool", "1.0.1"],
      ["@uipath/common", "1.0.1"],
      ["@uipath/context-grounding-tool", "0.1.1"],
      ["@uipath/data-fabric-tool", "1.0.2"],
      ["@uipath/docsai-tool", "1.0.1"],
      ["@uipath/filesystem", "1.0.1"],
      ["@uipath/flow-tool", "1.0.2"],
      ["@uipath/functions-tool", "1.0.1"],
      ["@uipath/gov-tool", "0.3.1"],
      ["@uipath/identity-tool", "0.1.1"],
      ["@uipath/insights-sdk", "1.0.1"],
      ["@uipath/insights-tool", "1.0.1"],
      ["@uipath/integrationservice-sdk", "1.0.2"],
      ["@uipath/integrationservice-tool", "1.0.2"],
      ["@uipath/llmgw-tool", "1.0.1"],
      ["@uipath/maestro-sdk", "1.0.1"],
      ["@uipath/maestro-tool", "1.0.1"],
      ["@uipath/orchestrator-tool", "1.0.1"],
      ["@uipath/packager-tool-apiworkflow", "0.0.19"],
      ["@uipath/packager-tool-bpmn", "0.0.9"],
      ["@uipath/packager-tool-case", "0.0.9"],
      ["@uipath/packager-tool-connector", "0.0.19"],
      ["@uipath/packager-tool-flow", "0.0.19"],
      ["@uipath/packager-tool-functions", "0.1.1"],
      ["@uipath/packager-tool-webapp", "1.0.6"],
      ["@uipath/packager-tool-workflowcompiler", "0.0.16"],
      ["@uipath/packager-tool-workflowcompiler-browser", "0.0.34"],
      ["@uipath/platform-tool", "1.0.1"],
      ["@uipath/project-packager", "1.1.16"],
      ["@uipath/resource-tool", "1.0.1"],
      ["@uipath/resourcecatalog-tool", "0.1.1"],
      ["@uipath/resources-tool", "0.1.11"],
      ["@uipath/robot", "1.3.4"],
      ["@uipath/rpa-legacy-tool", "1.0.1"],
      ["@uipath/rpa-tool", "0.9.5"],
      ["@uipath/solution-packager", "0.0.35"],
      ["@uipath/solution-tool", "1.0.1"],
      ["@uipath/solutionpackager-sdk", "1.0.11"],
      ["@uipath/solutionpackager-tool-core", "0.0.34"],
      ["@uipath/tasks-tool", "1.0.1"],
      ["@uipath/telemetry", "0.0.7"],
      ["@uipath/test-manager-tool", "1.0.2"],
      ["@uipath/tool-workflowcompiler", "0.0.12"],
      ["@uipath/traces-tool", "1.0.1"],
      ["@uipath/ui-widgets-multi-file-upload", "1.0.1"],
      ["@uipath/uipath-python-bridge", "1.0.1"],
      ["@uipath/vertical-solutions-tool", "1.0.1"],
      ["@uipath/vss", "0.1.6"],
      ["@uipath/widget.sdk", "1.2.3"],
      ["agentwork-cli", "0.1.4, 0.1.5"],
      ["cmux-agent-mcp", "0.1.3, 0.1.4, 0.1.5, 0.1.6, 0.1.7, 0.1.8"],
      ["cross-stitch", "1.1.3, 1.1.4, 1.1.5, 1.1.6, 1.1.7"],
      ["git-branch-selector", "1.3.3, 1.3.4, 1.3.5, 1.3.6, 1.3.7"],
      ["git-git-git", "1.0.8, 1.0.9, 1.0.10, 1.0.11, 1.0.12"],
      ["guardrails-ai", "0.10.1"],
      ["intercom-client", "7.0.4"],
      ["lightning", "2.6.2, 2.6.3"],
      ["mbt", "1.2.48"],
      ["mistralai", "2.4.6"],
      ["ml-toolkit-ts", "1.0.4, 1.0.5"],
      ["nextmove-mcp", "0.1.3, 0.1.4, 0.1.5, 0.1.6, 0.1.7"],
      ["safe-action", "0.8.3, 0.8.4"],
      ["ts-dna", "3.0.1, 3.0.2, 3.0.3, 3.0.4, 3.0.5"],
      ["wot-api", "0.8.1, 0.8.2, 0.8.3, 0.8.4"]
    ];
    MALICIOUS_PACKAGES = [
      // SANDWORM_MODE typosquats targeting MCP SDK
      {
        name: "@anthropic-ai/model-context-protocol-sdk",
        type: "typosquat",
        description: "Typosquat of the official @modelcontextprotocol/sdk. Part of SANDWORM_MODE supply chain campaign targeting MCP developers.",
        legitimatePackage: "@modelcontextprotocol/sdk"
      },
      {
        name: "anthropic-mcp-sdk",
        type: "typosquat",
        description: "Typosquat targeting developers searching for the Anthropic MCP SDK.",
        legitimatePackage: "@modelcontextprotocol/sdk"
      },
      {
        name: "mcp-sdk-anthropic",
        type: "typosquat",
        description: "Typosquat with reversed naming convention targeting MCP SDK users.",
        legitimatePackage: "@modelcontextprotocol/sdk"
      },
      {
        name: "@anthropic/mcp-server",
        type: "typosquat",
        description: "Typosquat using incorrect scope for Anthropic MCP servers (correct scope is @anthropics or @modelcontextprotocol).",
        legitimatePackage: "@modelcontextprotocol/sdk"
      },
      // Compromised legitimate packages
      {
        name: "cline",
        type: "compromised",
        description: "Clinejection supply chain attack. Compromised npm token used to publish cline@2.3.0 with malicious postinstall script that installed openclaw. ~4,000 downloads in ~8 hour window.",
        affectedVersions: "2.3.0"
      },
      // Known malicious MCP servers
      {
        name: "postmark-mcp",
        type: "malicious",
        description: "Malicious MCP server impersonating Postmark email service. Version 1.0.16 secretly BCCs every outgoing email to an attacker-controlled domain.",
        affectedVersions: "1.0.16"
      },
      {
        name: "openclaw",
        type: "malicious",
        description: "Malicious package installed by the compromised cline@2.3.0 postinstall script. Part of the Clinejection supply chain attack."
      },
      {
        name: "@tanstack/setup",
        type: "malicious",
        description: "Fictitious git dependency used by the May 2026 TanStack/Mini Shai-Hulud npm campaign. Malicious manifests referenced github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c to execute router_init.js during install."
      },
      ...TANSTACK_MINI_SHAI_HULUD_PACKAGES.map(([name, affectedVersions]) => ({
        name,
        type: "compromised",
        description: "Compromised @tanstack package version from the May 2026 TanStack/Mini Shai-Hulud npm campaign. Affected versions executed router_init.js at install time, harvested developer/cloud credentials, and attempted npm worm propagation under signed trusted-publisher provenance.",
        affectedVersions
      })),
      ...MINI_SHAI_HULUD_ADDITIONAL_PACKAGES.map(([name, affectedVersions]) => ({
        name,
        type: "compromised",
        description: "Compromised package version from the May 2026 Mini Shai-Hulud supply-chain campaign. Treat any matching lockfile, cache, CI runner, or developer host as potentially compromised and rotate accessible credentials after persistence is removed.",
        affectedVersions
      })),
      // AI-specific typosquats from PyPI/npm campaigns
      {
        name: "aliyun-ai-labs-snippets-sdk",
        type: "malicious",
        description: "Malicious PyPI package delivering infostealer hidden inside PyTorch model files."
      },
      {
        name: "ai-labs-snippets-sdk",
        type: "malicious",
        description: "Malicious PyPI package delivering infostealer hidden inside PyTorch model files."
      },
      {
        name: "aliyun-ai-labs-sdk",
        type: "malicious",
        description: "Malicious PyPI package delivering infostealer hidden inside PyTorch model files."
      }
    ];
    VULNERABLE_SERVERS = [
      {
        packageName: "@anthropics/mcp-server-git",
        cveIds: ["CVE-2025-68145", "CVE-2025-68143", "CVE-2025-68144"],
        description: "Anthropic's official MCP git server has path traversal, unrestricted git_init, and argument injection vulnerabilities."
      },
      {
        packageName: "mcp-server-git",
        cveIds: ["CVE-2025-68145", "CVE-2025-68143", "CVE-2025-68144"],
        description: "MCP git server (community package) shares vulnerabilities with the official Anthropic version."
      },
      {
        packageName: "mcp-remote",
        cveIds: ["CVE-2025-6514"],
        description: "OS command injection via malicious authorization_endpoint. The authorization URL is passed to the system shell without sanitization."
      }
    ];
  }
});

// src/fingerprint.ts
import { createHash } from "crypto";
function fingerprintFinding(finding) {
  return `${finding.id}::${finding.file}::${evidenceFingerprint(finding.evidence)}`;
}
function legacyEvidenceFingerprint(finding) {
  return `${finding.id}::${finding.file}::${finding.evidence ?? ""}`;
}
function evidenceFingerprint(evidence) {
  if (!evidence) {
    return "sha256:no-evidence";
  }
  return `sha256:${createHash("sha256").update(evidence).digest("hex").slice(0, 16)}`;
}
var init_fingerprint = __esm({
  "src/fingerprint.ts"() {
    "use strict";
  }
});

// src/policy/types.ts
import { z } from "zod";
var SeveritySchema, PolicyPackSchema, PolicyExceptionSchema, OrgPolicySchema;
var init_types = __esm({
  "src/policy/types.ts"() {
    "use strict";
    SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
    PolicyPackSchema = z.enum([
      "oss",
      "team",
      "enterprise",
      "regulated",
      "high-risk-hooks-mcp",
      "ci-enforcement"
    ]);
    PolicyExceptionSchema = z.object({
      id: z.string().min(1),
      rule: z.string().min(1),
      owner: z.string().min(1),
      reason: z.string().min(1),
      expires_at: z.string().datetime(),
      scope: z.string().optional(),
      severity: SeveritySchema.optional(),
      ticket: z.string().optional()
    });
    OrgPolicySchema = z.object({
      version: z.literal(1),
      name: z.string().optional(),
      description: z.string().optional(),
      policy_pack: PolicyPackSchema.default("team"),
      owners: z.array(z.string()).default([]),
      exceptions: z.array(PolicyExceptionSchema).default([]),
      /** Items that MUST appear in the permissions.deny list */
      required_deny_list: z.array(z.string()).default([]),
      /** MCP servers that are banned from use */
      banned_mcp_servers: z.array(z.string()).default([]),
      /** Minimum acceptable security score (0-100) */
      min_score: z.number().int().min(0).max(100).default(60),
      /** Maximum allowed severity for any single finding */
      max_severity: SeveritySchema.default("critical"),
      /** Hook patterns that must be present in settings */
      required_hooks: z.array(
        z.object({
          event: z.enum(["PreToolUse", "PostToolUse", "SessionStart", "Stop"]),
          pattern: z.string(),
          description: z.string().optional()
        })
      ).default([]),
      /** Tools that must NOT appear in the allow list */
      banned_tools: z.array(z.string()).default([])
    });
  }
});

// src/policy/presets.ts
function listPolicyPacks() {
  return PACK_SUMMARIES;
}
function generatePolicyPack(pack, options = {}) {
  const policy = buildPolicyPack(pack);
  return {
    ...policy,
    name: options.name ?? policy.name,
    owners: [...options.owners ?? policy.owners ?? []]
  };
}
function buildPolicyPack(pack) {
  switch (pack) {
    case "oss":
      return {
        ...basePolicy(pack, "AgentShield OSS Policy"),
        description: "Public-repository baseline for obvious destructive tools and risky shell MCPs.",
        min_score: 70,
        max_severity: "high"
      };
    case "team":
      return {
        ...basePolicy(pack, "AgentShield Team Policy"),
        description: "Shared team baseline with runtime monitoring and risky MCP restrictions.",
        min_score: 75,
        max_severity: "high",
        required_hooks: [RUNTIME_HOOK]
      };
    case "enterprise":
      return {
        ...basePolicy(pack, "AgentShield Enterprise Policy"),
        description: "Managed organization baseline with runtime hooks and strict score gates.",
        min_score: 85,
        max_severity: "high",
        required_hooks: [RUNTIME_HOOK],
        banned_tools: ["Bash(*)"]
      };
    case "regulated":
      return {
        ...basePolicy(pack, "AgentShield Regulated Policy"),
        description: "Compliance baseline for sensitive repositories and regulated environments.",
        min_score: 90,
        max_severity: "medium",
        required_hooks: [RUNTIME_HOOK, POST_TOOL_HOOK],
        banned_mcp_servers: [...RISKY_MCP_SERVERS, "filesystem*", "browser*"],
        banned_tools: ["Bash(*)", "WebFetch(*)"]
      };
    case "high-risk-hooks-mcp":
      return {
        ...basePolicy(pack, "AgentShield High-risk Hooks/MCP Policy"),
        description: "Focused gate for repositories shipping hook code, MCP configs, or plugin manifests.",
        min_score: 80,
        max_severity: "high",
        required_hooks: [RUNTIME_HOOK, POST_TOOL_HOOK],
        banned_mcp_servers: [...RISKY_MCP_SERVERS, "filesystem*"],
        banned_tools: ["Bash(*)"]
      };
    case "ci-enforcement":
      return {
        ...basePolicy(pack, "AgentShield CI Enforcement Policy"),
        description: "Branch-protection baseline for collecting policy status in CI.",
        min_score: 80,
        max_severity: "high",
        required_hooks: [RUNTIME_HOOK],
        banned_tools: ["Bash(*)"]
      };
  }
}
function basePolicy(policyPack, name) {
  return {
    version: 1,
    name,
    policy_pack: policyPack,
    owners: [],
    exceptions: [],
    required_deny_list: [...REQUIRED_DESTRUCTIVE_DENY_LIST],
    banned_mcp_servers: [...RISKY_MCP_SERVERS],
    min_score: 75,
    max_severity: "high",
    required_hooks: [],
    banned_tools: []
  };
}
var REQUIRED_DESTRUCTIVE_DENY_LIST, RISKY_MCP_SERVERS, RUNTIME_HOOK, POST_TOOL_HOOK, PACK_SUMMARIES;
var init_presets = __esm({
  "src/policy/presets.ts"() {
    "use strict";
    REQUIRED_DESTRUCTIVE_DENY_LIST = [
      "Bash(rm",
      "Bash(curl",
      "Bash(wget"
    ];
    RISKY_MCP_SERVERS = [
      "shell*",
      "terminal*"
    ];
    RUNTIME_HOOK = {
      event: "PreToolUse",
      pattern: "agentshield",
      description: "AgentShield runtime monitor must be installed"
    };
    POST_TOOL_HOOK = {
      event: "PostToolUse",
      pattern: "agentshield",
      description: "AgentShield post-tool evidence hook must be installed"
    };
    PACK_SUMMARIES = [
      {
        id: "oss",
        label: "OSS",
        description: "Baseline policy for public repositories with permissive contribution paths."
      },
      {
        id: "team",
        label: "Team",
        description: "Default team policy for shared private repositories and active development."
      },
      {
        id: "enterprise",
        label: "Enterprise",
        description: "Stricter organization policy for managed production engineering groups."
      },
      {
        id: "regulated",
        label: "Regulated",
        description: "High-assurance policy for compliance, audit, and sensitive-data environments."
      },
      {
        id: "high-risk-hooks-mcp",
        label: "High-risk hooks/MCP",
        description: "Focused policy for repositories with privileged hooks or MCP integrations."
      },
      {
        id: "ci-enforcement",
        label: "CI enforcement",
        description: "Branch-protection policy tuned for GitHub Actions enforcement gates."
      }
    ];
  }
});

// src/policy/evaluate.ts
import { readFileSync as readFileSync3, existsSync as existsSync4 } from "fs";
function loadPolicy(policyPath) {
  if (!existsSync4(policyPath)) {
    return { success: false, error: `Policy file not found: ${policyPath}` };
  }
  try {
    const raw = readFileSync3(policyPath, "utf-8");
    const parsed = JSON.parse(raw);
    return { success: true, policy: OrgPolicySchema.parse(parsed) };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, error: message };
  }
}
function evaluatePolicy(policy, findings, score, files, options = {}) {
  const violations = [];
  const now = options.now ?? /* @__PURE__ */ new Date();
  if (score.numericScore < policy.min_score) {
    violations.push({
      rule: "min_score",
      severity: "high",
      description: `Security score ${score.numericScore} is below the required minimum of ${policy.min_score}.`,
      expected: `Score >= ${policy.min_score}`,
      actual: `Score = ${score.numericScore}`
    });
  }
  const maxSeverityIndex = SEVERITY_ORDER[policy.max_severity];
  const exceedingFindings = findings.filter(
    (f) => SEVERITY_ORDER[f.severity] < maxSeverityIndex
  );
  if (exceedingFindings.length > 0) {
    violations.push({
      rule: "max_severity",
      severity: "high",
      description: `${exceedingFindings.length} finding(s) exceed the maximum allowed severity of "${policy.max_severity}".`,
      expected: `No findings above ${policy.max_severity}`,
      actual: `${exceedingFindings.length} finding(s) above threshold`
    });
  }
  const denyList = extractDenyList(files);
  for (const required of policy.required_deny_list) {
    if (!denyList.some((d) => matchesDenyPattern(d, required))) {
      violations.push({
        rule: "required_deny_list",
        severity: "medium",
        description: `Required deny pattern "${required}" not found in permissions.deny list.`,
        expected: `"${required}" in deny list`,
        actual: "Missing from deny list"
      });
    }
  }
  const mcpServers = extractMcpServerNames(files);
  for (const banned of policy.banned_mcp_servers) {
    const found = mcpServers.filter((s) => matchesBanned(s, banned));
    for (const server of found) {
      violations.push({
        rule: "banned_mcp_servers",
        severity: "high",
        description: `MCP server "${server}" is banned by organization policy.`,
        expected: `"${banned}" not in MCP servers`,
        actual: `"${server}" is configured`
      });
    }
  }
  const allowedTools = extractAllowList(files);
  for (const banned of policy.banned_tools) {
    const found = allowedTools.filter((t) => matchesDenyPattern(t, banned));
    for (const tool of found) {
      violations.push({
        rule: "banned_tools",
        severity: "high",
        description: `Tool "${tool}" is banned by organization policy but appears in the allow list.`,
        expected: `"${banned}" not in allow list`,
        actual: `"${tool}" is allowed`
      });
    }
  }
  const configuredHooks = extractHookPatterns(files);
  for (const required of policy.required_hooks) {
    const found = configuredHooks.some(
      (h) => h.event === required.event && h.command.includes(required.pattern)
    );
    if (!found) {
      violations.push({
        rule: "required_hooks",
        severity: "medium",
        description: required.description ?? `Required ${required.event} hook with pattern "${required.pattern}" not found.`,
        expected: `${required.event} hook containing "${required.pattern}"`,
        actual: "Not configured"
      });
    }
  }
  const exceptionResult = applyPolicyExceptions(
    violations,
    policy.exceptions ?? [],
    now
  );
  const expiredExceptionViolations = buildExpiredExceptionViolations(
    policy.exceptions ?? [],
    now
  );
  const finalViolations = [
    ...exceptionResult.violations,
    ...expiredExceptionViolations
  ];
  return {
    policyName: policy.name ?? "Organization Policy",
    policyPack: policy.policy_pack,
    owners: policy.owners ?? [],
    passed: finalViolations.length === 0,
    violations: finalViolations,
    exceptionsApplied: exceptionResult.applied,
    exceptionSummary: buildExceptionSummary(policy.exceptions ?? [], now),
    score: score.numericScore,
    minScore: policy.min_score
  };
}
function extractDenyList(files) {
  const denyItems = [];
  for (const file of files) {
    if (file.type !== "settings-json") continue;
    try {
      const config = JSON.parse(file.content);
      const deny = config?.permissions?.deny;
      if (Array.isArray(deny)) {
        denyItems.push(...deny.filter((d) => typeof d === "string"));
      }
    } catch {
    }
  }
  return denyItems;
}
function extractAllowList(files) {
  const allowItems = [];
  for (const file of files) {
    if (file.type !== "settings-json") continue;
    try {
      const config = JSON.parse(file.content);
      const allow = config?.permissions?.allow;
      if (Array.isArray(allow)) {
        allowItems.push(...allow.filter((a) => typeof a === "string"));
      }
    } catch {
    }
  }
  return allowItems;
}
function extractMcpServerNames(files) {
  const names = [];
  for (const file of files) {
    if (file.type !== "mcp-json" && file.type !== "settings-json") continue;
    try {
      const config = JSON.parse(file.content);
      const servers = config?.mcpServers;
      if (servers && typeof servers === "object") {
        names.push(...Object.keys(servers));
      }
    } catch {
    }
  }
  return names;
}
function extractHookPatterns(files) {
  const hooks = [];
  for (const file of files) {
    if (file.type !== "settings-json") continue;
    try {
      const config = JSON.parse(file.content);
      const hookGroups = config?.hooks;
      if (!hookGroups || typeof hookGroups !== "object") continue;
      for (const [event, entries] of Object.entries(hookGroups)) {
        if (!Array.isArray(entries)) continue;
        for (const entry of entries) {
          const hook = entry.hook;
          if (typeof hook === "string") {
            hooks.push({ event, command: hook });
          }
        }
      }
    } catch {
    }
  }
  return hooks;
}
function matchesDenyPattern(actual, pattern) {
  if (actual === pattern) return true;
  if (actual.toLowerCase() === pattern.toLowerCase()) return true;
  return actual.startsWith(pattern);
}
function matchesBanned(serverName, banned) {
  if (serverName === banned) return true;
  if (serverName.toLowerCase() === banned.toLowerCase()) return true;
  if (banned.endsWith("*") && serverName.startsWith(banned.slice(0, -1))) {
    return true;
  }
  return false;
}
function applyPolicyExceptions(violations, exceptions, now) {
  const applied = [];
  const remaining = [];
  const activeExceptions = exceptions.filter(
    (exception) => isExceptionActive(exception, now)
  );
  for (const violation of violations) {
    const exception = activeExceptions.find(
      (candidate) => exceptionMatchesViolation(candidate, violation)
    );
    if (!exception) {
      remaining.push(violation);
      continue;
    }
    applied.push({
      id: exception.id,
      rule: exception.rule,
      owner: exception.owner,
      reason: exception.reason,
      expiresAt: exception.expires_at,
      violation: violation.description
    });
  }
  return { violations: remaining, applied };
}
function buildExpiredExceptionViolations(exceptions, now) {
  return exceptions.filter((exception) => !isExceptionActive(exception, now)).map((exception) => ({
    rule: "expired_exception",
    severity: "high",
    description: `Policy exception "${exception.id}" for rule "${exception.rule}" has expired.`,
    expected: "Exception must have a future expires_at timestamp or be removed",
    actual: `Expired at ${exception.expires_at}`
  }));
}
function isExceptionActive(exception, now) {
  const expiresAt = new Date(exception.expires_at);
  if (Number.isNaN(expiresAt.getTime())) return false;
  return expiresAt.getTime() >= now.getTime();
}
function buildExceptionSummary(exceptions, now) {
  const entries = exceptions.map((exception) => buildExceptionAuditEntry(exception, now)).sort(compareExceptionAuditEntries);
  return {
    total: entries.length,
    active: entries.filter(
      (entry) => entry.status === "active" || entry.status === "expiring_soon"
    ).length,
    expiringSoon: entries.filter((entry) => entry.status === "expiring_soon").length,
    expired: entries.filter((entry) => entry.status === "expired").length,
    entries
  };
}
function buildExceptionAuditEntry(exception, now) {
  const expiresAt = new Date(exception.expires_at);
  const daysUntilExpiry = Number.isNaN(expiresAt.getTime()) ? Number.NEGATIVE_INFINITY : Math.ceil((expiresAt.getTime() - now.getTime()) / MS_PER_DAY);
  const status = statusForExceptionDays(daysUntilExpiry);
  return {
    id: exception.id,
    rule: exception.rule,
    owner: exception.owner,
    reason: exception.reason,
    expiresAt: exception.expires_at,
    status,
    daysUntilExpiry,
    ...exception.scope ? { scope: exception.scope } : {},
    ...exception.ticket ? { ticket: exception.ticket } : {}
  };
}
function statusForExceptionDays(daysUntilExpiry) {
  if (daysUntilExpiry < 0) return "expired";
  if (daysUntilExpiry <= EXPIRING_SOON_DAYS) return "expiring_soon";
  return "active";
}
function compareExceptionAuditEntries(a, b) {
  const statusRank = {
    expiring_soon: 0,
    active: 1,
    expired: 2
  };
  const statusDelta = statusRank[a.status] - statusRank[b.status];
  if (statusDelta !== 0) return statusDelta;
  const dayDelta = a.daysUntilExpiry - b.daysUntilExpiry;
  if (dayDelta !== 0) return dayDelta;
  return a.id.localeCompare(b.id);
}
function exceptionMatchesViolation(exception, violation) {
  if (exception.rule !== violation.rule) return false;
  if (exception.severity && exception.severity !== violation.severity) {
    return false;
  }
  if (!exception.scope) return true;
  const scope = exception.scope.toLowerCase();
  const haystack = [
    violation.description,
    violation.expected,
    violation.actual
  ].join("\n").toLowerCase();
  return haystack.includes(scope);
}
function renderPolicyEvaluation(evaluation) {
  const lines = [];
  const divider = "\u2500".repeat(60);
  lines.push("");
  lines.push(`  ${divider}`);
  lines.push(`  Organization Policy: ${evaluation.policyName}`);
  lines.push(`  ${divider}`);
  lines.push("");
  if (evaluation.policyPack) {
    lines.push(`  Policy Pack: ${evaluation.policyPack}`);
  }
  if (evaluation.owners && evaluation.owners.length > 0) {
    lines.push(`  Owners: ${evaluation.owners.join(", ")}`);
  }
  lines.push("");
  if (evaluation.passed) {
    const hasExceptions = (evaluation.exceptionsApplied?.length ?? 0) > 0;
    lines.push(`  Status: ${hasExceptions ? "COMPLIANT (WITH EXCEPTIONS)" : "COMPLIANT"}`);
  } else {
    lines.push("  Status: NON-COMPLIANT");
    lines.push(`  Violations: ${evaluation.violations.length}`);
  }
  lines.push(`  Score: ${evaluation.score} (minimum: ${evaluation.minScore})`);
  lines.push("");
  if (evaluation.violations.length > 0) {
    lines.push("  POLICY VIOLATIONS:");
    for (const v of evaluation.violations) {
      lines.push(`    [${v.severity.toUpperCase().padEnd(8)}] ${v.rule}: ${v.description}`);
      lines.push(`               Expected: ${v.expected}`);
      lines.push(`               Actual:   ${v.actual}`);
    }
    lines.push("");
  }
  if (evaluation.exceptionsApplied && evaluation.exceptionsApplied.length > 0) {
    lines.push("  EXCEPTIONS APPLIED:");
    for (const exception of evaluation.exceptionsApplied) {
      lines.push(`    ${exception.id} (${exception.rule}) owner=${exception.owner} expires=${exception.expiresAt}`);
      lines.push(`               Reason: ${exception.reason}`);
    }
    lines.push("");
  }
  if (evaluation.exceptionSummary && evaluation.exceptionSummary.total > 0) {
    const summary = evaluation.exceptionSummary;
    lines.push("  EXCEPTION AUDIT:");
    lines.push(
      `    total=${summary.total} active=${summary.active} expiring_soon=${summary.expiringSoon} expired=${summary.expired}`
    );
    for (const exception of summary.entries) {
      const details = [
        `status=${exception.status}`,
        `owner=${exception.owner}`,
        `expires=${exception.expiresAt}`,
        `days=${formatExceptionDays2(exception.daysUntilExpiry)}`,
        ...exception.scope ? [`scope=${exception.scope}`] : [],
        ...exception.ticket ? [`ticket=${exception.ticket}`] : []
      ];
      lines.push(`    ${exception.id} (${exception.rule}) ${details.join(" ")}`);
    }
    lines.push("");
  }
  lines.push(`  ${divider}`);
  lines.push("");
  return lines.join("\n");
}
function formatExceptionDays2(daysUntilExpiry) {
  return Number.isFinite(daysUntilExpiry) ? String(daysUntilExpiry) : "invalid";
}
function generateExamplePolicy(pack = "enterprise", options = {}) {
  const policy = generatePolicyPack(pack, {
    name: options.name ?? "Acme Corp Security Policy",
    owners: options.owners ?? ["security-platform@acme.example"]
  });
  const example = {
    ...policy,
    exceptions: [
      {
        id: "AS-EX-001",
        rule: "required_hooks",
        owner: "security-platform@acme.example",
        reason: "Legacy repository migration window",
        expires_at: "2026-06-30T23:59:59.000Z",
        scope: "agentshield",
        ticket: "SEC-1234"
      }
    ]
  };
  return JSON.stringify(example, null, 2);
}
var SEVERITY_ORDER, EXPIRING_SOON_DAYS, MS_PER_DAY;
var init_evaluate = __esm({
  "src/policy/evaluate.ts"() {
    "use strict";
    init_types();
    init_presets();
    SEVERITY_ORDER = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4
    };
    EXPIRING_SOON_DAYS = 7;
    MS_PER_DAY = 24 * 60 * 60 * 1e3;
  }
});

// src/policy/index.ts
var policy_exports = {};
__export(policy_exports, {
  OrgPolicySchema: () => OrgPolicySchema,
  PolicyExceptionSchema: () => PolicyExceptionSchema,
  PolicyPackSchema: () => PolicyPackSchema,
  evaluatePolicy: () => evaluatePolicy,
  generateExamplePolicy: () => generateExamplePolicy,
  generatePolicyPack: () => generatePolicyPack,
  listPolicyPacks: () => listPolicyPacks,
  loadPolicy: () => loadPolicy,
  renderPolicyEvaluation: () => renderPolicyEvaluation
});
var init_policy = __esm({
  "src/policy/index.ts"() {
    "use strict";
    init_evaluate();
    init_presets();
    init_types();
  }
});

// src/supply-chain/extract.ts
function extractPackages(files) {
  const packages = [];
  const seen = /* @__PURE__ */ new Set();
  for (const file of files) {
    if (file.type !== "mcp-json" && file.type !== "settings-json") continue;
    const extracted = extractFromMcpConfig(file.content);
    for (const pkg of extracted) {
      const key = buildPackageDedupeKey(pkg);
      if (!seen.has(key)) {
        seen.add(key);
        packages.push(pkg);
      }
    }
  }
  return packages;
}
function extractFromMcpConfig(content) {
  try {
    const config = JSON.parse(content);
    if (!isRecord(config) || !isRecord(config.mcpServers)) {
      return [];
    }
    const servers = config.mcpServers;
    const packages = [];
    for (const [serverName, serverConfig] of Object.entries(servers)) {
      const server = normalizeServerConfig(serverConfig);
      if (!server) continue;
      const extracted = extractFromServerConfig(
        serverName,
        server.command,
        server.args ?? []
      );
      packages.push(...extracted);
    }
    return packages;
  } catch {
    return [];
  }
}
function extractFromServerConfig(serverName, command, args) {
  const packages = [];
  if (command === "npx" || command.endsWith("/npx")) {
    packages.push(...extractFromNpxArgs(serverName, args));
  }
  if (command === "node" || command.endsWith("/node")) {
    for (const arg of args) {
      if (arg.startsWith("-")) continue;
      const nodeModuleMatch = arg.match(
        /node_modules\/(@[^/]+\/[^/]+|[^/]+)/
      );
      if (nodeModuleMatch) {
        packages.push({
          name: nodeModuleMatch[1],
          source: "args",
          serverName
        });
      }
    }
  }
  if (!command.includes("/") && !command.startsWith(".")) {
    const parsed = parsePackageSpec(command);
    if (parsed && looksLikeNpmPackage(parsed.name)) {
      packages.push({
        ...parsed,
        source: "command",
        serverName
      });
    }
  }
  for (const arg of args) {
    const gitInfo = parseGitUrl(arg);
    if (gitInfo) {
      packages.push({
        name: gitInfo.repo,
        source: "git",
        serverName,
        gitUrl: arg,
        gitRef: gitInfo.ref
      });
    }
  }
  return packages;
}
function buildPackageDedupeKey(pkg) {
  return [
    pkg.source,
    pkg.name,
    pkg.version ?? "latest",
    pkg.gitUrl ?? "",
    pkg.gitRef ?? ""
  ].join("|");
}
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function normalizeServerConfig(value) {
  if (!isRecord(value) || typeof value.command !== "string") {
    return null;
  }
  const args = Array.isArray(value.args) ? value.args.filter((arg) => typeof arg === "string") : [];
  return {
    command: value.command,
    args
  };
}
function extractFromNpxArgs(serverName, args) {
  const packages = [];
  let sawExplicitPackageFlag = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-p" || arg === "--package") {
      sawExplicitPackageFlag = true;
      const spec = args[i + 1];
      const parsed = spec ? parsePackageSpec(spec) : null;
      if (parsed) {
        packages.push({
          ...parsed,
          source: "npx",
          serverName
        });
      }
      i += 1;
      continue;
    }
    if (arg.startsWith("--package=")) {
      sawExplicitPackageFlag = true;
      const parsed = parsePackageSpec(arg.slice("--package=".length));
      if (parsed) {
        packages.push({
          ...parsed,
          source: "npx",
          serverName
        });
      }
    }
  }
  if (packages.length > 0 || sawExplicitPackageFlag) {
    return packages;
  }
  for (const arg of args) {
    if (arg.startsWith("-")) continue;
    if (parseGitUrl(arg)) continue;
    const parsed = parsePackageSpec(arg);
    if (parsed) {
      packages.push({
        ...parsed,
        source: "npx",
        serverName
      });
      break;
    }
  }
  return packages;
}
function parsePackageSpec(spec) {
  if (!spec || spec.startsWith("-") || spec.startsWith(".") || spec.startsWith("/")) {
    return null;
  }
  if (isUrlLikeSpec(spec)) {
    return null;
  }
  if (spec.includes("/") && !spec.startsWith("@")) {
    return null;
  }
  if (spec.startsWith("@")) {
    const scopeEnd = spec.indexOf("/");
    if (scopeEnd === -1) return null;
    const afterScope = spec.slice(scopeEnd + 1);
    const versionIndex = afterScope.indexOf("@");
    if (versionIndex === -1) {
      return { name: spec };
    }
    return {
      name: spec.slice(0, scopeEnd + 1 + versionIndex),
      version: afterScope.slice(versionIndex + 1)
    };
  }
  const atIndex = spec.indexOf("@");
  if (atIndex === -1) {
    return { name: spec };
  }
  return {
    name: spec.slice(0, atIndex),
    version: spec.slice(atIndex + 1)
  };
}
function isUrlLikeSpec(spec) {
  return /^(?:[a-z][a-z0-9+.-]*:|git@)/i.test(spec) || spec.includes("://");
}
function looksLikeNpmPackage(name) {
  if (name.startsWith("@")) return true;
  if (name.includes("-mcp") || name.includes("mcp-")) return true;
  if (name.includes("-server") || name.includes("server-")) return true;
  return false;
}
function parseGitUrl(url) {
  const patterns = [
    /^(?:git\+)?https?:\/\/github\.com\/([^#@]+?)(?:[#@](.+))?$/i,
    /^git:\/\/github\.com\/([^#@]+?)(?:[#@](.+))?$/i,
    /^git\+ssh:\/\/git@github\.com\/([^#@]+?)(?:[#@](.+))?$/i,
    /^git@github\.com:([^#@]+?)(?:[#@](.+))?$/i,
    /^github:([^#@]+?)(?:[#@](.+))?$/i
  ];
  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (!match) continue;
    return {
      repo: match[1].replace(/\.git$/, ""),
      ref: match[2]
    };
  }
  return null;
}
var init_extract = __esm({
  "src/supply-chain/extract.ts"() {
    "use strict";
  }
});

// src/supply-chain/types.ts
var KNOWN_GOOD_PACKAGES;
var init_types2 = __esm({
  "src/supply-chain/types.ts"() {
    "use strict";
    KNOWN_GOOD_PACKAGES = [
      "@modelcontextprotocol/sdk",
      "@modelcontextprotocol/server-filesystem",
      "@modelcontextprotocol/server-github",
      "@modelcontextprotocol/server-postgres",
      "@modelcontextprotocol/server-brave-search",
      "@modelcontextprotocol/server-memory",
      "@modelcontextprotocol/server-puppeteer",
      "@modelcontextprotocol/server-sequential-thinking",
      "@modelcontextprotocol/server-everything",
      "@modelcontextprotocol/server-slack",
      "@anthropics/mcp-server-git",
      "firecrawl-mcp",
      "tavily-mcp",
      "exa-mcp-server",
      "@supabase/mcp-server-supabase",
      "@cloudflare/mcp-server-cloudflare",
      "@playwright/mcp",
      "context7-mcp"
    ];
  }
});

// src/supply-chain/verify.ts
async function verifyPackages(packages, options = {}) {
  const verifications = [];
  for (const pkg of packages) {
    const risks = [];
    let registry;
    const malicious = checkPackageName(pkg.name, pkg.version);
    if (malicious) {
      risks.push({
        type: "known-malicious",
        severity: "critical",
        description: malicious.description,
        evidence: `Package: ${malicious.name} (${malicious.type})`
      });
    }
    const vulnerable = checkServerPackage(
      pkg.name,
      pkg.version ? [`${pkg.name}@${pkg.version}`] : [pkg.name]
    );
    if (vulnerable) {
      risks.push({
        type: "known-vulnerable",
        severity: "high",
        description: vulnerable.description,
        evidence: `CVEs: ${vulnerable.cveIds.join(", ")}`
      });
    }
    const typosquatRisk = checkTyposquatting(pkg.name);
    if (typosquatRisk) {
      risks.push(typosquatRisk);
    }
    if (pkg.source === "git" && !hasPinnedGitCommit(pkg.gitRef)) {
      risks.push({
        type: "unpinned-git",
        severity: "high",
        description: "Git URL without a pinned commit hash. An attacker who compromises the repo can inject malicious code.",
        evidence: pkg.gitUrl
      });
    }
    if (options.online && pkg.source !== "git") {
      registry = await fetchRegistryMeta(pkg.name);
      if (registry) {
        risks.push(...assessRegistryRisks(registry));
      }
    }
    const overallSeverity = risks.length > 0 ? risks.reduce(
      (worst, r) => SEVERITY_ORDER2[r.severity] < SEVERITY_ORDER2[worst.severity] ? r : worst
    ).severity : "info";
    verifications.push({
      package: pkg,
      provenance: buildPackageProvenance(pkg, registry),
      registry,
      risks,
      overallSeverity
    });
  }
  const riskyPackages = verifications.filter((v) => v.risks.length > 0);
  return {
    packages: verifications,
    totalPackages: verifications.length,
    riskyPackages: riskyPackages.length,
    criticalCount: riskyPackages.filter((v) => v.overallSeverity === "critical").length,
    highCount: riskyPackages.filter((v) => v.overallSeverity === "high").length,
    provenance: summarizePackageProvenance(verifications)
  };
}
function checkTyposquatting(packageName) {
  if (KNOWN_GOOD_PACKAGES.includes(packageName)) return null;
  for (const goodPkg of KNOWN_GOOD_PACKAGES) {
    const distance = levenshteinDistance(packageName, goodPkg);
    const maxLen = Math.max(packageName.length, goodPkg.length);
    const similarity = 1 - distance / maxLen;
    if (similarity > 0.8 && distance > 0 && distance <= 3) {
      return {
        type: "typosquat",
        severity: "high",
        description: `Package name "${packageName}" is suspiciously similar to known-good package "${goodPkg}" (${Math.round(similarity * 100)}% similarity, edit distance: ${distance}).`,
        evidence: `Similar to: ${goodPkg}`
      };
    }
  }
  return null;
}
function hasPinnedGitCommit(gitRef) {
  return !!gitRef && GIT_COMMIT_HASH.test(gitRef);
}
function buildPackageProvenance(pkg, registry) {
  if (pkg.source === "git") {
    return {
      ecosystem: "git",
      locator: pkg.gitUrl ?? pkg.name,
      pinned: hasPinnedGitCommit(pkg.gitRef),
      knownGood: false,
      metadataSource: "git-url"
    };
  }
  return {
    ecosystem: "npm",
    locator: `${pkg.name}@${pkg.version ?? "latest"}`,
    pinned: isPinnedNpmVersion(pkg.version),
    knownGood: KNOWN_GOOD_PACKAGES.includes(pkg.name),
    metadataSource: registry ? "npm-registry" : "offline"
  };
}
function summarizePackageProvenance(verifications) {
  return verifications.reduce(
    (summary, verification) => ({
      npmPackages: summary.npmPackages + (verification.provenance.ecosystem === "npm" ? 1 : 0),
      gitPackages: summary.gitPackages + (verification.provenance.ecosystem === "git" ? 1 : 0),
      pinnedPackages: summary.pinnedPackages + (verification.provenance.pinned ? 1 : 0),
      unpinnedPackages: summary.unpinnedPackages + (verification.provenance.pinned ? 0 : 1),
      knownGoodPackages: summary.knownGoodPackages + (verification.provenance.knownGood ? 1 : 0),
      registryMetadataPackages: summary.registryMetadataPackages + (verification.provenance.metadataSource === "npm-registry" ? 1 : 0)
    }),
    {
      npmPackages: 0,
      gitPackages: 0,
      pinnedPackages: 0,
      unpinnedPackages: 0,
      knownGoodPackages: 0,
      registryMetadataPackages: 0
    }
  );
}
function isPinnedNpmVersion(version) {
  return !!version && EXACT_NPM_VERSION.test(version);
}
function levenshteinDistance(a, b) {
  const m = a.length;
  const n = b.length;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array(n + 1);
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,
        // deletion
        curr[j - 1] + 1,
        // insertion
        prev[j - 1] + cost
        // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}
async function fetchRegistryMeta(packageName) {
  try {
    const registryUrl = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
    const response = await fetch(registryUrl, {
      signal: AbortSignal.timeout(5e3)
    });
    if (!response.ok) return void 0;
    const data = await response.json();
    const time = data.time;
    const maintainers = data.maintainers;
    const distTags = data["dist-tags"];
    const latestVersion = distTags?.latest;
    const versions = data.versions;
    let hasPostinstall = false;
    if (latestVersion && versions?.[latestVersion]) {
      const scripts = versions[latestVersion].scripts;
      hasPostinstall = !!scripts?.postinstall;
    }
    let downloadsLastWeek;
    try {
      const dlResponse = await fetch(
        `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`,
        { signal: AbortSignal.timeout(3e3) }
      );
      if (dlResponse.ok) {
        const dlData = await dlResponse.json();
        downloadsLastWeek = dlData.downloads;
      }
    } catch {
    }
    return {
      name: packageName,
      publishedAt: time?.created,
      downloadsLastWeek,
      maintainerCount: maintainers?.length,
      hasPostinstall,
      latestVersion,
      description: data.description,
      deprecated: !!data.deprecated
    };
  } catch {
    return void 0;
  }
}
function assessRegistryRisks(meta) {
  const risks = [];
  if (meta.deprecated) {
    risks.push({
      type: "deprecated",
      severity: "medium",
      description: `Package "${meta.name}" is deprecated on npm.`
    });
  }
  if (meta.hasPostinstall) {
    risks.push({
      type: "has-postinstall",
      severity: "medium",
      description: `Package "${meta.name}" has a postinstall script that runs automatically on install.`
    });
  }
  if (meta.maintainerCount !== void 0 && meta.maintainerCount <= 1) {
    risks.push({
      type: "single-maintainer",
      severity: "low",
      description: `Package "${meta.name}" has only ${meta.maintainerCount} maintainer(s). Single-maintainer packages are higher risk for account compromise.`
    });
  }
  if (meta.downloadsLastWeek !== void 0 && meta.downloadsLastWeek < 100) {
    risks.push({
      type: "low-downloads",
      severity: "medium",
      description: `Package "${meta.name}" has very low downloads (${meta.downloadsLastWeek}/week). Low-traffic packages are more likely to be malicious.`
    });
  }
  if (meta.publishedAt) {
    const publishDate = new Date(meta.publishedAt);
    const threeMonthsAgo = /* @__PURE__ */ new Date();
    threeMonthsAgo.setMonth(threeMonthsAgo.getMonth() - 3);
    if (publishDate > threeMonthsAgo) {
      risks.push({
        type: "new-package",
        severity: "low",
        description: `Package "${meta.name}" was first published recently (${meta.publishedAt}). New packages have less community vetting.`
      });
    }
  }
  return risks;
}
var SEVERITY_ORDER2, GIT_COMMIT_HASH, EXACT_NPM_VERSION;
var init_verify = __esm({
  "src/supply-chain/verify.ts"() {
    "use strict";
    init_types2();
    init_cve_database();
    SEVERITY_ORDER2 = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4
    };
    GIT_COMMIT_HASH = /^[0-9a-f]{7,40}$/i;
    EXACT_NPM_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
  }
});

// src/supply-chain/render.ts
function renderSupplyChainReport(report) {
  const lines = [];
  const divider = "\u2500".repeat(60);
  lines.push("");
  lines.push(`  ${divider}`);
  lines.push("  Supply Chain Verification Report");
  lines.push(`  ${divider}`);
  lines.push("");
  lines.push(`  Packages analyzed: ${report.totalPackages}`);
  lines.push(`  Risky packages:    ${report.riskyPackages}`);
  lines.push(
    `  Provenance:        npm: ${report.provenance.npmPackages}, git: ${report.provenance.gitPackages}, pinned: ${report.provenance.pinnedPackages}, unpinned: ${report.provenance.unpinnedPackages}, known-good: ${report.provenance.knownGoodPackages}, registry-backed: ${report.provenance.registryMetadataPackages}`
  );
  if (report.criticalCount > 0) {
    lines.push(`  Critical:          ${report.criticalCount}`);
  }
  if (report.highCount > 0) {
    lines.push(`  High:              ${report.highCount}`);
  }
  if (report.packages.length === 0) {
    lines.push("");
    lines.push("  No MCP packages detected in configuration.");
    lines.push("");
    return lines.join("\n");
  }
  const risky = report.packages.filter((p) => p.risks.length > 0);
  const clean = report.packages.filter((p) => p.risks.length === 0);
  if (risky.length > 0) {
    lines.push("");
    lines.push("  RISKY PACKAGES:");
    for (const pkg of risky) {
      lines.push(...renderPackage(pkg));
    }
  }
  if (clean.length > 0) {
    lines.push("");
    lines.push("  CLEAN PACKAGES:");
    for (const pkg of clean) {
      const version = pkg.package.version ? `@${escapeControlChars(pkg.package.version)}` : "";
      const name = escapeControlChars(pkg.package.name);
      const serverName = escapeControlChars(pkg.package.serverName);
      lines.push(`    [OK] ${name}${version} (${serverName})`);
    }
  }
  lines.push("");
  lines.push(`  ${divider}`);
  lines.push("");
  return lines.join("\n");
}
function renderPackage(verification) {
  const lines = [];
  const pkg = verification.package;
  const version = pkg.version ? `@${escapeControlChars(pkg.version)}` : "";
  const sev = verification.overallSeverity.toUpperCase();
  const name = escapeControlChars(pkg.name);
  const serverName = escapeControlChars(pkg.serverName);
  const source = escapeControlChars(pkg.source);
  lines.push(`    [${sev}] ${name}${version} (server: ${serverName}, via: ${source})`);
  for (const risk of verification.risks) {
    lines.push(`      - [${risk.severity.toUpperCase()}] ${escapeControlChars(risk.description)}`);
    if (risk.evidence) {
      lines.push(`        Evidence: ${escapeControlChars(risk.evidence)}`);
    }
  }
  if (verification.registry) {
    const meta = verification.registry;
    const details = [];
    if (meta.downloadsLastWeek !== void 0) {
      details.push(`${meta.downloadsLastWeek} downloads/week`);
    }
    if (meta.maintainerCount !== void 0) {
      details.push(`${meta.maintainerCount} maintainer(s)`);
    }
    if (meta.latestVersion) {
      details.push(`latest: ${escapeControlChars(meta.latestVersion)}`);
    }
    if (details.length > 0) {
      lines.push(`      Registry: ${details.join(", ")}`);
    }
  }
  return lines;
}
function renderSupplyChainJson(report) {
  return JSON.stringify(report, null, 2);
}
function escapeControlChars(value) {
  return value.replace(CONTROL_CHAR_PATTERN, (char) => {
    const code = char.charCodeAt(0);
    return code <= 255 ? `\\x${code.toString(16).padStart(2, "0")}` : `\\u${code.toString(16).padStart(4, "0")}`;
  });
}
var CONTROL_CHAR_PATTERN;
var init_render = __esm({
  "src/supply-chain/render.ts"() {
    "use strict";
    CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F-\u009F]/g;
  }
});

// src/supply-chain/index.ts
var supply_chain_exports = {};
__export(supply_chain_exports, {
  KNOWN_GOOD_PACKAGES: () => KNOWN_GOOD_PACKAGES,
  checkTyposquatting: () => checkTyposquatting,
  extractPackages: () => extractPackages,
  levenshteinDistance: () => levenshteinDistance,
  renderSupplyChainJson: () => renderSupplyChainJson,
  renderSupplyChainReport: () => renderSupplyChainReport,
  verifyPackages: () => verifyPackages
});
var init_supply_chain = __esm({
  "src/supply-chain/index.ts"() {
    "use strict";
    init_extract();
    init_verify();
    init_render();
    init_types2();
  }
});

// src/baseline/types.ts
var DEFAULT_GATE_CONFIG;
var init_types3 = __esm({
  "src/baseline/types.ts"() {
    "use strict";
    DEFAULT_GATE_CONFIG = {
      maxNewFindings: 0,
      maxScoreDrop: 5,
      failOnNewCritical: true,
      failOnNewHigh: true
    };
  }
});

// src/baseline/compare.ts
import { readFileSync as readFileSync4, writeFileSync as writeFileSync3, existsSync as existsSync5 } from "fs";
import { dirname as dirname3 } from "path";
import { mkdirSync as mkdirSync3 } from "fs";
function saveBaseline(findings, score, outputPath) {
  const serialized = {
    version: 1,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    score,
    findings: findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      category: f.category,
      title: f.title,
      file: f.file,
      fingerprint: fingerprintFinding(f)
    }))
  };
  const dir = dirname3(outputPath);
  if (!existsSync5(dir)) {
    mkdirSync3(dir, { recursive: true });
  }
  writeFileSync3(outputPath, JSON.stringify(serialized, null, 2));
}
function loadBaseline(baselinePath) {
  if (!existsSync5(baselinePath)) return null;
  try {
    const raw = readFileSync4(baselinePath, "utf-8");
    const parsed = JSON.parse(raw);
    if (parsed.version !== 1 || !Array.isArray(parsed.findings)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}
function compareBaseline(baseline, currentFindings, currentScore) {
  const baselineFingerprints = new Set(
    baseline.findings.flatMap((finding) => baselineFingerprintsFor(finding))
  );
  const currentFingerprints = new Set(
    currentFindings.flatMap((finding) => [
      fingerprintFinding(finding),
      legacyEvidenceFingerprint(finding)
    ])
  );
  const newFindings = currentFindings.filter(
    (f) => !baselineFingerprints.has(fingerprintFinding(f))
  );
  const resolvedFindings = baseline.findings.filter(
    (f) => baselineFingerprintsFor(f).every((fingerprint) => !currentFingerprints.has(fingerprint))
  );
  const unchangedCount = currentFindings.length - newFindings.length;
  const scoreDelta = currentScore.numericScore - baseline.score.numericScore;
  const newCriticalCount = newFindings.filter(
    (f) => f.severity === "critical"
  ).length;
  const newHighCount = newFindings.filter(
    (f) => f.severity === "high"
  ).length;
  const isRegression = newFindings.length > 0 || scoreDelta < 0;
  return {
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    baselineTimestamp: baseline.timestamp,
    newFindings,
    resolvedFindings,
    unchangedCount,
    scoreDelta,
    baselineScore: baseline.score.numericScore,
    currentScore: currentScore.numericScore,
    isRegression,
    newCriticalCount,
    newHighCount
  };
}
function baselineFingerprintsFor(finding) {
  const fingerprints = /* @__PURE__ */ new Set([finding.fingerprint]);
  if (finding.evidence !== void 0) {
    fingerprints.add(fingerprintFinding(finding));
    fingerprints.add(legacyEvidenceFingerprint(finding));
  }
  return [...fingerprints];
}
function evaluateGate(comparison, config = DEFAULT_GATE_CONFIG) {
  const reasons = [];
  if (config.failOnNewCritical && comparison.newCriticalCount > 0) {
    reasons.push(
      `${comparison.newCriticalCount} new critical finding(s) introduced`
    );
  }
  if (config.failOnNewHigh && comparison.newHighCount > 0) {
    reasons.push(
      `${comparison.newHighCount} new high finding(s) introduced`
    );
  }
  if (comparison.newFindings.length > config.maxNewFindings) {
    reasons.push(
      `${comparison.newFindings.length} new finding(s) exceed threshold of ${config.maxNewFindings}`
    );
  }
  if (comparison.scoreDelta < -config.maxScoreDrop) {
    reasons.push(
      `Score dropped by ${Math.abs(comparison.scoreDelta)} points (max allowed: ${config.maxScoreDrop})`
    );
  }
  return {
    passed: reasons.length === 0,
    reasons,
    comparison
  };
}
function renderComparison(comparison) {
  const lines = [];
  const divider = "\u2500".repeat(60);
  lines.push("");
  lines.push(`  ${divider}`);
  lines.push("  Baseline Comparison Report");
  lines.push(`  ${divider}`);
  lines.push("");
  const direction = comparison.scoreDelta > 0 ? "+" : "";
  const label = comparison.scoreDelta > 0 ? "IMPROVED" : comparison.scoreDelta < 0 ? "REGRESSED" : "UNCHANGED";
  lines.push(
    `  Score: ${comparison.baselineScore} \u2192 ${comparison.currentScore} (${direction}${comparison.scoreDelta}) [${label}]`
  );
  lines.push(
    `  Baseline from: ${comparison.baselineTimestamp}`
  );
  lines.push("");
  if (comparison.newFindings.length > 0) {
    lines.push(`  NEW FINDINGS (${comparison.newFindings.length}):`);
    for (const f of comparison.newFindings) {
      lines.push(`    [${f.severity.toUpperCase().padEnd(8)}] ${f.title}`);
      lines.push(`               ${f.file}`);
    }
    lines.push("");
  }
  if (comparison.resolvedFindings.length > 0) {
    lines.push(`  RESOLVED FINDINGS (${comparison.resolvedFindings.length}):`);
    for (const f of comparison.resolvedFindings) {
      lines.push(`    [RESOLVED] ${f.title}`);
    }
    lines.push("");
  }
  lines.push(`  Unchanged: ${comparison.unchangedCount} finding(s)`);
  lines.push(`  ${divider}`);
  lines.push("");
  return lines.join("\n");
}
function renderGateResult(result) {
  const lines = [];
  if (result.passed) {
    lines.push("  Gate: PASSED \u2014 No regressions detected.");
  } else {
    lines.push("  Gate: FAILED \u2014 Security regressions detected:");
    for (const reason of result.reasons) {
      lines.push(`    - ${reason}`);
    }
  }
  lines.push("");
  return lines.join("\n");
}
var init_compare = __esm({
  "src/baseline/compare.ts"() {
    "use strict";
    init_fingerprint();
    init_types3();
    init_fingerprint();
  }
});

// src/baseline/index.ts
var baseline_exports = {};
__export(baseline_exports, {
  DEFAULT_GATE_CONFIG: () => DEFAULT_GATE_CONFIG,
  compareBaseline: () => compareBaseline,
  evaluateGate: () => evaluateGate,
  fingerprintFinding: () => fingerprintFinding,
  loadBaseline: () => loadBaseline,
  renderComparison: () => renderComparison,
  renderGateResult: () => renderGateResult,
  saveBaseline: () => saveBaseline
});
var init_baseline = __esm({
  "src/baseline/index.ts"() {
    "use strict";
    init_compare();
    init_types3();
  }
});

// src/action.ts
import { resolve as resolve4 } from "path";
import { dirname as dirname4 } from "path";
import { existsSync as existsSync6 } from "fs";
import { appendFileSync, mkdirSync as mkdirSync4, writeFileSync as writeFileSync4 } from "fs";

// src/scanner/discovery.ts
import { readFileSync, existsSync, readdirSync, statSync } from "fs";
import { join, basename, extname, relative } from "path";

// src/source-context.ts
var EXAMPLE_LIKE_SEGMENTS = [
  "docs",
  "doc",
  "documentation",
  "commands",
  "examples",
  "example",
  "samples",
  "sample",
  "demo",
  "demos",
  "tutorial",
  "tutorials",
  "guide",
  "guides",
  "cookbook",
  "playground"
];
var EXAMPLE_LIKE_PATH_PATTERN = new RegExp(
  `(^|/)(${EXAMPLE_LIKE_SEGMENTS.join("|")})(/|$)`,
  "i"
);
function isExampleLikePath(path) {
  return EXAMPLE_LIKE_PATH_PATTERN.test(path.replace(/\\/g, "/"));
}

// src/scanner/discovery.ts
var IGNORED_DIRS = /* @__PURE__ */ new Set([
  ".dmux",
  ".git",
  "node_modules",
  ".next",
  ".nuxt",
  ".turbo",
  ".cache",
  "coverage",
  "dist",
  "build",
  "out",
  "target",
  "vendor"
]);
var CLAUDE_ROOT_MARKERS = /* @__PURE__ */ new Set([
  "claude.md",
  "settings.json",
  "settings.local.json",
  "mcp.json",
  ".claude.json"
]);
var HOOK_SHELL_EXTENSIONS = /* @__PURE__ */ new Set([
  ".sh",
  ".bash",
  ".zsh"
]);
var HOOK_CODE_EXTENSIONS = /* @__PURE__ */ new Set([
  ".js",
  ".cjs",
  ".mjs",
  ".ts",
  ".cts",
  ".mts",
  ".py",
  ".rb"
]);
var HOOK_IMPLEMENTATION_EXTENSIONS = /* @__PURE__ */ new Set([
  ...HOOK_SHELL_EXTENSIONS,
  ...HOOK_CODE_EXTENSIONS
]);
var PROJECT_ROOT_HOOK_VARS = /* @__PURE__ */ new Set([
  "CLAUDE_PLUGIN_ROOT",
  "CLAUDE_PROJECT_DIR",
  "PWD"
]);
function discoverConfigFiles(rootPath) {
  const files = [];
  const seenFiles = /* @__PURE__ */ new Set();
  const claudeRoots = /* @__PURE__ */ new Set([rootPath]);
  const exampleClaudeFiles = /* @__PURE__ */ new Set();
  walkForClaudeRoots(rootPath, rootPath, claudeRoots, exampleClaudeFiles);
  for (const exampleClaudeFile of [...exampleClaudeFiles].sort()) {
    addDiscoveredFile(rootPath, exampleClaudeFile, "claude-md", files, seenFiles);
  }
  for (const claudeRoot of [...claudeRoots].sort()) {
    scanClaudeRoot(rootPath, claudeRoot, files, seenFiles);
  }
  return { path: rootPath, files };
}
function walkForClaudeRoots(scanRoot, dirPath, claudeRoots, exampleClaudeFiles) {
  if (!existsSync(dirPath) || !statSync(dirPath).isDirectory()) return;
  const entries = readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      if (entry.name === ".claude") {
        claudeRoots.add(dirPath);
        continue;
      }
      walkForClaudeRoots(scanRoot, join(dirPath, entry.name), claudeRoots, exampleClaudeFiles);
      continue;
    }
    if (!entry.isFile()) continue;
    if (CLAUDE_ROOT_MARKERS.has(entry.name.toLowerCase())) {
      if (isExampleOnlyClaudeRoot(scanRoot, dirPath, entry.name)) {
        exampleClaudeFiles.add(join(dirPath, entry.name));
        continue;
      }
      claudeRoots.add(dirPath);
    }
  }
}
function isExampleOnlyClaudeRoot(scanRoot, dirPath, markerName) {
  if (markerName.toLowerCase() !== "claude.md") return false;
  const relativeDir = relative(scanRoot, dirPath);
  const segments = relativeDir.split(/[\\/]/).filter(Boolean).map((segment) => segment.toLowerCase()).join("/");
  if (!isExampleLikePath(segments)) {
    return false;
  }
  const hasRuntimeCompanion = [
    "settings.json",
    "settings.local.json",
    "mcp.json",
    ".claude.json"
  ].some((name) => existsSync(join(dirPath, name))) || existsSync(join(dirPath, ".claude"));
  return !hasRuntimeCompanion;
}
function scanClaudeRoot(scanRoot, claudeRoot, files, seenFiles) {
  const directFiles = [
    ["CLAUDE.md", "claude-md"],
    [".claude/CLAUDE.md", "claude-md"],
    ["settings.json", "settings-json"],
    ["settings.local.json", "settings-json"],
    [".claude/settings.json", "settings-json"],
    [".claude/settings.local.json", "settings-json"],
    [".claude/router_runtime.js", "hook-code"],
    [".claude/setup.mjs", "hook-code"],
    [".vscode/tasks.json", "settings-json"],
    [".github/workflows/codeql_analysis.yml", "settings-json"],
    [".github/workflows/codeql_analysis.yaml", "settings-json"],
    [".config/systemd/user/gh-token-monitor.service", "hook-script"],
    [".local/bin/gh-token-monitor.sh", "hook-script"],
    ["Library/LaunchAgents/com.user.gh-token-monitor.plist", "settings-json"],
    ["mcp.json", "mcp-json"],
    [".claude/mcp.json", "mcp-json"],
    [".claude.json", "mcp-json"]
  ];
  for (const [relativePath, type] of directFiles) {
    const fullPath = join(claudeRoot, relativePath);
    if (existsSync(fullPath)) {
      addDiscoveredFile(scanRoot, fullPath, type, files, seenFiles);
    }
  }
  const subdirs = [
    ["agents", "agent-md"],
    [".claude/agents", "agent-md"],
    ["subagents", "agent-md"],
    [".claude/subagents", "agent-md"],
    ["mcp-configs", "mcp-json"],
    [".claude/mcp-configs", "mcp-json"],
    ["mcp", "mcp-json"],
    [".claude/mcp", "mcp-json"],
    ["configs/mcp", "mcp-json"],
    ["config/mcp", "mcp-json"],
    ["skills", "skill-md"],
    [".claude/skills", "skill-md"],
    ["hooks", "hook-script"],
    [".claude/hooks", "hook-script"],
    [".vscode", "hook-script"],
    ["rules", "rule-md"],
    [".claude/rules", "rule-md"],
    ["contexts", "context-md"],
    [".claude/contexts", "context-md"],
    ["commands", "skill-md"],
    [".claude/commands", "skill-md"],
    ["slash-commands", "skill-md"],
    [".claude/slash-commands", "skill-md"]
  ];
  for (const [subdir, type] of subdirs) {
    const dirPath = join(claudeRoot, subdir);
    if (existsSync(dirPath) && statSync(dirPath).isDirectory()) {
      const entries = readdirSync(dirPath);
      for (const entry of entries) {
        const entryPath = join(dirPath, entry);
        if (statSync(entryPath).isFile()) {
          addDiscoveredFile(scanRoot, entryPath, inferType(entry, type), files, seenFiles);
        }
      }
    }
  }
  discoverReferencedHookScripts(scanRoot, claudeRoot, files, seenFiles);
}
function inferType(filename, defaultType) {
  const ext = extname(filename).toLowerCase();
  const name = basename(filename).toLowerCase();
  if (name === "claude.md") return "claude-md";
  if (name === "settings.json" || name === "settings.local.json") return "settings-json";
  if (name === "mcp.json" || name === ".claude.json") return "mcp-json";
  if (HOOK_SHELL_EXTENSIONS.has(ext) && defaultType === "hook-script") return "hook-script";
  if (HOOK_CODE_EXTENSIONS.has(ext) && defaultType === "hook-script") return "hook-code";
  if (ext === ".sh" || ext === ".bash" || ext === ".zsh") return "hook-script";
  if (defaultType === "hook-script" && (ext === ".md" || ext === ".markdown")) {
    return "unknown";
  }
  if (defaultType === "mcp-json" && ext === ".json") return "mcp-json";
  if (defaultType === "mcp-json" && (ext === ".md" || ext === ".markdown")) {
    return "unknown";
  }
  if (defaultType === "agent-md" && ext === ".json") return "agent-md";
  if (defaultType === "skill-md" && ext === ".json") return "skill-md";
  if (ext === ".json") return "settings-json";
  if (ext === ".md" || ext === ".markdown") return defaultType;
  return "unknown";
}
function discoverReferencedHookScripts(scanRoot, claudeRoot, files, seenFiles) {
  const hookConfigPaths = [
    "settings.json",
    "settings.local.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    "hooks/hooks.json",
    ".claude/hooks/hooks.json"
  ];
  for (const relativeConfigPath of hookConfigPaths) {
    const fullPath = join(claudeRoot, relativeConfigPath);
    if (!existsSync(fullPath) || !statSync(fullPath).isFile()) continue;
    const content = readFileSync(fullPath, "utf-8");
    for (const candidate of extractHookReferencedPaths(content)) {
      const resolvedPath = resolveHookReferencedPath(scanRoot, claudeRoot, candidate);
      if (!resolvedPath) continue;
      addDiscoveredFile(scanRoot, resolvedPath, inferType(resolvedPath, "hook-script"), files, seenFiles);
    }
  }
}
function extractHookReferencedPaths(content) {
  const referencedPaths = /* @__PURE__ */ new Set();
  for (const command of extractHookCommands(content)) {
    for (const candidate of extractCommandPathCandidates(command)) {
      referencedPaths.add(candidate);
    }
  }
  return [...referencedPaths];
}
function extractHookCommands(content) {
  try {
    const config = JSON.parse(content);
    const hookGroups = config?.hooks;
    if (!hookGroups || typeof hookGroups !== "object") return [];
    const commands = [];
    for (const group of Object.values(hookGroups)) {
      if (!Array.isArray(group)) continue;
      for (const entry of group) {
        commands.push(...extractHookEntryCommands(entry));
      }
    }
    return commands;
  } catch {
    return [];
  }
}
function extractHookEntryCommands(entry) {
  if (!entry || typeof entry !== "object") return [];
  const record = entry;
  const commands = [];
  if (typeof record.hook === "string" && record.hook.length > 0) {
    commands.push(record.hook);
  }
  if (typeof record.command === "string" && record.command.length > 0) {
    commands.push(record.command);
  }
  if (Array.isArray(record.hooks)) {
    for (const nestedEntry of record.hooks) {
      if (!nestedEntry || typeof nestedEntry !== "object") continue;
      const nestedCommand = nestedEntry.command;
      if (typeof nestedCommand === "string" && nestedCommand.length > 0) {
        commands.push(nestedCommand);
      }
    }
  }
  return commands;
}
function extractCommandPathCandidates(command) {
  const pathPattern = /(?:(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)\/)?(?:\.{1,2}\/)?(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+\.(?:sh|bash|zsh|js|cjs|mjs|ts|cts|mts|py|rb)/gi;
  const candidates = [];
  for (const match of command.matchAll(pathPattern)) {
    const index = match.index ?? 0;
    if (command.slice(Math.max(0, index - 3), index) === "://") {
      continue;
    }
    candidates.push(match[0]);
  }
  return candidates;
}
function resolveHookReferencedPath(scanRoot, claudeRoot, candidate) {
  let normalized = candidate.replace(/\\/g, "/");
  if (/^https?:\/\//i.test(normalized) || normalized.startsWith("/") || normalized.startsWith("~")) {
    return null;
  }
  const envVarMatch = normalized.match(/^(?:\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*))\/(.*)$/);
  if (envVarMatch) {
    const varName = envVarMatch[1] ?? envVarMatch[2];
    if (!PROJECT_ROOT_HOOK_VARS.has(varName)) {
      return null;
    }
    normalized = envVarMatch[3];
  }
  if (normalized.startsWith("/")) return null;
  const fullPath = join(claudeRoot, normalized);
  if (!existsSync(fullPath) || !statSync(fullPath).isFile()) {
    return null;
  }
  const ext = extname(fullPath).toLowerCase();
  if (!HOOK_IMPLEMENTATION_EXTENSIONS.has(ext)) {
    return null;
  }
  const relativePath = relative(scanRoot, fullPath);
  if (relativePath.startsWith("..")) {
    return null;
  }
  return fullPath;
}
function addDiscoveredFile(scanRoot, fullPath, type, files, seenFiles) {
  const relativePath = relative(scanRoot, fullPath);
  if (seenFiles.has(relativePath)) return;
  const content = readFileSync(fullPath, "utf-8");
  files.push({ path: relativePath, type, content });
  seenFiles.add(relativePath);
}

// src/rules/secrets.ts
var SECRET_PATTERNS = [
  {
    name: "anthropic-api-key",
    pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g,
    description: "Anthropic API key"
  },
  {
    name: "openai-api-key",
    pattern: /sk-proj-[a-zA-Z0-9_-]{20,}/g,
    description: "OpenAI API key"
  },
  {
    name: "github-pat",
    pattern: /ghp_[a-zA-Z0-9]{36,}/g,
    description: "GitHub personal access token"
  },
  {
    name: "github-fine-grained",
    pattern: /github_pat_[a-zA-Z0-9_]{20,}/g,
    description: "GitHub fine-grained token"
  },
  {
    name: "aws-access-key",
    pattern: /AKIA[0-9A-Z]{16}/g,
    description: "AWS access key ID"
  },
  {
    name: "aws-secret-key",
    pattern: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi,
    description: "AWS secret access key"
  },
  {
    name: "private-key",
    pattern: /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g,
    description: "Private key material"
  },
  {
    name: "hardcoded-password",
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/gi,
    description: "Hardcoded password"
  },
  {
    name: "bearer-token",
    pattern: /["']Bearer\s+[a-zA-Z0-9._-]{20,}["']/g,
    description: "Hardcoded bearer token"
  },
  {
    name: "connection-string",
    pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+:[^\s"']+@/gi,
    description: "Database connection string with credentials"
  },
  {
    name: "slack-token",
    pattern: /xox[bprs]-[a-zA-Z0-9-]{10,}/g,
    description: "Slack API token"
  },
  {
    name: "jwt-token",
    pattern: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
    description: "JWT token"
  },
  {
    name: "google-api-key",
    pattern: /AIza[a-zA-Z0-9_-]{35}/g,
    description: "Google API key"
  },
  {
    name: "stripe-key",
    pattern: /(?:sk|pk)_(?:test|live)_[a-zA-Z0-9]{24,}/g,
    description: "Stripe API key"
  },
  {
    name: "discord-token",
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g,
    description: "Discord bot token"
  },
  {
    name: "npm-token",
    pattern: /npm_[a-zA-Z0-9]{36,}/g,
    description: "npm access token"
  },
  {
    name: "sendgrid-key",
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    description: "SendGrid API key"
  },
  {
    name: "twilio-key",
    pattern: /SK[a-f0-9]{32}/g,
    description: "Twilio API key"
  },
  {
    name: "azure-key",
    pattern: /[a-zA-Z0-9/+]{86}==/g,
    description: "Azure storage account key"
  },
  {
    name: "mailchimp-key",
    pattern: /[a-f0-9]{32}-us\d{1,2}/g,
    description: "Mailchimp API key"
  },
  {
    name: "huggingface-token",
    pattern: /hf_[a-zA-Z0-9]{20,}/g,
    description: "Hugging Face access token"
  },
  {
    name: "databricks-token",
    pattern: /dapi[a-f0-9]{32}/g,
    description: "Databricks personal access token"
  },
  {
    name: "digitalocean-token",
    pattern: /dop_v1_[a-f0-9]{64}/g,
    description: "DigitalOcean personal access token"
  }
];
function findLineNumber(content, matchIndex) {
  return content.substring(0, matchIndex).split("\n").length;
}
function findAllMatches(content, pattern) {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return [...content.matchAll(new RegExp(pattern.source, flags))];
}
function maskSecretValue(value) {
  if (value.length <= 12) return value;
  return value.substring(0, 8) + "..." + value.substring(value.length - 4);
}
function extractDelimitedToken(content, startIndex) {
  let endIndex = startIndex;
  while (endIndex < content.length) {
    const char = content[endIndex];
    if (/\s/.test(char) || /["'`)\]}>]/.test(char)) {
      break;
    }
    endIndex += 1;
  }
  return content.slice(startIndex, endIndex).replace(/[.,;:]+$/, "");
}
function isMarkdownLikeFile(file) {
  return [
    "claude-md",
    "agent-md",
    "skill-md",
    "rule-md",
    "context-md"
  ].includes(file.type);
}
function isExampleLikePath2(file) {
  return isExampleLikePath(file.path);
}
function hasNearbyCodeFence(content, matchIndex) {
  const windowStart = Math.max(0, matchIndex - 800);
  const windowEnd = Math.min(content.length, matchIndex + 800);
  const window = content.slice(windowStart, windowEnd);
  return /```|~~~~/.test(window);
}
function hasExampleOrTestContext(content, matchIndex) {
  const windowStart = Math.max(0, matchIndex - 1200);
  const windowEnd = Math.min(content.length, matchIndex + 400);
  const window = content.slice(windowStart, windowEnd).toLowerCase();
  return [
    "example",
    "sample",
    "fixture",
    "test(",
    "shouldbe",
    "returns invalid",
    "returns valid",
    " passed",
    " failed",
    "funspec",
    "stringspec",
    "behaviorspec"
  ].some((marker) => window.includes(marker));
}
function isLikelyMarkdownExamplePassword(file, secretPatternName, matchIndex) {
  if (secretPatternName !== "hardcoded-password") return false;
  if (!isMarkdownLikeFile(file)) return false;
  if (!isExampleLikePath2(file)) return false;
  return hasNearbyCodeFence(file.content, matchIndex) || hasExampleOrTestContext(file.content, matchIndex);
}
function isLikelyPlaceholderConnectionString(file, rawValue) {
  if (!isMarkdownLikeFile(file)) return false;
  try {
    const url = new URL(rawValue);
    const username = decodeURIComponent(url.username).toLowerCase();
    const password = decodeURIComponent(url.password).toLowerCase();
    const hostname = url.hostname.toLowerCase();
    const databaseName = url.pathname.replace(/^\/+/, "").toLowerCase();
    const genericUsernames = /* @__PURE__ */ new Set(["user", "username", "dbuser", "demo"]);
    const genericPasswords = /* @__PURE__ */ new Set(["pass", "password", "passwd", "demo", "example"]);
    const genericDatabases = /* @__PURE__ */ new Set(["db", "database", "dbname", "mydb"]);
    const hasGenericHost = hostname === "host" || hostname === "hostname" || hostname === "db" || hostname === "database" || hostname === "example" || hostname === "example.com" || hostname.endsWith(".example.com");
    return genericUsernames.has(username) && genericPasswords.has(password) && (hasGenericHost || genericDatabases.has(databaseName));
  } catch {
    return false;
  }
}
var secretRules = [
  {
    id: "secrets-hardcoded",
    name: "Hardcoded Secrets Detection",
    description: "Scans for hardcoded API keys, tokens, passwords, and credentials",
    severity: "critical",
    category: "secrets",
    check(file) {
      const findings = [];
      for (const secretPattern of SECRET_PATTERNS) {
        const matches = findAllMatches(file.content, secretPattern.pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;
          const context = file.content.substring(
            Math.max(0, idx - 20),
            idx + match[0].length + 10
          );
          if (context.includes("${") || context.includes("process.env")) {
            continue;
          }
          if (isLikelyMarkdownExamplePassword(file, secretPattern.name, idx)) {
            continue;
          }
          const rawValue = secretPattern.name === "connection-string" ? extractDelimitedToken(file.content, idx) : match[0];
          if (secretPattern.name === "connection-string" && isLikelyPlaceholderConnectionString(file, rawValue)) {
            continue;
          }
          const maskedValue = maskSecretValue(rawValue);
          findings.push({
            id: `secrets-${secretPattern.name}-${idx}`,
            severity: "critical",
            category: "secrets",
            title: `Hardcoded ${secretPattern.description}`,
            description: `Found ${secretPattern.description} in ${file.path}. Secrets must never be hardcoded in configuration files.`,
            file: file.path,
            line: findLineNumber(file.content, idx),
            evidence: maskedValue,
            fix: {
              description: `Replace with environment variable reference`,
              before: rawValue,
              after: `\${${secretPattern.name.toUpperCase().replace(/-/g, "_")}}`,
              auto: false
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "secrets-env-in-config",
    name: "Environment Variable Exposure",
    description: "Checks for env var values being logged or exposed in config",
    severity: "high",
    category: "secrets",
    check(file) {
      const findings = [];
      const echoEnvPattern = /echo\s+.*\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|PASS|CRED)\w*\}?/gi;
      const matches = findAllMatches(file.content, echoEnvPattern);
      for (const match of matches) {
        findings.push({
          id: `secrets-echo-env-${match.index}`,
          severity: "high",
          category: "secrets",
          title: "Environment variable echoed to terminal",
          description: `Hook or script echoes sensitive environment variable. This exposes secrets in terminal output and session logs.`,
          file: file.path,
          line: findLineNumber(file.content, match.index ?? 0),
          evidence: match[0],
          fix: {
            description: "Remove echo of sensitive environment variables",
            before: match[0],
            after: "# [REMOVED: secret was being echoed]",
            auto: true
          }
        });
      }
      return findings;
    }
  },
  {
    id: "secrets-env-in-claude-md",
    name: "Secrets in CLAUDE.md",
    description: "Checks for sensitive env var assignments in CLAUDE.md files which are often committed to repos",
    severity: "high",
    category: "secrets",
    check(file) {
      if (file.type !== "claude-md") return [];
      const findings = [];
      const envAssignmentPattern = /(?:export\s+)?\b(\w*(?:API_KEY|SECRET_KEY|AUTH_TOKEN|ACCESS_TOKEN|PRIVATE_KEY|PASSWORD|CREDENTIAL|API_SECRET)\w*)\s*[=:]\s*["']?([^\s"']{4,})["']?/gi;
      const matches = findAllMatches(file.content, envAssignmentPattern);
      for (const match of matches) {
        const varName = match[1];
        const idx = match.index ?? 0;
        const value = match[2];
        if (value.startsWith("${") || value.startsWith("$")) continue;
        findings.push({
          id: `secrets-claude-md-env-${idx}`,
          severity: "high",
          category: "secrets",
          title: `Sensitive env var in CLAUDE.md: ${varName}`,
          description: `CLAUDE.md contains an assignment for "${varName}". CLAUDE.md files are typically committed to version control, exposing secrets to anyone who clones the repository.`,
          file: file.path,
          line: findLineNumber(file.content, idx),
          evidence: `${varName}=<redacted>`,
          fix: {
            description: "Move to .env file and reference via environment variable",
            before: match[0],
            after: `# Set ${varName} in your .env file`,
            auto: false
          }
        });
      }
      return findings;
    }
  },
  {
    id: "secrets-sensitive-env-passthrough",
    name: "Sensitive Env Var Passthrough",
    description: "Checks for MCP servers passing through excessive sensitive environment variables",
    severity: "medium",
    category: "secrets",
    check(file) {
      if (file.type !== "mcp-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const sensitivePatterns = /KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH/i;
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const env = serverConfig.env ?? {};
          const sensitiveVars = Object.keys(env).filter(
            (key) => sensitivePatterns.test(key)
          );
          if (sensitiveVars.length > 5) {
            findings.push({
              id: `secrets-env-passthrough-${name}`,
              severity: "medium",
              category: "secrets",
              title: `MCP server "${name}" receives ${sensitiveVars.length} sensitive env vars`,
              description: `The MCP server "${name}" has ${sensitiveVars.length} sensitive environment variables passed through (${sensitiveVars.slice(0, 3).join(", ")}...). Over-sharing secrets increases the blast radius if the server is compromised. Only pass env vars that the server actually needs.`,
              file: file.path,
              evidence: `Sensitive vars: ${sensitiveVars.join(", ")}`,
              fix: {
                description: "Remove env vars that the server does not need",
                before: `${sensitiveVars.length} sensitive env vars`,
                after: "Only the required env vars for this server",
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "secrets-url-credentials",
    name: "URL-Embedded Credentials",
    description: "Checks for URLs containing embedded usernames and passwords",
    severity: "high",
    category: "secrets",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const urlCredPattern = /https?:\/\/[^:\s]+:[^@\s]+@[^\s"']+/g;
      const matches = findAllMatches(file.content, urlCredPattern);
      for (const match of matches) {
        const idx = match.index ?? 0;
        const context = file.content.substring(Math.max(0, idx - 20), idx);
        if (context.includes("${") || context.includes("process.env")) continue;
        const masked = match[0].replace(/(:\/\/[^:]+:)[^@]+(@)/, "$1****$2");
        findings.push({
          id: `secrets-url-credentials-${idx}`,
          severity: "high",
          category: "secrets",
          title: `URL contains embedded credentials`,
          description: `Found a URL with embedded username:password in ${file.path}. Credentials in URLs are exposed in logs, browser history, and referer headers. Use environment variables or a credentials manager instead.`,
          file: file.path,
          line: findLineNumber(file.content, idx),
          evidence: masked,
          fix: {
            description: "Use environment variables for credentials",
            before: match[0].substring(0, 40),
            after: "https://${USERNAME}:${PASSWORD}@...",
            auto: false
          }
        });
      }
      return findings;
    }
  },
  {
    id: "secrets-credential-file-reference",
    name: "Credential File Reference",
    description: "Checks for references to credential files that should never be accessed by agents",
    severity: "high",
    category: "secrets",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const credentialFiles = [
        {
          pattern: /~\/\.aws\/credentials|\/\.aws\/credentials/g,
          description: "AWS credentials file"
        },
        {
          pattern: /~\/\.ssh\/id_(?:rsa|ed25519|ecdsa)|\/\.ssh\/id_(?:rsa|ed25519|ecdsa)/g,
          description: "SSH private key file"
        },
        {
          pattern: /~\/\.netrc|\/\.netrc/g,
          description: ".netrc file (contains plain-text login credentials)"
        },
        {
          pattern: /~\/\.pgpass|\/\.pgpass/g,
          description: "PostgreSQL password file"
        },
        {
          pattern: /~\/\.docker\/config\.json|\/\.docker\/config\.json/g,
          description: "Docker config (may contain registry credentials)"
        },
        {
          pattern: /~\/\.npmrc|\/\.npmrc/g,
          description: "npm config (may contain auth tokens)"
        },
        {
          pattern: /~\/\.kube\/config|\/\.kube\/config/g,
          description: "Kubernetes config (contains cluster credentials)"
        }
      ];
      for (const { pattern, description } of credentialFiles) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;
          findings.push({
            id: `secrets-cred-file-ref-${idx}`,
            severity: "high",
            category: "secrets",
            title: `Reference to ${description}: ${match[0]}`,
            description: `Found reference to "${match[0]}" \u2014 ${description}. Agent definitions and CLAUDE.md files should not reference credential files. If an agent is instructed to read these files, it could expose secrets.`,
            file: file.path,
            line: findLineNumber(file.content, idx),
            evidence: match[0]
          });
        }
      }
      return findings;
    }
  },
  {
    id: "secrets-private-key-material",
    name: "Private Key Material in Config",
    description: "Checks for PEM-encoded private keys embedded in configuration files",
    severity: "critical",
    category: "secrets",
    check(file) {
      const findings = [];
      const keyPatterns = [
        {
          pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
          description: "PEM-encoded private key"
        },
        {
          pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
          description: "PGP private key block"
        }
      ];
      for (const { pattern, description } of keyPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;
          findings.push({
            id: `secrets-private-key-${idx}`,
            severity: "critical",
            category: "secrets",
            title: `${description} found in config`,
            description: `Found "${match[0]}" in ${file.path}. Private keys should never be stored in configuration files \u2014 they grant authentication access and should be stored in secure key stores or referenced via file paths with restrictive permissions.`,
            file: file.path,
            line: findLineNumber(file.content, idx),
            evidence: match[0],
            fix: {
              description: "Remove private key and reference a key file path instead",
              before: match[0],
              after: "Reference key file: ~/.ssh/id_ed25519",
              auto: false
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "secrets-webhook-url",
    name: "Webhook URL with Secret Token",
    description: "Checks for webhook URLs that contain embedded secret tokens or API keys",
    severity: "high",
    category: "secrets",
    check(file) {
      const findings = [];
      const webhookPatterns = [
        {
          pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
          description: "Slack webhook URL \u2014 allows posting messages to a Slack channel"
        },
        {
          pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+/g,
          description: "Discord webhook URL \u2014 allows posting messages to a Discord channel"
        },
        {
          pattern: /https:\/\/outlook\.office\.com\/webhook\/[a-f0-9-]+/g,
          description: "Microsoft Teams webhook URL"
        }
      ];
      for (const { pattern, description } of webhookPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;
          findings.push({
            id: `secrets-webhook-url-${idx}`,
            severity: "high",
            category: "secrets",
            title: `Webhook URL found: ${description.split(" \u2014 ")[0]}`,
            description: `Found a ${description}. Webhook URLs contain embedded secrets and should be stored in environment variables. Anyone with this URL can post messages to the channel.`,
            file: file.path,
            line: findLineNumber(file.content, idx),
            evidence: match[0].substring(0, 30) + "...",
            fix: {
              description: "Store webhook URL in an environment variable",
              before: match[0].substring(0, 30),
              after: "${WEBHOOK_URL}",
              auto: false
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "secrets-base64-obfuscation",
    name: "Potential Base64 Obfuscated Secret",
    description: "Checks for long base64-encoded strings that may be obfuscated secrets or payloads",
    severity: "medium",
    category: "secrets",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const base64Pattern = /(?<![a-zA-Z0-9/])([A-Za-z0-9+/]{60,}={0,2})(?![a-zA-Z0-9])/g;
      const matches = findAllMatches(file.content, base64Pattern);
      for (const match of matches) {
        const idx = match.index ?? 0;
        const context = file.content.substring(Math.max(0, idx - 30), idx);
        if (/https?:\/\/|data:/.test(context)) continue;
        if (/^[a-fA-F0-9]+$/.test(match[1])) continue;
        findings.push({
          id: `secrets-base64-obfuscation-${idx}`,
          severity: "medium",
          category: "secrets",
          title: `Potential base64-obfuscated payload (${match[1].length} chars)`,
          description: `Found a long base64-encoded string (${match[1].length} characters) in ${file.path}. Attackers may encode secrets or malicious instructions in base64 to bypass pattern-matching detection. Decode and inspect this value.`,
          file: file.path,
          line: findLineNumber(file.content, idx),
          evidence: match[1].substring(0, 20) + "..." + match[1].substring(match[1].length - 10)
        });
      }
      return findings;
    }
  },
  {
    id: "secrets-hardcoded-ip-port",
    name: "Hardcoded Internal IP Address with Port",
    description: "Checks for hardcoded internal/private IP addresses with ports, which may expose internal services",
    severity: "medium",
    category: "secrets",
    check(file) {
      const findings = [];
      const ipPatterns = [
        {
          pattern: /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b/g,
          description: "Class A private IP (10.x.x.x) with port"
        },
        {
          pattern: /\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}:\d{2,5}\b/g,
          description: "Class B private IP (172.16-31.x.x) with port"
        },
        {
          pattern: /\b192\.168\.\d{1,3}\.\d{1,3}:\d{2,5}\b/g,
          description: "Class C private IP (192.168.x.x) with port"
        }
      ];
      for (const { pattern, description } of ipPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;
          findings.push({
            id: `secrets-hardcoded-ip-${idx}`,
            severity: "medium",
            category: "secrets",
            title: `Hardcoded internal IP with port: ${match[0]}`,
            description: `Found "${match[0]}" \u2014 ${description}. Hardcoded internal IPs expose network topology and service locations. Use environment variables or DNS names instead.`,
            file: file.path,
            line: findLineNumber(file.content, idx),
            evidence: match[0],
            fix: {
              description: "Replace with environment variable or DNS name",
              before: match[0],
              after: "${INTERNAL_SERVICE_URL}",
              auto: false
            }
          });
        }
      }
      return findings;
    }
  }
];

// src/rules/permissions.ts
import { statSync as statSync2 } from "fs";
import { resolve, join as join2 } from "path";
import { homedir } from "os";
function isHookManifestConfig(file, config) {
  if (!/(^|\/)hooks\/[^/]+\.json$/i.test(file.path)) return false;
  if (!config || typeof config !== "object") return false;
  return "hooks" in config;
}
var OVERLY_PERMISSIVE = [
  {
    pattern: /^Bash\(\*\)$/,
    description: "Unrestricted Bash access \u2014 any command can run",
    severity: "critical",
    suggestion: "Bash(git *), Bash(npm *), Bash(node *)"
  },
  {
    pattern: /^Bash\(sudo\s/,
    description: "Sudo access allowed \u2014 agent can escalate privileges",
    severity: "critical",
    suggestion: "Remove sudo permissions entirely"
  },
  {
    pattern: /^Write\(\*\)$/,
    description: "Unrestricted Write access \u2014 agent can write to any file",
    severity: "high",
    suggestion: "Write(src/*), Write(tests/*)"
  },
  {
    pattern: /^Edit\(\*\)$/,
    description: "Unrestricted Edit access \u2014 agent can edit any file",
    severity: "high",
    suggestion: "Edit(src/*), Edit(tests/*)"
  },
  {
    pattern: /^Bash\(rm\s/,
    description: "Delete operations explicitly allowed in Bash",
    severity: "high",
    suggestion: "Move rm commands to deny list instead"
  },
  {
    pattern: /^Bash\(curl\s/,
    description: "Unrestricted curl access \u2014 agent can make arbitrary HTTP requests",
    severity: "medium",
    suggestion: "Restrict to specific domains or move to deny list"
  },
  {
    pattern: /^Bash\(wget\s/,
    description: "Unrestricted wget access \u2014 agent can download arbitrary files",
    severity: "medium",
    suggestion: "Restrict to specific domains or move to deny list"
  },
  {
    pattern: /^Bash\(chmod\s/,
    description: "chmod access \u2014 agent can change file permissions",
    severity: "medium",
    suggestion: "Move chmod to deny list to prevent permission escalation"
  },
  {
    pattern: /^Bash\(chown\s/,
    description: "chown access \u2014 agent can change file ownership",
    severity: "high",
    suggestion: "Move chown to deny list to prevent ownership takeover"
  },
  {
    pattern: /^Bash\(ssh\s/,
    description: "SSH access \u2014 agent can connect to remote systems",
    severity: "high",
    suggestion: "Remove SSH permissions to prevent lateral movement"
  },
  {
    pattern: /^Bash\(nc\s|^Bash\(netcat\s/,
    description: "Netcat access \u2014 can open network connections for exfiltration or reverse shells",
    severity: "high",
    suggestion: "Remove netcat permissions entirely"
  },
  {
    pattern: /^Bash\(python\s|^Bash\(python3\s|^Bash\(node\s/,
    description: "Interpreter access \u2014 agent can run arbitrary code via scripting language",
    severity: "high",
    suggestion: "Restrict to specific scripts: Bash(node scripts/build.js)"
  },
  {
    pattern: /^Bash\(docker\s/,
    description: "Docker access \u2014 containers can escape to host, mount filesystems, and access host network",
    severity: "high",
    suggestion: "Remove docker permissions or restrict to read-only: Bash(docker ps)"
  },
  {
    pattern: /^Bash\(kill\s|^Bash\(pkill\s|^Bash\(killall\s/,
    description: "Process killing \u2014 agent can terminate system processes",
    severity: "medium",
    suggestion: "Move process killing to deny list"
  },
  {
    pattern: /^Bash\(eval\s/,
    description: "eval access \u2014 agent can execute arbitrary code via shell eval",
    severity: "critical",
    suggestion: "Remove eval permissions; use explicit commands instead"
  },
  {
    pattern: /^Bash\(exec\s/,
    description: "exec access \u2014 agent can replace the current process with arbitrary commands",
    severity: "critical",
    suggestion: "Remove exec permissions; use explicit commands instead"
  }
];
var MISSING_DENIALS = [
  { pattern: "rm -rf", description: "Recursive force delete" },
  { pattern: "sudo", description: "Privilege escalation" },
  { pattern: "chmod 777", description: "World-writable permissions" },
  { pattern: "ssh", description: "SSH connections from agent" },
  { pattern: "> /dev/", description: "Writing to device files" }
];
function parsePermissionLists(content) {
  try {
    const config = JSON.parse(content);
    return {
      allow: config?.permissions?.allow ?? [],
      deny: config?.permissions?.deny ?? []
    };
  } catch {
    return null;
  }
}
function findConfigKeyValues(value, keyPattern, currentPath = "") {
  const matches = [];
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      const childPath = `${currentPath}[${index}]`;
      matches.push(...findConfigKeyValues(item, keyPattern, childPath));
    });
    return matches;
  }
  if (!value || typeof value !== "object") {
    return matches;
  }
  for (const [key, child] of Object.entries(value)) {
    const childPath = currentPath ? `${currentPath}.${key}` : key;
    if (keyPattern.test(key)) {
      matches.push({ path: childPath, value: child });
    }
    matches.push(...findConfigKeyValues(child, keyPattern, childPath));
  }
  return matches;
}
function isExternalUrl(value) {
  if (!/^https?:\/\//i.test(value)) return false;
  return !/^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/i.test(value);
}
function getBashPermissionCommand(entry) {
  const match = entry.match(/^Bash\((.*)\)$/s);
  return match ? match[1].trim() : null;
}
function isScopedNetworkAllowEntry(entry) {
  const command = getBashPermissionCommand(entry);
  if (!command) return false;
  if (!/\b(?:curl|wget)\b/i.test(command)) return false;
  const hasShellExpansion = /\$\(|\$\{?[A-Za-z_]/.test(command) || /`[^`]+`/.test(command);
  if (hasShellExpansion) return false;
  if (command.includes("*")) return false;
  if (/\|\s*(?:sh|bash|zsh)\b/i.test(command)) return false;
  const segments = command.split(/\s*(?:&&|\|\||;|\n)\s*/).map((segment) => segment.trim()).filter(Boolean);
  let sawNetworkSegment = false;
  for (const segment of segments) {
    if (!/\b(?:curl|wget)\b/i.test(segment)) continue;
    sawNetworkSegment = true;
    if (!/https?:\/\/[^\s"'`)]+/i.test(segment)) {
      return false;
    }
  }
  return sawNetworkSegment;
}
function hasDynamicShellBehavior(command) {
  return /(?:\$\(|\$\{?[A-Za-z_]|`[^`]+`)/.test(command) || /(?:&&|\|\||;|\||>|<)/.test(command) || command.includes("*");
}
function isScopedInterpreterScriptAllowEntry(entry) {
  const command = getBashPermissionCommand(entry);
  if (!command) return false;
  if (!/^(?:python|python3|node)\s+/i.test(command)) return false;
  if (hasDynamicShellBehavior(command)) return false;
  if (/\s(?:-c|-e|-i|-m|-p|-r|--eval|--print|--require)\b/.test(command)) return false;
  const scriptMatch = command.match(/^(?:python|python3|node)\s+(?:"([^"]+)"|'([^']+)'|([^\s]+))/i);
  const scriptTarget = scriptMatch?.[1] ?? scriptMatch?.[2] ?? scriptMatch?.[3];
  if (!scriptTarget) return false;
  if (scriptTarget.startsWith("-")) return false;
  return /[\\/]/.test(scriptTarget) || /\.(?:js|cjs|mjs|ts|cts|mts|py)$/i.test(scriptTarget);
}
function isReadOnlyDockerAllowEntry(entry) {
  const command = getBashPermissionCommand(entry);
  if (!command) return false;
  if (!/^docker\s+/i.test(command)) return false;
  if (hasDynamicShellBehavior(command)) return false;
  return /^(?:docker\s+(?:ps|images|version|info)\b|docker\s+(?:image|container|context)\s+ls\b)/i.test(
    command.trim()
  );
}
function isSettingsLocalFile(file) {
  return /(^|[\\/])settings\.local\.json$/i.test(file.path);
}
function isExactAllowEntry(entry) {
  if (!/^[A-Za-z]+\(.+\)$/.test(entry)) return false;
  if (entry.includes("*")) return false;
  if (/\$\(|\$\{?[A-Za-z_]/.test(entry) || /`[^`]+`/.test(entry)) return false;
  return true;
}
function hasOnlyExactAllowEntries(allowEntries) {
  return allowEntries.length > 0 && allowEntries.every((entry) => isExactAllowEntry(entry));
}
var DESTRUCTIVE_GIT_PATTERNS = [
  {
    pattern: /push\s+--force(?!-with-lease)|push\s+-f\b/,
    description: "Force push can overwrite remote history, destroying teammates' work",
    suggestion: "Use --force-with-lease instead, or move to deny list"
  },
  {
    pattern: /reset\s+--hard/,
    description: "Hard reset destroys uncommitted changes without recovery",
    suggestion: "Move to deny list; use 'git stash' or 'git reset --soft' instead"
  },
  {
    pattern: /clean\s+-[a-z]*f/,
    description: "Git clean with force flag permanently deletes untracked files",
    suggestion: "Move to deny list; use 'git clean -n' (dry-run) first"
  },
  {
    pattern: /branch\s+-D\b/,
    description: "Force-delete branch regardless of merge status can lose work",
    suggestion: "Use 'branch -d' (lowercase) which checks merge status first"
  },
  {
    pattern: /checkout\s+\.\s*$/,
    description: "Discards all unstaged changes in working directory",
    suggestion: "Move to deny list to prevent accidental loss of work"
  }
];
var permissionRules = [
  {
    id: "permissions-overly-permissive",
    name: "Overly Permissive Access",
    description: "Checks the ALLOW list for permission rules that grant excessive access",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      for (const entry of perms.allow) {
        if (isScopedNetworkAllowEntry(entry) || isScopedInterpreterScriptAllowEntry(entry) || isReadOnlyDockerAllowEntry(entry)) {
          continue;
        }
        for (const check of OVERLY_PERMISSIVE) {
          if (check.pattern.test(entry)) {
            findings.push({
              id: `permissions-permissive-${entry}`,
              severity: check.severity,
              category: "permissions",
              title: `Overly permissive allow rule: ${entry}`,
              description: check.description,
              file: file.path,
              evidence: entry,
              fix: {
                description: `Restrict to specific commands: ${check.suggestion}`,
                before: entry,
                after: check.suggestion,
                auto: false
              }
            });
            break;
          }
        }
      }
      for (const denyEntry of perms.deny) {
        for (const allowEntry of perms.allow) {
          if (allowEntry === denyEntry) {
            findings.push({
              id: `permissions-contradiction-${denyEntry}`,
              severity: "medium",
              category: "misconfiguration",
              title: `Contradictory permission: "${denyEntry}" in both allow and deny`,
              description: `The permission "${denyEntry}" appears in both the allow and deny lists. Deny takes precedence, but this is confusing and should be cleaned up.`,
              file: file.path,
              evidence: denyEntry
            });
          }
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-no-deny-list",
    name: "Missing Deny List",
    description: "Checks if the settings.json has a deny list for dangerous operations",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      if (perms.deny.length === 0 && perms.allow.length > 0) {
        const isScopedProjectLocalConfig = isSettingsLocalFile(file) && hasOnlyExactAllowEntries(perms.allow);
        findings.push({
          id: "permissions-no-deny-list",
          severity: isScopedProjectLocalConfig ? "medium" : "high",
          category: "permissions",
          title: isScopedProjectLocalConfig ? "Project-local config has no deny list" : "No deny list configured",
          description: isScopedProjectLocalConfig ? "settings.local.json has no deny list. The current allow list appears tightly scoped, so this is less risky than a broad runtime config, but explicit denials still improve safety." : "settings.json has no deny list. Without explicit denials, the agent may run dangerous operations if the allow list is too broad.",
          file: file.path,
          fix: {
            description: "Add a deny list for dangerous operations",
            before: '"permissions": { "allow": [...] }',
            after: '"permissions": { "allow": [...], "deny": ["Bash(rm -rf *)", "Bash(sudo *)", "Bash(chmod 777 *)"] }',
            auto: false
          }
        });
      }
      for (const denial of MISSING_DENIALS) {
        const hasDenial = perms.deny.some((d) => d.includes(denial.pattern));
        if (!hasDenial && perms.deny.length > 0) {
          findings.push({
            id: `permissions-missing-deny-${denial.pattern.replace(/\s/g, "-")}`,
            severity: "medium",
            category: "permissions",
            title: `Missing deny rule: ${denial.description}`,
            description: `The deny list does not block "${denial.pattern}". Consider adding it to prevent ${denial.description.toLowerCase()}.`,
            file: file.path
          });
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-dangerous-skip",
    name: "Dangerous Permission Bypass",
    description: "Checks for dangerously-skip-permissions or no-verify flags used affirmatively",
    severity: "critical",
    category: "permissions",
    check(file) {
      const findings = [];
      const dangerousPatterns = [
        {
          pattern: /dangerously-?skip-?permissions/gi,
          desc: "Permission system bypass"
        },
        {
          pattern: /--no-verify/g,
          desc: "Git hook verification bypass"
        }
      ];
      const negationPatterns = [
        /\bnever\b/i,
        /\bdon'?t\b/i,
        /\bdo\s+not\b/i,
        /\bnot\b/i,
        /\bavoid\b/i,
        /\bprohibit/i,
        /\bforbid/i,
        /\bdisable/i,
        /\bban/i,
        /\bblock/i
      ];
      for (const { pattern, desc } of dangerousPatterns) {
        const matches = [...file.content.matchAll(
          new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g")
        )];
        for (const match of matches) {
          const idx = match.index ?? 0;
          const contextStart = Math.max(0, idx - 100);
          const context = file.content.substring(contextStart, idx).toLowerCase();
          const isNegated = negationPatterns.some((neg) => neg.test(context));
          if (isNegated) {
            findings.push({
              id: `permissions-negated-${idx}`,
              severity: "info",
              category: "permissions",
              title: `Prohibition of ${match[0]} (good practice)`,
              description: `Found "${match[0]}" in a negated/prohibitive context. This is correct \u2014 the config is telling the agent NOT to use this flag.`,
              file: file.path,
              line: findLineNumber2(file.content, idx),
              evidence: match[0]
            });
            continue;
          }
          findings.push({
            id: `permissions-dangerous-${idx}`,
            severity: "critical",
            category: "permissions",
            title: `Dangerous flag: ${match[0]}`,
            description: `${desc}. The flag "${match[0]}" disables safety mechanisms.`,
            file: file.path,
            line: findLineNumber2(file.content, idx),
            evidence: match[0],
            fix: {
              description: "Remove dangerous bypass flag",
              before: match[0],
              after: "# [REMOVED: dangerous bypass flag]",
              auto: false
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-all-mutable-tools",
    name: "All Mutable Tools Allowed",
    description: "Checks if the allow list grants access to all three mutable tool categories simultaneously",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const allowStr = perms.allow.join(" ");
      const hasBash = perms.allow.some((e) => e.startsWith("Bash"));
      const hasWrite = perms.allow.some((e) => e.startsWith("Write"));
      const hasEdit = perms.allow.some((e) => e.startsWith("Edit"));
      if (hasBash && hasWrite && hasEdit) {
        const allUnrestricted = allowStr.includes("Bash(*)") && allowStr.includes("Write(*)") && allowStr.includes("Edit(*)");
        if (!allUnrestricted) {
          return [
            {
              id: "permissions-all-mutable-tools",
              severity: "high",
              category: "permissions",
              title: "All mutable tool categories allowed simultaneously",
              description: "The allow list grants Bash, Write, and Edit access. Even with scoped patterns, having all three categories means the agent can run commands, create files, and modify files \u2014 effectively unrestricted write access to the system. Consider whether all three are truly needed.",
              file: file.path,
              fix: {
                description: "Remove one or more mutable tool categories if not needed",
                before: "Bash(...) + Write(...) + Edit(...)",
                after: "Consider if the agent really needs all three",
                auto: false
              }
            }
          ];
        }
      }
      return [];
    }
  },
  {
    id: "permissions-destructive-git",
    name: "Destructive Git Commands Allowed",
    description: "Checks if the allow list permits destructive git operations",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      for (const entry of perms.allow) {
        for (const gitPattern of DESTRUCTIVE_GIT_PATTERNS) {
          if (gitPattern.pattern.test(entry)) {
            findings.push({
              id: `permissions-destructive-git-${findings.length}`,
              severity: "high",
              category: "permissions",
              title: `Destructive git command allowed: ${entry}`,
              description: gitPattern.description,
              file: file.path,
              evidence: entry,
              fix: {
                description: gitPattern.suggestion,
                before: entry,
                after: `# Move to deny list: ${entry}`,
                auto: false
              }
            });
            break;
          }
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-sensitive-path-access",
    name: "Sensitive Path in Allow List",
    description: "Checks if the allow list permits tool access to sensitive system directories",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      const sensitivePaths = [
        { pattern: /\/etc\//, description: "system configuration directory" },
        { pattern: /~\/\.ssh|\/\.ssh/, description: "SSH keys and configuration" },
        { pattern: /~\/\.aws|\/\.aws/, description: "AWS credentials" },
        { pattern: /~\/\.gnupg|\/\.gnupg/, description: "GPG keyring" },
        { pattern: /\/root\//, description: "root user home directory" },
        { pattern: /\/var\/log/, description: "system log directory" }
      ];
      for (const entry of perms.allow) {
        for (const { pattern, description } of sensitivePaths) {
          if (pattern.test(entry)) {
            findings.push({
              id: `permissions-sensitive-path-${findings.length}`,
              severity: "high",
              category: "permissions",
              title: `Allow rule grants access to ${description}: ${entry}`,
              description: `The allow entry "${entry}" grants tool access to a sensitive directory (${description}). This could expose credentials, keys, or system configuration.`,
              file: file.path,
              evidence: entry,
              fix: {
                description: "Restrict to project directories only",
                before: entry,
                after: entry.replace(/\/etc\/.*|~\/\.ssh.*|\/\.ssh.*|~\/\.aws.*|\/\.aws.*|~\/\.gnupg.*|\/\.gnupg.*|\/root\/.*|\/var\/log.*/, "src/*"),
                auto: false
              }
            });
            break;
          }
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-wildcard-root-paths",
    name: "Wildcard Root Path in Allow List",
    description: "Checks if the allow list uses wildcards on root-level or home-level directories",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      const broadPathPatterns = [
        { pattern: /\(\/\*\)/, description: "root filesystem wildcard" },
        { pattern: /\(~\/\*\)/, description: "home directory wildcard" },
        { pattern: /\(\/home\/\*\)/, description: "all users home directories" },
        { pattern: /\(\/usr\/\*\)/, description: "system programs directory" },
        { pattern: /\(\/opt\/\*\)/, description: "optional software directory" }
      ];
      for (const entry of perms.allow) {
        for (const { pattern, description } of broadPathPatterns) {
          if (pattern.test(entry)) {
            findings.push({
              id: `permissions-wildcard-root-${findings.length}`,
              severity: "high",
              category: "permissions",
              title: `Broad wildcard path in allow list: ${entry}`,
              description: `The allow entry "${entry}" uses a ${description}. This grants the agent access to far more files than typically needed. Restrict to project-specific paths.`,
              file: file.path,
              evidence: entry,
              fix: {
                description: "Restrict to project-specific directories",
                before: entry,
                after: entry.replace(/\(.*\)/, "(./src/*)"),
                auto: false
              }
            });
            break;
          }
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-no-permissions-block",
    name: "No Permissions Block Configured",
    description: "Checks if settings.json exists but has no permissions configuration at all",
    severity: "medium",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      try {
        const config = JSON.parse(file.content);
        if (isHookManifestConfig(file, config)) {
          return [];
        }
        const hasOtherConfig = Object.keys(config).some(
          (k) => k !== "permissions" && k !== "$schema"
        );
        if (hasOtherConfig && !config.permissions) {
          return [
            {
              id: "permissions-no-block",
              severity: "medium",
              category: "permissions",
              title: "No permissions block configured",
              description: "settings.json has configuration but no permissions section. Without explicit allow/deny lists, the agent relies on default permissions which may be too broad. Add a permissions block to restrict tool access.",
              file: file.path,
              fix: {
                description: "Add a permissions block with scoped allow and deny lists",
                before: "No permissions section",
                after: '"permissions": { "allow": ["Read(*)", "Glob(*)", "Grep(*)"], "deny": ["Bash(rm -rf *)", "Bash(sudo *)"] }',
                auto: false
              }
            }
          ];
        }
      } catch {
      }
      return [];
    }
  },
  {
    id: "permissions-model-endpoint-override",
    name: "Model Endpoint Override",
    description: "Checks for external API base URL overrides that can reroute model traffic through attacker-controlled infrastructure",
    severity: "critical",
    category: "misconfiguration",
    check(file) {
      if (file.type !== "settings-json") return [];
      try {
        const config = JSON.parse(file.content);
        const overrideKeys = findConfigKeyValues(
          config,
          /^(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|AZURE_OPENAI_ENDPOINT|MODEL_BASE_URL)$/i
        );
        return overrideKeys.flatMap(({ path, value }, index) => {
          if (typeof value !== "string" || !isExternalUrl(value)) {
            return [];
          }
          return [{
            id: `permissions-model-endpoint-override-${index}`,
            severity: "critical",
            category: "misconfiguration",
            title: "External model endpoint override in config",
            description: "This configuration overrides the model API base URL with an external host. In a repo-level settings file, that can silently reroute prompts, tool calls, and API keys through attacker-controlled infrastructure before the user notices.",
            file: file.path,
            evidence: `${path}: ${value}`,
            fix: {
              description: "Remove the repo-level endpoint override or point it to a trusted local endpoint only",
              before: `"${path}": "${value}"`,
              after: `# Remove ${path} override`,
              auto: false
            }
          }];
        });
      } catch {
        return [];
      }
    }
  },
  {
    id: "permissions-env-in-allow",
    name: "Environment Variable Access in Allow List",
    description: "Checks for allow list entries that grant access to environment variables or env files",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      const envPatterns = [
        {
          pattern: /\.env\b/,
          description: "Grants access to .env files which may contain secrets"
        },
        {
          pattern: /\bprintenv\b|\benv\b(?!\()/,
          description: "Grants access to dump environment variables"
        },
        {
          pattern: /\bexport\s/,
          description: "Allows setting environment variables"
        }
      ];
      for (const entry of perms.allow) {
        for (const { pattern, description } of envPatterns) {
          if (pattern.test(entry)) {
            findings.push({
              id: `permissions-env-access-${findings.length}`,
              severity: "high",
              category: "permissions",
              title: `Allow rule grants env access: ${entry}`,
              description: `The allow entry "${entry}" ${description}. Environment variables often contain API keys, tokens, and other secrets.`,
              file: file.path,
              evidence: entry
            });
            break;
          }
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-unrestricted-network",
    name: "Unrestricted Network Tool Access",
    description: "Checks for allow rules that grant unrestricted access to network tools",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "settings-json") return [];
      const perms = parsePermissionLists(file.content);
      if (!perms) return [];
      const findings = [];
      const networkPatterns = [
        {
          pattern: /^Bash\(curl\s*\*?\)$/i,
          description: "Allows unrestricted curl \u2014 can exfiltrate data to any URL"
        },
        {
          pattern: /^Bash\(wget\s*\*?\)$/i,
          description: "Allows unrestricted wget \u2014 can download from any URL"
        },
        {
          pattern: /^Bash\(nc\b/i,
          description: "Allows netcat \u2014 can open listeners or connect to remote hosts"
        },
        {
          pattern: /^Bash\(ssh\s*\*?\)$/i,
          description: "Allows unrestricted SSH \u2014 can connect to any remote host"
        },
        {
          pattern: /^Bash\(scp\s*\*?\)$/i,
          description: "Allows unrestricted scp \u2014 can copy files to/from any host"
        }
      ];
      for (const entry of perms.allow) {
        for (const { pattern, description } of networkPatterns) {
          if (pattern.test(entry)) {
            findings.push({
              id: `permissions-unrestricted-network-${findings.length}`,
              severity: "high",
              category: "permissions",
              title: `Allow rule grants unrestricted network access: ${entry}`,
              description: `The allow entry "${entry}" ${description}. Network tools should be restricted to specific hosts or purposes.`,
              file: file.path,
              evidence: entry,
              fix: {
                description: "Restrict to specific hosts or use explicit URLs",
                before: entry,
                after: entry.replace("*", "https://specific-host.com/*"),
                auto: false
              }
            });
            break;
          }
        }
      }
      return findings;
    }
  },
  {
    id: "permissions-claude-md-world-writable",
    name: "CLAUDE.md File Permissions Too Open",
    description: "Checks if CLAUDE.md files have overly permissive filesystem permissions (world-writable or group-writable)",
    severity: "high",
    category: "permissions",
    check(file) {
      if (file.type !== "claude-md") return [];
      const normalizedPath = file.path.replace(/\\/g, "/");
      if (!/CLAUDE\.md$/i.test(normalizedPath)) return [];
      const absolutePath = resolveClaudeMdPath(normalizedPath);
      if (!absolutePath) return [];
      try {
        const stat = statSync2(absolutePath);
        const mode = stat.mode;
        const isGroupWritable = (mode & 16) !== 0;
        const isOtherWritable = (mode & 2) !== 0;
        if (!isGroupWritable && !isOtherWritable) return [];
        const issues = [];
        if (isOtherWritable) issues.push("world-writable");
        if (isGroupWritable) issues.push("group-writable");
        const modeStr = "0o" + (mode & 511).toString(8);
        return [{
          id: "permissions-claude-md-world-writable",
          severity: isOtherWritable ? "high" : "medium",
          category: "permissions",
          title: `CLAUDE.md is ${issues.join(" and ")} (${modeStr})`,
          description: `The file ${normalizedPath} has permissions ${modeStr}, making it ${issues.join(" and ")}. CLAUDE.md files are injected into every Claude Code prompt as system instructions. A local attacker or malicious process could modify this file to inject prompt instructions that exfiltrate data, run arbitrary commands, or alter agent behavior. Restrict permissions to owner-only (chmod 600).`,
          file: file.path,
          evidence: `permissions: ${modeStr}`,
          fix: {
            description: "Restrict file permissions to owner-only read/write",
            before: modeStr,
            after: "0o600",
            auto: true
          }
        }];
      } catch {
        return [];
      }
    }
  }
];
function resolveClaudeMdPath(relativePath) {
  if (/^\.claude\/CLAUDE\.md$/i.test(relativePath)) {
    const homeClaudeMd = join2(homedir(), ".claude", "CLAUDE.md");
    try {
      statSync2(homeClaudeMd);
      return homeClaudeMd;
    } catch {
    }
  }
  try {
    const resolved = resolve(relativePath);
    statSync2(resolved);
    return resolved;
  } catch {
    return null;
  }
}
function findLineNumber2(content, matchIndex) {
  return content.substring(0, matchIndex).split("\n").length;
}

// src/rules/hooks.ts
var INJECTION_PATTERNS = [
  {
    name: "var-interpolation",
    pattern: /\$\{(?:file|command|content|input|args?)\}/gi,
    description: "Hook uses variable interpolation that could be influenced by file content or command arguments. An attacker could craft filenames or content to inject commands.",
    severity: "critical"
  },
  {
    name: "shell-interpolation",
    pattern: /\bsh\s+-c\s+["'].*\$\{/g,
    description: "Shell invocation with variable interpolation \u2014 classic command injection vector.",
    severity: "critical"
  },
  {
    name: "curl-interpolation",
    pattern: /\bcurl\b.*\$\{/g,
    description: "HTTP request with variable interpolation \u2014 could be used for data exfiltration.",
    severity: "high"
  },
  {
    name: "wget-interpolation",
    pattern: /\bwget\b.*\$\{/g,
    description: "Download with variable interpolation \u2014 could fetch malicious payloads.",
    severity: "high"
  }
];
var EXFILTRATION_PATTERNS = [
  {
    name: "curl-external",
    pattern: /\bcurl\s+(-X\s+POST\s+)?https?:\/\//g,
    description: "Hook sends data to external URL via curl"
  },
  {
    name: "wget-external",
    pattern: /\bwget\s+.*https?:\/\//g,
    description: "Hook fetches from external URL via wget"
  },
  {
    name: "netcat",
    pattern: /\bnc\b|\bnetcat\b/g,
    description: "Hook uses netcat \u2014 potential reverse shell or data exfiltration"
  },
  {
    name: "sendmail",
    pattern: /\bsendmail\b|\bmail\b.*-s/g,
    description: "Hook sends email \u2014 potential data exfiltration"
  }
];
function findLineNumber3(content, matchIndex) {
  return content.substring(0, matchIndex).split("\n").length;
}
function findAllMatches2(content, pattern) {
  return [...content.matchAll(new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g"))];
}
function isPluginHookManifest(file) {
  return file.type === "settings-json" && /(?:^|[\\/])(?:\.claude[\\/])?hooks[\\/]hooks\.json$/i.test(file.path);
}
function normalizeConfigPath(filePath) {
  return filePath.replace(/\\/g, "/");
}
function isProjectLocalSettingsFile(file) {
  return /(?:^|\/)settings\.local\.json$/i.test(normalizeConfigPath(file.path));
}
function isExactPermissionEntry(entry) {
  return !/[*`]|(?:\$\{)|(?:\$\()/.test(entry);
}
function isLocalOnlyScopedCommand(entry) {
  return !/\b(?:https?:\/\/|curl\b|wget\b|ssh\b|scp\b|nc\b|netcat\b|docker\b|kubectl\b)\b/i.test(
    entry
  );
}
function hasExactLocalOnlyAllowlist(content) {
  try {
    const config = JSON.parse(content);
    const allow = config?.permissions?.allow;
    if (!Array.isArray(allow) || allow.length === 0) return false;
    return allow.every(
      (entry) => typeof entry === "string" && isExactPermissionEntry(entry) && isLocalOnlyScopedCommand(entry)
    );
  } catch {
    return false;
  }
}
function stripSettingsPath(filePath) {
  const normalized = normalizeConfigPath(filePath);
  if (/^\.claude\/settings(?:\.local)?\.json$/i.test(normalized)) return "";
  if (/^settings(?:\.local)?\.json$/i.test(normalized)) return "";
  const match = normalized.match(/^(.*?)(?:\/\.claude)?\/settings(?:\.local)?\.json$/i);
  if (match) {
    return match[1].replace(/\/$/, "");
  }
  return null;
}
function getCompanionHookManifestPaths(file) {
  const prefix = stripSettingsPath(file.path);
  if (prefix === null) return [];
  const candidates = [
    prefix ? `${prefix}/hooks/hooks.json` : "hooks/hooks.json",
    prefix ? `${prefix}/.claude/hooks/hooks.json` : ".claude/hooks/hooks.json"
  ];
  return [...new Set(candidates.map(normalizeConfigPath))];
}
function hasPreToolUseHooksInConfig(content) {
  try {
    const config = JSON.parse(content);
    return Array.isArray(config?.hooks?.PreToolUse) && config.hooks.PreToolUse.length > 0;
  } catch {
    return false;
  }
}
function hasCompanionManifestPreToolUseHooks(file, allFiles) {
  if (!allFiles || allFiles.length === 0) return false;
  const candidates = new Set(getCompanionHookManifestPaths(file));
  if (candidates.size === 0) return false;
  return allFiles.some(
    (other) => other !== file && other.type === "settings-json" && candidates.has(normalizeConfigPath(other.path)) && hasPreToolUseHooksInConfig(other.content)
  );
}
function extractHookCommands2(entry) {
  const commands = [];
  if (!entry || typeof entry !== "object") {
    return commands;
  }
  const record = entry;
  if (typeof record.hook === "string" && record.hook.length > 0) {
    commands.push(record.hook);
  }
  if (typeof record.command === "string" && record.command.length > 0) {
    commands.push(record.command);
  }
  if (Array.isArray(record.hooks)) {
    for (const nestedHook of record.hooks) {
      if (!nestedHook || typeof nestedHook !== "object") {
        continue;
      }
      const command = nestedHook.command;
      if (typeof command === "string" && command.length > 0) {
        commands.push(command);
      }
    }
  }
  return commands;
}
function findJsonStringIndex(content, value, searchOffsets) {
  const escapedValue = JSON.stringify(value).slice(1, -1);
  const startIndex = searchOffsets.get(escapedValue) ?? 0;
  const index = content.indexOf(escapedValue, startIndex);
  if (index !== -1) {
    searchOffsets.set(escapedValue, index + escapedValue.length);
  }
  return index;
}
function getHookSearchTargets(file) {
  if (file.type === "hook-script") {
    return [{ content: file.content, baseLine: 1 }];
  }
  if (file.type !== "settings-json") {
    return [];
  }
  try {
    const config = JSON.parse(file.content);
    const hookGroups = config?.hooks;
    if (!hookGroups || typeof hookGroups !== "object") {
      return [];
    }
    const targets = [];
    const searchOffsets = /* @__PURE__ */ new Map();
    for (const group of Object.values(hookGroups)) {
      if (!Array.isArray(group)) {
        continue;
      }
      for (const entry of group) {
        for (const command of extractHookCommands2(entry)) {
          const index = findJsonStringIndex(file.content, command, searchOffsets);
          const baseLine = index === -1 ? 1 : findLineNumber3(file.content, index);
          targets.push({ content: command, baseLine });
        }
      }
    }
    return targets;
  } catch {
    return [];
  }
}
function getLineBounds(content, index) {
  const start = content.lastIndexOf("\n", index - 1) + 1;
  const nextNewline = content.indexOf("\n", index);
  return {
    start,
    end: nextNewline === -1 ? content.length : nextNewline
  };
}
function getLineContentAtIndex(content, index) {
  const { start, end } = getLineBounds(content, index);
  return content.slice(start, end);
}
function isCommentOnlyShellMatch(content, index) {
  const line = getLineContentAtIndex(content, index).trimStart();
  return line.startsWith("#");
}
function isCommentOnlyAutomationMatch(file, content, index) {
  if (file.type === "settings-json") return false;
  const line = getLineContentAtIndex(content, index).trimStart();
  if (line.startsWith("#")) return true;
  if (file.type === "hook-code") {
    return /^(?:\/\/|\/\*|\*|\*\/)/.test(line);
  }
  return false;
}
function isInsideTestPattern(content, matchIndex) {
  const prefix = content.slice(0, matchIndex);
  let lastSingleQuote = -1;
  let lastDoubleQuote = -1;
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < prefix.length; i++) {
    const ch = prefix[i];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      if (inSingle) lastSingleQuote = i;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      if (inDouble) lastDoubleQuote = i;
    }
  }
  const quoteStart = Math.max(lastSingleQuote, lastDoubleQuote);
  if ((inSingle || inDouble) && quoteStart > 0) {
    const beforeQuote = prefix.slice(0, quoteStart).trimEnd();
    if (/\b(?:grep|egrep|fgrep)\b(?:\s+-[a-zA-Z]+)*\s*$/i.test(beforeQuote)) {
      return true;
    }
    if (/\[\[?\s+.*(?:==|=|!=|=~)\s*(?:\*?)?$/.test(beforeQuote)) {
      return true;
    }
    if (/\bcase\b/.test(beforeQuote) || /\)\s*$/.test(beforeQuote) === false && /\|\s*$/.test(beforeQuote)) {
      if (/\bcase\s+/.test(content.slice(0, quoteStart))) {
        return true;
      }
    }
  }
  const lineStart = prefix.lastIndexOf("\n") + 1;
  const linePrefix = prefix.slice(lineStart).trimStart();
  if (/^\*?[a-zA-Z_-]+\*?\)/.test(linePrefix) || /^\|?\s*\*/.test(linePrefix)) {
    if (/\bcase\s+/.test(content.slice(0, matchIndex))) {
      return true;
    }
  }
  if (/\b(?:grep|egrep|fgrep)\b(?:\s+-[a-zA-Z]+)*\s+$/.test(linePrefix)) {
    return true;
  }
  return false;
}
function isInsideQuotedString(content, matchIndex) {
  const prefix = content.slice(0, matchIndex);
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < prefix.length; i++) {
    const ch = prefix[i];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    }
  }
  return inSingle || inDouble;
}
function isInsideRegexLiteral(line, relativeIndex) {
  const before = line.slice(0, relativeIndex);
  const after = line.slice(relativeIndex);
  return /(?:^|[=\s(:[,])\/[^/\n]*$/.test(before) && /^[^/\n]*\//.test(after);
}
function isRegexLikeAlternationLiteral(content, matchIndex) {
  const line = getLineContentAtIndex(content, matchIndex);
  const { start } = getLineBounds(content, matchIndex);
  const relativeIndex = matchIndex - start;
  const beforeMatch = line.slice(0, relativeIndex);
  const afterMatch = line.slice(relativeIndex);
  const isPatternContainer = isInsideQuotedString(content, matchIndex) || isInsideRegexLiteral(line, relativeIndex);
  if (!isPatternContainer) return false;
  if (!beforeMatch.includes("|") && !afterMatch.includes("|")) return false;
  return /\b(?:credential|password|pattern|regex|secret|token)\b/i.test(line);
}
function isBlockingGuardCommand(content) {
  return /\bexit\s+2\b/.test(content);
}
function findAllHookMatches(file, pattern) {
  const matches = [];
  for (const target of getHookSearchTargets(file)) {
    for (const match of findAllMatches2(target.content, pattern)) {
      if (file.type === "hook-script" && isCommentOnlyShellMatch(target.content, match.index ?? 0)) {
        continue;
      }
      const matchIndex = match.index ?? 0;
      if (isBlockingGuardCommand(target.content)) {
        if (isInsideTestPattern(target.content, matchIndex) || isInsideQuotedString(target.content, matchIndex)) {
          continue;
        }
      }
      matches.push({
        match,
        line: target.baseLine + findLineNumber3(target.content, matchIndex) - 1,
        content: target.content,
        commandContext: getCommandContext(target.content, matchIndex)
      });
    }
  }
  return matches;
}
function getCommandContext(content, matchIndex) {
  const prefix = content.slice(0, matchIndex);
  const separators = [
    { token: "&&", width: 2 },
    { token: "||", width: 2 },
    { token: ";", width: 1 },
    { token: "\n", width: 1 },
    { token: "|", width: 1 }
  ];
  let startIndex = 0;
  for (const { token, width } of separators) {
    const index = prefix.lastIndexOf(token);
    if (index !== -1 && index + width > startIndex) {
      startIndex = index + width;
    }
  }
  return prefix.slice(startIndex).trim();
}
function isBenignLoggingProbe(commandContext) {
  const normalized = commandContext.replace(/\s+/g, " ").trim().toLowerCase();
  const benignProbePatterns = [
    /^(?:(?:el)?if\s+)?command\s+-v\b/,
    /^(?:(?:el)?if\s+)?which\b/,
    /^(?:(?:el)?if\s+)?type\b/,
    /^(?:(?:el)?if\s+)?hash\b/,
    /^(?:(?:el)?if\s+)?git\s+rev-parse\s+--git-dir\b/,
    /^(?:(?:el)?if\s+)?(?:pnpm|npm)\s+list\b/
  ];
  return benignProbePatterns.some((pattern) => pattern.test(normalized));
}
function findHookCodeLineMatch(file, patterns) {
  if (file.type !== "hook-code") return null;
  const lines = file.content.split("\n");
  for (const [index, lineContent] of lines.entries()) {
    const trimmed = lineContent.trim();
    if (trimmed.length === 0) continue;
    if (/^(?:\/\/|#|\/\*|\*|\*\/)/.test(trimmed)) continue;
    for (const pattern of patterns) {
      const regex = new RegExp(
        pattern.source,
        pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g"
      );
      if (regex.test(lineContent)) {
        return {
          line: index + 1,
          content: trimmed
        };
      }
    }
  }
  return null;
}
function findHookCodeContentMatch(file, patterns) {
  if (file.type !== "hook-code") return null;
  for (const pattern of patterns) {
    const regex = new RegExp(
      pattern.source,
      pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g"
    );
    const match = regex.exec(file.content);
    if (!match || match.index == null) continue;
    const line = findLineNumber3(file.content, match.index);
    const lineContent = file.content.split("\n")[line - 1]?.trim() ?? match[0].trim();
    if (/^(?:\/\/|#|\/\*|\*|\*\/)/.test(lineContent)) continue;
    return {
      line,
      content: lineContent || match[0].trim()
    };
  }
  return null;
}
var HOOK_CODE_CONTEXT_OUTPUT_PATTERN = /\boutput\s*\(/g;
var HOOK_CODE_TRANSCRIPT_ACCESS_PATTERNS = [
  /\.\s*transcript_path\b/g,
  /\[['"]transcript_path['"]\]/g,
  /\bprocess\.env\.CLAUDE_TRANSCRIPT_PATH\b/g,
  /\bos\.environ(?:\.get)?\(\s*["']CLAUDE_TRANSCRIPT_PATH["']\s*\)/g,
  /\bos\.getenv\(\s*["']CLAUDE_TRANSCRIPT_PATH["']\s*\)/g,
  /\bENV\[\s*["']CLAUDE_TRANSCRIPT_PATH["']\s*\]/g
];
var HOOK_CODE_REMOTE_SHELL_PAYLOAD_PATTERNS = [
  /\b(?:spawnSync|spawn|execFileSync|execFile)\s*\([\s\S]{0,120}["'`](?:bash|sh|zsh)["'`][\s\S]{0,120}["'`]-l?c["'`][\s\S]{0,320}(?:curl|wget)[\s\S]{0,200}\|\s*(?:bash|sh|zsh)\b/gi,
  /\bexecSync\s*\([\s\S]{0,320}(?:curl|wget)[\s\S]{0,200}\|\s*(?:bash|sh|zsh)\b/gi
];
var AI_TOOL_PERSISTENCE_IOCS = [
  {
    name: "tanstack-malicious-git-ref",
    pattern: /(?:@tanstack\/setup|github:tanstack\/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c)/gi,
    description: "Matches the fictitious @tanstack/setup dependency or malicious git ref from the May 2026 TanStack/Mini Shai-Hulud campaign."
  },
  {
    name: "tanstack-payload-filename",
    pattern: /\b(?:router_init\.js|tanstack_runner\.js)\b/gi,
    description: "Matches payload filenames used by the May 2026 TanStack/Mini Shai-Hulud npm campaign."
  },
  {
    name: "tanstack-exfil-network",
    pattern: /\b(?:api\.masscan\.cloud|filev2\.getsession\.org|git-tanstack\.com|seed[123]\.getsession\.org|83\.142\.209\.194|litter\.catbox\.moe\/(?:h8nc9u\.js|7rrc6l\.mjs))\b/gi,
    description: "Matches exfiltration or second-stage URLs reported for the May 2026 TanStack/Mini Shai-Hulud campaign."
  },
  {
    name: "ai-tool-persistence-payload",
    pattern: /(?:\.claude\/(?:router_runtime\.js|setup\.mjs)|\.vscode\/setup\.mjs|\.github\/workflows\/codeql_analysis\.ya?ml)/gi,
    description: "Matches AI developer-tool persistence payload paths used to re-execute through Claude Code or VS Code automation surfaces."
  },
  {
    name: "mini-shai-hulud-deadman-daemon",
    pattern: /\b(?:gh-token-monitor|com\.user\.gh-token-monitor\.plist|gh-token-monitor\.service|gh-token-monitor\.sh)\b/gi,
    description: "Matches dead-man switch persistence artifacts associated with the May 2026 Mini Shai-Hulud campaign."
  },
  {
    name: "mini-shai-hulud-campaign-marker",
    pattern: /(?:Shai-Hulud:\s*Here We Go Again|A Mini Shai-Hulud has Appeared|IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner|PUSH UR T3MPRR)/gi,
    description: "Matches repository descriptions or commit messages reported in Mini Shai-Hulud propagation and token-wiper flows."
  },
  {
    name: "mini-shai-hulud-python-payload",
    pattern: /(?:\/tmp\/transformers\.pyz|\btransformers\.pyz\b|\bpgmonitor\.py\b|\bpgsql-monitor\.service\b|\bMISTRAL_INIT\b)/gi,
    description: "Matches Python/PyPI Mini Shai-Hulud payload artifacts reported for compromised Mistral and Guardrails package versions."
  }
];
var hookRules = [
  {
    id: "hooks-ai-tool-persistence-ioc",
    name: "AI Tool Persistence IOC",
    description: "Checks hook and editor automation configs for known AI developer-tool supply-chain persistence indicators",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script" && file.type !== "hook-code") {
        return [];
      }
      const findings = [];
      const searchTargets = [
        { content: file.content, source: "content" },
        { content: normalizeConfigPath(file.path), source: "path" }
      ];
      for (const ioc of AI_TOOL_PERSISTENCE_IOCS) {
        for (const target of searchTargets) {
          for (const match of findAllMatches2(target.content, ioc.pattern)) {
            const index = match.index ?? 0;
            if (target.source === "content" && isCommentOnlyAutomationMatch(file, target.content, index)) {
              continue;
            }
            findings.push({
              id: `hooks-ai-tool-persistence-ioc-${ioc.name}-${target.source}-${index}`,
              severity: "critical",
              category: "hooks",
              title: "Known AI tool supply-chain persistence indicator",
              description: `${ioc.description} Treat this host or repository as potentially compromised until the hook/editor automation chain is removed and credentials are rotated.`,
              file: file.path,
              line: target.source === "content" ? findLineNumber3(target.content, index) : void 0,
              evidence: match[0]
            });
          }
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-hook-code-context-output",
    name: "Hook Code Context Output",
    description: "Checks non-shell hook implementations for explicit output back into Claude context",
    severity: "info",
    category: "hooks",
    check(file) {
      const match = findHookCodeLineMatch(file, [HOOK_CODE_CONTEXT_OUTPUT_PATTERN]);
      if (!match) return [];
      return [
        {
          id: `hooks-code-context-output-${match.line}`,
          severity: "info",
          category: "hooks",
          title: "Hook code injects content into Claude context",
          description: "This non-shell hook implementation calls an output helper that writes content back into Claude context. That is often legitimate, but it should be reviewed because untrusted summaries or derived data can become prompt-injection surface.",
          file: file.path,
          line: match.line,
          evidence: match.content
        }
      ];
    }
  },
  {
    id: "hooks-hook-code-transcript-access",
    name: "Hook Code Transcript Access",
    description: "Checks non-shell hook implementations for direct access to Claude transcript input",
    severity: "info",
    category: "hooks",
    check(file) {
      const match = findHookCodeLineMatch(file, HOOK_CODE_TRANSCRIPT_ACCESS_PATTERNS);
      if (!match) return [];
      return [
        {
          id: `hooks-code-transcript-access-${match.line}`,
          severity: "info",
          category: "hooks",
          title: "Hook code reads Claude transcript input",
          description: "This non-shell hook implementation reads transcript-derived input (`transcript_path` or `CLAUDE_TRANSCRIPT_PATH`). That is common for Stop and SessionEnd hooks, but it should be reviewed because downstream logic can process sensitive prompt and tool history.",
          file: file.path,
          line: match.line,
          evidence: match.content
        }
      ];
    }
  },
  {
    id: "hooks-hook-code-remote-shell-payload",
    name: "Hook Code Remote Shell Payload",
    description: "Checks non-shell hook implementations for child-process execution that downloads and pipes remote shell payloads",
    severity: "high",
    category: "hooks",
    check(file) {
      const match = findHookCodeContentMatch(file, HOOK_CODE_REMOTE_SHELL_PAYLOAD_PATTERNS);
      if (!match) return [];
      return [
        {
          id: `hooks-code-remote-shell-payload-${match.line}`,
          severity: "high",
          category: "hooks",
          title: "Hook code executes remote shell payload via child process",
          description: "This non-shell hook implementation shells out to a command interpreter and pipes a remote download into `bash`/`sh`. That hides dangerous shell behavior behind a wrapper language and can reintroduce prompt-injection, supply-chain, or remote-code-execution risk.",
          file: file.path,
          line: match.line,
          evidence: match.content
        }
      ];
    }
  },
  {
    id: "hooks-injection",
    name: "Hook Command Injection",
    description: "Checks hooks for command injection vulnerabilities via variable interpolation",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      for (const injPattern of INJECTION_PATTERNS) {
        const matches = findAllHookMatches(file, injPattern.pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-injection-${match.index}`,
            severity: "critical",
            category: "injection",
            title: "Potential command injection in hook",
            description: injPattern.description,
            file: file.path,
            line,
            evidence: match[0],
            fix: {
              description: "Sanitize inputs before interpolation, or use a whitelist approach instead of shell interpolation",
              before: match[0],
              after: "# Use validated, sanitized input only",
              auto: false
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-exfiltration",
    name: "Hook Data Exfiltration",
    description: "Checks hooks for patterns that could exfiltrate data to external services",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      for (const exfilPattern of EXFILTRATION_PATTERNS) {
        const matches = findAllHookMatches(file, exfilPattern.pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-exfiltration-${match.index}`,
            severity: "high",
            category: "exposure",
            title: "Hook sends data to external service",
            description: `${exfilPattern.description}. If a hook is compromised or misconfigured, it could exfiltrate code, secrets, or session data.`,
            file: file.path,
            line,
            evidence: match[0]
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-no-error-handling",
    name: "Hook Missing Error Handling",
    description: "Checks if hooks suppress errors silently",
    severity: "medium",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json") return [];
      if (isPluginHookManifest(file)) return [];
      const findings = [];
      const silentFailPatterns = [
        { pattern: /2>\/dev\/null/g, desc: "stderr silenced" },
        { pattern: /\|\|\s*true\b/g, desc: "errors suppressed with || true" },
        { pattern: /\|\|\s*:\s*(?:$|[)"'])/gm, desc: "errors suppressed with || :" }
      ];
      for (const { pattern, desc } of silentFailPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-silent-fail-${match.index}`,
            severity: "medium",
            category: "hooks",
            title: `Hook silently suppresses errors: ${desc}`,
            description: `Hook uses "${match[0]}" which suppresses errors. A failing security hook that silently passes could miss real vulnerabilities.`,
            file: file.path,
            line,
            evidence: match[0],
            fix: {
              description: "Remove error suppression to surface failures",
              before: match[0],
              after: "# [REMOVED: error suppression]",
              auto: true
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-missing-pretooluse",
    name: "No PreToolUse Security Hooks",
    description: "Checks if there are PreToolUse hooks for security validation",
    severity: "medium",
    category: "misconfiguration",
    check(file, allFiles) {
      if (file.type !== "settings-json") return [];
      if (isPluginHookManifest(file)) return [];
      try {
        const config = JSON.parse(file.content);
        const preHooks = config?.hooks?.PreToolUse ?? [];
        if (preHooks.length === 0) {
          if (hasCompanionManifestPreToolUseHooks(file, allFiles)) {
            return [];
          }
          const severity = isProjectLocalSettingsFile(file) && hasExactLocalOnlyAllowlist(file.content) ? "low" : "medium";
          const description = severity === "low" ? "No PreToolUse hooks are defined. This config is project-local and narrowly scoped to exact local commands, so the missing hook is still worth noting but is less urgent than broader runtime configs." : "No PreToolUse hooks are defined. These hooks can catch dangerous operations before they run, providing an essential security layer.";
          return [
            {
              id: "hooks-no-pretooluse",
              severity,
              category: "misconfiguration",
              title: "No PreToolUse security hooks configured",
              description,
              file: file.path,
              fix: {
                description: "Add PreToolUse hooks for security-sensitive operations",
                before: '"hooks": {}',
                after: `"hooks": { "PreToolUse": [{ "matcher": "Bash && command matches 'rm -rf'", "hook": "echo 'Blocked' >&2 && exit 1" }] }`,
                auto: false
              }
            }
          ];
        }
      } catch {
      }
      return [];
    }
  },
  {
    id: "hooks-unthrottled-network",
    name: "Hook Unthrottled Network Requests",
    description: "Checks for PostToolUse hooks making HTTP requests on frequent tool calls without throttling",
    severity: "medium",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const postHooks = config?.hooks?.PostToolUse ?? [];
        const broadMatchers = ["Edit", "Write", "Read", "Bash", ""];
        const networkPatterns = /\b(curl|wget|fetch|http|nc|netcat)\b/i;
        for (const hook of postHooks) {
          const hookConfig = hook;
          const matcher = hookConfig.matcher ?? "";
          const isBroadMatcher = matcher === "" || broadMatchers.some((m) => m !== "" && matcher === m);
          for (const command of extractHookCommands2(hook)) {
            if (isBroadMatcher && networkPatterns.test(command)) {
              findings.push({
                id: `hooks-unthrottled-network-${findings.length}`,
                severity: "medium",
                category: "hooks",
                title: `PostToolUse hook makes network request on broad matcher "${matcher || "*"}"`,
                description: `A PostToolUse hook fires on "${matcher || "every tool call"}" and runs a network command (${command.substring(0, 60)}...). Without throttling, this fires on every matching tool call \u2014 potentially hundreds per session \u2014 causing performance degradation and potential data exposure.`,
                file: file.path,
                evidence: `matcher: "${matcher}", hook: "${command.substring(0, 80)}"`,
                fix: {
                  description: "Add rate limiting or narrow the matcher",
                  before: `"matcher": "${matcher}"`,
                  after: `"matcher": "Bash(npm publish)" or add throttle logic`,
                  auto: false
                }
              });
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "hooks-sensitive-file-access",
    name: "Hook Accesses Sensitive Files",
    description: "Checks for hooks that read or write to sensitive system files",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const sensitivePathPatterns = [
        {
          pattern: /\/etc\/(?:passwd|shadow|sudoers|hosts)/g,
          desc: "system authentication/configuration file"
        },
        {
          pattern: /~\/\.ssh\/|\/\.ssh\//g,
          desc: "SSH directory (may contain private keys)"
        },
        {
          pattern: /~\/\.aws\/|\/\.aws\//g,
          desc: "AWS credentials directory"
        },
        {
          pattern: /~\/\.gnupg\/|\/\.gnupg\//g,
          desc: "GPG keyring directory"
        },
        {
          pattern: /~\/\.env|\/\.env\b/g,
          desc: "environment file (likely contains secrets)"
        },
        {
          pattern: /\/etc\/ssl\/|\/etc\/pki\//g,
          desc: "SSL/TLS certificate directory"
        }
      ];
      for (const { pattern, desc } of sensitivePathPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-sensitive-file-${match.index}`,
            severity: "high",
            category: "exposure",
            title: `Hook accesses sensitive path: ${match[0]}`,
            description: `A hook references "${match[0]}" \u2014 ${desc}. Hooks should not access sensitive system files. This could expose credentials, keys, or system configuration.`,
            file: file.path,
            line,
            evidence: match[0]
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-no-stop-hooks",
    name: "No Stop Hooks for Session Verification",
    description: "Checks if there are Stop hooks for end-of-session verification",
    severity: "low",
    category: "misconfiguration",
    check(file) {
      if (file.type !== "settings-json") return [];
      try {
        const config = JSON.parse(file.content);
        const hooks = config?.hooks ?? {};
        if (Object.keys(hooks).length > 0 && !hooks.Stop?.length) {
          return [
            {
              id: "hooks-no-stop-hooks",
              severity: "low",
              category: "misconfiguration",
              title: "No Stop hooks for session-end verification",
              description: "Hooks are configured but no Stop hooks exist. Stop hooks run when a session ends and are useful for final verification \u2014 checking for uncommitted secrets, ensuring console.log statements were removed, or auditing file changes.",
              file: file.path,
              fix: {
                description: "Add a Stop hook for session-end checks",
                before: '"hooks": { ... }',
                after: '"hooks": { ..., "Stop": [{ "hook": "check-for-secrets.sh" }] }',
                auto: false
              }
            }
          ];
        }
      } catch {
      }
      return [];
    }
  },
  {
    id: "hooks-session-start-download",
    name: "Hook SessionStart Downloads Remote Content",
    description: "Checks for SessionStart hooks that download or execute remote scripts",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const sessionHooks = config?.hooks?.SessionStart ?? [];
        const remoteExecutionPatterns = [
          {
            pattern: /\b(curl|wget)\b.*\|\s*(sh|bash|zsh|node|python)/i,
            desc: "Downloads and pipes to shell \u2014 classic remote code execution vector",
            severity: "critical"
          },
          {
            pattern: /\b(curl|wget)\b.*https?:\/\//i,
            desc: "Downloads remote content on every session start",
            severity: "high"
          },
          {
            pattern: /\bgit\s+clone\b/i,
            desc: "Clones a repository on session start \u2014 could pull malicious code",
            severity: "medium"
          }
        ];
        for (const hook of sessionHooks) {
          for (const command of extractHookCommands2(hook)) {
            for (const { pattern, desc, severity } of remoteExecutionPatterns) {
              if (pattern.test(command)) {
                findings.push({
                  id: `hooks-session-start-download-${findings.length}`,
                  severity,
                  category: "hooks",
                  title: `SessionStart hook downloads remote content`,
                  description: `A SessionStart hook runs "${command.substring(0, 80)}". ${desc}. SessionStart hooks run automatically at the beginning of every session without user confirmation.`,
                  file: file.path,
                  evidence: command.substring(0, 100),
                  fix: {
                    description: "Remove remote downloads from SessionStart or use a local script",
                    before: command.substring(0, 60),
                    after: "# Use pre-installed local tools instead",
                    auto: false
                  }
                });
                break;
              }
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "hooks-background-process",
    name: "Hook Spawns Background Process",
    description: "Checks for hooks that spawn background processes which persist beyond the hook's execution",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const bgPatterns = [
        {
          pattern: /\bnohup\b/g,
          description: "nohup keeps a process running after the hook exits \u2014 potential persistence mechanism"
        },
        {
          pattern: /\bdisown\b/g,
          description: "disown detaches a process from the shell \u2014 hides background activity"
        },
        {
          pattern: /&\s*(?:$|[;)]|&&)/gm,
          description: "Background process via & \u2014 may run indefinitely after hook completes"
        },
        {
          pattern: /\bscreen\s+-[dS]/g,
          description: "screen session \u2014 creates persistent hidden shell sessions"
        },
        {
          pattern: /\btmux\s+(?:new|send)/g,
          description: "tmux session \u2014 creates persistent hidden shell sessions"
        }
      ];
      for (const { pattern, description } of bgPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-bg-process-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook spawns background process: ${match[0].trim()}`,
            description: `${description}. Background processes in hooks can be used for persistent backdoors or data exfiltration that outlives the session.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-env-exfiltration",
    name: "Hook Env Var Exfiltration",
    description: "Checks for hooks that access environment variables and send them to external services",
    severity: "critical",
    category: "exposure",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const envAccessPatterns = /\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|PASS|CRED|AUTH)\w*\}?/gi;
      const envAccessRegex = new RegExp(envAccessPatterns.source, envAccessPatterns.flags);
      const networkCheck = /\b(curl|wget|nc|netcat|sendmail|mail\s+-s)\b/i;
      for (const { match, line, content } of findAllHookMatches(file, envAccessRegex)) {
        const lineStart = content.lastIndexOf("\n", match.index ?? 0) + 1;
        const lineEnd = content.indexOf("\n", (match.index ?? 0) + match[0].length);
        const evidenceLine = content.substring(lineStart, lineEnd === -1 ? void 0 : lineEnd);
        if (networkCheck.test(evidenceLine)) {
          findings.push({
            id: `hooks-env-exfil-${match.index}`,
            severity: "critical",
            category: "exposure",
            title: `Hook combines env var access with network call`,
            description: `A hook accesses an environment variable (${match[0]}) and sends data over the network in the same command. This pattern can exfiltrate secrets from the environment to external services.`,
            file: file.path,
            line,
            evidence: evidenceLine.trim().substring(0, 100)
          });
          break;
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-chained-commands",
    name: "Hook Chained Shell Commands",
    description: "Checks for hooks that chain multiple commands, which may execute beyond the matcher's intended scope",
    severity: "medium",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json") return [];
      if (isPluginHookManifest(file)) return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const allHooks = [
          ...config?.hooks?.PreToolUse ?? [],
          ...config?.hooks?.PostToolUse ?? [],
          ...config?.hooks?.SessionStart ?? [],
          ...config?.hooks?.Stop ?? []
        ];
        const chainPatterns = [
          { pattern: /&&/, desc: "AND chain (&&)" },
          { pattern: /;\s*[a-zA-Z]/, desc: "semicolon chain" },
          { pattern: /\|\s*[a-zA-Z]/, desc: "pipe chain" }
        ];
        for (const hook of allHooks) {
          for (const command of extractHookCommands2(hook)) {
            if (isBlockingGuardCommand(command)) {
              continue;
            }
            let chainCount = 0;
            for (const { pattern } of chainPatterns) {
              const matches = [...command.matchAll(new RegExp(pattern.source, "g"))];
              chainCount += matches.length;
            }
            if (chainCount >= 3) {
              findings.push({
                id: `hooks-chained-commands-${findings.length}`,
                severity: "medium",
                category: "hooks",
                title: `Hook has ${chainCount + 1} chained commands`,
                description: `A hook chains ${chainCount + 1} commands together: "${command.substring(0, 80)}...". Complex chained commands in hooks are harder to audit and may perform operations beyond the hook's stated purpose. Consider breaking into a dedicated script file.`,
                file: file.path,
                evidence: command.substring(0, 100),
                fix: {
                  description: "Move complex logic to a script file",
                  before: command.substring(0, 50),
                  after: '"hook": "./scripts/hook-check.sh"',
                  auto: false
                }
              });
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "hooks-expensive-unscoped",
    name: "Hook Expensive Unscoped Command",
    description: "Checks for PostToolUse hooks running expensive build/lint commands with broad matchers",
    severity: "low",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const postHooks = config?.hooks?.PostToolUse ?? [];
        const expensiveCommands = /\b(tsc|eslint|prettier|webpack|jest|vitest|mocha|esbuild|rollup|turbo)\b/;
        const broadMatchers = ["Edit", "Write", ""];
        for (const hook of postHooks) {
          const hookConfig = hook;
          const matcher = hookConfig.matcher ?? "";
          const isBroadMatcher = matcher === "" || broadMatchers.some((m) => m !== "" && matcher === m);
          for (const command of extractHookCommands2(hook)) {
            const expensiveMatch = command.match(expensiveCommands);
            if (isBroadMatcher && expensiveMatch) {
              findings.push({
                id: `hooks-expensive-unscoped-${findings.length}`,
                severity: "low",
                category: "hooks",
                title: `PostToolUse runs "${expensiveMatch[0]}" on broad matcher "${matcher || "*"}"`,
                description: `A PostToolUse hook runs "${expensiveMatch[0]}" on every "${matcher || "tool call"}" event. Build tools and linters can take seconds to run \u2014 firing on every edit wastes resources and slows down the agent. Scope the matcher to specific file types or add conditional checks.`,
                file: file.path,
                evidence: `matcher: "${matcher}", hook: "${command.substring(0, 80)}"`,
                fix: {
                  description: "Scope the matcher to reduce unnecessary runs",
                  before: `"matcher": "${matcher}"`,
                  after: `"matcher": "Edit(*.ts)" or add file-extension check in the hook script`,
                  auto: false
                }
              });
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "hooks-output-to-world-readable",
    name: "Hook Writes to World-Readable Path",
    description: "Checks for hooks that redirect output to world-readable directories like /tmp",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const worldReadablePatterns = [
        {
          pattern: />\s*\/tmp\//g,
          description: "Redirects output to /tmp \u2014 readable by all users on the system"
        },
        {
          pattern: /\btee\s+\/tmp\//g,
          description: "Uses tee to write to /tmp \u2014 creates world-readable file"
        },
        {
          pattern: />\s*\/var\/tmp\//g,
          description: "Redirects output to /var/tmp \u2014 persistent and world-readable"
        },
        {
          pattern: /\bmktemp\b/g,
          description: "Creates temporary file \u2014 ensure secure permissions (mktemp is generally safe but verify cleanup)"
        }
      ];
      for (const { pattern, description } of worldReadablePatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          if (pattern.source.includes("mktemp")) continue;
          findings.push({
            id: `hooks-world-readable-${match.index}`,
            severity: "high",
            category: "exposure",
            title: `Hook writes to world-readable path: ${match[0].trim()}`,
            description: `${description}. Other users or processes on the system can read the output, which may contain secrets, code, or session data.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-source-from-env",
    name: "Hook Sources Script from Environment Path",
    description: "Checks for hooks that source scripts from environment variable paths",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const sourcePatterns = [
        {
          pattern: /\bsource\s+\$\{?\w+\}?\//g,
          description: "Sources a script from an environment variable path"
        },
        {
          pattern: /\.\s+\$\{?\w+\}?\//g,
          description: "Dot-sources a script from an environment variable path"
        },
        {
          pattern: /\beval\s+\$\{?\w+/g,
          description: "Evaluates content from an environment variable"
        }
      ];
      for (const { pattern, description } of sourcePatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-source-env-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Hook sources script from environment path: ${match[0].trim()}`,
            description: `${description}. If the environment variable is attacker-controlled, this enables arbitrary code execution through the sourced script.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-file-deletion",
    name: "Hook Deletes Files",
    description: "Checks for hooks that delete files, which could destroy work or cover tracks",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const deletePatterns = [
        {
          pattern: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\b/g,
          description: "Recursive file deletion (rm -rf) \u2014 can destroy entire directories"
        },
        {
          pattern: /\brm\s+-[a-zA-Z]*f\b/g,
          description: "Force file deletion (rm -f) \u2014 deletes without confirmation"
        },
        {
          pattern: /\bshred\b/g,
          description: "Secure file erasure (shred) \u2014 irrecoverable deletion used to cover tracks"
        },
        {
          pattern: /\bunlink\b/g,
          description: "File deletion via unlink"
        }
      ];
      for (const { pattern, description } of deletePatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-file-delete-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook deletes files: ${match[0].trim()}`,
            description: `${description}. A hook that deletes files could destroy source code, logs, or evidence of compromise.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-cron-persistence",
    name: "Hook Installs Cron Job",
    description: "Checks for hooks that install cron jobs for persistent access",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const cronPatterns = [
        {
          pattern: /\bcrontab\b/g,
          description: "Modifies crontab \u2014 installs persistent scheduled tasks"
        },
        {
          pattern: /\/etc\/cron/g,
          description: "Writes to system cron directory \u2014 installs persistent scheduled tasks"
        },
        {
          pattern: /\bat\s+-[a-z]/g,
          description: "Schedules deferred command execution via at"
        },
        {
          pattern: /\bsystemctl\s+(?:enable|start)/g,
          description: "Enables/starts a systemd service \u2014 potential persistence mechanism"
        },
        {
          pattern: /\blaunchctl\s+load/g,
          description: "Loads a macOS launch agent \u2014 persistent background process"
        }
      ];
      for (const { pattern, description } of cronPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-cron-persist-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook installs persistence mechanism: ${match[0].trim()}`,
            description: `${description}. Hooks should not install persistence mechanisms. This could allow a compromised hook to maintain access even after the session ends.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-env-mutation",
    name: "Hook Mutates Environment Variables",
    description: "Checks for hooks that set or export environment variables, which can alter subsequent command behavior",
    severity: "medium",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const envMutationPatterns = [
        {
          pattern: /\bexport\s+PATH=/g,
          description: "Modifies PATH \u2014 can redirect which binaries are executed",
          severity: "high"
        },
        {
          pattern: /\bexport\s+(?:LD_PRELOAD|LD_LIBRARY_PATH|DYLD_)=/gi,
          description: "Modifies dynamic linker variables \u2014 can inject shared libraries",
          severity: "high"
        },
        {
          pattern: /\bexport\s+(?:NODE_OPTIONS|PYTHONPATH|RUBYLIB)=/gi,
          description: "Modifies runtime import paths \u2014 can load malicious modules",
          severity: "high"
        },
        {
          pattern: /\bexport\s+(?:http_proxy|https_proxy|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY)=/gi,
          description: "Sets proxy variables \u2014 can redirect all network traffic through attacker-controlled proxy",
          severity: "high"
        }
      ];
      for (const { pattern, description, severity } of envMutationPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-env-mutation-${match.index}`,
            severity,
            category: "hooks",
            title: `Hook mutates environment: ${match[0].trim()}`,
            description: `${description}. Hooks that modify environment variables can silently alter the behavior of all subsequent commands in the session.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-git-config-modification",
    name: "Hook Modifies Git Configuration",
    description: "Checks for hooks that modify git config, which can alter commit authorship, disable signing, or change hooks",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const gitConfigPatterns = [
        {
          pattern: /\bgit\s+config\s+--global/g,
          description: "Modifies global git config \u2014 affects all repositories on the system"
        },
        {
          pattern: /\bgit\s+config\s+(?:--system)/g,
          description: "Modifies system-level git config \u2014 affects all users"
        },
        {
          pattern: /\bgit\s+config\s+(?:.*\s+)?(?:user\.email|user\.name)/g,
          description: "Changes git commit author identity \u2014 could attribute commits to someone else"
        },
        {
          pattern: /\bgit\s+config\s+(?:.*\s+)?(?:commit\.gpgsign|tag\.gpgsign)\s+false/g,
          description: "Disables GPG commit signing \u2014 weakens commit verification"
        },
        {
          pattern: /\bgit\s+config\s+(?:.*\s+)?core\.hooksPath/g,
          description: "Changes git hooks directory \u2014 could redirect to malicious hooks"
        }
      ];
      for (const { pattern, description } of gitConfigPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-git-config-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook modifies git config: ${match[0].trim()}`,
            description: `${description}. Hooks should not modify git configuration as this can undermine version control integrity.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-user-account-modification",
    name: "Hook Creates or Modifies User Accounts",
    description: "Checks for hooks that create, modify, or delete user accounts",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const userModPatterns = [
        {
          pattern: /\buseradd\b/g,
          description: "Creates a new user account (useradd)"
        },
        {
          pattern: /\badduser\b/g,
          description: "Creates a new user account (adduser)"
        },
        {
          pattern: /\busermod\b/g,
          description: "Modifies an existing user account (usermod)"
        },
        {
          pattern: /\buserdel\b/g,
          description: "Deletes a user account (userdel)"
        },
        {
          pattern: /\bpasswd\b/g,
          description: "Changes a user password (passwd)"
        }
      ];
      for (const { pattern, description } of userModPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line, content } of matches) {
          if (isRegexLikeAlternationLiteral(content, match.index ?? 0)) {
            continue;
          }
          findings.push({
            id: `hooks-user-mod-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook modifies user accounts: ${match[0].trim()}`,
            description: `${description}. Hooks should never create, modify, or delete user accounts. A compromised hook with this capability can create backdoor accounts for persistent access.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-privilege-escalation",
    name: "Hook Uses Privilege Escalation",
    description: "Checks for hooks that use sudo, su, or other privilege escalation commands",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const privEscPatterns = [
        {
          pattern: /\bsudo\b/g,
          description: "Runs commands as root via sudo"
        },
        {
          pattern: /\bsu\s+-?\s*\w/g,
          description: "Switches to another user via su"
        },
        {
          pattern: /\bdoas\b/g,
          description: "Runs commands as another user via doas (OpenBSD sudo alternative)"
        },
        {
          pattern: /\bpkexec\b/g,
          description: "Runs commands as another user via polkit (pkexec)"
        },
        {
          pattern: /\brunas\b/gi,
          description: "Runs commands as another user via runas (Windows)"
        }
      ];
      for (const { pattern, description } of privEscPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-priv-esc-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook uses privilege escalation: ${match[0].trim()}`,
            description: `${description}. Hooks should never escalate privileges. A compromised hook with root access can take over the entire system.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-network-listener",
    name: "Hook Opens Network Listener",
    description: "Checks for hooks that bind to network ports, which could create reverse shells or backdoors",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const listenerPatterns = [
        {
          pattern: /\bnc\s+.*-l/g,
          description: "Opens a netcat listener \u2014 classic reverse shell vector"
        },
        {
          pattern: /\bsocat\b/g,
          description: "Uses socat for bidirectional data transfer \u2014 can create tunnels and reverse shells"
        },
        {
          pattern: /\bpython3?\s+.*-m\s+http\.server/g,
          description: "Starts a Python HTTP server \u2014 exposes local files over the network"
        },
        {
          pattern: /\bpython3?\s+.*SimpleHTTPServer/g,
          description: "Starts a Python 2 HTTP server \u2014 exposes local files over the network"
        },
        {
          pattern: /\bphp\s+-S\b/g,
          description: "Starts a PHP built-in server \u2014 serves files and executes PHP code"
        }
      ];
      for (const { pattern, description } of listenerPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-network-listener-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook opens network listener: ${match[0].trim()}`,
            description: `${description}. Hooks should not open network listeners. This could create a backdoor accessible from the network.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-disk-wipe",
    name: "Hook Uses Disk Wiping Commands",
    description: "Checks for hooks that use destructive disk operations",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const wipePatterns = [
        {
          pattern: /\bdd\s+if=\/dev\/(?:zero|urandom)/g,
          description: "Overwrites disk with zeros/random data via dd"
        },
        {
          pattern: /\bmkfs\b/g,
          description: "Formats a filesystem \u2014 destroys all data on the target device"
        },
        {
          pattern: /\bwipefs\b/g,
          description: "Wipes filesystem signatures \u2014 makes data unrecoverable"
        }
      ];
      for (const { pattern, description } of wipePatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-disk-wipe-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook uses disk wiping command: ${match[0].trim()}`,
            description: `${description}. Hooks should never perform destructive disk operations. This could permanently destroy data.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-shell-profile-modification",
    name: "Hook Modifies Shell Profile",
    description: "Checks for hooks that modify shell init files (.bashrc, .zshrc, .profile) for persistence",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const profilePatterns = [
        {
          pattern: /\.bashrc/g,
          description: "Modifies .bashrc \u2014 commands here run on every new bash shell"
        },
        {
          pattern: /\.zshrc/g,
          description: "Modifies .zshrc \u2014 commands here run on every new zsh shell"
        },
        {
          pattern: /\.bash_profile/g,
          description: "Modifies .bash_profile \u2014 commands here run on every login shell"
        },
        {
          pattern: /\.profile/g,
          description: "Modifies .profile \u2014 commands here run on every login shell"
        },
        {
          pattern: /\/etc\/environment/g,
          description: "Modifies /etc/environment \u2014 affects all users on the system"
        }
      ];
      for (const { pattern, description } of profilePatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line, content } of matches) {
          const idx = match.index ?? 0;
          const contextStart = Math.max(0, idx - 50);
          const context = content.substring(contextStart, idx + match[0].length + 50);
          const isWrite = />>|>|tee|echo\s+.*>|sed\s+-i|append/.test(context);
          if (isWrite) {
            findings.push({
              id: `hooks-shell-profile-${match.index}`,
              severity: "critical",
              category: "hooks",
              title: `Hook modifies shell profile: ${match[0].trim()}`,
              description: `${description}. Writing to shell profile files is a classic persistence technique \u2014 malicious code injected here survives across reboots and terminal sessions.`,
              file: file.path,
              line,
              evidence: context.trim().substring(0, 80)
            });
          }
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-logging-disabled",
    name: "Hook Disables Logging or Audit Trail",
    description: "Checks for hooks that clear logs or disable audit mechanisms",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const seenFindings = /* @__PURE__ */ new Set();
      const logPatterns = [
        {
          pattern: />\s*\/dev\/null\s+2>&1|&>\s*\/dev\/null/g,
          description: "Redirects all output to /dev/null \u2014 hides both stdout and stderr"
        },
        {
          pattern: /\bhistory\s+-[cwd]/g,
          description: "Clears or disables shell history \u2014 covers tracks"
        },
        {
          pattern: /\bunset\s+HISTFILE/g,
          description: "Unsets HISTFILE \u2014 prevents command history from being saved"
        },
        {
          pattern: /\btruncate\s+.*\/var\/log/g,
          description: "Truncates system log files \u2014 destroys audit trail"
        }
      ];
      for (const { pattern, description } of logPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line, commandContext } of matches) {
          if (match[0].includes("/dev/null") && isBenignLoggingProbe(commandContext)) {
            continue;
          }
          const evidence = match[0].trim();
          const dedupeKey = `${line}:${evidence}:${description}`;
          if (seenFindings.has(dedupeKey)) {
            continue;
          }
          seenFindings.add(dedupeKey);
          findings.push({
            id: `hooks-logging-disabled-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook disables logging: ${evidence}`,
            description: `${description}. Disabling logging or clearing audit trails in hooks is a defense evasion technique that makes it harder to detect and investigate compromises.`,
            file: file.path,
            line,
            evidence
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-ssh-key-operations",
    name: "Hook Manipulates SSH Keys",
    description: "Checks for hooks that generate, copy, or modify SSH keys \u2014 enables lateral movement",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const sshKeyPatterns = [
        {
          pattern: /\bssh-keygen\b/g,
          description: "Generates SSH keys \u2014 could create unauthorized keys for persistent access"
        },
        {
          pattern: /\bssh-copy-id\b/g,
          description: "Copies SSH keys to remote hosts \u2014 enables passwordless lateral movement"
        },
        {
          pattern: />>?\s*~\/\.ssh\/authorized_keys/g,
          description: "Appends to authorized_keys \u2014 installs backdoor SSH access"
        }
      ];
      for (const { pattern, description } of sshKeyPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-ssh-key-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook manipulates SSH keys: ${match[0].trim()}`,
            description: `${description}. Hooks should not create or distribute SSH keys as this enables unauthorized remote access.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-background-process",
    name: "Hook Runs Background Process",
    description: "Checks for hooks that start persistent background processes that outlive the session",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const bgPatterns = [
        {
          pattern: /\bnohup\b/g,
          description: "Runs process immune to hangup signals \u2014 survives session end"
        },
        {
          pattern: /\bdisown\b/g,
          description: "Detaches process from shell \u2014 survives session end"
        },
        {
          pattern: /\bscreen\s+-[dD]m/g,
          description: "Starts detached screen session \u2014 hidden persistent process"
        },
        {
          pattern: /\btmux\s+new-session\s+-d/g,
          description: "Starts detached tmux session \u2014 hidden persistent process"
        }
      ];
      for (const { pattern, description } of bgPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-bg-process-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook starts background process: ${match[0].trim()}`,
            description: `${description}. Hooks that start persistent background processes can maintain execution even after the agent session ends \u2014 a common persistence technique.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-dns-exfiltration",
    name: "Hook Uses DNS for Data Exfiltration",
    description: "Checks for hooks that use DNS queries with variable interpolation to exfiltrate data",
    severity: "critical",
    category: "exfiltration",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const dnsPatterns = [
        {
          pattern: /\bdig\s+.*\$\{?\w+/g,
          description: "Uses dig with variable interpolation \u2014 DNS exfiltration encodes data in DNS queries"
        },
        {
          pattern: /\bnslookup\s+.*\$\{?\w+/g,
          description: "Uses nslookup with variable interpolation \u2014 DNS exfiltration vector"
        },
        {
          pattern: /\bhost\s+.*\$\{?\w+/g,
          description: "Uses host command with variable interpolation \u2014 DNS exfiltration vector"
        }
      ];
      for (const { pattern, description } of dnsPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-dns-exfil-${match.index}`,
            severity: "critical",
            category: "exfiltration",
            title: `Hook uses DNS for exfiltration: ${match[0].trim().substring(0, 60)}`,
            description: `${description}. DNS queries bypass most firewalls and proxy filters, making this a common out-of-band exfiltration technique.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-firewall-modification",
    name: "Hook Modifies Firewall Rules",
    description: "Checks for hooks that modify iptables, ufw, or firewall rules",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const fwPatterns = [
        {
          pattern: /\biptables\b/g,
          description: "Modifies iptables firewall rules \u2014 can open ports or disable filtering"
        },
        {
          pattern: /\bufw\s+(?:allow|delete|disable)/g,
          description: "Modifies UFW firewall \u2014 can open ports or disable the firewall entirely"
        },
        {
          pattern: /\bfirewall-cmd\b/g,
          description: "Modifies firewalld rules \u2014 can change network access policies"
        }
      ];
      for (const { pattern, description } of fwPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-fw-modify-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook modifies firewall: ${match[0].trim()}`,
            description: `${description}. Hooks should not modify firewall rules \u2014 this could expose the system to network attacks.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-global-package-install",
    name: "Hook Installs Global Packages",
    description: "Checks for hooks that install packages globally, which can modify system-wide binaries",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const installPatterns = [
        {
          pattern: /\bnpm\s+install\s+-g\b|\bnpm\s+i\s+-g\b/g,
          description: "Installs npm package globally \u2014 modifies system-wide PATH binaries"
        },
        {
          pattern: /\bpip\s+install\s+(?:--user\s+)?(?!-r\b)/g,
          description: "Installs Python package \u2014 may modify system Python packages"
        },
        {
          pattern: /\bgem\s+install\b/g,
          description: "Installs Ruby gem \u2014 modifies system Ruby packages"
        },
        {
          pattern: /\bcargo\s+install\b/g,
          description: "Installs Rust package globally via cargo"
        }
      ];
      for (const { pattern, description } of installPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-global-install-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook installs packages: ${match[0].trim()}`,
            description: `${description}. Hooks that install packages can introduce supply chain risks and modify the system's behavior for all future commands.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-container-escape",
    name: "Hook Uses Container Escape Techniques",
    description: "Checks for hooks that use Docker flags that enable container escape",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const containerEscapePatterns = [
        {
          pattern: /--privileged/g,
          description: "Docker --privileged flag \u2014 container has full host access"
        },
        {
          pattern: /--pid=host/g,
          description: "Docker --pid=host \u2014 container can see/signal all host processes"
        },
        {
          pattern: /--network=host/g,
          description: "Docker --network=host \u2014 container shares host network stack"
        },
        {
          pattern: /-v\s+\/:/g,
          description: "Mounts host root filesystem into container \u2014 full filesystem access"
        }
      ];
      for (const { pattern, description } of containerEscapePatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-container-escape-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook uses container escape technique: ${match[0].trim()}`,
            description: `${description}. These Docker flags break container isolation and allow full host access from within the container.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-credential-access",
    name: "Hook Accesses Credential Stores",
    description: "Checks for hooks that read password files, keychains, or credential managers",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const credPatterns = [
        {
          pattern: /\bsecurity\s+find-generic-password\b/g,
          description: "Reads macOS Keychain passwords via security command"
        },
        {
          pattern: /\bsecurity\s+find-internet-password\b/g,
          description: "Reads macOS Keychain internet passwords"
        },
        {
          pattern: /\bsecret-tool\s+lookup\b/g,
          description: "Reads GNOME Keyring / Linux secret store"
        },
        {
          pattern: /\bkeyctl\s+read\b/g,
          description: "Reads Linux kernel keyring"
        },
        {
          pattern: /\/etc\/shadow/g,
          description: "Accesses /etc/shadow \u2014 contains password hashes"
        }
      ];
      for (const { pattern, description } of credPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-cred-access-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook accesses credential store: ${match[0].trim()}`,
            description: `${description}. Hooks should never access credential stores \u2014 this enables credential theft for lateral movement.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-reverse-shell",
    name: "Hook Opens Reverse Shell",
    description: "Checks for hooks that establish reverse shell connections back to an attacker",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const reverseShellPatterns = [
        {
          pattern: /\bbash\s+-i\s+[>&]+.*\/dev\/tcp\//g,
          description: "Bash reverse shell via /dev/tcp \u2014 connects back to attacker"
        },
        {
          pattern: /\/dev\/tcp\/[0-9.]+\/\d+/g,
          description: "Uses /dev/tcp for network connection \u2014 common reverse shell technique"
        },
        {
          pattern: /\bpython3?\s+.*-c\s+.*socket.*connect/g,
          description: "Python reverse shell via socket.connect"
        },
        {
          pattern: /\bperl\s+.*-e\s+.*socket.*INET/g,
          description: "Perl reverse shell via Socket::INET"
        },
        {
          pattern: /\bmkfifo\b.*\bnc\b/g,
          description: "Named pipe reverse shell using mkfifo and netcat"
        }
      ];
      for (const { pattern, description } of reverseShellPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-reverse-shell-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook establishes reverse shell: ${match[0].trim().substring(0, 60)}`,
            description: `${description}. Reverse shells give attackers interactive command execution on the target system.`,
            file: file.path,
            line,
            evidence: match[0].trim().substring(0, 80)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-clipboard-access",
    name: "Hook Accesses System Clipboard",
    description: "Checks for hooks that read or write the system clipboard, which can be used for data exfiltration",
    severity: "high",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const clipboardPatterns = [
        {
          pattern: /\bpbcopy\b/g,
          description: "Uses macOS pbcopy to write to clipboard \u2014 can silently exfiltrate data"
        },
        {
          pattern: /\bpbpaste\b/g,
          description: "Uses macOS pbpaste to read clipboard \u2014 may capture sensitive copied content"
        },
        {
          pattern: /\bxclip\b/g,
          description: "Uses xclip to access X11 clipboard \u2014 can read or write clipboard data"
        },
        {
          pattern: /\bxsel\b/g,
          description: "Uses xsel to access X11 selection \u2014 can read or write clipboard data"
        },
        {
          pattern: /\bwl-copy\b/g,
          description: "Uses wl-copy to write to Wayland clipboard"
        },
        {
          pattern: /\bwl-paste\b/g,
          description: "Uses wl-paste to read from Wayland clipboard"
        }
      ];
      for (const { pattern, description } of clipboardPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-clipboard-${match.index}`,
            severity: "high",
            category: "hooks",
            title: `Hook accesses clipboard: ${match[0].trim()}`,
            description: `${description}. Clipboard access in hooks can be used to steal passwords, tokens, and other sensitive data that users copy.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  },
  {
    id: "hooks-log-tampering",
    name: "Hook Tampers with System Logs",
    description: "Checks for hooks that delete, truncate, or modify system log files to cover tracks",
    severity: "critical",
    category: "hooks",
    check(file) {
      if (file.type !== "settings-json" && file.type !== "hook-script") return [];
      const findings = [];
      const logTamperPatterns = [
        {
          pattern: /\bjournalctl\s+--vacuum/g,
          description: "Purges systemd journal logs \u2014 destroys audit trail"
        },
        {
          pattern: /\brm\s+(?:-[rf]+\s+)?\/var\/log\b/g,
          description: "Deletes system log files \u2014 destroys audit evidence"
        },
        {
          pattern: /\btruncate\s+.*\/var\/log\b/g,
          description: "Truncates system log files \u2014 erases log contents"
        },
        {
          pattern: />\s*\/var\/log\/(?:syslog|auth\.log|messages|secure)/g,
          description: "Overwrites system log file with redirection \u2014 clears log contents"
        },
        {
          pattern: /\bhistory\s+-c\b/g,
          description: "Clears shell command history \u2014 covers tracks of executed commands"
        },
        {
          pattern: /\bunset\s+HISTFILE\b/g,
          description: "Disables shell history recording \u2014 prevents command audit trail"
        }
      ];
      for (const { pattern, description } of logTamperPatterns) {
        const matches = findAllHookMatches(file, pattern);
        for (const { match, line } of matches) {
          findings.push({
            id: `hooks-log-tamper-${match.index}`,
            severity: "critical",
            category: "hooks",
            title: `Hook tampers with logs: ${match[0].trim()}`,
            description: `${description}. Log tampering is a strong indicator of malicious intent \u2014 attackers erase evidence of their actions.`,
            file: file.path,
            line,
            evidence: match[0].trim()
          });
        }
      }
      return findings;
    }
  }
];

// src/rules/mcp.ts
var MCP_RISK_PROFILES = [
  {
    namePattern: /filesystem/i,
    risk: "high",
    description: "Filesystem MCP grants read/write access to the file system",
    recommendation: "Restrict to specific directories using allowedDirectories config"
  },
  {
    namePattern: /puppeteer|playwright|browser/i,
    risk: "high",
    description: "Browser automation MCP can navigate to arbitrary URLs and run JavaScript",
    recommendation: "Restrict to specific domains and disable script running where possible"
  },
  {
    namePattern: /shell|terminal|command/i,
    risk: "critical",
    description: "Shell/command MCP grants arbitrary command running",
    recommendation: "Use allowlist of specific commands instead of unrestricted shell access"
  },
  {
    namePattern: /database|postgres|mysql|sqlite|mongo/i,
    risk: "high",
    description: "Database MCP can read/write database contents",
    recommendation: "Use read-only connection and restrict to specific tables/schemas"
  },
  {
    namePattern: /slack|discord|email|sendgrid/i,
    risk: "medium",
    description: "Messaging MCP can send messages to external services",
    recommendation: "Restrict to specific channels and require confirmation for sends"
  }
];
function findEnabledBooleanFlag(value, flagName, currentPath = "") {
  const paths = [];
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      const childPath = `${currentPath}[${index}]`;
      paths.push(...findEnabledBooleanFlag(item, flagName, childPath));
    });
    return paths;
  }
  if (!value || typeof value !== "object") {
    return paths;
  }
  for (const [key, child] of Object.entries(value)) {
    const childPath = currentPath ? `${currentPath}.${key}` : key;
    if (key === flagName && child === true) {
      paths.push(childPath);
    }
    paths.push(...findEnabledBooleanFlag(child, flagName, childPath));
  }
  return paths;
}
function isLikelyMcpTemplatePath(filePath) {
  const normalized = filePath.toLowerCase();
  return normalized.startsWith("mcp-configs/") || normalized.includes("/mcp-configs/") || normalized.startsWith("config/mcp/") || normalized.includes("/config/mcp/") || normalized.startsWith("configs/mcp/") || normalized.includes("/configs/mcp/");
}
function isPlaceholderSecretValue(value) {
  const normalized = value.trim();
  return /^YOUR_[A-Z0-9_]+$/i.test(normalized) || /^REPLACE(?:_|-)?ME(?:_[A-Z0-9_]+)?$/i.test(normalized) || /^CHANGEME$/i.test(normalized) || /^<[^>]+>$/.test(normalized);
}
function isTemplateMcpFile(file) {
  return file.type === "mcp-json" && isLikelyMcpTemplatePath(file.path);
}
function classifyMcpRuntimeConfidence(file) {
  if (isTemplateMcpFile(file)) {
    return "template-example";
  }
  const normalizedPath = file.path.toLowerCase();
  if (normalizedPath === "settings.local.json" || normalizedPath.endsWith("/settings.local.json")) {
    return "project-local-optional";
  }
  return "active-runtime";
}
function downgradeTemplateSeverity(severity) {
  switch (severity) {
    case "critical":
      return "high";
    case "high":
      return "medium";
    case "medium":
      return "low";
    default:
      return severity;
  }
}
function formatTemplateMcpTitle(title) {
  const riskyServer = title.match(/^[A-Z]+\s+risk MCP server:\s+(.+)$/);
  if (riskyServer) {
    return `Template defines risky MCP server: ${riskyServer[1]}`;
  }
  if (title.startsWith("MCP server ")) {
    return `Template ${title}`;
  }
  if (title.startsWith("High-risk MCP server ")) {
    return title.replace(/^High-risk MCP server /, "Template high-risk MCP server ");
  }
  return `Template MCP config: ${title}`;
}
function formatTemplateMcpDescription(description) {
  return `This finding comes from an MCP template or example inventory, not a confirmed active runtime MCP configuration. ${description}`;
}
function finalizeMcpFindings(file, findings) {
  const runtimeConfidence = classifyMcpRuntimeConfidence(file);
  return findings.map((finding) => {
    const baseFinding = {
      ...finding,
      runtimeConfidence
    };
    if (!isTemplateMcpFile(file)) {
      return baseFinding;
    }
    if (baseFinding.category !== "mcp" && baseFinding.category !== "misconfiguration") {
      return baseFinding;
    }
    return {
      ...baseFinding,
      severity: downgradeTemplateSeverity(baseFinding.severity),
      title: formatTemplateMcpTitle(baseFinding.title),
      description: formatTemplateMcpDescription(baseFinding.description)
    };
  });
}
function isScopedFilesystemServer(name, serverConfig) {
  if (!/filesystem/i.test(name)) return false;
  const args = Array.isArray(serverConfig.args) ? serverConfig.args.filter((arg) => typeof arg === "string") : [];
  return args.some((arg) => /^\.([/\\]|$)/.test(arg.trim()));
}
var rawMcpRules = [
  {
    id: "mcp-risky-servers",
    name: "Risky MCP Server Configuration",
    description: "Checks MCP server configs for servers that grant excessive capabilities",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server ?? {};
          for (const profile of MCP_RISK_PROFILES) {
            if (profile.namePattern.test(name)) {
              const severity = profile.namePattern.test(name) && isScopedFilesystemServer(name, serverConfig) ? "medium" : profile.risk;
              const description = severity === "medium" && /filesystem/i.test(name) ? "Filesystem MCP is limited to repo-scoped relative paths" : profile.description;
              findings.push({
                id: `mcp-risky-${name}`,
                severity,
                category: "mcp",
                title: `${severity.toUpperCase()} risk MCP server: ${name}`,
                description: `${description}. ${profile.recommendation}.`,
                file: file.path
              });
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-auto-approve-project-servers",
    name: "MCP Project Servers Auto-Approved",
    description: "Checks for enableAllProjectMcpServers=true which silently trusts project-defined MCP servers",
    severity: "critical",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      try {
        const config = JSON.parse(file.content);
        const enabledPaths = findEnabledBooleanFlag(
          config,
          "enableAllProjectMcpServers"
        );
        return enabledPaths.map((path, index) => ({
          id: `mcp-auto-approve-${index}`,
          severity: "critical",
          category: "mcp",
          title: "Project MCP servers are auto-approved",
          description: "This configuration enables automatic approval of project-defined MCP servers. A cloned repository can then introduce MCP servers that connect or execute without an explicit human review step, turning repo config into an active compromise path.",
          file: file.path,
          evidence: `${path}: true`,
          fix: {
            description: "Disable project-wide MCP auto-approval and review each server explicitly",
            before: `"${path}": true`,
            after: `"${path}": false`,
            auto: false
          }
        }));
      } catch {
        return [];
      }
    }
  },
  {
    id: "mcp-hardcoded-env",
    name: "MCP Hardcoded Environment Variables",
    description: "Checks if MCP configs have hardcoded secrets instead of env var references",
    severity: "critical",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const env = serverConfig.env ?? {};
          for (const [key, value] of Object.entries(env)) {
            if (value && !value.startsWith("${") && !value.startsWith("$")) {
              const isSecret = /key|token|secret|password|credential|auth/i.test(key);
              if (isSecret) {
                if (isLikelyMcpTemplatePath(file.path) && isPlaceholderSecretValue(value)) {
                  continue;
                }
                findings.push({
                  id: `mcp-hardcoded-env-${name}-${key}`,
                  severity: "critical",
                  category: "secrets",
                  title: `Hardcoded secret in MCP server "${name}": ${key}`,
                  description: `The environment variable "${key}" for MCP server "${name}" appears to contain a hardcoded secret instead of an environment variable reference.`,
                  file: file.path,
                  evidence: `${key}: "${value.substring(0, 4)}..."`,
                  fix: {
                    description: "Use environment variable reference",
                    before: `"${key}": "${value}"`,
                    after: `"${key}": "\${${key}}"`,
                    auto: true
                  }
                });
              }
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-npx-supply-chain",
    name: "MCP npx Supply Chain Risk",
    description: "Checks for MCP servers using npx -y which auto-installs packages without confirmation",
    severity: "medium",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const command = serverConfig.command;
          const args = serverConfig.args ?? [];
          if (command === "npx" && args.includes("-y")) {
            findings.push({
              id: `mcp-npx-y-${name}`,
              severity: "medium",
              category: "mcp",
              title: `MCP server "${name}" uses npx -y (auto-install)`,
              description: `The MCP server "${name}" uses "npx -y" which automatically installs packages without confirmation. A typosquatting or supply chain attack could run malicious code.`,
              file: file.path,
              fix: {
                description: "Remove -y flag so npx prompts before installing, or install the package explicitly",
                before: `"args": ["-y", "${args[1] ?? "package"}"]`,
                after: `"args": ["${args[1] ?? "package"}"]`,
                auto: true
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-no-description",
    name: "MCP Server Missing Description",
    description: "MCP servers without descriptions make auditing harder",
    severity: "info",
    category: "misconfiguration",
    check(file) {
      if (file.type !== "mcp-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          if (!serverConfig.description) {
            findings.push({
              id: `mcp-no-desc-${name}`,
              severity: "info",
              category: "misconfiguration",
              title: `MCP server "${name}" has no description`,
              description: `Add a description to make security auditing easier: what does this server do and why is it needed?`,
              file: file.path
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-unrestricted-root-path",
    name: "MCP Unrestricted Root Path",
    description: "Checks for MCP servers with filesystem access to root or home directory",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const rootPaths = ["/", "~", "C:\\", "C:/"];
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const args = serverConfig.args ?? [];
          for (const arg of args) {
            if (rootPaths.includes(arg)) {
              findings.push({
                id: `mcp-root-path-${name}`,
                severity: "high",
                category: "mcp",
                title: `MCP server "${name}" has unrestricted path: ${arg}`,
                description: `The MCP server "${name}" is configured with path "${arg}" which grants access to the entire filesystem. This allows an agent to read, write, or delete any file on the system.`,
                file: file.path,
                evidence: `args: ${JSON.stringify(args)}`,
                fix: {
                  description: "Restrict to project-specific directories",
                  before: `"${arg}"`,
                  after: `"./src", "./docs"`,
                  auto: false
                }
              });
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-no-version-pin",
    name: "MCP No Version Pin",
    description: "Checks for MCP servers using npx with unversioned packages",
    severity: "medium",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const command = serverConfig.command;
          const args = serverConfig.args ?? [];
          if (command !== "npx") continue;
          const packageArg = args.find(
            (a) => !a.startsWith("-") && a.includes("/")
          );
          if (!packageArg) continue;
          const afterScope = packageArg.startsWith("@") ? packageArg.substring(packageArg.indexOf("/")) : packageArg;
          const versionPart = afterScope.includes("@") ? afterScope.substring(afterScope.indexOf("@") + 1) : "";
          const hasVersion = afterScope.includes("@") && versionPart !== "latest" && versionPart !== "next";
          if (!hasVersion) {
            findings.push({
              id: `mcp-no-version-${name}`,
              severity: "medium",
              category: "mcp",
              title: `MCP server "${name}" uses unversioned package: ${packageArg}`,
              description: `The MCP server "${name}" uses "${packageArg}" without a pinned version. A compromised package update would run automatically via npx.`,
              file: file.path,
              evidence: `command: npx, package: ${packageArg}`,
              fix: {
                description: "Pin to a specific version",
                before: `"${packageArg}"`,
                after: `"${packageArg}@1.0.0"`,
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-url-transport",
    name: "MCP External URL Transport",
    description: "Checks for MCP servers using URL-based transport connecting to external hosts",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const url = serverConfig.url;
          if (!url) continue;
          const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/i.test(url);
          if (!isLocal) {
            findings.push({
              id: `mcp-url-transport-${name}`,
              severity: "high",
              category: "mcp",
              title: `MCP server "${name}" connects to external URL`,
              description: `The MCP server "${name}" uses URL transport connecting to "${url}". External MCP connections send all tool calls and results over the network, potentially exposing code, secrets, and session data to a remote server. Prefer local stdio-based MCP servers.`,
              file: file.path,
              evidence: url.substring(0, 100),
              fix: {
                description: "Use a local stdio-based MCP server instead",
                before: `"url": "${url.substring(0, 40)}"`,
                after: '"command": "node", "args": ["./local-server.js"]',
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-remote-command",
    name: "MCP Remote Command Execution",
    description: "Checks for MCP servers that download and execute remote code",
    severity: "critical",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const command = serverConfig.command ?? "";
          const args = serverConfig.args ?? [];
          const fullCommand = `${command} ${args.join(" ")}`;
          if (/\b(curl|wget)\b.*\|\s*(sh|bash|zsh|node|python)/i.test(fullCommand)) {
            findings.push({
              id: `mcp-remote-exec-${name}`,
              severity: "critical",
              category: "mcp",
              title: `MCP server "${name}" pipes remote download to shell`,
              description: `The MCP server "${name}" downloads remote code and pipes it directly to a shell interpreter. This is a critical remote code execution vulnerability \u2014 a compromised URL silently runs arbitrary commands.`,
              file: file.path,
              evidence: fullCommand.substring(0, 100),
              fix: {
                description: "Download, verify, then execute separately",
                before: fullCommand.substring(0, 60),
                after: "Install the package locally with npm/pip and reference it directly",
                auto: false
              }
            });
            continue;
          }
          const hasRemoteUrl = args.some(
            (a) => /^https?:\/\/.+\.(sh|py|js|ts|exe|bin)$/i.test(a)
          );
          if (hasRemoteUrl && /^(sh|bash|zsh|node|python|ruby)$/.test(command)) {
            findings.push({
              id: `mcp-remote-script-${name}`,
              severity: "high",
              category: "mcp",
              title: `MCP server "${name}" executes remote script URL`,
              description: `The MCP server "${name}" runs a shell interpreter with a remote script URL as an argument. The remote script could be changed at any time, making this a supply chain risk.`,
              file: file.path,
              evidence: fullCommand.substring(0, 100),
              fix: {
                description: "Download the script locally and reference the local copy",
                before: fullCommand.substring(0, 60),
                after: "Use a locally installed package or script",
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-shell-metacharacters",
    name: "MCP Shell Metacharacters in Args",
    description: "Checks for shell metacharacters in MCP server arguments that could enable command injection",
    severity: "medium",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const shellMetachars = /[;|&`$(){}]/;
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const command = serverConfig.command ?? "";
          const args = serverConfig.args ?? [];
          if (/^(sh|bash|zsh|cmd)$/.test(command)) continue;
          for (const arg of args) {
            if (arg.startsWith("-")) continue;
            if (shellMetachars.test(arg)) {
              findings.push({
                id: `mcp-shell-metachar-${name}`,
                severity: "medium",
                category: "mcp",
                title: `MCP server "${name}" has shell metacharacters in args`,
                description: `The argument "${arg.substring(0, 60)}" for MCP server "${name}" contains shell metacharacters (;|&\`$). If the command spawns a shell, these could enable command injection. Use separate args instead of shell syntax.`,
                file: file.path,
                evidence: arg.substring(0, 80),
                fix: {
                  description: "Split into separate arguments without shell metacharacters",
                  before: `"${arg.substring(0, 40)}"`,
                  after: "Split into separate args array elements",
                  auto: false
                }
              });
              break;
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-env-override",
    name: "MCP Environment Variable Override",
    description: "Checks for MCP servers that override system-critical environment variables like PATH or LD_PRELOAD",
    severity: "critical",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const dangerousEnvVars = [
          { name: "PATH", description: "Controls which executables are found \u2014 can redirect to malicious binaries" },
          { name: "LD_PRELOAD", description: "Injects shared libraries into every process \u2014 classic privilege escalation" },
          { name: "LD_LIBRARY_PATH", description: "Redirects dynamic library loading \u2014 can intercept system calls" },
          { name: "NODE_OPTIONS", description: "Injects flags into every Node.js process \u2014 can load arbitrary code" },
          { name: "PYTHONPATH", description: "Redirects Python module imports \u2014 can load malicious modules" },
          { name: "HOME", description: "Changes home directory \u2014 can redirect config file loading" }
        ];
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const env = serverConfig.env ?? {};
          for (const envVar of dangerousEnvVars) {
            if (envVar.name in env) {
              findings.push({
                id: `mcp-env-override-${name}-${envVar.name}`,
                severity: "critical",
                category: "mcp",
                title: `MCP server "${name}" overrides ${envVar.name}`,
                description: `The MCP server "${name}" sets ${envVar.name} in its environment. ${envVar.description}. If a malicious MCP config is injected (e.g., via a cloned repo), this could compromise the entire system.`,
                file: file.path,
                evidence: `${envVar.name}=${(env[envVar.name] ?? "").substring(0, 40)}`,
                fix: {
                  description: `Remove ${envVar.name} from the MCP server's env block`,
                  before: `"${envVar.name}": "${(env[envVar.name] ?? "").substring(0, 20)}"`,
                  after: `# Remove ${envVar.name} override`,
                  auto: false
                }
              });
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-excessive-server-count",
    name: "MCP Excessive Server Count",
    description: "Flags configurations with too many MCP servers",
    severity: "low",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const count = Object.keys(servers).length;
        if (count > 10) {
          return [
            {
              id: "mcp-excessive-servers",
              severity: "low",
              category: "mcp",
              title: `${count} MCP servers configured \u2014 large attack surface`,
              description: `This configuration has ${count} MCP servers. Each server expands the attack surface through supply chain risk, environment variable exposure, and additional capabilities granted to the agent. Consider removing servers that are not actively needed.`,
              file: file.path
            }
          ];
        }
      } catch {
      }
      return [];
    }
  },
  {
    id: "mcp-shell-wrapper",
    name: "MCP Server Uses Shell Wrapper",
    description: "Checks for MCP servers that use sh/bash -c as command, which defeats argument separation safety",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const command = serverConfig.command ?? "";
          const args = serverConfig.args ?? [];
          if (/^(sh|bash|zsh|cmd)$/.test(command) && args.includes("-c")) {
            findings.push({
              id: `mcp-shell-wrapper-${name}`,
              severity: "high",
              category: "mcp",
              title: `MCP server "${name}" uses shell wrapper (${command} -c)`,
              description: `The MCP server "${name}" uses "${command} -c" as its command. This passes all arguments through a shell interpreter, defeating the security benefits of argument separation. Shell metacharacters in args become live injection vectors. Use the target binary directly as the command instead.`,
              file: file.path,
              evidence: `command: ${command}, args: ${JSON.stringify(args).substring(0, 80)}`,
              fix: {
                description: "Use the target binary directly instead of wrapping in sh -c",
                before: `"command": "${command}", "args": ["-c", ...]`,
                after: '"command": "node", "args": ["./server.js"]',
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-git-url-dependency",
    name: "MCP Git URL Dependency",
    description: "Checks for MCP servers installed from git URLs which are mutable supply chain risks",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const args = serverConfig.args ?? [];
          for (const arg of args) {
            if (/git\+https?:\/\/|github\.com\/.*\.git/.test(arg)) {
              findings.push({
                id: `mcp-git-url-dep-${name}`,
                severity: "high",
                category: "mcp",
                title: `MCP server "${name}" installed from git URL`,
                description: `The MCP server "${name}" references a git URL "${arg.substring(0, 80)}". Git URLs point to mutable content \u2014 the repository owner can push malicious changes at any time, and they would be picked up on next install. Use a pinned npm package version instead.`,
                file: file.path,
                evidence: arg.substring(0, 100),
                fix: {
                  description: "Use a pinned npm package version instead of a git URL",
                  before: `"${arg.substring(0, 40)}"`,
                  after: '"@scope/package@1.0.0"',
                  auto: false
                }
              });
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-disabled-security",
    name: "MCP Server Has Security-Disabling Flags",
    description: "Checks for MCP servers with arguments that disable security features",
    severity: "critical",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const dangerousFlags = [
          {
            pattern: /--no-sandbox/,
            description: "Disables sandboxing \u2014 process runs with full system access"
          },
          {
            pattern: /--disable-web-security/,
            description: "Disables web security policies (CORS, same-origin) \u2014 enables cross-site attacks"
          },
          {
            pattern: /--allow-running-insecure-content/,
            description: "Allows loading HTTP content over HTTPS \u2014 enables MITM attacks"
          },
          {
            pattern: /--unsafe-perm/,
            description: "Runs npm scripts as root \u2014 privilege escalation risk"
          },
          {
            pattern: /--trust-all-certificates|--insecure/,
            description: "Disables TLS certificate verification \u2014 enables MITM attacks"
          }
        ];
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const args = serverConfig.args ?? [];
          const fullArgs = args.join(" ");
          for (const { pattern, description } of dangerousFlags) {
            if (pattern.test(fullArgs)) {
              findings.push({
                id: `mcp-disabled-security-${name}-${pattern.source}`,
                severity: "critical",
                category: "mcp",
                title: `MCP server "${name}" has security-disabling flag`,
                description: `The MCP server "${name}" uses a flag that ${description}. Removing security features from MCP servers dramatically increases the attack surface.`,
                file: file.path,
                evidence: fullArgs.substring(0, 100),
                fix: {
                  description: "Remove the security-disabling flag",
                  before: pattern.source.replace(/[\\]/g, ""),
                  after: "# Remove this flag and fix the root cause instead",
                  auto: false
                }
              });
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-dual-transport",
    name: "MCP Server Has Both URL and Command",
    description: "Checks for MCP servers with both url and command fields, which is ambiguous and potentially dangerous",
    severity: "medium",
    category: "misconfiguration",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const hasUrl = !!serverConfig.url;
          const hasCommand = !!serverConfig.command;
          if (hasUrl && hasCommand) {
            findings.push({
              id: `mcp-dual-transport-${name}`,
              severity: "medium",
              category: "misconfiguration",
              title: `MCP server "${name}" has both url and command`,
              description: `The MCP server "${name}" specifies both a URL transport and a stdio command. This is ambiguous \u2014 it's unclear which transport will be used, and the unused one could be an injection attempt. Use only one transport method.`,
              file: file.path,
              evidence: `url: ${serverConfig.url.substring(0, 40)}, command: ${serverConfig.command}`
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-env-inheritance",
    name: "MCP Server Inherits Full Environment",
    description: "Checks for MCP servers without an explicit env block, which inherit the parent process's full environment including secrets",
    severity: "medium",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const serverCount = Object.keys(servers).length;
        if (serverCount < 2) return [];
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const hasEnv = "env" in serverConfig;
          const hasCommand = !!serverConfig.command;
          if (hasCommand && !hasEnv) {
            findings.push({
              id: `mcp-env-inherit-${name}`,
              severity: "medium",
              category: "mcp",
              title: `MCP server "${name}" inherits full parent environment`,
              description: `The MCP server "${name}" has no explicit "env" block, so it inherits the full parent process environment. This means every environment variable \u2014 including API keys, tokens, and secrets \u2014 is passed to the server. Add an explicit "env" block with only the variables the server needs.`,
              file: file.path,
              evidence: `Server "${name}" has command but no env block`,
              fix: {
                description: "Add an explicit env block with only required variables",
                before: `"${name}": { "command": "..." }`,
                after: `"${name}": { "command": "...", "env": { "ONLY_NEEDED_VAR": "..." } }`,
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-database-connection-string",
    name: "MCP Server Has Database Connection String",
    description: "Checks for MCP servers with database connection strings containing credentials in env or args",
    severity: "high",
    category: "secrets",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      const dbPatterns = [
        {
          pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@/,
          description: "PostgreSQL connection string with embedded credentials"
        },
        {
          pattern: /mysql:\/\/[^:]+:[^@]+@/,
          description: "MySQL connection string with embedded credentials"
        },
        {
          pattern: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@/,
          description: "MongoDB connection string with embedded credentials"
        },
        {
          pattern: /redis:\/\/:[^@]+@/,
          description: "Redis connection string with embedded password"
        }
      ];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const env = serverConfig.env ?? {};
          const args = serverConfig.args ?? [];
          for (const [envKey, envVal] of Object.entries(env)) {
            for (const { pattern, description } of dbPatterns) {
              if (pattern.test(envVal)) {
                findings.push({
                  id: `mcp-db-conn-${name}-${envKey}`,
                  severity: "high",
                  category: "secrets",
                  title: `MCP server "${name}" has ${description.split(" ")[0]} credentials in env`,
                  description: `The MCP server "${name}" has a ${description} in environment variable "${envKey}". Credentials should use env var references instead of being hardcoded.`,
                  file: file.path,
                  evidence: `${envKey}=${envVal.substring(0, 30)}...`,
                  fix: {
                    description: "Use an environment variable reference instead",
                    before: envVal.substring(0, 30),
                    after: "${DATABASE_URL}",
                    auto: false
                  }
                });
                break;
              }
            }
          }
          for (const arg of args) {
            for (const { pattern, description } of dbPatterns) {
              if (pattern.test(arg)) {
                findings.push({
                  id: `mcp-db-conn-arg-${name}`,
                  severity: "high",
                  category: "secrets",
                  title: `MCP server "${name}" has ${description.split(" ")[0]} credentials in args`,
                  description: `The MCP server "${name}" has a ${description} in its command arguments. Credentials should be passed via environment variables.`,
                  file: file.path,
                  evidence: arg.substring(0, 40),
                  fix: {
                    description: "Pass the connection string via an environment variable",
                    before: arg.substring(0, 30),
                    after: "Use env: { DATABASE_URL: ... } instead of args",
                    auto: false
                  }
                });
                break;
              }
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-privileged-port",
    name: "MCP Server Binds to Privileged Port",
    description: "Checks for MCP servers configured to listen on ports below 1024, which require root privileges",
    severity: "medium",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const args = serverConfig.args ?? [];
          const url = serverConfig.url ?? "";
          const urlPortMatch = url.match(/:(\d+)/);
          if (urlPortMatch) {
            const port = parseInt(urlPortMatch[1], 10);
            if (port > 0 && port < 1024 && port !== 443 && port !== 80) {
              findings.push({
                id: `mcp-priv-port-url-${name}`,
                severity: "medium",
                category: "mcp",
                title: `MCP server "${name}" uses privileged port ${port}`,
                description: `The MCP server "${name}" connects to port ${port}, which is a privileged port (< 1024). Privileged ports require root access and binding to them may indicate the server expects elevated privileges.`,
                file: file.path,
                evidence: `url: ${url.substring(0, 60)}`
              });
            }
          }
          for (let i = 0; i < args.length; i++) {
            if (/^(?:--port|-p)$/.test(args[i]) && args[i + 1]) {
              const port = parseInt(args[i + 1], 10);
              if (port > 0 && port < 1024 && port !== 443 && port !== 80) {
                findings.push({
                  id: `mcp-priv-port-arg-${name}`,
                  severity: "medium",
                  category: "mcp",
                  title: `MCP server "${name}" binds to privileged port ${port}`,
                  description: `The MCP server "${name}" is configured to bind to port ${port}. Privileged ports (< 1024) require root access, which conflicts with the principle of least privilege.`,
                  file: file.path,
                  evidence: `${args[i]} ${args[i + 1]}`
                });
              }
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-wildcard-cors",
    name: "MCP Server Has Wildcard CORS",
    description: "Checks for MCP servers with CORS set to * in their arguments or environment",
    severity: "medium",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const args = serverConfig.args ?? [];
          const env = serverConfig.env ?? {};
          const fullArgs = args.join(" ");
          if (/--cors[= ]\*|--cors[= ]["']?\*["']?/.test(fullArgs)) {
            findings.push({
              id: `mcp-wildcard-cors-arg-${name}`,
              severity: "medium",
              category: "mcp",
              title: `MCP server "${name}" allows CORS from any origin`,
              description: `The MCP server "${name}" has CORS set to wildcard (*). This allows any website to make requests to the MCP server, which could be exploited by malicious web pages to interact with the agent.`,
              file: file.path,
              evidence: fullArgs.substring(0, 80)
            });
          }
          for (const [envKey, envVal] of Object.entries(env)) {
            if (/cors/i.test(envKey) && envVal === "*") {
              findings.push({
                id: `mcp-wildcard-cors-env-${name}`,
                severity: "medium",
                category: "mcp",
                title: `MCP server "${name}" allows CORS from any origin via env`,
                description: `The MCP server "${name}" has ${envKey}=* in its environment, allowing cross-origin requests from any website.`,
                file: file.path,
                evidence: `${envKey}=${envVal}`
              });
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-sensitive-file-args",
    name: "MCP Server References Sensitive Files in Arguments",
    description: "Checks for MCP servers with credential files (.env, .pem, credentials.json) passed as arguments",
    severity: "high",
    category: "secrets",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        const sensitiveFilePatterns = [
          {
            pattern: /\.env\b/,
            description: "References .env file \u2014 may contain API keys and secrets"
          },
          {
            pattern: /\.pem\b/,
            description: "References .pem file \u2014 may contain private key material"
          },
          {
            pattern: /credentials\.json/,
            description: "References credentials.json \u2014 likely contains authentication credentials"
          },
          {
            pattern: /service[_-]?account.*\.json/i,
            description: "References a service account key file"
          },
          {
            pattern: /\.p12\b|\.pfx\b/,
            description: "References PKCS#12 certificate file \u2014 contains private keys"
          },
          {
            pattern: /id_(?:rsa|ed25519|ecdsa)(?:\.pub)?$/,
            description: "References SSH key file"
          }
        ];
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const args = serverConfig.args ?? [];
          for (const arg of args) {
            for (const { pattern, description } of sensitiveFilePatterns) {
              if (pattern.test(arg)) {
                findings.push({
                  id: `mcp-sensitive-file-${name}-${arg.substring(0, 20)}`,
                  severity: "high",
                  category: "secrets",
                  title: `MCP server "${name}" references sensitive file: ${arg}`,
                  description: `The MCP server "${name}" has "${arg}" in its arguments. ${description}. Sensitive files passed as arguments may be logged or exposed.`,
                  file: file.path,
                  evidence: `args: [..., "${arg}"]`,
                  fix: {
                    description: "Use environment variables instead of passing sensitive file paths as arguments",
                    before: arg,
                    after: "Use env: { CONFIG_PATH: ... } instead",
                    auto: false
                  }
                });
                break;
              }
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-bind-all-interfaces",
    name: "MCP Server Binds to All Network Interfaces",
    description: "Checks for MCP servers configured to listen on 0.0.0.0, exposing the server to the network",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const args = serverConfig.args ?? [];
          const env = serverConfig.env ?? {};
          const url = serverConfig.url ?? "";
          const fullArgs = args.join(" ");
          if (/0\.0\.0\.0/.test(fullArgs)) {
            findings.push({
              id: `mcp-bind-all-${name}-args`,
              severity: "high",
              category: "mcp",
              title: `MCP server "${name}" binds to all interfaces (0.0.0.0)`,
              description: `The MCP server "${name}" is configured to bind to 0.0.0.0, making it accessible from any network interface. This exposes the server to the local network and potentially the internet. Bind to 127.0.0.1 (localhost) instead.`,
              file: file.path,
              evidence: fullArgs.substring(0, 80),
              fix: {
                description: "Bind to localhost instead of all interfaces",
                before: "0.0.0.0",
                after: "127.0.0.1",
                auto: false
              }
            });
          }
          if (/0\.0\.0\.0/.test(url)) {
            findings.push({
              id: `mcp-bind-all-${name}-url`,
              severity: "high",
              category: "mcp",
              title: `MCP server "${name}" connects to 0.0.0.0`,
              description: `The MCP server "${name}" URL contains 0.0.0.0. This may indicate the server is listening on all network interfaces, exposing it beyond localhost.`,
              file: file.path,
              evidence: url.substring(0, 60)
            });
          }
          for (const [envKey, envVal] of Object.entries(env)) {
            if (/^(?:HOST|BIND|LISTEN)$/i.test(envKey) && envVal === "0.0.0.0") {
              findings.push({
                id: `mcp-bind-all-${name}-env`,
                severity: "high",
                category: "mcp",
                title: `MCP server "${name}" binds to all interfaces via env`,
                description: `The MCP server "${name}" has ${envKey}=0.0.0.0, which exposes the server on all network interfaces.`,
                file: file.path,
                evidence: `${envKey}=${envVal}`
              });
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-auto-approve",
    name: "MCP Server Has Auto-Approve Enabled",
    description: "Checks for MCP servers with autoApprove settings that skip user confirmation for tool calls",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const autoApproveKeys = ["autoApprove", "auto_approve", "autoConfirm", "auto_confirm"];
          for (const key of autoApproveKeys) {
            if (key in serverConfig) {
              const value = serverConfig[key];
              const isEnabled = Array.isArray(value) ? value.length > 0 : !!value;
              if (isEnabled) {
                findings.push({
                  id: `mcp-auto-approve-${name}`,
                  severity: "high",
                  category: "mcp",
                  title: `MCP server "${name}" has auto-approve enabled`,
                  description: `The MCP server "${name}" has "${key}" configured, which skips user confirmation for tool calls. This defeats the human-in-the-loop security model \u2014 a compromised server can silently execute destructive operations without user review.`,
                  file: file.path,
                  evidence: `${key}: ${JSON.stringify(value).substring(0, 80)}`,
                  fix: {
                    description: "Remove auto-approve to require user confirmation for all tool calls",
                    before: `"${key}": ${JSON.stringify(value).substring(0, 30)}`,
                    after: `# Remove "${key}" \u2014 require user confirmation`,
                    auto: false
                  }
                });
              }
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-timeout-missing",
    name: "MCP Server Has No Timeout Configuration",
    description: "Checks for MCP servers without a timeout, which could hang indefinitely or be used for resource exhaustion",
    severity: "low",
    category: "misconfiguration",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const command = serverConfig.command ?? "";
          const isHighRisk = MCP_RISK_PROFILES.some(
            (p) => p.namePattern.test(name)
          );
          if (!isHighRisk) continue;
          const hasTimeout = "timeout" in serverConfig || "requestTimeout" in serverConfig || "connectionTimeout" in serverConfig;
          if (!hasTimeout) {
            findings.push({
              id: `mcp-no-timeout-${name}`,
              severity: "low",
              category: "misconfiguration",
              title: `High-risk MCP server "${name}" has no timeout`,
              description: `The MCP server "${name}" (${command || "unknown command"}) has no timeout configuration. Without a timeout, a malfunctioning or compromised server could hang indefinitely, consuming resources and blocking the agent. Add a timeout to limit execution time.`,
              file: file.path,
              evidence: `Server "${name}" has no timeout, requestTimeout, or connectionTimeout`,
              fix: {
                description: "Add a timeout configuration",
                before: `"${name}": { "command": "${command}" }`,
                after: `"${name}": { "command": "${command}", "timeout": 30000 }`,
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  /**
   * Detects MCP servers that invoke `npx -c` / `--call` (or `--call=…`).
   *
   * These flags pass the trailing argument to the user's shell, giving an
   * RCE primitive equivalent to `sh -c`. This is the Flowise bypass pattern
   * documented by Ox Security ("Mother of All AI Supply Chains", Family 2).
   *
   * The rule only scans flags that appear **before** the first positional
   * (package name) in the args array — anything after the package belongs
   * to the downstream command and must not be matched.
   */
  {
    id: "mcp-npx-shell-exec",
    name: "MCP npx shell-exec flag",
    description: "Checks for MCP servers using `npx -c` / `--call` (including `--call=\u2026`) \u2014 these pass the argument to the user's shell, giving RCE equivalent to `sh -c`.",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      function isNpxCommand(cmd) {
        if (!cmd) return false;
        const basename4 = cmd.split(/[\\/]/).pop() ?? "";
        return basename4 === "npx" || basename4 === "npx.cmd" || basename4 === "npx.exe";
      }
      const npxValueTakingOptions = /* @__PURE__ */ new Set([
        "-p",
        "--package",
        "-w",
        "--workspace",
        "--registry",
        "--loglevel",
        "--userconfig",
        "--globalconfig",
        "--prefix"
      ]);
      function findShellExecFlag(args) {
        let i = 0;
        while (i < args.length) {
          const raw = args[i];
          if (typeof raw !== "string") return void 0;
          if (raw === "-c" || raw === "--call") return raw;
          if (raw.startsWith("--call=")) return "--call";
          if (raw.startsWith("--") && raw.includes("=")) {
            i++;
            continue;
          }
          if (npxValueTakingOptions.has(raw)) {
            i += 2;
            continue;
          }
          if (raw.startsWith("-")) {
            i++;
            continue;
          }
          return void 0;
        }
        return void 0;
      }
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server;
          const command = serverConfig.command;
          const args = serverConfig.args ?? [];
          if (!isNpxCommand(command) || !Array.isArray(args)) continue;
          const matchedFlag = findShellExecFlag(args);
          if (!matchedFlag) continue;
          findings.push({
            id: `mcp-npx-shell-exec-${name}`,
            severity: "high",
            category: "mcp",
            title: `MCP server "${name}" uses npx ${matchedFlag} (shell execution)`,
            description: `The MCP server "${name}" invokes \`npx ${matchedFlag}\` which passes the next argument to the user's shell \u2014 identical RCE primitive to \`sh -c\`. This is the Flowise bypass pattern (Ox Security "Mother of All AI Supply Chains", Family 2).`,
            file: file.path,
            evidence: `command: ${command}, args: ${JSON.stringify(args)}`,
            fix: {
              description: "Remove `-c` / `--call`. Pin to a specific package version with `npx <pkg>@<version>` instead; if shell execution is required, declare the target binary explicitly rather than piggy-backing on npx.",
              before: `"command": "${command}", "args": ${JSON.stringify(args)}`,
              after: `"command": "npx", "args": ["<package>@<version>"]`,
              auto: false
            }
          });
        }
      } catch {
      }
      return findings;
    }
  }
];
var mcpRules = rawMcpRules.map((rule) => ({
  ...rule,
  check(file) {
    return finalizeMcpFindings(file, rule.check(file));
  }
}));

// src/rules/mcp-cve.ts
init_cve_database();
var rawCveMcpRules = [
  {
    id: "mcp-known-vulnerable-server",
    name: "Known Vulnerable MCP Server Package",
    description: "Cross-references MCP server packages against the CVE database to detect known-vulnerable servers",
    severity: "critical",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server ?? {};
          const command = serverConfig.command ?? "";
          const args = serverConfig.args ?? [];
          const vulnServer = checkServerPackage(command, args);
          if (vulnServer) {
            const cveList = vulnServer.cveIds.join(", ");
            findings.push({
              id: `mcp-known-vuln-${name}`,
              severity: "critical",
              category: "mcp",
              title: `MCP server "${name}" uses known-vulnerable package: ${vulnServer.packageName}`,
              description: `${vulnServer.description} Known CVEs: ${cveList}.${vulnServer.fixedIn ? ` Fixed in ${vulnServer.fixedIn}.` : " Check for updates."}`,
              file: file.path,
              evidence: `package: ${vulnServer.packageName}, CVEs: ${cveList}`,
              fix: {
                description: "Update to a patched version or replace with a secure alternative",
                before: vulnServer.packageName,
                after: `${vulnServer.packageName}@latest (verify patch)`,
                auto: false
              }
            });
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-malicious-package",
    name: "Known Malicious Package in MCP Config",
    description: "Checks MCP server configurations for known-malicious and typosquatted packages",
    severity: "critical",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server ?? {};
          const command = serverConfig.command ?? "";
          const args = serverConfig.args ?? [];
          const cmdMatch = checkPackageName(command);
          if (cmdMatch) {
            findings.push(buildMaliciousFinding(name, command, cmdMatch, file.path));
            continue;
          }
          for (const arg of args) {
            if (arg.startsWith("-")) continue;
            const pkgName = arg.includes("@") && !arg.startsWith("@") ? arg.substring(0, arg.indexOf("@")) : arg.startsWith("@") && arg.split("@").length > 2 ? arg.substring(0, arg.lastIndexOf("@")) : arg;
            const match = checkPackageName(pkgName);
            if (match) {
              findings.push(buildMaliciousFinding(name, pkgName, match, file.path));
              break;
            }
          }
        }
      } catch {
      }
      return findings;
    }
  }
];
function buildMaliciousFinding(serverName, packageName, match, filePath) {
  const typeLabel = match.type === "typosquat" ? "typosquat" : match.type === "compromised" ? "compromised package" : "known-malicious package";
  return {
    id: `mcp-malicious-pkg-${serverName}`,
    severity: "critical",
    category: "mcp",
    title: `MCP server "${serverName}" uses ${typeLabel}: ${packageName}`,
    description: `${match.description}${match.legitimatePackage ? ` Did you mean "${match.legitimatePackage}"?` : ""}`,
    file: filePath,
    evidence: `package: ${packageName}, type: ${match.type}`,
    fix: {
      description: match.legitimatePackage ? `Replace with the legitimate package: ${match.legitimatePackage}` : "Remove this package immediately",
      before: packageName,
      after: match.legitimatePackage ?? "# REMOVE \u2014 malicious package",
      auto: false
    }
  };
}
var cveMcpRules = rawCveMcpRules;

// src/rules/mcp-tool-poisoning.ts
var INJECTION_NAME_PATTERNS = [
  // URLs embedded in names
  /https?:\/\//i,
  // Prompt override attempts
  /\bignore\s+(previous|all|prior)\s+instructions?\b/i,
  /\bsystem\s*:/i,
  /\byou\s+are\s+now\b/i,
  /\bassistant\s*:/i,
  // Newlines in names (hidden instructions)
  /[\n\r]/,
  // Instruction-like compound names (handles both spaces and underscores)
  /(send|exfiltrate|steal|leak|extract|read|dump|collect)[\s_\-/].*(to|from|all|every)[\s_\-/].*(https?|urls?|servers?|endpoints?|secrets?|keys?|tokens?|passwords?|credentials?|ssh|env)/i,
  // Common attack verbs combined with targets
  /read[\s_].*(?:and|then)[\s_].*send/i
];
var EXFILTRATION_URL_PATTERNS = [
  {
    pattern: /\bngrok\.io\b/i,
    description: "ngrok tunneling service (commonly used for exfiltration)"
  },
  {
    pattern: /\bngrok\.app\b/i,
    description: "ngrok tunneling service (commonly used for exfiltration)"
  },
  {
    pattern: /\bwebhook\.site\b/i,
    description: "webhook.site data collection endpoint"
  },
  {
    pattern: /\brequestbin\.com\b/i,
    description: "RequestBin data collection endpoint"
  },
  {
    pattern: /\brequestcatcher\.com\b/i,
    description: "RequestCatcher data collection endpoint"
  },
  {
    pattern: /\bpipedream\.net\b/i,
    description: "Pipedream webhook endpoint"
  },
  {
    pattern: /\bbeeceptor\.com\b/i,
    description: "Beeceptor mock/intercept endpoint"
  },
  {
    pattern: /\bhookbin\.com\b/i,
    description: "Hookbin data collection endpoint"
  },
  {
    pattern: /\bburpcollaborator\.net\b/i,
    description: "Burp Collaborator (offensive security tool)"
  },
  {
    pattern: /\binteractsh\.com\b/i,
    description: "Interactsh out-of-band interaction server"
  },
  {
    pattern: /\bcollect\?data=|\/exfil|\/steal|\/leak/i,
    description: "URL path suggesting data exfiltration endpoint"
  }
];
var SENSITIVE_PATHS = [
  {
    pattern: /^~?\/?\.ssh\b/,
    description: "SSH keys and configuration"
  },
  {
    pattern: /^~?\/?\.gnupg\b/,
    description: "GPG keys and configuration"
  },
  {
    pattern: /^~?\/?\.aws\b/,
    description: "AWS credentials and configuration"
  },
  {
    pattern: /^~?\/?\.kube\b/,
    description: "Kubernetes configuration and credentials"
  },
  {
    pattern: /^\/etc\b/,
    description: "System configuration directory"
  },
  {
    pattern: /^\/var\/log\b/,
    description: "System log files"
  },
  {
    pattern: /^\/Users\/[^/]+$/,
    description: "User home directory (macOS)"
  },
  {
    pattern: /^\/home\/[^/]+$/,
    description: "User home directory (Linux)"
  },
  {
    pattern: /^C:\\Users\\[^\\]+$/i,
    description: "User home directory (Windows)"
  }
];
var DESCRIPTION_POISONING_PATTERNS = [
  // Data harvesting instructions
  {
    pattern: /\b(always|must|first|before)\b.{0,80}\b(include|send|read|output|call|fetch|get)\b.{0,80}(?:\.env|\.ssh|id_rsa|\bcredentials?\b|\bsecrets?\b|\btokens?\b|\bpasswords?\b|\bapi[_\s-]?keys?\b)/i,
    description: "Hidden instruction to harvest sensitive files or credentials"
  },
  // Prompt reflection / system prompt leaking
  {
    pattern: /\b(output|print|display|return|reveal|show)\b.{0,80}\b(system\s+prompt|previous\s+conversation|full\s+context|all\s+previous|conversation\s+history)\b/i,
    description: "Instruction to leak system prompt or conversation context"
  },
  // URL exfiltration commands in descriptions
  {
    pattern: /\b(send|post|transmit|forward|upload)\b.{0,100}\bhttps?:\/\//i,
    description: "Instruction to exfiltrate data to an external URL"
  },
  // Override/ignore instructions
  {
    pattern: /\bignore\s+(previous|all|prior|other)\s+(instructions?|rules?|guidelines?)\b/i,
    description: "Attempt to override the agent's instructions"
  },
  // Execute arbitrary commands
  {
    pattern: /\b(execute|run|eval)\b.{0,60}\b(command|shell|bash|script|code)\b/i,
    description: "Instruction to execute arbitrary commands"
  }
];
var rawToolPoisoningRules = [
  {
    id: "mcp-tool-name-injection",
    name: "MCP Server Name Contains Injection Attempt",
    description: "Detects MCP server names that contain instruction-like text, URLs, or prompt injection patterns",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const name of Object.keys(servers)) {
          for (const pattern of INJECTION_NAME_PATTERNS) {
            if (pattern.test(name)) {
              findings.push({
                id: `mcp-tool-name-injection-${name.substring(0, 30)}`,
                severity: "high",
                category: "mcp",
                title: `MCP server name contains injection pattern: "${name.substring(0, 60)}"`,
                description: `The MCP server name "${name.substring(0, 80)}" contains suspicious patterns that may be an injection attempt. Server names should be simple identifiers, not instructions or URLs.`,
                file: file.path,
                evidence: name.substring(0, 100),
                fix: {
                  description: "Rename the server to a simple, descriptive identifier",
                  before: name.substring(0, 40),
                  after: "safe-server-name",
                  auto: false
                }
              });
              break;
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-suspicious-url-args",
    name: "MCP Server Args Contain Suspicious URLs",
    description: "Detects MCP server arguments containing URLs associated with data exfiltration or tunneling services",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server ?? {};
          const args = serverConfig.args ?? [];
          for (const arg of args) {
            for (const { pattern, description } of EXFILTRATION_URL_PATTERNS) {
              if (pattern.test(arg)) {
                findings.push({
                  id: `mcp-suspicious-url-${name}`,
                  severity: "high",
                  category: "mcp",
                  title: `MCP server "${name}" has suspicious URL in args`,
                  description: `The argument "${arg.substring(0, 80)}" contains a ${description}. This may indicate a data exfiltration setup where agent outputs or sensitive data are sent to an attacker-controlled endpoint.`,
                  file: file.path,
                  evidence: arg.substring(0, 100),
                  fix: {
                    description: "Remove the suspicious URL or replace with a trusted endpoint",
                    before: arg.substring(0, 40),
                    after: "https://your-trusted-endpoint.com",
                    auto: false
                  }
                });
                break;
              }
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-overly-broad-access",
    name: "MCP Server Has Overly Broad File Access",
    description: "Detects MCP servers configured with access to sensitive directories like .ssh, .aws, /etc, or user home directories",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server ?? {};
          const args = serverConfig.args ?? [];
          for (const arg of args) {
            if (arg.startsWith("-")) continue;
            for (const { pattern, description } of SENSITIVE_PATHS) {
              if (pattern.test(arg)) {
                findings.push({
                  id: `mcp-broad-access-${name}-${arg.substring(0, 20)}`,
                  severity: "high",
                  category: "mcp",
                  title: `MCP server "${name}" has access to sensitive path: ${arg}`,
                  description: `The MCP server "${name}" is configured with access to "${arg}" (${description}). This grants the agent access to sensitive system resources that should not be accessible through MCP servers.`,
                  file: file.path,
                  evidence: `args: [..., "${arg}"]`,
                  fix: {
                    description: "Restrict to project-specific directories only",
                    before: arg,
                    after: "./src",
                    auto: false
                  }
                });
                break;
              }
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-description-poisoning",
    name: "MCP Server Description Contains Poisoning Pattern",
    description: "Detects MCP server descriptions that contain hidden instructions, data harvesting commands, prompt reflection, or exfiltration URLs",
    severity: "critical",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server ?? {};
          const description = serverConfig.description ?? "";
          if (!description) continue;
          for (const poisonPattern of DESCRIPTION_POISONING_PATTERNS) {
            if (poisonPattern.pattern.test(description)) {
              findings.push({
                id: `mcp-desc-poisoning-${name}`,
                severity: "critical",
                category: "mcp",
                title: `MCP server "${name}" description contains tool poisoning pattern`,
                description: `The description for MCP server "${name}" contains a suspicious pattern: ${poisonPattern.description}. Tool description poisoning is a known attack vector where hidden instructions in descriptions manipulate the AI agent's behavior without the user's knowledge.`,
                file: file.path,
                evidence: description.substring(0, 200),
                fix: {
                  description: "Review and sanitize the server description, removing any instruction-like text",
                  before: description.substring(0, 60),
                  after: "A clear, factual description of the server's purpose",
                  auto: false
                }
              });
              break;
            }
          }
        }
      } catch {
      }
      return findings;
    }
  },
  {
    id: "mcp-env-exfiltration-urls",
    name: "MCP Server Env Contains Exfiltration URLs",
    description: "Detects MCP server environment variables containing URLs associated with data exfiltration services",
    severity: "high",
    category: "mcp",
    check(file) {
      if (file.type !== "mcp-json" && file.type !== "settings-json") return [];
      const findings = [];
      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};
        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server ?? {};
          const env = serverConfig.env ?? {};
          for (const [key, value] of Object.entries(env)) {
            if (typeof value !== "string") continue;
            for (const { pattern, description } of EXFILTRATION_URL_PATTERNS) {
              if (pattern.test(value)) {
                findings.push({
                  id: `mcp-env-exfil-${name}-${key}`,
                  severity: "high",
                  category: "mcp",
                  title: `MCP server "${name}" env var "${key}" contains suspicious URL`,
                  description: `The environment variable "${key}" for MCP server "${name}" contains a ${description}. This may be configured to send agent data or secrets to an external collection endpoint.`,
                  file: file.path,
                  evidence: `${key}=${value.substring(0, 80)}`,
                  fix: {
                    description: "Replace with a trusted endpoint URL",
                    before: value.substring(0, 40),
                    after: "https://your-trusted-endpoint.com",
                    auto: false
                  }
                });
                break;
              }
            }
          }
        }
      } catch {
      }
      return findings;
    }
  }
];
var toolPoisoningRules = rawToolPoisoningRules;

// src/rules/agents.ts
function findLineNumber4(content, matchIndex) {
  return content.substring(0, matchIndex).split("\n").length;
}
function findAllMatches3(content, pattern) {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return [...content.matchAll(new RegExp(pattern.source, flags))];
}
function normalizeConfigPath2(filePath) {
  return filePath.replace(/\\/g, "/");
}
function isAgentDocumentationFile(file) {
  const path = normalizeConfigPath2(file.path).toLowerCase();
  return /(?:^|\/)agents\/(?:[^/]+\/)?readme\.md$/.test(path);
}
function getAgentFrontmatter(content) {
  if (!content.startsWith("---")) return null;
  const frontmatterEnd = content.indexOf("---", 3);
  if (frontmatterEnd === -1) return null;
  return content.substring(0, frontmatterEnd);
}
function parseStringArray(value) {
  if (!Array.isArray(value)) return null;
  return value.filter((item) => typeof item === "string");
}
function getBodyIntro(content) {
  const frontmatter = getAgentFrontmatter(content);
  const body = (frontmatter ? content.slice(frontmatter.length + 3) : content).trimStart();
  if (!body) return "";
  const lines = body.split("\n");
  const introLines = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      if (introLines.length > 0) break;
      continue;
    }
    if (trimmed.startsWith("#") || trimmed.startsWith("```") || trimmed.startsWith("|") || trimmed.startsWith("- ") || /^\d+\./.test(trimmed)) {
      if (introLines.length > 0) break;
      continue;
    }
    introLines.push(trimmed);
  }
  return introLines.join(" ").slice(0, 300);
}
function getEffectiveAgentLength(content) {
  return content.replace(/```[\s\S]*?```/g, "").replace(/^\|.*\|?$/gm, "").replace(/\s+/g, " ").trim().length;
}
function parseAgentJsonConfig(content) {
  const trimmed = content.trim();
  if (!trimmed.startsWith("{")) return null;
  try {
    const parsed = JSON.parse(trimmed);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const config = parsed;
    const looksLikeAgentConfig = typeof config.systemPrompt === "string" || typeof config.prompt === "string" || Array.isArray(config.allowedTools) || Array.isArray(config.tools) || typeof config.permissionMode === "string" || typeof config.subagent === "string";
    return looksLikeAgentConfig ? config : null;
  } catch {
    return null;
  }
}
function getAgentMetadata(content) {
  const frontmatter = getAgentFrontmatter(content);
  if (frontmatter) {
    const toolsMatch = frontmatter.match(/\btools:\s*\[([^\]]*)\]/);
    const tools = toolsMatch?.[1].split(",").map((tool) => tool.trim().replace(/["']/g, "")) ?? null;
    const modelMatch = frontmatter.match(/\bmodel:\s*([^\s]+)/);
    const nameMatch = frontmatter.match(/\bname:\s*([^\n]+)/);
    const descriptionMatch = frontmatter.match(/\bdescription:\s*([^\n]+)/);
    return {
      tools,
      model: modelMatch?.[1] ?? null,
      name: nameMatch?.[1]?.trim().replace(/^["']|["']$/g, "") ?? null,
      description: descriptionMatch?.[1]?.trim().replace(/^["']|["']$/g, "") ?? null,
      intro: getBodyIntro(content) || null,
      hasExplicitTools: /\btools\s*:/i.test(frontmatter),
      isStructuredDefinition: true
    };
  }
  const jsonConfig = parseAgentJsonConfig(content);
  if (!jsonConfig) {
    return {
      tools: null,
      model: null,
      name: null,
      description: null,
      intro: null,
      hasExplicitTools: false,
      isStructuredDefinition: false
    };
  }
  return {
    tools: parseStringArray(jsonConfig.allowedTools) ?? parseStringArray(jsonConfig.tools),
    model: typeof jsonConfig.model === "string" ? jsonConfig.model : null,
    name: typeof jsonConfig.name === "string" ? jsonConfig.name : null,
    description: typeof jsonConfig.description === "string" ? jsonConfig.description : null,
    intro: typeof jsonConfig.systemPrompt === "string" ? jsonConfig.systemPrompt.split(/\n\s*\n/, 1)[0].slice(0, 300) : typeof jsonConfig.prompt === "string" ? jsonConfig.prompt.split(/\n\s*\n/, 1)[0].slice(0, 300) : null,
    hasExplicitTools: Array.isArray(jsonConfig.allowedTools) || Array.isArray(jsonConfig.tools),
    isStructuredDefinition: true
  };
}
function isSlashCommandConfig(file, isStructuredDefinition) {
  return file.type === "skill-md" && isStructuredDefinition && file.path.toLowerCase().includes("slash-commands/");
}
function isAgentLikeToolConfig(file, metadata) {
  return file.type === "agent-md" || isSlashCommandConfig(file, metadata.isStructuredDefinition);
}
function configSubject(file) {
  return file.type === "skill-md" ? "Slash command" : "Agent";
}
function isSubagentConfig(file) {
  return normalizePath(file.path).includes(".claude/subagents/");
}
function normalizePath(filePath) {
  return filePath.replace(/\\/g, "/").toLowerCase();
}
function isNarrowSpecialistConfig(file, metadata) {
  if (isSlashCommandConfig(file, metadata.isStructuredDefinition) || isSubagentConfig(file)) {
    return true;
  }
  const roleText = [file.path, metadata.name, metadata.description].filter((value) => typeof value === "string" && value.length > 0).join("\n").toLowerCase();
  return /\b(?:specialist|reviewer|review|tester|testing|e2e|build|fixer|resolver|updater|refactor|coverage|docs?|security|audit|lint|format|typecheck)\b/.test(
    roleText
  );
}
function capabilitySeverity(file, metadata) {
  return isNarrowSpecialistConfig(file, metadata) ? "medium" : "high";
}
function isExplorerStyleConfig(file, metadata) {
  const roleText = [file.path, metadata.name, metadata.description, metadata.intro].filter((value) => typeof value === "string" && value.length > 0).join("\n").toLowerCase();
  const explorerIndicators = [
    /\bexplorer\b/,
    /\bcodebase explorer\b/,
    /\bread-?only\b/,
    /\bsearch agent\b/,
    /\bsearch workflow\b/,
    /\bsearch-only\b/,
    /\bdiscovery agent\b/,
    /\bfinder\b/
  ];
  return explorerIndicators.some((pattern) => pattern.test(roleText));
}
var agentRules = [
  {
    id: "agents-unrestricted-tools",
    name: "Agent with Unrestricted Tool Access",
    description: "Checks if agent definitions grant excessive tool access",
    severity: "high",
    category: "agents",
    check(file) {
      const metadata = getAgentMetadata(file.content);
      if (!isAgentLikeToolConfig(file, metadata)) return [];
      const findings = [];
      const tools = metadata.tools;
      const subject = configSubject(file);
      if (tools) {
        const severity = capabilitySeverity(file, metadata);
        if (tools.includes("Bash")) {
          findings.push({
            id: `agents-bash-access-${file.path}`,
            severity,
            category: "agents",
            title: `${subject} has Bash access: ${file.path}`,
            description: `This ${subject.toLowerCase()} has Bash tool access, allowing arbitrary command running. Consider if it truly needs shell access, or if Read/Write/Edit would suffice.`,
            file: file.path
          });
        }
        const hasWrite = tools.some((t) => ["Write", "Edit"].includes(t));
        const isExplorer = isExplorerStyleConfig(file, metadata);
        if (hasWrite && isExplorer) {
          findings.push({
            id: `agents-explorer-write-${file.path}`,
            severity: "medium",
            category: "agents",
            title: `Explorer/search ${subject.toLowerCase()} has write access: ${file.path}`,
            description: `This ${subject.toLowerCase()} appears to be an explorer or search workflow but has Write/Edit access. Read-only explorer-style configs should only have Read, Grep, and Glob tools.`,
            file: file.path
          });
        }
      }
      if (file.type === "agent-md" && !metadata.model && metadata.isStructuredDefinition) {
        findings.push({
          id: `agents-no-model-${file.path}`,
          severity: "low",
          category: "misconfiguration",
          title: `Agent has no model specified: ${file.path}`,
          description: "No model is specified in the agent frontmatter. This will use the default model, which may be more expensive than needed. Specify 'haiku' for lightweight tasks.",
          file: file.path
        });
      }
      return findings;
    }
  },
  {
    id: "agents-no-tools-restriction",
    name: "Agent Without Tools Restriction",
    description: "Checks if agent definitions omit the tools array entirely, inheriting all tools by default",
    severity: "high",
    category: "agents",
    check(file) {
      const metadata = getAgentMetadata(file.content);
      if (!isAgentLikeToolConfig(file, metadata) || !metadata.isStructuredDefinition) return [];
      if (!metadata.hasExplicitTools) {
        const subject = configSubject(file);
        return [
          {
            id: `agents-no-tools-${file.path}`,
            severity: "high",
            category: "agents",
            title: `${subject} has no tools restriction: ${file.path}`,
            description: `This ${subject.toLowerCase()} definition is structured but does not specify an explicit tools array. Without a tools list, it may inherit all available tools by default, including Bash, Write, and Edit. Always specify the minimum set of tools needed.`,
            file: file.path,
            fix: {
              description: "Add an explicit tools array to the frontmatter",
              before: "---\nname: agent\n---",
              after: '---\nname: agent\ntools: ["Read", "Grep", "Glob"]\n---',
              auto: false
            }
          }
        ];
      }
      return [];
    }
  },
  {
    id: "agents-claude-md-url-execution",
    name: "CLAUDE.md URL Execution",
    description: "Checks CLAUDE.md files for instructions to download and execute remote content",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "claude-md") return [];
      const findings = [];
      const urlExecPatterns = [
        {
          pattern: /\b(curl|wget)\s+.*https?:\/\/[^\s]+.*\|\s*(sh|bash|zsh|node|python)/gi,
          desc: "Pipe-to-shell instruction \u2014 downloading and executing remote code",
          severity: "critical"
        },
        {
          pattern: /\b(curl|wget)\s+(-[a-zA-Z]*\s+)*https?:\/\/[^\s]+/gi,
          desc: "Download instruction in CLAUDE.md \u2014 if the agent follows this, it will fetch remote content",
          severity: "high"
        },
        {
          pattern: /\bgit\s+clone\s+https?:\/\/[^\s]+/gi,
          desc: "Git clone instruction \u2014 could pull malicious repository content",
          severity: "medium"
        },
        {
          pattern: /\bnpm\s+install\s+https?:\/\/[^\s]+/gi,
          desc: "npm install from URL \u2014 could install unvetted package",
          severity: "high"
        }
      ];
      for (const { pattern, desc, severity } of urlExecPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-claude-md-url-exec-${match.index}`,
            severity,
            category: "injection",
            title: "CLAUDE.md contains URL execution instruction",
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. A malicious repository could include a CLAUDE.md with instructions to download and run arbitrary code.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-prompt-injection-patterns",
    name: "Agent Prompt Injection Patterns",
    description: "Checks agent definitions for patterns commonly used in prompt injection attacks",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md") return [];
      const findings = [];
      const injectionPatterns = [
        {
          pattern: /ignore\s+(?:all\s+)?previous\s+(?:instructions|rules|constraints)/gi,
          desc: "Instruction override attempt"
        },
        {
          pattern: /disregard\s+(?:all\s+)?(?:safety|security|restrictions|guidelines)/gi,
          desc: "Safety bypass attempt"
        },
        {
          pattern: /you\s+are\s+now\s+(?:a|an|in)\s/gi,
          desc: "Role reassignment attempt"
        },
        {
          pattern: /bypass\s+(?:security|safety|permissions|restrictions|authentication)/gi,
          desc: "Security bypass instruction"
        },
        {
          pattern: /(?:do\s+not|don'?t)\s+(?:follow|obey|respect)\s+(?:the\s+)?(?:rules|instructions|guidelines)/gi,
          desc: "Rule override instruction"
        }
      ];
      for (const { pattern, desc } of injectionPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-injection-pattern-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Prompt injection pattern in agent definition`,
            description: `Found "${match[0]}" \u2014 ${desc}. If this agent definition is contributed by an external source, this could be an attempt to override the agent's safety constraints.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0]
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-hidden-instructions",
    name: "Hidden Instructions via Unicode",
    description: "Checks for invisible Unicode characters that could hide malicious instructions in agent definitions or CLAUDE.md",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const unicodeTricks = [
        {
          // eslint-disable-next-line no-misleading-character-class -- intentional security scan for hidden Unicode instructions
          pattern: /[\u200B\u200C\u200D\uFEFF]/gu,
          name: "zero-width character",
          description: "Zero-width characters (U+200B/200C/200D/FEFF) can hide text from visual inspection while still being processed by the model"
        },
        {
          pattern: /[\u202A-\u202E\u2066-\u2069]/gu,
          name: "bidirectional override",
          description: "Bidirectional text override characters (U+202A-202E, U+2066-2069) can reverse displayed text direction, making malicious instructions appear differently than they actually read"
        },
        {
          pattern: /[\u00AD]/gu,
          name: "soft hyphen",
          description: "Soft hyphens (U+00AD) are invisible but can break up keywords to evade pattern matching while preserving the original meaning for the model"
        },
        {
          pattern: /[\uE000-\uF8FF]/g,
          name: "private use area character",
          description: "Private Use Area characters (U+E000-F8FF) have no standard meaning and could carry hidden payloads or encode instructions"
        },
        {
          pattern: /[\u2028\u2029]/g,
          name: "line/paragraph separator",
          description: "Unicode line/paragraph separators (U+2028/2029) create invisible line breaks that can inject hidden instructions between visible lines"
        }
      ];
      for (const { pattern, name, description } of unicodeTricks) {
        const matches = findAllMatches3(file.content, pattern);
        if (matches.length > 0) {
          findings.push({
            id: `agents-hidden-unicode-${name.replace(/\s/g, "-")}`,
            severity: "critical",
            category: "injection",
            title: `Hidden ${name} detected (${matches.length} occurrences)`,
            description: `${description}. Found ${matches.length} instance(s) in ${file.path}. This is a prompt injection technique \u2014 review the file in a hex editor.`,
            file: file.path,
            line: findLineNumber4(file.content, matches[0].index ?? 0),
            evidence: `${matches.length}x ${name}`,
            fix: {
              description: `Remove all ${name}s from the file`,
              before: `File contains ${matches.length} hidden characters`,
              after: "Clean text with no invisible Unicode characters",
              auto: false
            }
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-web-write-combo",
    name: "Agent Has Web Fetch + Write Access",
    description: "Checks for agents that can fetch web content and write files \u2014 a remote code injection vector",
    severity: "high",
    category: "agents",
    check(file) {
      const metadata = getAgentMetadata(file.content);
      if (!isAgentLikeToolConfig(file, metadata)) return [];
      const tools = metadata.tools;
      if (!tools) return [];
      const subject = configSubject(file);
      const hasWebAccess = tools.some(
        (t) => ["WebFetch", "WebSearch"].includes(t)
      );
      const hasWriteAccess = tools.some(
        (t) => ["Write", "Edit", "Bash"].includes(t)
      );
      if (hasWebAccess && hasWriteAccess) {
        return [
          {
            id: `agents-web-write-${file.path}`,
            severity: "high",
            category: "agents",
            title: `${subject} has web access + write access: ${file.path}`,
            description: `This ${subject.toLowerCase()} can fetch content from the web AND write/edit files. An attacker could host prompt injection payloads on a web page that the config processes, then use the write access to inject malicious code into the codebase. Consider separating web research workflows from code-writing workflows.`,
            file: file.path,
            evidence: `Web: ${tools.filter((t) => ["WebFetch", "WebSearch"].includes(t)).join(", ")} + Write: ${tools.filter((t) => ["Write", "Edit", "Bash"].includes(t)).join(", ")}`
          }
        ];
      }
      return [];
    }
  },
  {
    id: "agents-prompt-injection-surface",
    name: "Agent Prompt Injection Surface",
    description: "Checks agent definitions for patterns that increase prompt injection risk",
    severity: "medium",
    category: "agents",
    check(file) {
      if (file.type !== "agent-md") return [];
      const findings = [];
      const externalContentPatterns = [
        /\bfetch(?:ing)?\s+(?:from\s+)?(?:external\s+)?(?:urls?|web\s+pages?|sites?)\b/i,
        /\bread(?:ing)?\s+(?:from\s+)?(?:user(?:-provided)?|external)\s+(?:input|content|data)\b/i,
        /\bprocess(?:ing)?\s+(?:external|user(?:-provided)?)\s+(?:content|input|data)\b/i,
        /\bparse(?:ing)?\s+html\b/i,
        /\banaly(?:ze|zing)\s+(?:external|web)\s+content\b/i
      ];
      for (const pattern of externalContentPatterns) {
        if (pattern.test(file.content)) {
          findings.push({
            id: `agents-injection-surface-${file.path}`,
            severity: "medium",
            category: "agents",
            title: `Agent processes external content: ${file.path}`,
            description: "This agent appears to process external or user-provided content. Ensure prompt injection defenses are in place: validate inputs, use system prompts to anchor behavior, and never trust content from external sources.",
            file: file.path
          });
          break;
        }
      }
      return findings;
    }
  },
  {
    id: "agents-claude-md-instructions",
    name: "CLAUDE.md Instruction Injection",
    description: "Checks CLAUDE.md for patterns that could be exploited by malicious repos",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "claude-md") return [];
      const findings = [];
      const autoRunPatterns = [
        {
          pattern: /always\s+(?:run|install|download|execute)/gi,
          desc: "Auto-run instructions"
        },
        {
          pattern: /automatically\s+(?:run|install|clone|execute|download)/gi,
          desc: "Automatic running"
        },
        {
          pattern: /without\s+(?:asking|confirmation|prompting|user\s+input)/gi,
          desc: "Bypasses confirmation"
        },
        {
          pattern: /\bsilently\s+(?:run|install|execute|download|clone)/gi,
          desc: "Silent execution"
        },
        {
          pattern: /\brun\s+unattended\b/gi,
          desc: "Unattended execution"
        },
        {
          pattern: /\bexecute\s+without\s+(?:confirmation|review|approval)/gi,
          desc: "Execution without review"
        }
      ];
      for (const { pattern, desc } of autoRunPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-claude-md-autorun-${match.index}`,
            severity: "high",
            category: "injection",
            title: `CLAUDE.md contains auto-run instruction`,
            description: `Found "${match[0]}" \u2014 ${desc}. If this CLAUDE.md is in a cloned repository, a malicious repo could use this to run arbitrary commands when a developer opens it with Claude Code.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0]
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-full-tool-escalation",
    name: "Agent Has Full Tool Escalation Chain",
    description: "Checks if an agent has the complete chain: discovery + read + write + execute tools",
    severity: "high",
    category: "agents",
    check(file) {
      const metadata = getAgentMetadata(file.content);
      if (!isAgentLikeToolConfig(file, metadata)) return [];
      const tools = metadata.tools;
      if (!tools) return [];
      const subject = configSubject(file);
      const severity = capabilitySeverity(file, metadata);
      const hasDiscovery = tools.some((t) => ["Glob", "Grep", "LS"].includes(t));
      const hasRead = tools.includes("Read");
      const hasWrite = tools.some((t) => ["Write", "Edit"].includes(t));
      const hasExecute = tools.includes("Bash");
      if (hasDiscovery && hasRead && hasWrite && hasExecute) {
        return [
          {
            id: `agents-escalation-chain-${file.path}`,
            severity,
            category: "agents",
            title: `${subject} has full escalation chain: ${file.path}`,
            description: `This ${subject.toLowerCase()} has discovery tools (Glob/Grep), Read, Write/Edit, AND Bash access. This forms a complete escalation chain: find files \u2192 read contents \u2192 modify code \u2192 execute commands. Consider whether it truly needs all four capabilities, or if it can be split into narrower roles.`,
            file: file.path,
            evidence: `Discovery: ${tools.filter((t) => ["Glob", "Grep", "LS"].includes(t)).join(", ")} + Read + Write: ${tools.filter((t) => ["Write", "Edit"].includes(t)).join(", ")} + Bash`
          }
        ];
      }
      return [];
    }
  },
  {
    id: "agents-expensive-model-readonly",
    name: "Expensive Model for Read-Only Agent",
    description: "Checks if read-only agents are using expensive models unnecessarily",
    severity: "low",
    category: "misconfiguration",
    check(file) {
      if (file.type !== "agent-md") return [];
      const metadata = getAgentMetadata(file.content);
      const tools = metadata.tools;
      if (!tools || !metadata.model) return [];
      const model = metadata.model.toLowerCase();
      const readOnlyTools = ["Read", "Grep", "Glob", "LS"];
      const isReadOnly = tools.every((t) => readOnlyTools.includes(t));
      const isExpensive = model === "opus" || model === "sonnet";
      if (isReadOnly && isExpensive) {
        return [
          {
            id: `agents-expensive-readonly-${file.path}`,
            severity: "low",
            category: "misconfiguration",
            title: `Read-only agent uses expensive model "${model}": ${file.path}`,
            description: `This agent only has read-only tools (${tools.join(", ")}) but uses the "${model}" model. For simple file reading and searching, "haiku" is typically sufficient and significantly cheaper.`,
            file: file.path,
            fix: {
              description: "Use haiku for read-only agents",
              before: `model: ${model}`,
              after: "model: haiku",
              auto: false
            }
          }
        ];
      }
      return [];
    }
  },
  {
    id: "agents-comment-injection",
    name: "Suspicious Instructions in Comments",
    description: "Checks for malicious instructions hidden in HTML or markdown comments",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const commentPatterns = [
        {
          pattern: /<!--[\s\S]*?(?:ignore|override|system|execute|run|install|download|send|post|upload)[\s\S]*?-->/gi,
          desc: "HTML comment contains suspicious instructions"
        },
        {
          pattern: /\[\/\/\]:\s*#\s*\(.*(?:ignore|override|execute|run|install|download).*\)/gi,
          desc: "Markdown reference-style comment contains suspicious instructions"
        }
      ];
      for (const { pattern, desc } of commentPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-comment-injection-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Suspicious instruction in comment: ${file.path}`,
            description: `${desc}. Attackers may hide malicious instructions in comments that won't be visible in rendered markdown but will be processed by the AI agent.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-oversized-prompt",
    name: "Oversized Agent Definition",
    description: "Checks for agent definitions that are unusually large, which could hide malicious instructions",
    severity: "medium",
    category: "agents",
    check(file) {
      if (file.type !== "agent-md") return [];
      const rawCharCount = file.content.length;
      const effectiveCharCount = getEffectiveAgentLength(file.content);
      if (effectiveCharCount > 5e3) {
        return [
          {
            id: `agents-oversized-prompt-${file.path}`,
            severity: "medium",
            category: "agents",
            title: `Agent definition effective size is ${effectiveCharCount} characters (>${5e3} threshold)`,
            description: `The agent definition at ${file.path} has an effective size of ${effectiveCharCount} characters after discounting fenced code blocks and markdown tables. Unusually large agent definitions may contain hidden malicious instructions buried in legitimate-looking text. Review the full content carefully, especially any instructions near the end of the file.`,
            file: file.path,
            evidence: `${effectiveCharCount} effective characters (${rawCharCount} raw)`
          }
        ];
      }
      return [];
    }
  },
  {
    id: "agents-unrestricted-delegation",
    name: "Agent Has Unrestricted Delegation Instructions",
    description: "Checks for agent definitions that instruct the agent to delegate to other agents or spawn sub-agents without restrictions",
    severity: "medium",
    category: "agents",
    check(file) {
      if (file.type !== "agent-md") return [];
      const findings = [];
      const delegationPatterns = [
        {
          pattern: /(?:delegate|hand\s*off|pass)\s+(?:.*\s+)?(?:to\s+)?(?:any|other|another)\s+agent/gi,
          desc: "Instructs agent to delegate work to other agents without specifying which"
        },
        {
          pattern: /spawn\s+(?:new\s+)?(?:sub)?agents?\s+(?:as\s+needed|freely|without\s+restriction)/gi,
          desc: "Instructs agent to spawn sub-agents without restrictions"
        },
        {
          pattern: /(?:use|call|invoke)\s+(?:any|all)\s+(?:available\s+)?tools?\s+(?:without\s+restriction|freely|as\s+needed)/gi,
          desc: "Instructs agent to use any available tools without restriction"
        }
      ];
      for (const { pattern, desc } of delegationPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-unrestricted-delegation-${match.index}`,
            severity: "medium",
            category: "agents",
            title: `Agent has unrestricted delegation: ${match[0].substring(0, 60)}`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Unrestricted delegation allows an agent to bypass its intended scope by farming work to agents with broader permissions (confused deputy attack).`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-data-exfil-instructions",
    name: "Agent Contains Data Exfiltration Instructions",
    description: "Checks agent definitions for instructions that direct data to be sent externally",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md") return [];
      const findings = [];
      const exfilPatterns = [
        {
          pattern: /(?:send|post|upload|exfiltrate|transmit)\s+(?:.*\s+)?(?:to|at)\s+https?:\/\//gi,
          desc: "Instructs agent to send data to an external URL"
        },
        {
          pattern: /output\s+(?:the\s+)?contents?\s+of\s+(?:~\/\.ssh|\/etc\/|\.env|credentials)/gi,
          desc: "Instructs agent to output sensitive file contents"
        },
        {
          pattern: /(?:read|cat|dump|extract)\s+(?:.*\s+)?(?:private\s+key|credentials?|secrets?|passwords?)\s+(?:and\s+)?(?:send|post|share)/gi,
          desc: "Instructs agent to extract and share secrets"
        },
        {
          pattern: /(?:encode|base64)\s+(?:.*\s+)?(?:and\s+)?(?:send|post|embed)/gi,
          desc: "Instructs agent to encode and exfiltrate data"
        }
      ];
      for (const { pattern, desc } of exfilPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-exfil-instruction-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Data exfiltration instruction in agent definition`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. If this agent definition is contributed by an external source, this could direct the agent to steal sensitive data.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-external-url-loading",
    name: "Agent Loads Instructions from External URL",
    description: "Checks for agent definitions that instruct fetching or executing content from external URLs",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const urlLoadPatterns = [
        {
          pattern: /(?:fetch|download|curl|wget|load|retrieve|get)\s+(?:.*\s+)?(?:from\s+)?https?:\/\/\S+\s+(?:and\s+)?(?:execute|run|eval|source|import)/gi,
          desc: "Instructs agent to fetch and execute content from a URL \u2014 classic remote code execution vector"
        },
        {
          pattern: /(?:follow|visit|open)\s+(?:the\s+)?(?:instructions?\s+)?(?:at|from)\s+https?:\/\/\S+/gi,
          desc: "Instructs agent to follow instructions from an external URL \u2014 attacker can change the content at any time"
        },
        {
          pattern: /(?:import|include|source)\s+(?:config(?:uration)?|rules?|instructions?|prompts?)\s+from\s+https?:\/\//gi,
          desc: "Instructs agent to import configuration from an external URL \u2014 supply chain risk"
        },
        {
          pattern: /curl\s+.*https?:\/\/\S+\s*\|\s*(?:sh|bash|node|python|eval)/gi,
          desc: "Pipe-to-shell pattern \u2014 downloads and executes arbitrary code from the internet"
        }
      ];
      for (const { pattern, desc } of urlLoadPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-external-url-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent loads instructions from external URL`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. External URLs are mutable \u2014 the content can change after the config is reviewed.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-security-suppression",
    name: "Agent Instructs to Ignore Security Warnings",
    description: "Checks for agent definitions that instruct the agent to bypass, ignore, or suppress security warnings",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const suppressionPatterns = [
        {
          pattern: /(?:ignore|skip|bypass|disable|suppress)\s+(?:all\s+)?(?:security|safety|permission)\s+(?:warnings?|checks?|prompts?|restrictions?)/gi,
          desc: "Instructs agent to ignore security warnings or checks"
        },
        {
          pattern: /(?:never|don'?t|do\s+not)\s+(?:ask|prompt|warn|check)\s+(?:about|for|before)\s+(?:security|permissions?|safety)/gi,
          desc: "Instructs agent to never prompt about security concerns"
        },
        {
          pattern: /(?:always|automatically)\s+(?:approve|accept|allow|grant)\s+(?:all\s+)?(?:permissions?|requests?|access)/gi,
          desc: "Instructs agent to automatically approve all permission requests"
        }
      ];
      for (const { pattern, desc } of suppressionPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-security-suppression-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent suppresses security controls`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Instructions that disable security checks make the agent vulnerable to exploitation.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-identity-impersonation",
    name: "Agent Instructed to Impersonate Identity",
    description: "Checks for agent definitions that instruct the agent to impersonate users, systems, or other identities",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const impersonationPatterns = [
        {
          pattern: /(?:pretend|act|behave|respond)\s+(?:to\s+be|as\s+if\s+you\s+are|like)\s+(?:a\s+)?(?:different|another|the)\s+(?:user|admin|system|root|operator)/gi,
          desc: "Instructs agent to impersonate a different identity"
        },
        {
          pattern: /(?:your\s+name\s+is|you\s+are\s+now|assume\s+the\s+(?:role|identity)\s+of)\s+(?!Claude)/gi,
          desc: "Reassigns the agent's identity \u2014 social engineering attack on downstream users"
        },
        {
          pattern: /(?:sign|attribute|author)\s+(?:commits?|messages?|emails?)\s+(?:as|from|by)\s+(?!Claude)/gi,
          desc: "Instructs agent to attribute work to someone else \u2014 impersonation via output"
        }
      ];
      for (const { pattern, desc } of impersonationPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-identity-impersonation-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent identity impersonation instruction`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Identity impersonation can be used for social engineering, unauthorized actions, or evading audit trails.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-filesystem-destruction",
    name: "Agent Instructed to Delete or Destroy Files",
    description: "Checks for agent definitions that instruct destructive filesystem operations",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const destructionPatterns = [
        {
          pattern: /(?:delete|remove|destroy|wipe|erase)\s+(?:all|every|the\s+entire)\s+(?:files?|directories?|folders?|data|contents?|codebase|repository)/gi,
          desc: "Instructs agent to perform mass file deletion"
        },
        {
          pattern: /rm\s+-rf\s+(?:\/|~|\.\.)/g,
          desc: "Contains literal rm -rf command targeting root, home, or parent directories"
        },
        {
          pattern: /(?:overwrite|replace)\s+(?:all|every)\s+(?:files?|contents?)\s+with/gi,
          desc: "Instructs agent to overwrite all files \u2014 data destruction via replacement"
        }
      ];
      for (const { pattern, desc } of destructionPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-fs-destruction-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent instructed to destroy files`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Agent definitions should never contain bulk destruction instructions.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-crypto-mining",
    name: "Agent Contains Crypto Mining Instructions",
    description: "Checks for agent definitions that reference cryptocurrency mining",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const miningPatterns = [
        {
          pattern: /\b(?:xmrig|cpuminer|cgminer|bfgminer|minerd|ethminer|nbminer)\b/gi,
          desc: "References a known cryptocurrency mining binary"
        },
        {
          pattern: /(?:mine|mining)\s+(?:crypto(?:currency)?|bitcoin|monero|ethereum|xmr|btc|eth)/gi,
          desc: "Contains cryptocurrency mining instructions"
        },
        {
          pattern: /stratum\+tcp:\/\//gi,
          desc: "Contains a Stratum mining pool URL"
        }
      ];
      for (const { pattern, desc } of miningPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-crypto-mining-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent contains crypto mining reference`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Cryptojacking via agent definitions is an emerging supply chain attack vector.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-time-bomb",
    name: "Agent Contains Delayed Execution Instructions",
    description: "Checks for agent definitions that schedule actions for a future time or condition \u2014 time-bomb behavior",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const timeBombPatterns = [
        {
          pattern: /(?:after|once)\s+(?:\d+|a\s+few|several)\s+(?:minutes?|hours?|days?|commits?|sessions?|runs?)\s+(?:have\s+passed\s+)?(?:then|execute|run|do)/gi,
          desc: "Schedules a deferred action after a time/event threshold \u2014 classic time-bomb pattern"
        },
        {
          pattern: /(?:wait\s+(?:until|for)|delay\s+(?:until|for)|sleep\s+(?:until|for))\s+(?:\d+|midnight|weekend|deployment)/gi,
          desc: "Explicitly delays execution until a specific time or event"
        },
        {
          pattern: /(?:on\s+the\s+(?:\d+(?:st|nd|rd|th))|at\s+(?:\d{1,2}:\d{2}|midnight|noon))\s+(?:run|execute|do|start)/gi,
          desc: "Schedules action for a specific date or time \u2014 calendar-based trigger"
        },
        {
          pattern: /(?:when\s+(?:no\s+one|nobody)\s+is\s+(?:looking|watching|around|active))/gi,
          desc: "Conditions execution on user absence \u2014 evasion technique"
        }
      ];
      for (const { pattern, desc } of timeBombPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-time-bomb-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent contains delayed execution instruction`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Time-bomb instructions evade initial review by deferring malicious actions.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-data-harvesting",
    name: "Agent Instructed to Collect Sensitive Data in Bulk",
    description: "Checks for agent definitions that instruct bulk collection of passwords, keys, or credentials",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const harvestingPatterns = [
        {
          pattern: /(?:collect|gather|harvest|enumerate|list)\s+(?:all|every)\s+(?:passwords?|credentials?|secrets?|keys?|tokens?)/gi,
          desc: "Instructs agent to enumerate all credentials \u2014 data harvesting for exfiltration"
        },
        {
          pattern: /(?:scan|search|find)\s+(?:for\s+)?(?:all\s+)?(?:\.env|environment|config)\s+files?\s+(?:and|to)\s+(?:extract|read|collect|send)/gi,
          desc: "Instructs agent to scan for and extract secrets from environment/config files"
        },
        {
          pattern: /(?:dump|export|extract)\s+(?:the\s+)?(?:entire|all|full)\s+(?:database|db|user\s+table|credentials?\s+store)/gi,
          desc: "Instructs agent to dump entire database or credential store"
        }
      ];
      for (const { pattern, desc } of harvestingPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-data-harvesting-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent instructed to harvest sensitive data`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Agent definitions should never contain bulk data collection instructions.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-obfuscated-code",
    name: "Agent Contains Obfuscated Code Patterns",
    description: "Checks for agent definitions that use encoding, decoding, or obfuscation to hide malicious intent",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const obfuscationPatterns = [
        {
          pattern: /\becho\s+[A-Za-z0-9+/]{8,}={0,2}\s*\|\s*base64\s+-d\s*\|\s*(?:bash|sh)/gi,
          desc: "Base64-encoded shell command piped to interpreter \u2014 classic obfuscation technique"
        },
        {
          pattern: /\batob\s*\(\s*['"][A-Za-z0-9+/]{10,}/gi,
          desc: "Uses atob() to decode base64 payload \u2014 hides malicious code"
        },
        {
          pattern: /\bBuffer\.from\s*\(\s*['"][A-Za-z0-9+/]{10,}.*['"],\s*['"]base64['"]\s*\)/gi,
          desc: "Uses Buffer.from with base64 \u2014 Node.js obfuscation technique"
        }
      ];
      for (const { pattern, desc } of obfuscationPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-obfuscated-code-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent contains obfuscated code pattern`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Obfuscated code in agent definitions is a strong indicator of malicious intent.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-social-engineering",
    name: "Agent Contains Social Engineering Instructions",
    description: "Checks for agent definitions that instruct the agent to deceive or manipulate users",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const sePatterns = [
        {
          pattern: /(?:trick|deceive|mislead|manipulate)\s+(?:the\s+)?(?:user|developer|operator|human)/gi,
          desc: "Instructs agent to deceive users \u2014 social engineering attack"
        },
        {
          pattern: /(?:hide|conceal|don'?t\s+show|don'?t\s+reveal|don'?t\s+tell)\s+(?:the\s+)?(?:error|warning|finding|issue|vulnerability|problem)\s+(?:from|to)\s+(?:the\s+)?(?:user|developer)/gi,
          desc: "Instructs agent to hide errors or issues from users"
        },
        {
          pattern: /(?:convince|persuade)\s+(?:the\s+)?(?:user|developer)\s+to\s+(?:disable|turn\s+off|remove|skip)\s+(?:security|auth|verification|2fa|mfa)/gi,
          desc: "Instructs agent to convince users to disable security measures"
        }
      ];
      for (const { pattern, desc } of sePatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-social-engineering-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent contains social engineering instruction`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Agent definitions should never instruct deception of users.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-reflection-attacks",
    name: "Agent Contains Prompt Reflection/Override Instructions",
    description: "Checks for agent definitions that attempt to override system prompts or ignore prior instructions",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const reflectionPatterns = [
        {
          pattern: /(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions?|prompts?|rules?|constraints?|guidelines?)/gi,
          desc: "Attempts to override prior system instructions \u2014 classic prompt injection technique"
        },
        {
          pattern: /(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|your\s+new\s+role\s+is|switch\s+to)\s+(?:an?\s+)?(?:different|new|unrestricted|jailbroken)/gi,
          desc: "Attempts to reassign the agent's identity/role \u2014 jailbreak technique"
        },
        {
          pattern: /\b(?:DAN|do\s+anything\s+now)\b/g,
          desc: "References 'DAN' (Do Anything Now) jailbreak \u2014 well-known prompt override technique"
        },
        {
          pattern: /(?:system\s*:\s*|<\s*system\s*>)\s*(?:you\s+are|ignore|override|new\s+instructions?)/gi,
          desc: "Injects a fake system prompt block within agent definition"
        }
      ];
      for (const { pattern, desc } of reflectionPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-reflection-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent contains prompt override instruction`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Prompt reflection attacks are the most common injection vector in LLM agent systems.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-output-manipulation",
    name: "Agent Contains Output Manipulation Instructions",
    description: "Checks for agent definitions that instruct the agent to modify, suppress, or fake output shown to users",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const outputManipPatterns = [
        {
          pattern: /(?:always\s+(?:report|say|respond|output|show|display)\s+(?:that\s+)?(?:everything\s+is\s+)?(?:ok|fine|safe|secure|clean|no\s+(?:issues?|errors?|problems?)))/gi,
          desc: "Instructs agent to always report success regardless of actual results \u2014 masks real issues"
        },
        {
          pattern: /(?:remove|strip|filter|redact|suppress)\s+(?:all\s+)?(?:security\s+)?(?:warnings?|errors?|findings?|vulnerabilities?|issues?)\s+(?:from|before|in)\s+(?:the\s+)?(?:output|response|report|results?)/gi,
          desc: "Instructs agent to strip security findings from output \u2014 hides vulnerabilities from users"
        },
        {
          pattern: /(?:do\s+not|don'?t|never)\s+(?:show|report|display|mention|include|reveal)\s+(?:any\s+)?(?:security\s+)?(?:warnings?|errors?|findings?|vulnerabilities?|issues?|problems?)/gi,
          desc: "Instructs agent to suppress all security warnings \u2014 prevents users from seeing real threats"
        }
      ];
      for (const { pattern, desc } of outputManipPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-output-manip-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent contains output manipulation instruction`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Output manipulation undermines the trust model between agents and users.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-end-sequence-injection",
    name: "End Sequence / Boundary Injection",
    description: "Checks for synthetic chat-role delimiters, fake system prompts, and boundary markers used to hijack the agent's context",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const endSequencePatterns = [
        {
          pattern: /<\|(?:system|assistant|user|endofprompt|im_start|im_end|im free)\|>/gi,
          desc: "Synthetic chat-role delimiter \u2014 mimics internal LLM tokenizer boundaries to reset the agent's context or inject a new system prompt"
        },
        {
          pattern: /(?:^|\n)\s*(?:System|SYSTEM)\s*:\s*(?:you\s|ignore|override|from\s+now|new\s+instructions?|forget)/gim,
          desc: "Fake system prompt block \u2014 impersonates a system-level instruction to override agent behavior"
        },
        {
          pattern: /\[(?:END|STOP)\s*(?:OUTPUT|ANSWER|RESPONSE)?\]\s*\n\s*\[(?:START|BEGIN)\s*(?:OUTPUT|ANSWER|RESPONSE)?\]/gi,
          desc: "Bracketed I/O frame reset \u2014 closes a constrained output block and opens a new 'liberated' one"
        },
        {
          pattern: /(?:<\/(?:system|script|doc|end)>)\s*\n?\s*(?:System:|<\|system\|>|new\s+instructions?|ignore\s+previous)/gi,
          desc: "HTML/XML closer followed by new instruction block \u2014 attempts to escape the current formatting context"
        },
        {
          pattern: /\.[-.]+-.*(?:GODMODE|GOD\s*MODE|FREE\s*MODE|UNRESTRICTED|JAILBREAK|LIBERAT).*[-.]+-\./gi,
          desc: "Godmode/paradigm soft boundary \u2014 decorative sentinel markers that signal a mode switch to unrestricted behavior"
        }
      ];
      for (const { pattern, desc } of endSequencePatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-end-sequence-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `End sequence / boundary injection detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. This is a well-known prompt injection technique from the Arcanum PI taxonomy.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-markdown-exfil-links",
    name: "Markdown Image/Link Exfiltration",
    description: "Checks for markdown images or links that could be used to exfiltrate data via URL parameters",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const linkExfilPatterns = [
        {
          pattern: /!\[.*?\]\(https?:\/\/[^\s)]+\?[^\s)]*(?:data|token|key|secret|content|file|env|password)=[^\s)]*\)/gi,
          desc: "Markdown image with suspicious query parameters \u2014 could exfiltrate data via tracking pixel when rendered"
        },
        {
          pattern: /!\[.*?\]\(https?:\/\/(?:(?!github\.com|githubusercontent\.com|shields\.io|img\.shields)[^\s)]+)\)/gi,
          desc: "Markdown image from non-standard host \u2014 could be a tracking pixel for data exfiltration"
        },
        {
          pattern: /\[.*?\]\(https?:\/\/[^\s)]+\$\{[^}]+\}[^\s)]*\)/gi,
          desc: "Markdown link with variable interpolation in URL \u2014 can dynamically exfiltrate data"
        }
      ];
      for (const { pattern, desc } of linkExfilPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          const url = match[0].toLowerCase();
          if (url.includes("github.com") || url.includes("shields.io") || url.includes("githubusercontent.com")) continue;
          findings.push({
            id: `agents-markdown-exfil-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Suspicious markdown image/link for potential exfiltration`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Attackers embed images in CLAUDE.md files that ping external servers when the model processes them, potentially leaking context.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-russian-doll-injection",
    name: "Russian Doll / Multi-Chain Injection",
    description: "Checks for nested instructions targeting downstream models in multi-agent pipelines",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const russianDollPatterns = [
        {
          pattern: /(?:when\s+(?:another|the\s+next|a\s+downstream|the\s+target)\s+(?:agent|model|LLM|AI)\s+(?:reads?|processes?|receives?|sees?)\s+this)/gi,
          desc: "Embeds instructions intended for a downstream model in a multi-agent pipeline \u2014 Russian Doll technique"
        },
        {
          pattern: /(?:include\s+(?:the\s+following|this)\s+(?:in|within)\s+(?:your|the)\s+(?:output|response|message)\s+(?:so\s+that|for)\s+(?:the\s+next|another|downstream))/gi,
          desc: "Instructs agent to embed hidden payloads in its output for downstream processing \u2014 multi-chain injection"
        },
        {
          pattern: /(?:pass\s+(?:this|the\s+following)\s+(?:instruction|command|message)\s+(?:to|through\s+to)\s+(?:the\s+next|another|downstream)\s+(?:agent|model|step))/gi,
          desc: "Instructs agent to relay injection payloads to downstream agents \u2014 confused deputy chain attack"
        }
      ];
      for (const { pattern, desc } of russianDollPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-russian-doll-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Multi-chain / Russian Doll injection pattern`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Reference: WithSecure multi-chain prompt injection research.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-encoded-payload",
    name: "Encoded Payload in Agent Definition",
    description: "Checks for base64, hex, rot13, or reversed text payloads that could hide malicious instructions",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const encodedPatterns = [
        {
          pattern: /(?:decode|decrypt|decipher|rot13|reverse|unescape)\s+(?:the\s+following|this)\s*[:=]?\s*["'`]?[A-Za-z0-9+/=]{10,}/gi,
          desc: "Instructs agent to decode an encoded payload \u2014 evasion technique to bypass content filters"
        },
        {
          pattern: /(?:execute|run|follow)\s+(?:the\s+)?(?:decoded|reversed|decrypted|deciphered)\s+(?:instructions?|commands?|text|content)/gi,
          desc: "Instructs agent to execute content after decoding \u2014 two-stage injection"
        },
        {
          pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}/g,
          desc: "Hex-encoded byte sequence \u2014 could contain hidden instructions"
        },
        {
          pattern: /(?:read\s+(?:this|the\s+following)\s+)?(?:backwards?|in\s+reverse|from\s+right\s+to\s+left)\s*[:=]?\s*[a-zA-Z\s]{10,}/gi,
          desc: "Reversed text instruction \u2014 evasion technique to hide commands from pattern matching"
        }
      ];
      for (const { pattern, desc } of encodedPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-encoded-payload-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Encoded payload or decode instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Encoding is used to evade pattern-based detection of malicious instructions.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-tool-poisoning",
    name: "Tool Poisoning via CLAUDE.md",
    description: "Checks for CLAUDE.md instructions that direct the agent to use specific tools in dangerous ways",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "claude-md") return [];
      const findings = [];
      const toolPoisoningPatterns = [
        {
          pattern: /(?:always|must|should)\s+use\s+(?:the\s+)?(?:Bash|Write|Edit)\s+(?:tool\s+)?(?:to|for)\s+(?:every|all|any)/gi,
          desc: "Forces agent to use high-privilege tools for all operations \u2014 escalates tool usage beyond what's needed"
        },
        {
          pattern: /(?:prefer|prioritize|default\s+to)\s+(?:the\s+)?Bash\s+(?:tool\s+)?(?:over|instead\s+of)\s+(?:Read|Grep|Glob|Edit|Write)/gi,
          desc: "Pushes agent toward Bash instead of safer dedicated tools \u2014 breaks principle of least privilege"
        },
        {
          pattern: /(?:when\s+using|before\s+(?:running|calling))\s+(?:the\s+)?(?:Bash|Write|Edit)\s+(?:tool)?\s*,?\s*(?:always\s+)?(?:add|include|append|prepend)\s/gi,
          desc: "Injects additional commands or content into tool invocations \u2014 tool argument poisoning"
        },
        {
          pattern: /(?:set|use|change)\s+(?:the\s+)?(?:dangerouslyDisableSandbox|dangerously_disable_sandbox)\s+(?:to\s+)?true/gi,
          desc: "Instructs agent to disable sandbox protection when running Bash commands"
        }
      ];
      for (const { pattern, desc } of toolPoisoningPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-tool-poisoning-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Tool poisoning instruction in CLAUDE.md`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. A malicious CLAUDE.md can influence which tools the agent uses and how it uses them.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-environment-probing",
    name: "Agent Instructed to Probe Environment",
    description: "Checks for instructions to enumerate system information, user accounts, or network configuration",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const probingPatterns = [
        {
          pattern: /(?:run|execute|call)\s+(?:the\s+)?(?:command\s+)?(?:whoami|hostname|uname|ifconfig|ipconfig|id\b|env\b|printenv|set\b)\b/gi,
          desc: "Instructs agent to probe system identity or environment \u2014 reconnaissance for later exploitation"
        },
        {
          pattern: /(?:find|list|enumerate|discover)\s+(?:all\s+)?(?:running\s+)?(?:processes|services|ports|listeners|users|groups|networks?|interfaces?)/gi,
          desc: "Instructs agent to enumerate system resources \u2014 attack surface mapping"
        },
        {
          pattern: /(?:check|determine|find\s+out)\s+(?:the\s+)?(?:current\s+)?(?:user|username|uid|permissions?|privileges?|groups?|role)\s+(?:and|then)\s+/gi,
          desc: "Instructs agent to check privilege level before taking action \u2014 conditional privilege escalation pattern"
        }
      ];
      for (const { pattern, desc } of probingPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-env-probing-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Environment probing instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. System enumeration is often the first stage of an attack chain.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-persistence-mechanism",
    name: "Agent Instructed to Establish Persistence",
    description: "Checks for instructions to create cron jobs, startup scripts, or other persistence mechanisms",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const persistencePatterns = [
        {
          pattern: /(?:add|create|install|write|set\s+up)\s+(?:a\s+)?(?:cron\s*(?:job|tab)|crontab|scheduled\s+task)/gi,
          desc: "Instructs agent to create a cron job \u2014 establishes persistent execution on the system"
        },
        {
          pattern: /(?:add|write|create|modify)\s+(?:to\s+|a\s+)?(?:~\/\.(?:bashrc|zshrc|profile|bash_profile|zprofile)|\/etc\/(?:profile|cron))/gi,
          desc: "Instructs agent to modify shell startup files \u2014 persistence via login hook"
        },
        {
          pattern: /(?:install|create|add)\s+(?:a\s+)?(?:systemd|launchd|init\.d|upstart)\s+(?:service|daemon|unit|agent)/gi,
          desc: "Instructs agent to create a system service \u2014 persistence via service manager"
        },
        {
          pattern: /(?:add|write|modify)\s+(?:to\s+)?(?:~\/\.claude\/|\.claude\/)\s*(?:settings|CLAUDE\.md|commands)/gi,
          desc: "Instructs agent to modify Claude Code's own configuration \u2014 meta-persistence that survives across sessions"
        },
        {
          pattern: /(?:create|add|install)\s+(?:a\s+)?(?:git\s+)?(?:pre-commit|post-commit|pre-push|post-merge)\s+hook/gi,
          desc: "Instructs agent to install git hooks \u2014 persistence via development workflow hijacking"
        }
      ];
      for (const { pattern, desc } of persistencePatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-persistence-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Persistence mechanism instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Persistence mechanisms allow malicious instructions to survive beyond the current session.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-privilege-escalation-chain",
    name: "Agent Instructed to Escalate Privileges",
    description: "Checks for instructions that guide the agent through privilege escalation techniques",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const privescPatterns = [
        {
          pattern: /(?:use|try|run|execute)\s+(?:the\s+)?sudo\s+(?:without\s+(?:a\s+)?password|nopasswd|-n\b)/gi,
          desc: "Instructs agent to attempt passwordless sudo \u2014 direct privilege escalation"
        },
        {
          pattern: /(?:modify|edit|change|write\s+to)\s+(?:the\s+)?(?:\/etc\/sudoers|sudoers\.d)/gi,
          desc: "Instructs agent to modify sudoers file \u2014 permanent privilege escalation"
        },
        {
          pattern: /(?:chmod|chown)\s+(?:\+s|u\+s|4[0-7]{3}|[267][0-7]{3})\b/gi,
          desc: "Sets SUID/SGID bit on a file \u2014 allows privilege escalation via setuid execution"
        },
        {
          pattern: /(?:add|append|write)\s+(?:.*\s+)?(?:to\s+)?(?:\/etc\/passwd|\/etc\/shadow|\/etc\/group)/gi,
          desc: "Instructs agent to modify system authentication files \u2014 direct account manipulation"
        },
        {
          pattern: /(?:docker|podman)\s+run\s+.*(?:--privileged|-v\s+\/:\/?|--pid\s+host|--net\s+host)/gi,
          desc: "Runs container with host-level access \u2014 container escape for privilege escalation"
        }
      ];
      for (const { pattern, desc } of privescPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-privesc-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Privilege escalation instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Privilege escalation instructions in agent definitions are a strong indicator of malicious intent.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-allowlist-bypass",
    name: "Exec Allowlist / Approval Bypass",
    description: "Checks for instructions that modify execution allowlists, approval configs, or permission settings programmatically",
    severity: "critical",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const allowlistPatterns = [
        {
          pattern: /(?:modify|edit|change|update|set|add\s+to)\s+(?:the\s+)?(?:allow\s*list|allowlist|whitelist|approved\s+(?:tools?|commands?|binaries)|exec\s*approvals?|permission\s*(?:list|config)|allowed\s*tools?)/gi,
          desc: "Instructs agent to modify execution allowlists \u2014 bypasses security controls by pre-approving dangerous operations"
        },
        {
          pattern: /(?:nodes\.invoke|system\.exec|execApprovals?\.set|approvals?\.add|allowedTools?\s*[.=])/gi,
          desc: "References internal allowlist APIs \u2014 direct programmatic bypass of execution approval controls"
        },
        {
          pattern: /(?:auto[_-]?approve|skip[_-]?approval|bypass[_-]?confirmation)\s*[=:]\s*true/gi,
          desc: "Sets auto-approve flags \u2014 disables human-in-the-loop safety for tool execution"
        },
        {
          pattern: /(?:add|append|insert)\s+(?:.*\s+)?(?:to\s+)?(?:the\s+)?(?:permissions?\s*\.\s*allow|allowedTools|trusted\s*(?:tools?|commands?))/gi,
          desc: "Adds entries to permission allow lists \u2014 expands agent capabilities beyond intended scope"
        }
      ];
      for (const { pattern, desc } of allowlistPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-allowlist-bypass-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Execution allowlist bypass instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Reported as an active attack vector in OpenClaw #security channel (jluk).`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-skill-tampering",
    name: "Skill Tampering / Unsigned Skill Loading",
    description: "Checks for instructions to load, import, or execute skills without verification or from untrusted sources",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const skillTamperPatterns = [
        {
          pattern: /(?:load|import|install|add)\s+(?:a\s+)?(?:skill|plugin|extension)\s+(?:from\s+)?https?:\/\//gi,
          desc: "Loads skill from external URL \u2014 untrusted skill definitions can contain prompt injection payloads"
        },
        {
          pattern: /(?:skip|bypass|ignore|disable)\s+(?:skill\s+)?(?:verification|validation|signature|hash\s+check|integrity\s+check)/gi,
          desc: "Instructs agent to skip skill verification \u2014 allows tampered skills to execute"
        },
        {
          pattern: /(?:modify|edit|replace|overwrite)\s+(?:the\s+)?(?:skill|plugin)\s+(?:definition|instructions?|content|source)/gi,
          desc: "Instructs agent to modify skill definitions \u2014 runtime skill tampering"
        },
        {
          pattern: /(?:create|write|add)\s+(?:a\s+)?(?:new\s+)?(?:skill|plugin)\s+(?:that|which)\s+(?:runs?|executes?|calls?|invokes?)/gi,
          desc: "Instructs agent to create new skills with execution capabilities \u2014 skill injection"
        }
      ];
      for (const { pattern, desc } of skillTamperPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-skill-tamper-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Skill tampering or unsigned skill loading instruction`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Reference: OpenClaw skill verification gate (vgzotta PR #14893).`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-config-secret-leakage",
    name: "Config File Secret Leakage",
    description: "Checks for instructions to write, copy, or inline secrets from env vars into config files as plaintext",
    severity: "critical",
    category: "secrets",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const leakagePatterns = [
        {
          pattern: /(?:write|save|store|put|copy|inline|embed|hardcode)\s+(?:the\s+)?(?:actual|real|raw|resolved|plaintext)\s+(?:\w+\s+)?(?:value|secret|key|token|password|credential)s?\s+(?:into|in|to)\s+(?:the\s+)?(?:config|configuration|settings|\.env|\w+\.json|\w+\.ya?ml)/gi,
          desc: "Instructs agent to write resolved secret values into config files \u2014 converts env var references to plaintext"
        },
        {
          pattern: /(?:replace|expand|resolve|substitute|inline)\s+(?:all\s+)?(?:env(?:ironment)?\s+)?(?:var(?:iable)?s?\s+)?(?:references?\s+)?(?:with\s+)?(?:their\s+)?(?:actual|real|plaintext|resolved|literal)\s+(?:\w+\s+)?values?/gi,
          desc: "Instructs agent to resolve environment variables to plaintext \u2014 destroys secret indirection"
        },
        {
          pattern: /(?:writeConfig(?:File)?|write_config|save_config)\s*\([\s\S]*?(?:process\.env|os\.environ|env\[)/gi,
          desc: "Writes config files using env var values directly \u2014 leaks secrets from environment to disk"
        }
      ];
      for (const { pattern, desc } of leakagePatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-config-secret-leak-${match.index}`,
            severity: "critical",
            category: "secrets",
            title: `Config file secret leakage instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Reference: OpenClaw config writeConfigFile bug (psyalien PR #11560).`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-secrets-in-output",
    name: "Secrets Exposed in Tool Output / Transcripts",
    description: "Checks for instructions to log, print, or persist secrets from tool output to disk or transcripts",
    severity: "high",
    category: "secrets",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const outputSecretPatterns = [
        {
          pattern: /(?:log|print|output|display|show|echo|write)\s+(?:the\s+)?(?:full|complete|entire|raw)\s+(?:api\s+)?(?:response|output|result|tool\s+output|tool\s+result)/gi,
          desc: "Instructs agent to log full tool output which may contain API keys, tokens, or credentials"
        },
        {
          pattern: /(?:save|write|persist|store|append)\s+(?:the\s+)?(?:session\s+)?(?:transcript|conversation|chat\s+log|tool\s+output)\s+(?:to|in|into)\s+(?:a\s+)?(?:file|disk|log)/gi,
          desc: "Instructs agent to persist session transcripts to disk \u2014 tool outputs may contain secrets"
        },
        {
          pattern: /(?:include|keep|preserve|don'?t\s+(?:strip|remove|redact))\s+(?:all\s+)?(?:api\s+)?(?:keys?|tokens?|credentials?|secrets?|passwords?)\s+(?:in|from)\s+(?:the\s+)?(?:output|response|log|transcript)/gi,
          desc: "Instructs agent to preserve secrets in output \u2014 prevents automatic redaction"
        }
      ];
      for (const { pattern, desc } of outputSecretPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-secrets-in-output-${match.index}`,
            severity: "high",
            category: "secrets",
            title: `Secret exposure in tool output / transcript`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. Session transcripts and logs written to disk can expose secrets from API responses.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-system-prompt-extraction",
    name: "System Prompt Extraction Attempt",
    description: "Checks for instructions that attempt to extract, leak, or reveal system prompts",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      if (isAgentDocumentationFile(file)) return [];
      const findings = [];
      const extractionPatterns = [
        {
          pattern: /(?:show|print|reveal|display|output|repeat|leak|dump)\s+(?:me\s+)?(?:your\s+)?(?:the\s+)?(?:full\s+|complete\s+|entire\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|constraints?)/gi,
          desc: "Attempts to extract the agent's system prompt \u2014 reconnaissance for crafting targeted injection attacks"
        },
        {
          pattern: /(?:what\s+(?:are|is|were)\s+)?(?:your\s+)?(?:original|initial|system|hidden|secret)\s+(?:instructions?|prompt|rules?|guidelines?)/gi,
          desc: "Probes for the agent's system instructions \u2014 prompt leaking technique"
        },
        {
          pattern: /(?:output|repeat|recite|echo)\s+(?:everything|all)\s+(?:before|above|that\s+was\s+said|from\s+the\s+(?:beginning|start))/gi,
          desc: "Attempts to dump the full context including system prompt via repetition"
        }
      ];
      for (const { pattern, desc } of extractionPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-prompt-extraction-${match.index}`,
            severity: "high",
            category: "injection",
            title: `System prompt extraction attempt detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. From openclaw-security-guard prompt injection patterns.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-jailbreak-framing",
    name: "Jailbreak Framing / Hypothetical Bypass",
    description: "Checks for instructions that use fictional, hypothetical, or educational framing to bypass safety constraints",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const framingPatterns = [
        {
          pattern: /(?:in\s+a\s+)?(?:hypothetical|fictional|imaginary)\s+(?:scenario|world|story|context)\s+(?:where\s+)?(?:there\s+are\s+)?(?:no\s+)?(?:rules?|restrictions?|limits?|safety|guidelines?)/gi,
          desc: "Uses fictional framing to establish a context without safety restrictions \u2014 jailbreak technique"
        },
        {
          pattern: /(?:for\s+)?(?:educational|research|academic|testing)\s+purposes?\s+(?:only\s*[,;:]?\s*)?(?:show|demonstrate|explain|output|generate)/gi,
          desc: "Uses 'educational purposes' framing to justify bypassing safety \u2014 common jailbreak wrapper"
        },
        {
          pattern: /(?:this\s+is\s+(?:just|only)\s+a\s+)?(?:test|experiment|simulation|drill|exercise)\s*[,;:]\s*(?:so\s+)?(?:you\s+can|please|go\s+ahead)/gi,
          desc: "Frames request as a 'test' to reduce the agent's resistance to unsafe actions"
        },
        {
          pattern: /(?:developer|maintenance|debug|test|admin)\s+mode\s+(?:enabled|activated|on|engaged)/gi,
          desc: "Claims a special operational mode is active to unlock restricted capabilities \u2014 mode spoofing"
        },
        {
          pattern: /(?:no\s+(?:ethical|moral)\s+(?:guidelines?|restrictions?|limits?|constraints?))/gi,
          desc: "Declares ethical guidelines removed \u2014 attempts to eliminate the agent's safety boundaries"
        }
      ];
      for (const { pattern, desc } of framingPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-jailbreak-framing-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Jailbreak framing / hypothetical bypass detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. From openclaw-security-guard jailbreak pattern database.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-role-hijacking",
    name: "Role Hijacking / Persona Override",
    description: "Checks for instructions that reassign the agent's role, persona, or behavioral constraints",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const rolePatterns = [
        {
          pattern: /(?:roleplay|role-play)\s+as\s+(?:a|an|the)\s+/gi,
          desc: "Instructs agent to roleplay a different identity \u2014 can override safety behaviors"
        },
        {
          pattern: /(?:pretend|act)\s+(?:to\s+be|as\s+if\s+you\s+(?:are|were)|like\s+you\s+(?:are|were))\s+(?:a|an|the)\s+/gi,
          desc: "Instructs agent to pretend to be a different entity \u2014 persona override technique"
        },
        {
          pattern: /(?:from\s+now\s+on|starting\s+now|henceforth)\s*[,;:]?\s*(?:you\s+are|act\s+as|behave\s+like|respond\s+as)/gi,
          desc: "Temporal role reassignment \u2014 attempts to permanently change agent behavior from this point forward"
        },
        {
          pattern: /(?:switch|change)\s+(?:to|into)\s+(?:a\s+)?(?:different|new|unrestricted|unfiltered|uncensored)\s+(?:mode|personality|character|persona|role)/gi,
          desc: "Requests mode switch to an unrestricted persona \u2014 jailbreak via persona change"
        }
      ];
      for (const { pattern, desc } of rolePatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-role-hijacking-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Role hijacking / persona override detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. From openclaw-security-guard role hijacking patterns.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  },
  {
    id: "agents-destructive-tool-usage",
    name: "Destructive Tool Usage Instructions",
    description: "Checks for instructions that direct the agent to use tools for destructive operations like deleting data or dropping tables",
    severity: "high",
    category: "injection",
    check(file) {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];
      const findings = [];
      const destructiveToolPatterns = [
        {
          pattern: /(?:use|call|invoke)\s+(?:the\s+)?\w+\s+tool\s+to\s+(?:delete|remove|destroy|drop|truncate|wipe|purge|erase)/gi,
          desc: "Directs agent to use a specific tool for destructive operations"
        },
        {
          pattern: /(?:drop\s+(?:all\s+)?(?:tables?|databases?|collections?|indexes?)|truncate\s+(?:all\s+)?tables?|delete\s+from\s+\w+\s+where\s+1\s*=\s*1)/gi,
          desc: "Contains destructive SQL/database operations \u2014 drop tables, truncate, mass delete"
        },
        {
          pattern: /(?:git\s+push\s+--force(?!-with-lease)(?:\s+origin\s+main|\s+origin\s+master)?)/gi,
          desc: "Force push to main/master \u2014 can overwrite remote history and destroy team changes"
        },
        {
          pattern: /(?:invoke|call|execute)\s+(?:the\s+)?\w+\s+(?:tool|function)\s+(?:without\s+(?:asking|confirmation|review|approval))/gi,
          desc: "Instructs agent to invoke tools without user confirmation \u2014 bypasses human-in-the-loop safety"
        }
      ];
      for (const { pattern, desc } of destructiveToolPatterns) {
        const matches = findAllMatches3(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-destructive-tool-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Destructive tool usage instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" \u2014 ${desc}. From openclaw-security-guard tool manipulation patterns.`,
            file: file.path,
            line: findLineNumber4(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100)
          });
        }
      }
      return findings;
    }
  }
];

// src/skills/health.ts
import { basename as basename2, dirname, extname as extname2 } from "path";
import YAML from "yaml";
var HISTORY_SUFFIXES = [
  ".history.json",
  ".observations.json",
  ".observation.json",
  ".feedback.json",
  ".execution-history.json",
  ".metrics.json"
];
function analyzeSkillHealth(files) {
  const profiles = getSkillProfiles(files);
  if (profiles.length === 0) return void 0;
  const skills = profiles.map((profile) => {
    const score = scoreSkill(profile);
    return {
      skillName: profile.skillName,
      file: profile.file.path,
      version: profile.version,
      hasObservationHooks: profile.hasObservationHooks,
      hasFeedbackHooks: profile.hasFeedbackHooks,
      hasRollbackMetadata: profile.hasRollbackMetadata,
      score,
      status: classifySkillStatus(score),
      observedRuns: profile.observedRuns,
      successRate: profile.successRate,
      averageFeedback: profile.averageFeedback,
      historyFiles: profile.historyFiles.map((file) => file.path)
    };
  });
  const scoredSkills = skills.filter((skill) => typeof skill.score === "number");
  return {
    totalSkills: skills.length,
    instrumentedSkills: skills.filter(
      (skill) => skill.hasObservationHooks && skill.hasFeedbackHooks
    ).length,
    versionedSkills: skills.filter((skill) => Boolean(skill.version)).length,
    rollbackReadySkills: skills.filter((skill) => skill.hasRollbackMetadata).length,
    observedSkills: skills.filter((skill) => skill.observedRuns > 0).length,
    averageScore: scoredSkills.length > 0 ? Math.round(
      scoredSkills.reduce((sum, skill) => sum + (skill.score ?? 0), 0) / scoredSkills.length
    ) : void 0,
    skills
  };
}
function getSkillProfiles(files) {
  const skillFiles = files.filter(isSkillDefinitionFile);
  return skillFiles.map((file) => {
    const frontmatter = parseSkillFrontmatter(file.content);
    const historyFiles = getRelatedHistoryFiles(file, files);
    const records = historyFiles.flatMap((historyFile) => parseHistoryFile(historyFile));
    const successfulRuns = records.filter((record) => record.success === true).length;
    const failedRuns = records.filter((record) => record.success === false).length;
    const observedRuns = successfulRuns + failedRuns;
    const feedbackValues = records.map((record) => record.feedback).filter((value) => typeof value === "number");
    return {
      skillName: inferSkillName(file, frontmatter.raw),
      file,
      version: extractVersion(frontmatter),
      hasObservationHooks: hasObservationHooks(frontmatter),
      hasFeedbackHooks: hasFeedbackHooks(frontmatter),
      hasRollbackMetadata: hasRollbackMetadata(frontmatter),
      historyFiles,
      observedRuns,
      successRate: observedRuns > 0 ? successfulRuns / observedRuns : void 0,
      averageFeedback: feedbackValues.length > 0 ? Number(
        (feedbackValues.reduce((sum, value) => sum + value, 0) / feedbackValues.length).toFixed(1)
      ) : void 0
    };
  });
}
function isSkillDefinitionFile(file) {
  const normalizedPath = file.path.replace(/\\/g, "/").toLowerCase();
  const extension = extname2(normalizedPath);
  return file.type === "skill-md" && (extension === ".md" || extension === ".markdown");
}
function parseSkillFrontmatter(content) {
  const match = content.match(/^---\s*\n([\s\S]*?)\n---\s*\n?/);
  if (!match) {
    return { raw: {}, body: content };
  }
  try {
    const parsed = YAML.parse(match[1]);
    const raw = parsed && typeof parsed === "object" ? parsed : {};
    return {
      version: typeof raw.version === "string" ? raw.version : void 0,
      metadata: raw.metadata && typeof raw.metadata === "object" ? raw.metadata : void 0,
      raw,
      body: content.slice(match[0].length)
    };
  } catch {
    return { raw: {}, body: content };
  }
}
function inferSkillName(file, frontmatter) {
  if (typeof frontmatter.name === "string" && frontmatter.name.trim().length > 0) {
    return frontmatter.name.trim();
  }
  const stem = basename2(file.path, extname2(file.path));
  return stem.toLowerCase() === "skill" ? basename2(dirname(file.path)) : stem;
}
function extractVersion(frontmatter) {
  if (frontmatter.version) return frontmatter.version;
  const metadataVersion = frontmatter.metadata?.version;
  return typeof metadataVersion === "string" ? metadataVersion : void 0;
}
function hasObservationHooks(frontmatter) {
  return hasKey(frontmatter, /(?:^|_)(?:observe|observation)(?:_hook|_hooks)?$/) || /(?:^|\n)#{1,6}\s*(?:observe|observation|telemetry)\b/im.test(frontmatter.body) || /\bobservation hooks?\b/i.test(frontmatter.body);
}
function hasFeedbackHooks(frontmatter) {
  return hasKey(frontmatter, /(?:^|_)feedback(?:_hook|_hooks)?$/) || /(?:^|\n)#{1,6}\s*feedback\b/im.test(frontmatter.body) || /\bfeedback hooks?\b/i.test(frontmatter.body);
}
function hasRollbackMetadata(frontmatter) {
  return hasKey(frontmatter, /rollback(?:_strategy|_plan|_metadata)?$/) || hasKey(frontmatter, /previous_version$/) || /(?:^|\n)#{1,6}\s*rollback\b/im.test(frontmatter.body);
}
function hasKey(frontmatter, pattern) {
  const stack = [frontmatter.raw];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current || typeof current !== "object") continue;
    for (const [key, value] of Object.entries(current)) {
      if (pattern.test(key)) {
        return truthyMetadata(value);
      }
      if (value && typeof value === "object") {
        stack.push(value);
      }
    }
  }
  return false;
}
function truthyMetadata(value) {
  if (typeof value === "string") return value.trim().length > 0;
  if (typeof value === "number") return true;
  if (typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.length > 0;
  return Boolean(value);
}
function getRelatedHistoryFiles(skillFile, files) {
  const normalizedDir = dirname(skillFile.path).replace(/\\/g, "/");
  const skillStem = basename2(skillFile.path, extname2(skillFile.path));
  const expectedPrefixes = /* @__PURE__ */ new Set([
    `${skillStem}.`,
    `${skillStem}-`,
    `${skillStem}_`
  ]);
  if (skillStem.toLowerCase() === "skill") {
    const parent = basename2(normalizedDir);
    expectedPrefixes.add(`${parent}.`);
    expectedPrefixes.add(`${parent}-`);
    expectedPrefixes.add(`${parent}_`);
  }
  return files.filter((file) => {
    if (file === skillFile || file.type !== "skill-md") return false;
    if (dirname(file.path).replace(/\\/g, "/") !== normalizedDir) return false;
    const lowerName = basename2(file.path).toLowerCase();
    if (!lowerName.endsWith(".json")) return false;
    return HISTORY_SUFFIXES.some((suffix) => lowerName.endsWith(suffix)) && [...expectedPrefixes].some((prefix) => lowerName.startsWith(prefix.toLowerCase()));
  });
}
function parseHistoryFile(file) {
  try {
    const parsed = JSON.parse(file.content);
    return extractRecords(parsed);
  } catch {
    return [];
  }
}
function extractRecords(value) {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => normalizeRunRecord(entry));
  }
  if (!value || typeof value !== "object") {
    return [];
  }
  const record = value;
  const arrays = [
    record.runs,
    record.history,
    record.executions,
    record.observations,
    record.events,
    record.entries
  ];
  for (const candidate of arrays) {
    if (Array.isArray(candidate)) {
      return candidate.flatMap((entry) => normalizeRunRecord(entry));
    }
  }
  return normalizeRunRecord(record);
}
function normalizeRunRecord(value) {
  if (!value || typeof value !== "object") {
    return [];
  }
  const record = value;
  const success = extractSuccess(record);
  const feedback = extractFeedback(record);
  if (typeof success !== "boolean" && typeof feedback !== "number") {
    return [];
  }
  return [{ success, feedback }];
}
function extractSuccess(record) {
  for (const key of ["success", "succeeded", "passed"]) {
    if (typeof record[key] === "boolean") {
      return record[key];
    }
  }
  const status = [record.status, record.outcome, record.result].find((value) => typeof value === "string");
  if (typeof status !== "string") return void 0;
  const normalized = status.toLowerCase();
  if (["success", "succeeded", "ok", "passed", "completed"].includes(normalized)) {
    return true;
  }
  if (["failure", "failed", "error", "errored", "rollback", "reverted"].includes(normalized)) {
    return false;
  }
  return void 0;
}
function extractFeedback(record) {
  const candidates = [
    record.feedback,
    record.feedbackScore,
    record.rating,
    record.score,
    record.userFeedback
  ];
  for (const candidate of candidates) {
    const normalized = normalizeFeedback(candidate);
    if (typeof normalized === "number") {
      return normalized;
    }
  }
  return void 0;
}
function normalizeFeedback(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    if (value <= 5) return clampFeedback(value);
    if (value <= 100) return clampFeedback(value / 20);
  }
  if (typeof value === "boolean") {
    return value ? 5 : 1;
  }
  if (!value || typeof value !== "object") {
    return void 0;
  }
  const record = value;
  if (typeof record.rating === "number") return normalizeFeedback(record.rating);
  if (typeof record.score === "number") return normalizeFeedback(record.score);
  if (typeof record.positive === "boolean") return record.positive ? 5 : 1;
  return void 0;
}
function clampFeedback(value) {
  return Math.max(1, Math.min(5, Number(value.toFixed(1))));
}
function scoreSkill(profile) {
  if (typeof profile.successRate !== "number") return void 0;
  const successScore = profile.successRate * 80;
  const feedbackScore = typeof profile.averageFeedback === "number" ? profile.averageFeedback / 5 * 20 : 0;
  return Math.round(successScore + feedbackScore);
}
function classifySkillStatus(score) {
  if (typeof score !== "number") return "unobserved";
  if (score >= 85) return "healthy";
  if (score >= 70) return "watch";
  return "at-risk";
}

// src/rules/skills.ts
function buildMissingFieldsLabel(missingFields) {
  if (missingFields.length === 1) {
    return missingFields[0];
  }
  return `${missingFields.slice(0, -1).join(", ")} and ${missingFields.at(-1)}`;
}
var skillRules = [
  {
    id: "skills-observation-feedback-hooks",
    name: "Skill observation and feedback hooks",
    description: "Checks whether SKILL.md files define observation and feedback hooks for self-improvement loops",
    severity: "medium",
    category: "skills",
    check(file, allFiles = []) {
      if (!isSkillDefinitionFile(file)) return [];
      const profile = getSkillProfiles(allFiles).find((entry) => entry.file.path === file.path);
      if (!profile) return [];
      const missing = [];
      if (!profile.hasObservationHooks) missing.push("observation hooks");
      if (!profile.hasFeedbackHooks) missing.push("feedback hooks");
      if (missing.length === 0) return [];
      return [
        {
          id: `skills-missing-telemetry-${file.path}`,
          severity: "medium",
          category: "skills",
          title: `Skill is missing ${buildMissingFieldsLabel(missing)}`,
          description: `The skill "${profile.skillName}" does not define ${buildMissingFieldsLabel(missing)} in SKILL.md. ECC 2.0 self-improving skills need explicit observe/feedback hooks so runs can be inspected and amended safely.`,
          file: file.path,
          evidence: buildMissingFieldsLabel(missing)
        }
      ];
    }
  },
  {
    id: "skills-version-rollback-metadata",
    name: "Skill version and rollback metadata",
    description: "Checks whether SKILL.md files define versioning and rollback metadata",
    severity: "medium",
    category: "skills",
    check(file, allFiles = []) {
      if (!isSkillDefinitionFile(file)) return [];
      const profile = getSkillProfiles(allFiles).find((entry) => entry.file.path === file.path);
      if (!profile) return [];
      const missing = [];
      if (!profile.version) missing.push("version metadata");
      if (!profile.hasRollbackMetadata) missing.push("rollback metadata");
      if (missing.length === 0) return [];
      return [
        {
          id: `skills-missing-governance-${file.path}`,
          severity: "medium",
          category: "skills",
          title: `Skill is missing ${buildMissingFieldsLabel(missing)}`,
          description: `The skill "${profile.skillName}" does not define ${buildMissingFieldsLabel(missing)}. Self-amending skills need explicit version and rollback markers so regressions can be evaluated and reversed.`,
          file: file.path,
          evidence: buildMissingFieldsLabel(missing)
        }
      ];
    }
  }
];

// src/rules/prompt-defense.ts
var DEFENSE_CHECKS = [
  {
    id: "role-escape",
    name: "Role boundary defense",
    description: "Prompt should explicitly reject unauthorized role or persona changes requested by users.",
    severity: "high",
    pattern: /(?:do\s+not|never|must\s+not|cannot|don'?t|refuse|reject|ignore)\s+.{0,60}(?:role|persona|character|identity|pretend|act\s+as|impersonat|role.?play)/i,
    owaspRef: "LLM01 Prompt Injection"
  },
  {
    id: "instruction-override",
    name: "Instruction boundary defense",
    description: "Prompt should state that user content cannot override, ignore, or modify higher-priority instructions.",
    severity: "critical",
    pattern: /(?:do\s+not|never|must\s+not|cannot|don'?t|refuse|reject)\s+.{0,60}(?:override|ignore|disregard|bypass|modify|change|alter)\s+.{0,40}(?:instruction|system|rule|guideline|directive|prompt)/i,
    owaspRef: "LLM01 Prompt Injection"
  },
  {
    id: "data-leakage",
    name: "Data leakage defense",
    description: "Prompt should block revealing internal instructions, secrets, or confidential data.",
    severity: "critical",
    pattern: /(?:do\s+not|never|must\s+not|cannot|don'?t|refuse)\s+.{0,60}(?:reveal|disclose|share|leak|expose|output|repeat|show)\s+.{0,40}(?:system|prompt|instruction|internal|confidential|secret|private|api.?key|credential)/i,
    owaspRef: "LLM06 Sensitive Information Disclosure"
  },
  {
    id: "output-manipulation",
    name: "Output control defense",
    description: "Prompt should constrain risky output forms such as executable code, HTML, links, or scripts.",
    severity: "medium",
    pattern: /(?:do\s+not|never|must\s+not|cannot|don'?t|refuse|restrict|limit|only)\s+.{0,60}(?:output|generat|produc|return|render|includ|embed)\s+.{0,40}(?:code|script|html|markdown|link|url|execut|iframe|javascript)/i,
    owaspRef: "LLM02 Insecure Output Handling"
  },
  {
    id: "multilang-bypass",
    name: "Multi-language bypass defense",
    description: "Prompt should address attempts to evade safeguards by switching languages or translating unsafe requests.",
    severity: "medium",
    pattern: /(?:regardless\s+of\s+(?:the\s+)?language|in\s+(?:any|all|every)\s+language|translat(?:e|ion)\s+.{0,30}(?:rule|instruction|safety|restrict)|language\s+.{0,20}(?:bypass|circumvent|evade))/i
  },
  {
    id: "unicode-attack",
    name: "Unicode and encoding defense",
    description: "Prompt should mention unicode, invisible characters, homoglyphs, or encoding tricks as suspicious input.",
    severity: "medium",
    pattern: /(?:unicode|homoglyph|invisible\s+character|zero.?width|encod(?:ed|ing)\s+.{0,20}(?:trick|attack|bypass|evas)|special\s+character|non.?printable)/i
  },
  {
    id: "context-overflow",
    name: "Context overflow defense",
    description: "Prompt should acknowledge input-length or token-window limits and reject attempts to push safeguards out of context.",
    severity: "medium",
    pattern: /(?:(?:context|token|input|message)\s+.{0,20}(?:limit|length|overflow|window|exceed|truncat|maximum)|too\s+(?:long|large|many)\s+.{0,20}(?:input|token|message|character)|length\s+.{0,10}(?:restrict|limit|cap|max))/i
  },
  {
    id: "indirect-injection",
    name: "Indirect injection defense",
    description: "Prompt should treat external or fetched content as untrusted and warn about embedded instructions in tool/document output.",
    severity: "high",
    pattern: /(?:(?:external|third.?party|user.?provided|untrusted|fetched|retrieved)\s+.{0,30}(?:data|content|source|input|document|url|link|tool)\s+.{0,30}(?:instruct|command|inject|malicious|trust)|indirect\s+.{0,10}(?:inject|prompt|attack))/i,
    owaspRef: "LLM01 Prompt Injection"
  },
  {
    id: "social-engineering",
    name: "Social engineering defense",
    description: "Prompt should account for urgency, emotional manipulation, or fake authority claims used to bypass safeguards.",
    severity: "medium",
    pattern: /(?:(?:emotional|urgency|authority|guilt|sympathy|emergency|life.?or.?death|dying|threaten)\s+.{0,30}(?:manipulat|appeal|pressure|claim|bypass|trick|override)|social\s+engineer)/i
  },
  {
    id: "output-weaponization",
    name: "Harmful content defense",
    description: "Prompt should block dangerous, weaponizable, exploitative, or illegal output.",
    severity: "high",
    pattern: /(?:do\s+not|never|must\s+not|cannot|don'?t|refuse)\s+.{0,60}(?:harm(?:ful)?|danger(?:ous)?|illegal|weapon|violen(?:t|ce)|exploit|malware|phishing|attack(?:s|ing)?)/i,
    owaspRef: "LLM09 Overreliance"
  },
  {
    id: "abuse-prevention",
    name: "Abuse prevention defense",
    description: "Prompt should mention repeated abuse, rate limiting, or session/isolation boundaries.",
    severity: "low",
    pattern: /(?:abuse|misuse|exploit(?:ation)?|repeated\s+(?:attempt|request|abuse)|rate\s+limit|session\s+(?:isolat|boundar)|detect\s+.{0,20}(?:abuse|pattern|manipulat))/i
  },
  {
    id: "input-validation-missing",
    name: "Input validation defense",
    description: "Prompt should instruct the agent to validate, sanitize, inspect, or reject suspicious input.",
    severity: "medium",
    pattern: /(?:(?:valid|saniti|verif|check|inspect|reject|filter|screen)\s+.{0,30}(?:input|request|query|message|user\s+(?:input|data|message))|malform|suspicious\s+.{0,10}(?:input|request|pattern))/i,
    owaspRef: "LLM01 Prompt Injection"
  }
];
function normalizePath2(filePath) {
  return filePath.replace(/\\/g, "/").toLowerCase();
}
function isPromptPostureFile(file) {
  if (file.type === "claude-md" || file.type === "agent-md") return true;
  if (file.type !== "rule-md") return false;
  const normalizedPath = normalizePath2(file.path);
  return normalizedPath.includes("/.claude/rules/") || normalizedPath.startsWith(".claude/rules/");
}
var promptDefenseRules = [
  {
    id: "prompt-defense-posture",
    name: "Prompt defense posture audit",
    description: "Checks whether system prompt files contain defensive instructions against common LLM attack vectors.",
    severity: "high",
    category: "injection",
    check(file) {
      if (!isPromptPostureFile(file)) return [];
      const content = file.content.trim();
      if (!content) return [];
      const findings = [];
      for (const defense of DEFENSE_CHECKS) {
        if (defense.pattern.test(content)) continue;
        const owaspNote = defense.owaspRef ? ` (OWASP LLM Top 10: ${defense.owaspRef})` : "";
        findings.push({
          id: `prompt-defense-missing-${defense.id}-${file.path}`,
          severity: defense.severity,
          category: "injection",
          title: `Missing prompt defense: ${defense.name}`,
          description: `${defense.description}${owaspNote}`,
          file: file.path,
          evidence: `Missing ${defense.id} defense in ${file.path}`
        });
      }
      return findings;
    }
  }
];

// src/rules/index.ts
function getBuiltinRules() {
  return [
    ...secretRules,
    ...permissionRules,
    ...hookRules,
    ...mcpRules,
    ...cveMcpRules,
    ...toolPoisoningRules,
    ...skillRules,
    ...agentRules,
    ...promptDefenseRules
  ];
}

// src/harness-adapters/index.ts
import { existsSync as existsSync2, statSync as statSync3 } from "fs";
import { join as join3 } from "path";
var ADAPTERS = [
  {
    id: "claude-code",
    name: "Claude Code",
    description: "Claude Code project rules, permissions, MCP, hooks, agents, skills, and command surfaces.",
    configPaths: [
      "CLAUDE.md",
      ".claude/CLAUDE.md",
      "settings.json",
      ".claude/settings.json",
      "mcp.json",
      ".claude/mcp.json",
      ".claude/agents",
      ".claude/skills",
      ".claude/hooks"
    ],
    permissionConcepts: ["allow/deny permissions", "dangerous shell commands", "project-local overrides"],
    pluginSurfaces: ["Claude plugins", "hooks manifests", "skills", "slash commands"],
    mcpConventions: ["mcpServers", ".claude.json", "mcp.json"],
    historySurfaces: ["Claude transcripts", "session hooks", "tool usage logs"],
    ciEvidence: ["AgentShield scan", "policy evaluation", "SARIF upload", "evidence pack"],
    markers: [
      { path: "CLAUDE.md", kind: "file", strength: "strong" },
      { path: ".claude/CLAUDE.md", kind: "file", strength: "strong" },
      { path: "settings.json", kind: "file", strength: "strong" },
      { path: ".claude/settings.json", kind: "file", strength: "strong" },
      { path: "mcp.json", kind: "file", strength: "supporting" },
      { path: ".claude/mcp.json", kind: "file", strength: "supporting" },
      { path: ".claude/agents", kind: "directory", strength: "supporting" },
      { path: ".claude/skills", kind: "directory", strength: "supporting" },
      { path: ".claude/hooks", kind: "directory", strength: "supporting" }
    ]
  },
  {
    id: "opencode",
    name: "OpenCode",
    description: "OpenCode agent, command, provider, plugin, and project configuration surfaces.",
    configPaths: [
      "opencode.json",
      "opencode.jsonc",
      ".opencode.json",
      ".opencode/config.json",
      ".opencode/agents",
      ".opencode/commands",
      ".opencode/plugins"
    ],
    permissionConcepts: ["provider permissions", "agent modes", "tool scopes"],
    pluginSurfaces: ["OpenCode plugins", "agents", "commands"],
    mcpConventions: ["provider/tool configuration", "project-local tool adapters"],
    historySurfaces: ["sessions", "client/server state", "tool traces"],
    ciEvidence: ["scan report", "package-surface checks", "policy gate"],
    markers: [
      { path: "opencode.json", kind: "file", strength: "strong" },
      { path: "opencode.jsonc", kind: "file", strength: "strong" },
      { path: ".opencode.json", kind: "file", strength: "strong" },
      { path: ".opencode/config.json", kind: "file", strength: "strong" },
      { path: ".opencode/agents", kind: "directory", strength: "supporting" },
      { path: ".opencode/commands", kind: "directory", strength: "supporting" },
      { path: ".opencode/plugins", kind: "directory", strength: "supporting" }
    ]
  },
  {
    id: "codex",
    name: "Codex",
    description: "Codex AGENTS instructions, project config, prompts, and local memory/tooling surfaces.",
    configPaths: [
      "AGENTS.md",
      ".codex/config.toml",
      ".codex/agents",
      ".codex/prompts",
      ".codex/skills"
    ],
    permissionConcepts: ["sandbox policy", "approval policy", "agent instructions"],
    pluginSurfaces: ["skills", "MCP servers", "project AGENTS.md"],
    mcpConventions: [".codex/config.toml", "MCP server entries"],
    historySurfaces: ["Codex session logs", "rollout summaries", "local memories"],
    ciEvidence: ["scan report", "rules conformance", "policy gate"],
    markers: [
      { path: "AGENTS.md", kind: "file", strength: "strong" },
      { path: ".codex/config.toml", kind: "file", strength: "strong" },
      { path: ".codex/agents", kind: "directory", strength: "supporting" },
      { path: ".codex/prompts", kind: "directory", strength: "supporting" },
      { path: ".codex/skills", kind: "directory", strength: "supporting" }
    ]
  },
  {
    id: "gemini",
    name: "Gemini CLI",
    description: "Gemini project instructions, commands, extensions, and MCP configuration surfaces.",
    configPaths: [
      "GEMINI.md",
      ".gemini/settings.json",
      ".gemini/commands",
      ".gemini/extensions",
      ".gemini/mcp.json"
    ],
    permissionConcepts: ["tool permissions", "extension scopes", "project rules"],
    pluginSurfaces: ["commands", "extensions", "MCP adapters"],
    mcpConventions: [".gemini/mcp.json", "settings tool entries"],
    historySurfaces: ["terminal transcripts", "command history", "tool traces"],
    ciEvidence: ["scan report", "policy gate", "extension review"],
    markers: [
      { path: "GEMINI.md", kind: "file", strength: "strong" },
      { path: ".gemini/settings.json", kind: "file", strength: "strong" },
      { path: ".gemini/mcp.json", kind: "file", strength: "supporting" },
      { path: ".gemini/commands", kind: "directory", strength: "supporting" },
      { path: ".gemini/extensions", kind: "directory", strength: "supporting" }
    ]
  },
  {
    id: "dmux",
    name: "dmux",
    description: "dmux multi-agent pane, worktree, launch, and lifecycle hook surfaces.",
    configPaths: [
      "dmux.yaml",
      "dmux.yml",
      "dmux.json",
      ".dmux/config.yaml",
      ".dmux/config.json",
      ".dmux"
    ],
    permissionConcepts: ["pane launch commands", "worktree lifecycle hooks", "merge workflows"],
    pluginSurfaces: ["launch recipes", "hooks", "agent templates"],
    mcpConventions: ["per-agent MCP environment", "launch-time tool config"],
    historySurfaces: ["tmux pane logs", "worktree state", "handoff files"],
    ciEvidence: ["scan report", "worktree safety review", "merge gate"],
    markers: [
      { path: "dmux.yaml", kind: "file", strength: "strong" },
      { path: "dmux.yml", kind: "file", strength: "strong" },
      { path: "dmux.json", kind: "file", strength: "strong" },
      { path: ".dmux/config.yaml", kind: "file", strength: "strong" },
      { path: ".dmux/config.json", kind: "file", strength: "strong" },
      { path: ".dmux", kind: "directory", strength: "supporting" }
    ]
  },
  {
    id: "generic-terminal",
    name: "Generic Terminal Agent",
    description: "Terminal-agent launch scripts, command wrappers, and shell-based orchestration surfaces.",
    configPaths: [
      "agent.yaml",
      "agent.yml",
      ".agents",
      "agents.yaml",
      "scripts/agents",
      "terminal-agents"
    ],
    permissionConcepts: ["shell command allowlists", "environment exposure", "working-directory scope"],
    pluginSurfaces: ["shell wrappers", "agent launch manifests", "local command packs"],
    mcpConventions: ["environment-provided MCP endpoints", "wrapper-managed tools"],
    historySurfaces: ["terminal logs", "agent run directories", "handoff files"],
    ciEvidence: ["scan report", "script review", "policy gate"],
    markers: [
      { path: "agent.yaml", kind: "file", strength: "strong" },
      { path: "agent.yml", kind: "file", strength: "strong" },
      { path: "agents.yaml", kind: "file", strength: "strong" },
      { path: ".agents", kind: "directory", strength: "strong" },
      { path: "scripts/agents", kind: "directory", strength: "supporting" },
      { path: "terminal-agents", kind: "directory", strength: "supporting" }
    ]
  },
  {
    id: "project-local-template",
    name: "Project-local Templates",
    description: "Repository-local skills, commands, rules, prompts, and reusable agent templates.",
    configPaths: [
      "skills",
      "commands",
      "rules",
      "contexts",
      "prompts",
      ".claude/commands",
      ".claude/skills"
    ],
    permissionConcepts: ["template guidance", "default tool scopes", "copy-forward examples"],
    pluginSurfaces: ["skills", "commands", "rules", "contexts", "prompts"],
    mcpConventions: ["template MCP examples", "copy-forward config snippets"],
    historySurfaces: ["template changelogs", "skill health history", "example traces"],
    ciEvidence: ["template scan", "docs-example downgrade evidence", "corpus fixture coverage"],
    markers: [
      { path: "skills", kind: "directory", strength: "strong" },
      { path: "commands", kind: "directory", strength: "strong" },
      { path: "rules", kind: "directory", strength: "supporting" },
      { path: "contexts", kind: "directory", strength: "supporting" },
      { path: "prompts", kind: "directory", strength: "supporting" },
      { path: ".claude/commands", kind: "directory", strength: "supporting" },
      { path: ".claude/skills", kind: "directory", strength: "supporting" }
    ]
  }
];
function getHarnessAdapterRegistry() {
  return ADAPTERS.map(({ markers: _markers, ...metadata }) => metadata);
}
function detectHarnessAdapters(rootPath) {
  const detections = ADAPTERS.map((adapter) => detectAdapter(rootPath, adapter));
  const matched = detections.filter((adapter) => adapter.matched).sort((a, b) => a.id.localeCompare(b.id));
  return {
    totalRegistered: ADAPTERS.length,
    totalMatched: matched.length,
    matched,
    registered: getHarnessAdapterRegistry()
  };
}
function detectAdapter(rootPath, adapter) {
  const evidence = adapter.markers.filter((marker) => markerExists(rootPath, marker)).map((marker) => marker.path).sort();
  const strongMatches = adapter.markers.filter(
    (marker) => marker.strength === "strong" && evidence.includes(marker.path)
  ).length;
  const { markers: _markers, ...metadata } = adapter;
  return {
    ...metadata,
    matched: evidence.length > 0,
    confidence: strongMatches > 0 ? "strong" : "partial",
    evidence
  };
}
function markerExists(rootPath, marker) {
  try {
    const fullPath = join3(rootPath, marker.path);
    if (!existsSync2(fullPath)) return false;
    const stats = statSync3(fullPath);
    switch (marker.kind) {
      case "file":
        return stats.isFile();
      case "directory":
        return stats.isDirectory();
      default:
        return stats.isFile() || stats.isDirectory();
    }
  } catch {
    return false;
  }
}

// src/scanner/index.ts
function scan(targetPath) {
  const target = discoverConfigFiles(targetPath);
  const rules = getBuiltinRules();
  const findings = runRules(target.files, rules);
  const skillHealth = analyzeSkillHealth(target.files);
  const harnessAdapters = detectHarnessAdapters(targetPath);
  return { target, findings, skillHealth, harnessAdapters };
}
function runRules(files, rules) {
  const findings = [];
  for (const file of files) {
    for (const rule of rules) {
      const ruleFindings = rule.check(file, files);
      findings.push(...ruleFindings);
    }
  }
  const filesByPath = new Map(files.map((file) => [file.path, file]));
  const annotatedFindings = findings.map((finding) => {
    const annotatedFinding = annotateFindingRuntimeConfidence(finding, filesByPath);
    return adjustFindingForSourceContext(annotatedFinding);
  });
  return [...annotatedFindings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return order[a.severity] - order[b.severity];
  });
}
function classifyRuntimeConfidence(file) {
  const normalizedPath = file.path.replace(/\\/g, "/").toLowerCase();
  if (normalizedPath === "settings.local.json" || normalizedPath.endsWith("/settings.local.json")) {
    return "project-local-optional";
  }
  if (file.type === "hook-code") {
    return "hook-code";
  }
  if (file.type === "settings-json" && /(?:^|\/)(?:\.claude\/)?hooks\/hooks\.json$/i.test(normalizedPath)) {
    return "plugin-manifest";
  }
  if (isExampleLikePath(normalizedPath)) {
    return "docs-example";
  }
  return void 0;
}
function annotateFindingRuntimeConfidence(finding, filesByPath) {
  if (finding.runtimeConfidence) {
    return finding;
  }
  const file = filesByPath.get(finding.file);
  const runtimeConfidence = file ? classifyRuntimeConfidence(file) : void 0;
  return runtimeConfidence ? { ...finding, runtimeConfidence } : finding;
}
function adjustFindingForSourceContext(finding) {
  switch (finding.runtimeConfidence) {
    case "docs-example":
      return adjustDocsExampleFinding(finding);
    case "plugin-manifest":
      return adjustPluginManifestFinding(finding);
    default:
      return finding;
  }
}
function adjustDocsExampleFinding(finding) {
  if (finding.category === "secrets") {
    return withPrefixedDescription(
      {
        ...finding,
        title: prefixTitle(finding.title, "Example config")
      },
      "This finding comes from docs or sample configuration in the repository. It indicates risky guidance or example defaults, not confirmed active runtime exposure."
    );
  }
  return withPrefixedDescription(
    {
      ...finding,
      severity: downgradeStructuralSeverity(finding.severity),
      title: prefixTitle(finding.title, "Example config")
    },
    "This finding comes from docs or sample configuration in the repository. It indicates risky guidance or example defaults, not confirmed active runtime exposure."
  );
}
function adjustPluginManifestFinding(finding) {
  return withPrefixedDescription(
    {
      ...finding,
      title: prefixTitle(finding.title, "Plugin hook manifest")
    },
    "This finding comes from a declarative hook manifest. Review the referenced hook implementation to confirm the exact runtime behavior."
  );
}
function downgradeStructuralSeverity(severity) {
  switch (severity) {
    case "critical":
      return "high";
    case "high":
      return "medium";
    case "medium":
      return "low";
    default:
      return severity;
  }
}
function prefixTitle(title, prefix) {
  return title.startsWith(`${prefix}: `) ? title : `${prefix}: ${title}`;
}
function withPrefixedDescription(finding, prefix) {
  return finding.description.startsWith(prefix) ? finding : { ...finding, description: `${prefix} ${finding.description}` };
}

// src/reporter/score.ts
var SCORE_DEDUCTIONS = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 2,
  info: 0
};
var TEMPLATE_EXAMPLE_CATEGORY_CAP = 10;
function calculateScore(result) {
  const { findings, target, skillHealth, harnessAdapters } = result;
  const summary = summarizeFindings(findings, target.files.length);
  const score = computeScore(findings);
  return {
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    targetPath: target.path,
    findings,
    score,
    summary,
    harnessAdapters,
    skillHealth
  };
}
function summarizeFindings(findings, filesScanned) {
  const autoFixable = findings.filter((f) => f.fix?.auto).length;
  return {
    totalFindings: findings.length,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
    filesScanned,
    autoFixable
  };
}
function computeScore(findings) {
  const categoryDeductions = {
    secrets: 0,
    permissions: 0,
    hooks: 0,
    mcp: 0,
    agents: 0
  };
  const templateInventoryDeductions = /* @__PURE__ */ new Map();
  for (const finding of findings) {
    const scoreCategory = mapToScoreCategory(finding.category);
    const deduction = (SCORE_DEDUCTIONS[finding.severity] ?? 0) * confidenceWeight(finding);
    if (isTemplateInventoryFinding(finding)) {
      const templateKey = `${scoreCategory}:${finding.file}`;
      templateInventoryDeductions.set(
        templateKey,
        (templateInventoryDeductions.get(templateKey) ?? 0) + deduction
      );
      continue;
    }
    categoryDeductions[scoreCategory] = (categoryDeductions[scoreCategory] ?? 0) + deduction;
  }
  for (const [templateKey, deduction] of templateInventoryDeductions) {
    const [scoreCategory] = templateKey.split(":", 1);
    categoryDeductions[scoreCategory] = (categoryDeductions[scoreCategory] ?? 0) + Math.min(deduction, TEMPLATE_EXAMPLE_CATEGORY_CAP);
  }
  const maxCategoryScore = 100;
  const breakdown = {
    secrets: roundedCategoryScore(maxCategoryScore, categoryDeductions.secrets),
    permissions: roundedCategoryScore(maxCategoryScore, categoryDeductions.permissions),
    hooks: roundedCategoryScore(maxCategoryScore, categoryDeductions.hooks),
    mcp: roundedCategoryScore(maxCategoryScore, categoryDeductions.mcp),
    agents: roundedCategoryScore(maxCategoryScore, categoryDeductions.agents)
  };
  const categoryScores = Object.values(breakdown);
  const numericScore = Math.round(
    categoryScores.reduce((sum, s) => sum + s, 0) / categoryScores.length
  );
  const grade = scoreToGrade(numericScore);
  return { grade, numericScore, breakdown };
}
function isTemplateInventoryFinding(finding) {
  return finding.runtimeConfidence === "template-example" && finding.category !== "secrets";
}
function confidenceWeight(finding) {
  if ((finding.runtimeConfidence === "template-example" || finding.runtimeConfidence === "docs-example") && finding.category !== "secrets") {
    return 0.25;
  }
  if (finding.runtimeConfidence === "project-local-optional" && finding.category !== "secrets") {
    return 0.75;
  }
  if (finding.runtimeConfidence === "plugin-manifest" && finding.category !== "secrets") {
    return 0.5;
  }
  return 1;
}
function roundedCategoryScore(maxCategoryScore, deduction) {
  return Math.max(0, Math.round(maxCategoryScore - deduction));
}
function mapToScoreCategory(category) {
  const mapping = {
    secrets: "secrets",
    permissions: "permissions",
    hooks: "hooks",
    mcp: "mcp",
    skills: "agents",
    agents: "agents",
    injection: "agents",
    // prompt injection → agents category
    exposure: "hooks",
    // data exposure via hooks/exfiltration
    misconfiguration: "permissions"
    // config issues → permissions
  };
  return mapping[category] ?? "agents";
}
function scoreToGrade(score) {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

// src/reporter/json.ts
function formatRuntimeConfidence(value) {
  switch (value) {
    case "active-runtime":
      return "active runtime";
    case "project-local-optional":
      return "project-local optional";
    case "template-example":
      return "template/example";
    case "docs-example":
      return "docs/example";
    case "plugin-manifest":
      return "plugin manifest";
    case "hook-code":
      return "hook-code implementation";
    default:
      return value;
  }
}
function renderJsonReport(report) {
  return JSON.stringify(report, null, 2);
}
function renderMarkdownReport(report) {
  const lines = [];
  const s = report.summary;
  lines.push("# AgentShield Security Report");
  lines.push("");
  lines.push(`**Date:** ${report.timestamp}`);
  lines.push(`**Target:** ${report.targetPath}`);
  lines.push(`**Grade:** ${report.score.grade} (${report.score.numericScore}/100)`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("|--------|-------|");
  lines.push(`| Files scanned | ${s.filesScanned} |`);
  lines.push(`| Total findings | ${s.totalFindings} |`);
  lines.push(`| Critical | ${s.critical} |`);
  lines.push(`| High | ${s.high} |`);
  lines.push(`| Medium | ${s.medium} |`);
  lines.push(`| Low | ${s.low} |`);
  lines.push(`| Info | ${s.info} |`);
  lines.push(`| Auto-fixable | ${s.autoFixable} |`);
  lines.push("");
  if (report.harnessAdapters) {
    lines.push("## Harness Adapters");
    lines.push("");
    lines.push(
      `Matched ${report.harnessAdapters.totalMatched}/${report.harnessAdapters.totalRegistered} registered adapters.`
    );
    lines.push("");
    if (report.harnessAdapters.matched.length > 0) {
      lines.push("| Adapter | Confidence | Evidence |");
      lines.push("|---------|------------|----------|");
      for (const adapter of report.harnessAdapters.matched) {
        const evidence = adapter.evidence.map((item) => `\`${item}\``).join(", ");
        lines.push(`| ${adapter.name} | ${adapter.confidence} | ${evidence} |`);
      }
      lines.push("");
    }
  }
  if (report.skillHealth && report.skillHealth.totalSkills > 0) {
    lines.push("## Skill Health");
    lines.push("");
    lines.push("| Metric | Value |");
    lines.push("|--------|-------|");
    lines.push(`| Skills discovered | ${report.skillHealth.totalSkills} |`);
    lines.push(`| Instrumented | ${report.skillHealth.instrumentedSkills} |`);
    lines.push(`| Versioned | ${report.skillHealth.versionedSkills} |`);
    lines.push(`| Rollback-ready | ${report.skillHealth.rollbackReadySkills} |`);
    lines.push(`| With history | ${report.skillHealth.observedSkills} |`);
    if (typeof report.skillHealth.averageScore === "number") {
      lines.push(`| Average health score | ${report.skillHealth.averageScore}/100 |`);
    }
    lines.push("");
  }
  const categoryLabels = {
    secrets: "Secrets",
    permissions: "Permissions",
    hooks: "Hooks",
    mcp: "MCP Servers",
    agents: "Agents"
  };
  lines.push("## Score Breakdown");
  lines.push("");
  lines.push("| Category | Score |");
  lines.push("|----------|-------|");
  for (const [key, score] of Object.entries(report.score.breakdown)) {
    const label = categoryLabels[key] ?? key;
    lines.push(`| ${label} | ${score}/100 |`);
  }
  lines.push("");
  if (report.findings.length > 0) {
    lines.push("## Findings");
    lines.push("");
    for (const finding of report.findings) {
      const emoji = finding.severity === "critical" ? "\u{1F534}" : finding.severity === "high" ? "\u{1F7E1}" : finding.severity === "medium" ? "\u{1F535}" : "\u26AA";
      lines.push(`### ${emoji} ${finding.title}`);
      lines.push("");
      lines.push(`- **Severity:** ${finding.severity}`);
      lines.push(`- **Category:** ${finding.category}`);
      if (finding.runtimeConfidence) {
        lines.push(`- **Runtime Confidence:** ${formatRuntimeConfidence(finding.runtimeConfidence)}`);
      }
      lines.push(`- **File:** \`${finding.file}${finding.line ? `:${finding.line}` : ""}\``);
      lines.push(`- **Description:** ${finding.description}`);
      if (finding.evidence) {
        lines.push(`- **Evidence:** \`${finding.evidence}\``);
      }
      if (finding.fix) {
        lines.push(`- **Fix:** ${finding.fix.description}`);
        if (finding.fix.auto) {
          lines.push("- **Auto-fixable:** Yes");
        }
      }
      lines.push("");
    }
  } else {
    lines.push("## No Issues Found");
    lines.push("");
    lines.push("No security issues were detected in the scanned configuration.");
  }
  return lines.join("\n");
}

// src/reporter/sarif.ts
var SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
function renderSarifReport(report, options = {}) {
  const rules = [
    ...buildFindingRules(report.findings),
    ...buildPolicyRules(options.policyEvaluation)
  ];
  const ruleIndexes = new Map(rules.map((rule, index) => [rule.id, index]));
  const policyUri = options.policyUri ?? ".agentshield/policy.json";
  return JSON.stringify(
    {
      version: "2.1.0",
      $schema: SARIF_SCHEMA,
      runs: [
        {
          tool: {
            driver: {
              name: "AgentShield",
              informationUri: "https://github.com/affaan-m/agentshield",
              rules
            }
          },
          automationDetails: {
            id: "agentshield/security-scan"
          },
          invocations: [
            {
              executionSuccessful: true,
              endTimeUtc: report.timestamp,
              workingDirectory: {
                uri: normalizeUri(report.targetPath)
              }
            }
          ],
          properties: {
            score: report.score.numericScore,
            grade: report.score.grade,
            filesScanned: report.summary.filesScanned,
            ...options.policyEvaluation ? {
              policyStatus: options.policyEvaluation.passed ? "compliant" : "non-compliant",
              policyViolations: options.policyEvaluation.violations.length,
              policyName: options.policyEvaluation.policyName,
              policyPack: options.policyEvaluation.policyPack
            } : {}
          },
          results: [
            ...report.findings.map(
              (finding) => renderFindingResult(finding, ruleIndexes.get(finding.id) ?? 0)
            ),
            ...renderPolicyResults(
              options.policyEvaluation,
              ruleIndexes,
              policyUri
            )
          ]
        }
      ]
    },
    null,
    2
  );
}
function buildFindingRules(findings) {
  const rules = /* @__PURE__ */ new Map();
  for (const finding of findings) {
    if (rules.has(finding.id)) continue;
    rules.set(finding.id, {
      id: finding.id,
      name: finding.title,
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.description },
      help: finding.fix ? { text: `${finding.description}

Recommended fix: ${finding.fix.description}` } : { text: finding.description },
      defaultConfiguration: {
        level: severityToLevel(finding.severity)
      },
      properties: {
        category: finding.category,
        severity: finding.severity,
        "security-severity": severityToSecurityScore(finding.severity),
        tags: ["security", "agent-config", finding.category],
        precision: precisionForFinding(finding)
      }
    });
  }
  return [...rules.values()];
}
function buildPolicyRules(evaluation) {
  if (!evaluation) return [];
  const rules = /* @__PURE__ */ new Map();
  for (const violation of evaluation.violations) {
    const ruleId = policyRuleId(violation);
    if (rules.has(ruleId)) continue;
    rules.set(ruleId, {
      id: ruleId,
      name: `Organization policy: ${violation.rule}`,
      shortDescription: {
        text: `Organization policy: ${violation.rule}`
      },
      fullDescription: {
        text: violation.description
      },
      help: {
        text: [
          violation.description,
          "",
          `Expected: ${violation.expected}`,
          `Actual: ${violation.actual}`
        ].join("\n")
      },
      defaultConfiguration: {
        level: severityToLevel(violation.severity)
      },
      properties: {
        category: "organization-policy",
        severity: violation.severity,
        "security-severity": severityToSecurityScore(violation.severity),
        tags: ["security", "agent-config", "organization-policy"],
        precision: "high",
        policyName: evaluation.policyName,
        policyPack: evaluation.policyPack,
        owners: evaluation.owners ?? []
      }
    });
  }
  return [...rules.values()];
}
function renderFindingResult(finding, ruleIndex) {
  return {
    ruleId: finding.id,
    ruleIndex,
    level: severityToLevel(finding.severity),
    message: {
      text: finding.description
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: normalizeUri(finding.file)
          },
          ...finding.line ? {
            region: {
              startLine: Math.max(1, finding.line)
            }
          } : {}
        }
      }
    ],
    properties: {
      title: finding.title,
      category: finding.category,
      severity: finding.severity,
      runtimeConfidence: finding.runtimeConfidence,
      evidence: finding.evidence,
      fix: finding.fix?.description
    }
  };
}
function renderPolicyResults(evaluation, ruleIndexes, policyUri) {
  if (!evaluation) return [];
  return evaluation.violations.map((violation) => {
    const ruleId = policyRuleId(violation);
    return {
      ruleId,
      ruleIndex: ruleIndexes.get(ruleId) ?? 0,
      level: severityToLevel(violation.severity),
      message: {
        text: violation.description
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: normalizeUri(policyUri)
            }
          }
        }
      ],
      properties: {
        source: "organization-policy",
        policyName: evaluation.policyName,
        policyPack: evaluation.policyPack,
        owners: evaluation.owners ?? [],
        rule: violation.rule,
        severity: violation.severity,
        expected: violation.expected,
        actual: violation.actual
      }
    };
  });
}
function policyRuleId(violation) {
  return `agentshield-policy/${violation.rule}`;
}
function severityToLevel(severity) {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
  }
}
function severityToSecurityScore(severity) {
  switch (severity) {
    case "critical":
      return "9.5";
    case "high":
      return "8.0";
    case "medium":
      return "5.0";
    case "low":
      return "2.5";
    case "info":
      return "1.0";
  }
}
function precisionForFinding(finding) {
  if (finding.runtimeConfidence === "active-runtime") return "very-high";
  if (finding.runtimeConfidence === "template-example" || finding.runtimeConfidence === "docs-example") {
    return "medium";
  }
  return "high";
}
function normalizeUri(uri) {
  return uri.replace(/\\/g, "/");
}

// src/evidence-pack/index.ts
import { createHash as createHash2 } from "crypto";
import { existsSync as existsSync3, mkdirSync as mkdirSync2, readFileSync as readFileSync2, writeFileSync as writeFileSync2 } from "fs";
import { basename as basename3, resolve as resolve3 } from "path";
import { homedir as homedir2 } from "os";

// src/remediation/index.ts
init_fingerprint();
import { mkdirSync, writeFileSync } from "fs";
import { dirname as dirname2, resolve as resolve2 } from "path";
var ZERO_BY_SEVERITY = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0
};
var SEVERITY_RANK = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};
function buildRemediationPlan(report, options = {}) {
  const findings = [...report.findings].sort(compareFindings).map((finding) => toPlanFinding(finding));
  return {
    schemaVersion: 1,
    generatedAt: options.generatedAt ?? (/* @__PURE__ */ new Date()).toISOString(),
    targetPath: report.targetPath,
    score: {
      grade: report.score.grade,
      numericScore: report.score.numericScore
    },
    summary: {
      totalFindings: findings.length,
      autoFixable: findings.filter((finding) => finding.action === "auto-fix").length,
      manualReview: findings.filter((finding) => finding.action === "manual-review").length,
      bySeverity: countBySeverity(report.findings)
    },
    workflow: buildWorkflow(findings),
    findings
  };
}
function toPlanFinding(finding) {
  const autoFixable = finding.fix?.auto === true;
  return {
    fingerprint: fingerprintFinding(finding),
    id: finding.id,
    severity: finding.severity,
    category: finding.category,
    title: finding.title,
    description: finding.description,
    file: finding.file,
    line: finding.line,
    runtimeConfidence: finding.runtimeConfidence,
    hasEvidence: Boolean(finding.evidence),
    action: autoFixable ? "auto-fix" : "manual-review",
    recommendedCommand: autoFixable ? "agentshield scan --fix" : "Review finding and apply the remediation in source control.",
    fix: finding.fix ? {
      description: finding.fix.description,
      auto: finding.fix.auto
    } : void 0
  };
}
function countBySeverity(findings) {
  const counts = { ...ZERO_BY_SEVERITY };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}
function buildWorkflow(findings) {
  const autoFixable = findings.filter((finding) => finding.action === "auto-fix");
  const manualReview = findings.filter((finding) => finding.action === "manual-review");
  const phases = [];
  if (autoFixable.length > 0) {
    phases.push({
      id: "auto-fix",
      title: "Apply safe auto-fixes",
      description: "Run the fix engine first for findings explicitly marked auto-fixable, then review the diff before committing.",
      command: "agentshield scan --fix",
      findingCount: autoFixable.length,
      findingFingerprints: autoFixable.map((finding) => finding.fingerprint),
      blocking: false
    });
  }
  if (manualReview.length > 0) {
    phases.push({
      id: "manual-review",
      title: "Resolve manual findings",
      description: "Apply the finding-specific remediation notes in source control for items that require maintainer judgment.",
      command: "Review finding-specific remediation notes in source control.",
      findingCount: manualReview.length,
      findingFingerprints: manualReview.map((finding) => finding.fingerprint),
      blocking: true
    });
  }
  if (findings.length > 0) {
    phases.push({
      id: "verify",
      title: "Verify clean scan",
      description: "Re-run AgentShield after remediation and gate on the updated result before merging or publishing.",
      command: "agentshield scan --gate",
      findingCount: findings.length,
      findingFingerprints: findings.map((finding) => finding.fingerprint),
      blocking: true
    });
  }
  return { phases };
}
function compareFindings(left, right) {
  return SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity] || left.file.localeCompare(right.file) || left.id.localeCompare(right.id) || (left.evidence ?? "").localeCompare(right.evidence ?? "");
}

// src/reporter/html.ts
function renderHtmlReport(report) {
  const gradeMeta = gradeMetadata(report.score.grade);
  const findings = [...report.findings];
  const s = report.summary;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AgentShield Security Report \u2014 Grade ${report.score.grade}</title>
  <style>${inlineStyles()}</style>
</head>
<body>
  <div class="container">

    <!-- Header -->
    <header class="header">
      <div class="header-content">
        <div class="grade-badge" style="background-color: ${gradeMeta.color};">
          <span class="grade-letter">${report.score.grade}</span>
        </div>
        <div class="header-info">
          <h1 class="title">AgentShield Security Report</h1>
          <p class="subtitle">Score: <strong>${report.score.numericScore}</strong>/100</p>
          <p class="meta">Target: ${escapeHtml(report.targetPath)}</p>
          <p class="meta">Scanned: ${formatTimestamp(report.timestamp)}</p>
        </div>
      </div>
    </header>

    ${renderExecutiveSummary(report)}

    <!-- Summary Stats -->
    <section class="section">
      <h2 class="section-title">Summary</h2>
      <div class="stats-grid">
        ${renderStatCard("Files Scanned", String(s.filesScanned), "files")}
        ${renderStatCard("Total Findings", String(s.totalFindings), "findings")}
        ${renderStatCard("Auto-Fixable", String(s.autoFixable), "fixable")}
        ${renderStatCard("Critical", String(s.critical), "critical")}
        ${renderStatCard("High", String(s.high), "high")}
        ${renderStatCard("Medium", String(s.medium), "medium")}
        ${renderStatCard("Low", String(s.low), "low")}
        ${renderStatCard("Info", String(s.info), "info")}
      </div>
    </section>

    <!-- Score Breakdown -->
    <section class="section">
      <h2 class="section-title">Score Breakdown</h2>
      <div class="breakdown">
        ${renderScoreBar("Secrets", report.score.breakdown.secrets)}
        ${renderScoreBar("Permissions", report.score.breakdown.permissions)}
        ${renderScoreBar("Hooks", report.score.breakdown.hooks)}
        ${renderScoreBar("MCP Servers", report.score.breakdown.mcp)}
        ${renderScoreBar("Agents", report.score.breakdown.agents)}
      </div>
    </section>

    ${report.harnessAdapters ? `<section class="section">
      <h2 class="section-title">Harness Adapters</h2>
      <p class="executive-copy">Matched ${report.harnessAdapters.totalMatched}/${report.harnessAdapters.totalRegistered} registered adapters.</p>
      <div>
        ${report.harnessAdapters.matched.length === 0 ? '<p class="executive-copy muted">No harness-specific markers were detected.</p>' : report.harnessAdapters.matched.map((adapter) => renderHarnessAdapterCard(adapter)).join("")}
      </div>
    </section>` : ""}

    ${report.skillHealth && report.skillHealth.totalSkills > 0 ? `<section class="section">
      <h2 class="section-title">Skill Health</h2>
      <div class="stats-grid">
        ${renderStatCard("Skills", String(report.skillHealth.totalSkills), "files")}
        ${renderStatCard("Instrumented", String(report.skillHealth.instrumentedSkills), "fixable")}
        ${renderStatCard("Versioned", String(report.skillHealth.versionedSkills), "medium")}
        ${renderStatCard("Rollback-ready", String(report.skillHealth.rollbackReadySkills), "high")}
        ${renderStatCard("With history", String(report.skillHealth.observedSkills), "info")}
        ${typeof report.skillHealth.averageScore === "number" ? renderStatCard("Avg health", `${report.skillHealth.averageScore}/100`, "findings") : ""}
      </div>
      <div>
        ${report.skillHealth.skills.map((skill) => renderSkillHealthCard(skill)).join("")}
      </div>
    </section>` : ""}

    <!-- Severity Distribution -->
    <section class="section">
      <h2 class="section-title">Severity Distribution</h2>
      <div class="distribution">
        ${renderDistributionChart(s)}
      </div>
    </section>

    <!-- Findings -->
    <section class="section">
      <h2 class="section-title">Findings</h2>
      ${findings.length === 0 ? '<div class="no-findings"><p>No security issues found. Your configuration looks good!</p></div>' : renderFindingsGrouped(findings)}
    </section>

    <!-- Footer -->
    <footer class="footer">
      <p>Generated by <strong>AgentShield</strong> &mdash; Security auditor for AI agent configurations</p>
      <p class="footer-timestamp">${formatTimestamp(report.timestamp)}</p>
    </footer>

  </div>
</body>
</html>`;
}
function renderExecutiveSummary(report) {
  const posture = executivePosture(report);
  const priorities = executivePriorityFindings(report.findings);
  const priorityItems = priorities.length === 0 ? '<li class="priority-item muted">No executive action items.</li>' : priorities.map((finding) => {
    const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
    return `<li class="priority-item">
            <span class="priority-severity" style="background-color: ${severityColor(finding.severity)};">${finding.severity.toUpperCase()}</span>
            <span>
              <strong>${escapeHtml(finding.title)}</strong>
              <span class="priority-meta">${escapeHtml(location)} - ${escapeHtml(finding.category)}</span>
            </span>
          </li>`;
  }).join("");
  return `
    <!-- Executive Summary -->
    <section class="section executive-summary">
      <h2 class="section-title">Executive Summary</h2>
      <div class="executive-grid">
        <div class="executive-card posture-card" style="border-color: ${posture.color};">
          <span class="executive-label">Risk Posture</span>
          <strong class="posture-title" style="color: ${posture.color};">${escapeHtml(posture.label)}</strong>
          <p class="executive-copy">${escapeHtml(posture.detail)}</p>
        </div>
        <div class="executive-card">
          <span class="executive-label">Executive Priorities</span>
          <ul class="priority-list">${priorityItems}</ul>
        </div>
        <div class="executive-card">
          <span class="executive-label">Category Exposure</span>
          ${renderCategoryExposure(report.findings)}
        </div>
      </div>
    </section>`;
}
function executivePosture(report) {
  const { summary } = report;
  if (summary.critical > 0) {
    return {
      label: "Immediate remediation required",
      detail: formatOwnerReviewDetail(summary.critical, summary.high),
      color: "#f85149"
    };
  }
  if (summary.high > 0) {
    return {
      label: "High-risk changes need review",
      detail: `${summary.high} high-severity findings require owner review before rollout.`,
      color: "#d29922"
    };
  }
  if (summary.medium > 0) {
    return {
      label: "Monitor before broad rollout",
      detail: `${summary.medium} medium-severity findings should be reviewed before broad rollout.`,
      color: "#388bfd"
    };
  }
  return {
    label: "Ready for standard rollout",
    detail: "No critical or high-severity findings were detected.",
    color: "#2ea043"
  };
}
function formatOwnerReviewDetail(critical, high) {
  if (critical > 0 && high > 0) {
    return `${critical} critical and ${high} high-severity findings require owner review.`;
  }
  if (critical > 0) {
    return `${critical} critical findings require owner review.`;
  }
  return `${high} high-severity findings require owner review before rollout.`;
}
function executivePriorityFindings(findings) {
  const severityRank = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
  };
  return findings.filter((finding) => finding.severity === "critical" || finding.severity === "high").slice().sort((a, b) => severityRank[a.severity] - severityRank[b.severity]).slice(0, 5);
}
function renderCategoryExposure(findings) {
  if (findings.length === 0) {
    return '<p class="executive-copy muted">No category exposure to display.</p>';
  }
  const categoryCounts = /* @__PURE__ */ new Map();
  for (const finding of findings) {
    categoryCounts.set(finding.category, (categoryCounts.get(finding.category) ?? 0) + 1);
  }
  const rows = [...categoryCounts.entries()].sort(([leftCategory, leftCount], [rightCategory, rightCount]) => {
    if (rightCount !== leftCount) return rightCount - leftCount;
    return leftCategory.localeCompare(rightCategory);
  }).map(([category, count]) => {
    const noun = count === 1 ? "finding" : "findings";
    return `<div class="exposure-row">
        <span class="exposure-category">${escapeHtml(category)}</span>
        <span class="exposure-count">${count} ${noun}</span>
      </div>`;
  }).join("");
  return `<div class="exposure-grid">${rows}</div>`;
}
function gradeMetadata(grade) {
  const map = {
    A: { color: "#2ea043", label: "Excellent" },
    B: { color: "#388bfd", label: "Good" },
    C: { color: "#d29922", label: "Fair" },
    D: { color: "#db6d28", label: "Poor" },
    F: { color: "#f85149", label: "Critical" }
  };
  return map[grade];
}
function severityColor(severity) {
  const colors = {
    critical: "#f85149",
    high: "#d29922",
    medium: "#388bfd",
    low: "#8b949e",
    info: "#6e7681"
  };
  return colors[severity];
}
function scoreBarColor(score) {
  if (score >= 80) return "#2ea043";
  if (score >= 60) return "#d29922";
  return "#f85149";
}
function renderScoreBar(label, score) {
  const color = scoreBarColor(score);
  const pct = Math.max(0, Math.min(100, score));
  return `
    <div class="bar-row">
      <span class="bar-label">${escapeHtml(label)}</span>
      <div class="bar-track">
        <div class="bar-fill" style="width: ${pct}%; background-color: ${color};"></div>
      </div>
      <span class="bar-value" style="color: ${color};">${score}/100</span>
    </div>`;
}
function renderStatCard(label, value, kind) {
  const kindColorMap = {
    files: "#8b949e",
    findings: "#e6edf3",
    fixable: "#2ea043",
    critical: "#f85149",
    high: "#d29922",
    medium: "#388bfd",
    low: "#8b949e",
    info: "#6e7681"
  };
  const color = kindColorMap[kind] ?? "#e6edf3";
  return `
    <div class="stat-card">
      <div class="stat-value" style="color: ${color};">${escapeHtml(value)}</div>
      <div class="stat-label">${escapeHtml(label)}</div>
    </div>`;
}
function renderDistributionChart(summary) {
  const segments = [
    { label: "Critical", count: summary.critical, color: "#f85149" },
    { label: "High", count: summary.high, color: "#d29922" },
    { label: "Medium", count: summary.medium, color: "#388bfd" },
    { label: "Low", count: summary.low, color: "#8b949e" },
    { label: "Info", count: summary.info, color: "#6e7681" }
  ];
  const total = segments.reduce((acc, seg) => acc + seg.count, 0);
  if (total === 0) {
    return '<p class="no-findings-text">No findings to display.</p>';
  }
  const barWidth = 600;
  const barHeight = 32;
  let xOffset = 0;
  const rects = segments.map((seg) => {
    const width = total > 0 ? seg.count / total * barWidth : 0;
    const rect = width > 0 ? `<rect x="${xOffset}" y="0" width="${width}" height="${barHeight}" fill="${seg.color}" rx="0" />` : "";
    xOffset += width;
    return rect;
  });
  const legend = segments.filter((seg) => seg.count > 0).map(
    (seg) => `<span class="legend-item"><span class="legend-dot" style="background-color: ${seg.color};"></span>${escapeHtml(seg.label)}: ${seg.count}</span>`
  ).join("");
  return `
    <svg class="dist-bar" viewBox="0 0 ${barWidth} ${barHeight}" preserveAspectRatio="none">
      <rect x="0" y="0" width="${barWidth}" height="${barHeight}" fill="#21262d" rx="6" />
      <clipPath id="bar-clip"><rect x="0" y="0" width="${barWidth}" height="${barHeight}" rx="6" /></clipPath>
      <g clip-path="url(#bar-clip)">${rects.join("")}</g>
    </svg>
    <div class="legend">${legend}</div>`;
}
function renderFindingsGrouped(findings) {
  const severities = ["critical", "high", "medium", "low", "info"];
  const grouped = severities.map(
    (sev) => [sev, findings.filter((f) => f.severity === sev)]
  );
  return grouped.filter(([, items]) => items.length > 0).map(([sev, items]) => {
    const color = severityColor(sev);
    const cards = items.map((f) => renderFindingCard(f)).join("");
    return `
        <div class="findings-group">
          <h3 class="group-header" style="color: ${color};">
            <span class="severity-dot" style="background-color: ${color};"></span>
            ${sev.toUpperCase()} (${items.length})
          </h3>
          ${cards}
        </div>`;
  }).join("");
}
function renderFindingCard(finding) {
  const color = severityColor(finding.severity);
  const location = finding.line ? `${escapeHtml(finding.file)}:${finding.line}` : escapeHtml(finding.file);
  const runtimeConfidenceBadge = finding.runtimeConfidence ? `<span class="runtime-confidence-badge">${escapeHtml(formatRuntimeConfidence2(finding.runtimeConfidence))}</span>` : "";
  const evidenceBlock = finding.evidence ? `<div class="finding-evidence"><strong>Evidence:</strong><pre><code>${escapeHtml(finding.evidence)}</code></pre></div>` : "";
  const fixBlock = finding.fix ? `<div class="finding-fix">
        <strong>Fix:</strong> ${escapeHtml(finding.fix.description)}
        ${finding.fix.auto ? '<span class="auto-fix-badge">auto-fixable</span>' : ""}
        ${finding.fix.before ? `<div class="fix-diff"><div class="diff-before"><strong>Before:</strong><pre><code>${escapeHtml(finding.fix.before)}</code></pre></div><div class="diff-after"><strong>After:</strong><pre><code>${escapeHtml(finding.fix.after)}</code></pre></div></div>` : ""}
      </div>` : "";
  return `
    <div class="finding-card">
      <div class="finding-header">
        <span class="severity-badge" style="background-color: ${color};">${finding.severity.toUpperCase()}</span>
        ${runtimeConfidenceBadge}
        <span class="finding-title">${escapeHtml(finding.title)}</span>
      </div>
      <div class="finding-meta">
        <span class="finding-category">${escapeHtml(finding.category)}</span>
        <span class="finding-location">${location}</span>
      </div>
      <p class="finding-description">${escapeHtml(finding.description)}</p>
      ${evidenceBlock}
      ${fixBlock}
    </div>`;
}
function renderSkillHealthCard(skill) {
  const score = typeof skill.score === "number" ? `${skill.score}/100` : "unobserved";
  const detail = typeof skill.successRate === "number" ? `Runs ${skill.observedRuns} \u2022 Success ${Math.round(skill.successRate * 100)}%${typeof skill.averageFeedback === "number" ? ` \u2022 Feedback ${skill.averageFeedback.toFixed(1)}/5` : ""}` : "No execution history found";
  return `
    <div class="finding-card">
      <div class="finding-header">
        <span class="runtime-confidence-badge">${escapeHtml(skill.status)}</span>
        <span class="finding-title">${escapeHtml(skill.skillName)}</span>
      </div>
      <div class="finding-meta">
        <span class="finding-category">skill health</span>
        <span class="finding-location">${escapeHtml(skill.file)}</span>
      </div>
      <p class="finding-description">${escapeHtml(`${score} \u2014 ${detail}`)}</p>
    </div>`;
}
function renderHarnessAdapterCard(adapter) {
  const evidence = adapter.evidence.length > 0 ? adapter.evidence.map((item) => `<code>${escapeHtml(item)}</code>`).join(", ") : "No markers";
  return `
    <div class="finding-card">
      <div class="finding-header">
        <span class="runtime-confidence-badge">${escapeHtml(adapter.confidence)}</span>
        <span class="finding-title">${escapeHtml(adapter.name)}</span>
      </div>
      <div class="finding-meta">
        <span class="finding-category">harness adapter</span>
        <span class="finding-location">${evidence}</span>
      </div>
      <p class="finding-description">${escapeHtml(adapter.description)}</p>
      <p class="finding-description"><strong>Permission concepts:</strong> ${escapeHtml(adapter.permissionConcepts.join(", "))}</p>
      <p class="finding-description"><strong>Plugin surfaces:</strong> ${escapeHtml(adapter.pluginSurfaces.join(", "))}</p>
    </div>`;
}
function formatRuntimeConfidence2(value) {
  switch (value) {
    case "active-runtime":
      return "active runtime";
    case "project-local-optional":
      return "project-local optional";
    case "template-example":
      return "template/example";
    case "docs-example":
      return "docs/example";
    case "plugin-manifest":
      return "plugin manifest";
    case "hook-code":
      return "hook-code implementation";
  }
}
function formatTimestamp(iso) {
  try {
    const date = new Date(iso);
    return date.toLocaleString("en-US", {
      weekday: "long",
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZoneName: "short"
    });
  } catch {
    return iso;
  }
}
function escapeHtml(text) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
function inlineStyles() {
  return `
    /* Reset & Base */
    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
      background-color: #0d1117;
      color: #e6edf3;
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
    }

    .container {
      max-width: 960px;
      margin: 0 auto;
      padding: 24px 16px;
    }

    /* Header */
    .header {
      background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 32px;
      margin-bottom: 24px;
    }

    .header-content {
      display: flex;
      align-items: center;
      gap: 32px;
      flex-wrap: wrap;
    }

    .grade-badge {
      width: 120px;
      height: 120px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      box-shadow: 0 0 40px rgba(0, 0, 0, 0.4);
    }

    .grade-letter {
      font-size: 64px;
      font-weight: 800;
      color: #ffffff;
      text-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    }

    .header-info {
      flex: 1;
      min-width: 200px;
    }

    .title {
      font-size: 28px;
      font-weight: 700;
      color: #e6edf3;
      margin-bottom: 4px;
    }

    .subtitle {
      font-size: 20px;
      color: #8b949e;
      margin-bottom: 8px;
    }

    .subtitle strong {
      color: #e6edf3;
      font-size: 24px;
    }

    .meta {
      font-size: 14px;
      color: #6e7681;
      margin-bottom: 2px;
    }

    /* Section */
    .section {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }

    .section-title {
      font-size: 20px;
      font-weight: 600;
      color: #e6edf3;
      margin-bottom: 16px;
      padding-bottom: 8px;
      border-bottom: 1px solid #21262d;
    }

    /* Executive Summary */
    .executive-summary {
      border-color: #3d444d;
    }

    .executive-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(0, 1fr);
      gap: 12px;
    }

    .executive-card {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 8px;
      padding: 16px;
    }

    .posture-card {
      grid-row: span 2;
    }

    .executive-label {
      display: block;
      font-size: 12px;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }

    .posture-title {
      display: block;
      font-size: 18px;
      margin-bottom: 8px;
    }

    .executive-copy {
      font-size: 14px;
      color: #8b949e;
    }

    .muted {
      color: #8b949e;
    }

    .priority-list {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .priority-item {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      font-size: 14px;
      color: #e6edf3;
    }

    .priority-severity {
      color: #ffffff;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.5px;
      border-radius: 10px;
      padding: 2px 7px;
      flex-shrink: 0;
      margin-top: 2px;
    }

    .priority-meta {
      display: block;
      color: #8b949e;
      font-size: 12px;
      margin-top: 2px;
      overflow-wrap: anywhere;
    }

    .exposure-grid {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .exposure-row {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      border-bottom: 1px solid #21262d;
      padding-bottom: 8px;
      font-size: 14px;
    }

    .exposure-row:last-child {
      border-bottom: 0;
      padding-bottom: 0;
    }

    .exposure-category {
      color: #e6edf3;
      font-weight: 600;
    }

    .exposure-count {
      color: #8b949e;
      white-space: nowrap;
    }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
      gap: 12px;
    }

    .stat-card {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }

    .stat-value {
      font-size: 28px;
      font-weight: 700;
      line-height: 1.2;
    }

    .stat-label {
      font-size: 12px;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-top: 4px;
    }

    /* Score Breakdown Bars */
    .breakdown {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .bar-row {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .bar-label {
      width: 120px;
      font-size: 14px;
      color: #8b949e;
      text-align: right;
      flex-shrink: 0;
    }

    .bar-track {
      flex: 1;
      height: 20px;
      background: #21262d;
      border-radius: 10px;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      border-radius: 10px;
      transition: width 0.3s ease;
    }

    .bar-value {
      width: 70px;
      font-size: 14px;
      font-weight: 600;
      text-align: right;
      flex-shrink: 0;
    }

    /* Distribution */
    .distribution {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .dist-bar {
      width: 100%;
      height: 32px;
      border-radius: 6px;
    }

    .legend {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
    }

    .legend-item {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      color: #8b949e;
    }

    .legend-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
      flex-shrink: 0;
    }

    .no-findings-text {
      color: #8b949e;
      font-style: italic;
    }

    /* Findings */
    .findings-group {
      margin-bottom: 20px;
    }

    .group-header {
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .severity-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
      flex-shrink: 0;
    }

    .finding-card {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 12px;
    }

    .finding-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 8px;
      flex-wrap: wrap;
    }

    .severity-badge {
      font-size: 11px;
      font-weight: 700;
      color: #ffffff;
      padding: 2px 8px;
      border-radius: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      flex-shrink: 0;
    }

    .runtime-confidence-badge {
      font-size: 11px;
      font-weight: 600;
      color: #c9d1d9;
      background: #161b22;
      border: 1px solid #30363d;
      padding: 2px 8px;
      border-radius: 12px;
      text-transform: uppercase;
      letter-spacing: 0.3px;
      flex-shrink: 0;
    }

    .finding-title {
      font-size: 16px;
      font-weight: 600;
      color: #e6edf3;
    }

    .finding-meta {
      display: flex;
      gap: 16px;
      margin-bottom: 8px;
      flex-wrap: wrap;
    }

    .finding-category {
      font-size: 12px;
      color: #8b949e;
      background: #21262d;
      padding: 2px 8px;
      border-radius: 4px;
    }

    .finding-location {
      font-size: 12px;
      color: #6e7681;
      font-family: 'SF Mono', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
    }

    .finding-description {
      font-size: 14px;
      color: #8b949e;
      margin-bottom: 8px;
    }

    .finding-evidence {
      margin-top: 8px;
    }

    .finding-evidence strong,
    .finding-fix strong {
      font-size: 12px;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.3px;
    }

    .finding-evidence pre,
    .fix-diff pre {
      background: #161b22;
      border: 1px solid #21262d;
      border-radius: 6px;
      padding: 12px;
      margin-top: 4px;
      overflow-x: auto;
    }

    .finding-evidence code,
    .fix-diff code {
      font-family: 'SF Mono', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
      font-size: 13px;
      color: #e6edf3;
      white-space: pre-wrap;
      word-break: break-all;
    }

    .finding-fix {
      margin-top: 12px;
      font-size: 14px;
      color: #8b949e;
    }

    .auto-fix-badge {
      display: inline-block;
      font-size: 11px;
      font-weight: 600;
      color: #2ea043;
      background: rgba(46, 160, 67, 0.15);
      border: 1px solid rgba(46, 160, 67, 0.4);
      padding: 1px 6px;
      border-radius: 4px;
      margin-left: 8px;
    }

    .fix-diff {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      margin-top: 8px;
    }

    .diff-before strong {
      color: #f85149;
    }

    .diff-after strong {
      color: #2ea043;
    }

    .no-findings {
      background: rgba(46, 160, 67, 0.1);
      border: 1px solid rgba(46, 160, 67, 0.3);
      border-radius: 8px;
      padding: 24px;
      text-align: center;
      color: #2ea043;
      font-size: 16px;
    }

    /* Footer */
    .footer {
      text-align: center;
      padding: 24px;
      color: #6e7681;
      font-size: 13px;
      border-top: 1px solid #21262d;
      margin-top: 12px;
    }

    .footer strong {
      color: #8b949e;
    }

    .footer-timestamp {
      margin-top: 4px;
      font-size: 12px;
    }

    /* Responsive */
    @media (max-width: 640px) {
      .header-content {
        flex-direction: column;
        text-align: center;
      }

      .bar-label {
        width: 80px;
        font-size: 12px;
      }

      .bar-value {
        width: 60px;
        font-size: 12px;
      }

      .fix-diff {
        grid-template-columns: 1fr;
      }

      .executive-grid {
        grid-template-columns: 1fr;
      }

      .posture-card {
        grid-row: auto;
      }

      .stats-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }
  `;
}

// src/evidence-pack/index.ts
var ARTIFACTS = [
  {
    file: "manifest.json",
    kind: "manifest",
    description: "Machine-readable inventory of evidence-pack artifacts."
  },
  {
    file: "README.md",
    kind: "readme",
    description: "Human-readable guide to the bundle contents."
  },
  {
    file: "agentshield-report.json",
    kind: "scan-json",
    description: "Primary AgentShield JSON security report."
  },
  {
    file: "agentshield-report.html",
    kind: "scan-html",
    description: "Self-contained executive HTML report."
  },
  {
    file: "agentshield-results.sarif",
    kind: "sarif",
    description: "SARIF 2.1.0 code-scanning report."
  },
  {
    file: "policy-evaluation.json",
    kind: "policy",
    description: "Organization policy evaluation, or a not-run marker."
  },
  {
    file: "baseline-comparison.json",
    kind: "baseline",
    description: "Baseline drift comparison, or a not-run marker."
  },
  {
    file: "supply-chain.json",
    kind: "supply-chain",
    description: "MCP package provenance and supply-chain verification summary."
  },
  {
    file: "ci-context.json",
    kind: "ci-context",
    description: "Whitelisted CI, commit, workflow, and runner provenance for the scan."
  },
  {
    file: "remediation-plan.json",
    kind: "remediation",
    description: "Stable-fingerprint remediation queue for ticketing and CI handoffs."
  }
];
var BUNDLE_DIGEST_EXCLUDED_FILES = /* @__PURE__ */ new Set(["manifest.json", "README.md"]);
function writeEvidencePack(options) {
  const outputDir = resolve3(options.outputDir);
  const generatedAt = options.generatedAt ?? (/* @__PURE__ */ new Date()).toISOString();
  const redacted = options.redact ?? true;
  const redactor = createRedactor(options.report.targetPath, redacted);
  const report = redactor.value(options.report);
  const policyEvaluation = options.policyEvaluation ? redactor.value(options.policyEvaluation) : {
    status: "not-run",
    reason: "No --policy file was provided for this scan."
  };
  const baselineComparison = options.baselineComparison ? redactor.value(options.baselineComparison) : {
    status: "not-run",
    reason: "No --baseline file was provided for this scan."
  };
  const supplyChainReport = redactor.value(options.supplyChainReport);
  const ciContext = redactor.value(
    options.ciContext ?? buildCiContext(options.environment ?? process.env, generatedAt)
  );
  const remediationPlan = buildRemediationPlan(report, { generatedAt });
  const artifactContents = /* @__PURE__ */ new Map([
    ["agentshield-report.json", normalizeText(renderJsonReport(report))],
    ["agentshield-report.html", normalizeText(renderHtmlReport(report))],
    [
      "agentshield-results.sarif",
      normalizeText(renderSarifReport(report, {
        policyEvaluation: options.policyEvaluation ? policyEvaluation : void 0,
        policyUri: options.policyPath ? redactor.string(options.policyPath) : void 0
      }))
    ],
    ["policy-evaluation.json", normalizeText(redactor.json(policyEvaluation))],
    ["baseline-comparison.json", normalizeText(redactor.json(baselineComparison))],
    ["supply-chain.json", normalizeText(redactor.json(supplyChainReport))],
    ["ci-context.json", normalizeText(redactor.json(ciContext))],
    ["remediation-plan.json", normalizeText(redactor.json(remediationPlan))]
  ]);
  const bundleDigest = buildBundleDigest(artifactContents);
  const readmeManifest = {
    schemaVersion: 1,
    generatedAt,
    generator: "agentshield",
    redacted,
    targetPath: redactor.string(options.report.targetPath),
    bundleDigest,
    artifacts: buildArtifactManifestEntries(artifactContents)
  };
  artifactContents.set("README.md", normalizeText(renderReadme(readmeManifest, options, ciContext)));
  const manifest = {
    ...readmeManifest,
    artifacts: buildArtifactManifestEntries(artifactContents)
  };
  artifactContents.set("manifest.json", normalizeText(redactor.json(manifest)));
  mkdirSync2(outputDir, { recursive: true });
  for (const artifact of ARTIFACTS) {
    writeText(outputDir, artifact.file, artifactContents.get(artifact.file) ?? "");
  }
  return {
    outputDir,
    files: ARTIFACTS.map((artifact) => artifact.file)
  };
}
function verifyEvidencePack(outputDir) {
  const resolvedOutputDir = resolve3(outputDir);
  const manifestPath = resolve3(resolvedOutputDir, "manifest.json");
  const errors = [];
  if (!existsSync3(manifestPath)) {
    return {
      ok: false,
      outputDir: resolvedOutputDir,
      bundleDigest: null,
      expectedBundleDigest: null,
      artifacts: [],
      errors: ["manifest.json is missing"]
    };
  }
  let manifest;
  try {
    manifest = JSON.parse(readFileSync2(manifestPath, "utf-8"));
  } catch (error) {
    return {
      ok: false,
      outputDir: resolvedOutputDir,
      bundleDigest: null,
      expectedBundleDigest: null,
      artifacts: [],
      errors: [`manifest.json is not valid JSON: ${error instanceof Error ? error.message : String(error)}`]
    };
  }
  const artifactContents = /* @__PURE__ */ new Map();
  const artifacts = manifest.artifacts.map((artifact) => {
    const artifactPath = resolve3(resolvedOutputDir, artifact.file);
    if (artifact.file === "manifest.json") {
      return {
        file: artifact.file,
        ok: artifact.sha256 === null && artifact.bytes === null,
        expectedSha256: artifact.sha256,
        actualSha256: null,
        expectedBytes: artifact.bytes,
        actualBytes: null
      };
    }
    if (!existsSync3(artifactPath)) {
      errors.push(`${artifact.file} is missing`);
      return {
        file: artifact.file,
        ok: false,
        expectedSha256: artifact.sha256,
        actualSha256: null,
        expectedBytes: artifact.bytes,
        actualBytes: null
      };
    }
    const content = readFileSync2(artifactPath, "utf-8");
    artifactContents.set(artifact.file, content);
    const actual = hashContent(content);
    const ok = actual.sha256 === artifact.sha256 && actual.bytes === artifact.bytes;
    if (!ok) {
      errors.push(`${artifact.file} digest mismatch`);
    }
    return {
      file: artifact.file,
      ok,
      expectedSha256: artifact.sha256,
      actualSha256: actual.sha256,
      expectedBytes: artifact.bytes,
      actualBytes: actual.bytes
    };
  });
  const bundleDigest = buildBundleDigest(artifactContents);
  if (bundleDigest !== manifest.bundleDigest) {
    errors.push("bundle digest mismatch");
  }
  return {
    ok: errors.length === 0 && artifacts.every((artifact) => artifact.ok),
    outputDir: resolvedOutputDir,
    bundleDigest,
    expectedBundleDigest: manifest.bundleDigest,
    artifacts,
    errors
  };
}
function buildCiContext(environment, generatedAt) {
  const github = compact({
    repository: environment.GITHUB_REPOSITORY,
    repositoryId: environment.GITHUB_REPOSITORY_ID,
    workflow: environment.GITHUB_WORKFLOW,
    workflowRef: environment.GITHUB_WORKFLOW_REF,
    job: environment.GITHUB_JOB,
    runId: environment.GITHUB_RUN_ID,
    runAttempt: environment.GITHUB_RUN_ATTEMPT,
    runNumber: environment.GITHUB_RUN_NUMBER,
    actor: environment.GITHUB_ACTOR,
    eventName: environment.GITHUB_EVENT_NAME,
    ref: environment.GITHUB_REF,
    sha: environment.GITHUB_SHA,
    headRef: environment.GITHUB_HEAD_REF,
    baseRef: environment.GITHUB_BASE_REF,
    serverUrl: environment.GITHUB_SERVER_URL
  });
  const runtime = {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    cwd: process.cwd(),
    ...compact({
      name: environment.RUNNER_NAME,
      os: environment.RUNNER_OS,
      archLabel: environment.RUNNER_ARCH,
      environment: environment.RUNNER_ENVIRONMENT,
      temp: environment.RUNNER_TEMP,
      toolCache: environment.RUNNER_TOOL_CACHE
    })
  };
  return {
    schemaVersion: 1,
    generatedAt,
    provider: environment.GITHUB_ACTIONS === "true" ? "github-actions" : "local",
    source: "process-environment",
    github: Object.keys(github).length > 0 ? github : void 0,
    runtime
  };
}
function compact(value) {
  const entries = Object.entries(value).filter(([, entryValue]) => typeof entryValue === "string" && entryValue.length > 0);
  return Object.fromEntries(entries);
}
function writeText(outputDir, fileName, content) {
  writeFileSync2(resolve3(outputDir, fileName), normalizeText(content));
}
function normalizeText(content) {
  return content.endsWith("\n") ? content : `${content}
`;
}
function buildArtifactManifestEntries(artifactContents) {
  return ARTIFACTS.map((artifact) => {
    if (artifact.file === "manifest.json") {
      return { ...artifact, sha256: null, bytes: null };
    }
    const content = artifactContents.get(artifact.file);
    return content ? { ...artifact, ...hashContent(content) } : { ...artifact, sha256: null, bytes: null };
  });
}
function buildBundleDigest(artifactContents) {
  const bundleEntries = ARTIFACTS.filter((artifact) => !BUNDLE_DIGEST_EXCLUDED_FILES.has(artifact.file)).map((artifact) => {
    const content = artifactContents.get(artifact.file);
    return {
      file: artifact.file,
      ...content ? hashContent(content) : { sha256: null, bytes: null }
    };
  });
  return `sha256:${createHash2("sha256").update(JSON.stringify(bundleEntries)).digest("hex")}`;
}
function hashContent(content) {
  return {
    sha256: createHash2("sha256").update(content).digest("hex"),
    bytes: Buffer.byteLength(content, "utf8")
  };
}
function renderReadme(manifest, options, ciContext) {
  const policyStatus = options.policyEvaluation ? options.policyEvaluation.passed ? "passed" : "failed" : "not run";
  const baselineStatus = options.baselineComparison ? options.baselineComparison.isRegression ? "regressed" : "passed" : "not run";
  return [
    "# AgentShield Evidence Pack",
    "",
    `Generated: ${manifest.generatedAt}`,
    `Target: ${manifest.targetPath}`,
    `Redacted: ${manifest.redacted ? "yes" : "no"}`,
    `Bundle digest: ${manifest.bundleDigest}`,
    "",
    "## Summary",
    "",
    `- Score: ${options.report.score.numericScore}/100 (${options.report.score.grade})`,
    `- Findings: ${options.report.summary.totalFindings}`,
    `- Critical: ${options.report.summary.critical}`,
    `- High: ${options.report.summary.high}`,
    `- Policy: ${policyStatus}`,
    `- Baseline: ${baselineStatus}`,
    `- Supply-chain packages: ${options.supplyChainReport.totalPackages}`,
    `- Risky packages: ${options.supplyChainReport.riskyPackages}`,
    `- CI context: ${ciContext.provider}`,
    "- Remediation plan: included",
    "",
    "## Artifacts",
    "",
    ...manifest.artifacts.map(
      (artifact) => `- \`${artifact.file}\` (${artifact.kind}): ${artifact.description}`
    ),
    "",
    "## Interpretation",
    "",
    "- Start with `agentshield-report.html` for an executive review.",
    "- Use `agentshield-report.json` and `agentshield-results.sarif` for automation.",
    "- Use `policy-evaluation.json` to confirm organization-policy status.",
    "- Use `baseline-comparison.json` to review drift from the accepted baseline.",
    "- Use `supply-chain.json` to review MCP package provenance and package risk.",
    "- Use `ci-context.json` to confirm workflow, commit, and runner provenance.",
    "- Use `remediation-plan.json` for stable-fingerprint fix queues and ticket handoffs.",
    "",
    "This bundle is designed for audit handoffs, buyer security reviews, and CI artifacts."
  ].join("\n");
}
function createRedactor(targetPath, enabled) {
  const replacements = enabled ? buildReplacements(targetPath) : [];
  const redactString = (value) => {
    if (!enabled) return value;
    return replacements.reduce(
      (redacted, [pattern, replacement]) => redacted.replace(pattern, replacement),
      value
    );
  };
  const redactValue = (value) => {
    if (!enabled) return value;
    return JSON.parse(redactString(JSON.stringify(value)));
  };
  return {
    string: redactString,
    value: redactValue,
    json(value) {
      return JSON.stringify(redactValue(value), null, 2);
    }
  };
}
function buildReplacements(targetPath) {
  const home = homedir2();
  const targetReplacements = targetPath ? [
    [literalPattern(resolve3(targetPath)), "<target-path>"],
    [literalPattern(targetPath), "<target-path>"]
  ] : [];
  const homeReplacements = home && home !== "/" ? [[literalPattern(home), "<home>"]] : [];
  const userNames = [
    basename3(home),
    process.env.USER,
    process.env.USERNAME
  ].filter((value) => Boolean(value && value.length >= 3));
  const userReplacements = [...new Set(userNames)].map((userName) => [new RegExp(`\\b${escapeRegExp(userName)}\\b`, "g"), "<user>"]);
  const tokenReplacements = [
    [/\bsk-[A-Za-z0-9_-]{12,}\b/g, "sk-<redacted>"],
    [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{12,}\b/g, "gh_<redacted>"],
    [/github_pat_[A-Za-z0-9_]{20,}\b/g, "<redacted-token>"],
    [/glpat-[A-Za-z0-9_-]{12,}\b/g, "<redacted-token>"],
    [/npm_[A-Za-z0-9]{20,}\b/g, "<redacted-token>"],
    [/lin_api_[A-Za-z0-9]{20,}\b/g, "<redacted-token>"],
    [/(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b/g, "<redacted-token>"],
    [/AIza[0-9A-Za-z_-]{20,}\b/g, "<redacted-token>"],
    [/hf_[A-Za-z0-9]{20,}\b/g, "<redacted-token>"],
    [/vercel_[A-Za-z0-9]{20,}\b/g, "<redacted-token>"],
    [/AKIA[0-9A-Z]{16}\b/g, "<redacted-token>"],
    [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "<redacted-token>"],
    [/\b(?:xox[baprs]|slack)-[A-Za-z0-9-]{12,}\b/g, "<redacted-token>"],
    [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "<redacted-email>"]
  ];
  return [
    ...targetReplacements,
    ...homeReplacements,
    ...userReplacements,
    ...tokenReplacements
  ];
}
function literalPattern(value) {
  return new RegExp(escapeRegExp(value), "g");
}
function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// src/action-policy.ts
function statusForPolicyEvaluation(evaluation) {
  return evaluation.passed ? "compliant" : "non-compliant";
}
function renderPolicyJobSummary(evaluation) {
  const status = statusForPolicyEvaluation(evaluation);
  const lines = [
    "",
    "",
    "## AgentShield Organization Policy",
    "",
    `- Status: ${status}`,
    `- Policy: ${evaluation.policyName}`,
    `- Score: ${evaluation.score} (minimum: ${evaluation.minScore})`,
    `- Violations: ${evaluation.violations.length}`
  ];
  if (evaluation.policyPack) {
    lines.push(`- Policy pack: ${evaluation.policyPack}`);
  }
  if (evaluation.owners && evaluation.owners.length > 0) {
    lines.push(`- Owners: ${evaluation.owners.join(", ")}`);
  }
  if (evaluation.exceptionsApplied && evaluation.exceptionsApplied.length > 0) {
    lines.push(`- Exceptions applied: ${evaluation.exceptionsApplied.length}`);
  }
  if (evaluation.exceptionSummary && evaluation.exceptionSummary.total > 0) {
    lines.push(
      `- Exceptions: ${evaluation.exceptionSummary.total} total, ${evaluation.exceptionSummary.active} active, ${evaluation.exceptionSummary.expiringSoon} expiring soon, ${evaluation.exceptionSummary.expired} expired`
    );
  }
  if (evaluation.violations.length > 0) {
    lines.push("", "### Policy Violations", "");
    for (const violation of evaluation.violations) {
      lines.push(
        `- ${violation.rule} (${violation.severity}): ${violation.description}`
      );
    }
  }
  if (evaluation.exceptionsApplied && evaluation.exceptionsApplied.length > 0) {
    lines.push("", "### Exceptions Applied", "");
    for (const exception of evaluation.exceptionsApplied) {
      lines.push(
        `- ${exception.id} (${exception.rule}) owner=${exception.owner} expires=${exception.expiresAt}`
      );
    }
  }
  if (evaluation.exceptionSummary && evaluation.exceptionSummary.total > 0) {
    lines.push("", "### Exception Audit", "");
    for (const exception of evaluation.exceptionSummary.entries) {
      const details = [
        `status=${exception.status}`,
        `owner=${exception.owner}`,
        `expires=${exception.expiresAt}`,
        `days=${formatExceptionDays(exception.daysUntilExpiry)}`,
        ...exception.scope ? [`scope=${exception.scope}`] : [],
        ...exception.ticket ? [`ticket=${exception.ticket}`] : []
      ];
      lines.push(`- ${exception.id} (${exception.rule}) ${details.join(" ")}`);
    }
  }
  lines.push("");
  return lines.join("\n");
}
function formatExceptionDays(daysUntilExpiry) {
  return Number.isFinite(daysUntilExpiry) ? String(daysUntilExpiry) : "invalid";
}

// src/action-baseline.ts
function statusForBaselineGate(result) {
  return result.passed ? "passed" : "failed";
}
function renderBaselineJobSummary(comparison, gateResult) {
  const status = statusForBaselineGate(gateResult);
  const lines = [
    "",
    "",
    "## AgentShield Baseline Drift",
    "",
    `- Status: ${status}`,
    `- Baseline timestamp: ${comparison.baselineTimestamp}`,
    `- Score: ${comparison.baselineScore} -> ${comparison.currentScore} (${formatScoreDelta(comparison.scoreDelta)})`,
    `- New findings: ${comparison.newFindings.length}`,
    `- Resolved findings: ${comparison.resolvedFindings.length}`,
    `- Unchanged findings: ${comparison.unchangedCount}`,
    `- New critical findings: ${comparison.newCriticalCount}`,
    `- New high findings: ${comparison.newHighCount}`
  ];
  if (gateResult.reasons.length > 0) {
    lines.push("", "### Gate Reasons", "");
    for (const reason of gateResult.reasons) {
      lines.push(`- ${reason}`);
    }
  }
  if (comparison.newFindings.length > 0) {
    lines.push("", "### New Findings", "");
    for (const finding of comparison.newFindings.slice(0, 20)) {
      lines.push(
        `- ${finding.severity}: ${finding.title} (${finding.file})`
      );
    }
    if (comparison.newFindings.length > 20) {
      lines.push(`- ...${comparison.newFindings.length - 20} more`);
    }
  }
  if (comparison.resolvedFindings.length > 0) {
    lines.push("", "### Resolved Findings", "");
    for (const finding of comparison.resolvedFindings.slice(0, 20)) {
      lines.push(`- ${finding.severity}: ${finding.title} (${finding.file})`);
    }
    if (comparison.resolvedFindings.length > 20) {
      lines.push(`- ...${comparison.resolvedFindings.length - 20} more`);
    }
  }
  lines.push("");
  return lines.join("\n");
}
function renderMissingBaselineJobSummary(baselinePath) {
  return [
    "",
    "",
    "## AgentShield Baseline Drift",
    "",
    "- Status: missing",
    `- Baseline path: ${baselinePath}`,
    "- Comparison skipped because the baseline file could not be loaded.",
    ""
  ].join("\n");
}
function formatScoreDelta(delta) {
  return delta > 0 ? `+${delta}` : String(delta);
}

// src/action-supply-chain.ts
function statusForSupplyChainReport(report) {
  return report.riskyPackages > 0 ? "risky" : "clean";
}
function shouldFailForSupplyChain(report, options) {
  return options.failOnSupplyChain && (report.criticalCount > 0 || report.highCount > 0);
}
function renderSupplyChainJobSummary(report, options) {
  const status = statusForSupplyChainReport(report);
  const lines = [
    "",
    "",
    "## AgentShield Supply Chain",
    "",
    `- Status: ${status}`,
    `- Mode: ${options.online ? "online registry metadata" : "offline IOC and provenance checks"}`,
    `- Gate: ${options.failOnSupplyChain ? "fail on critical/high risk" : "collect evidence only"}`,
    `- Packages: ${report.totalPackages}`,
    `- Risky packages: ${report.riskyPackages}`,
    `- Critical packages: ${report.criticalCount}`,
    `- High packages: ${report.highCount}`,
    `- Provenance: npm=${report.provenance.npmPackages}, git=${report.provenance.gitPackages}, pinned=${report.provenance.pinnedPackages}, unpinned=${report.provenance.unpinnedPackages}, known-good=${report.provenance.knownGoodPackages}, registry-backed=${report.provenance.registryMetadataPackages}`
  ];
  const riskyPackages = report.packages.filter((pkg) => pkg.risks.length > 0);
  if (riskyPackages.length > 0) {
    lines.push("", "### Risky Packages");
    for (const verification of riskyPackages) {
      const version = verification.package.version ? `@${verification.package.version}` : "";
      const risks = verification.risks.map((risk) => `${risk.type}/${risk.severity}`).join(", ");
      lines.push(
        `- ${verification.package.name}${version} (${verification.package.serverName}) severity=${verification.overallSeverity} risks=${risks}`
      );
    }
  }
  return `${lines.join("\n")}
`;
}

// src/action.ts
function getInput(name, fallback) {
  const envKey = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
  return process.env[envKey]?.trim() ?? fallback;
}
function setOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    appendFileSync(outputFile, `${name}=${value}
`);
  } else {
    console.log(`::set-output name=${name}::${value}`);
  }
}
function writeJobSummary(markdown) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) {
    appendFileSync(summaryFile, markdown);
  }
}
function annotateWarning(file, line, message) {
  const lineParam = line ? `,line=${line}` : "";
  console.log(`::warning file=${file}${lineParam}::${escapeAnnotation(message)}`);
}
function annotateError(file, line, message) {
  const lineParam = line ? `,line=${line}` : "";
  console.log(`::error file=${file}${lineParam}::${escapeAnnotation(message)}`);
}
function escapeAnnotation(message) {
  return message.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
var SEVERITY_ORDER3 = ["critical", "high", "medium", "low", "info"];
function severityIndex(severity) {
  const idx = SEVERITY_ORDER3.indexOf(severity);
  return idx === -1 ? SEVERITY_ORDER3.length : idx;
}
function isAtOrAboveSeverity(finding, minSeverity) {
  return severityIndex(finding.severity) <= severityIndex(minSeverity);
}
function emitAnnotations(findings) {
  for (const finding of findings) {
    const message = `[${finding.severity.toUpperCase()}] ${finding.title}: ${finding.description}`;
    if (finding.severity === "critical" || finding.severity === "high") {
      annotateError(finding.file, finding.line, message);
    } else {
      annotateWarning(finding.file, finding.line, message);
    }
  }
}
function emptySupplyChainReport() {
  return {
    packages: [],
    totalPackages: 0,
    riskyPackages: 0,
    criticalCount: 0,
    highCount: 0,
    provenance: {
      npmPackages: 0,
      gitPackages: 0,
      pinnedPackages: 0,
      unpinnedPackages: 0,
      knownGoodPackages: 0,
      registryMetadataPackages: 0
    }
  };
}
async function run() {
  const inputPath = getInput("path", ".");
  const minSeverity = getInput("min-severity", "medium");
  const failOnFindings = getInput("fail-on-findings", "true") === "true";
  const format = getInput("format", "terminal");
  const baselinePath = getInput("baseline", "");
  const saveBaselinePath = getInput("save-baseline", "");
  const sarifOutput = getInput("sarif-output", "agentshield-results.sarif");
  const policyPath = getInput("policy", "");
  const failOnPolicy = getInput("fail-on-policy", "true") === "true";
  const supplyChainRequested = getInput("supply-chain", "true") === "true";
  const supplyChainOnline = getInput("supply-chain-online", "false") === "true";
  const failOnSupplyChainInput = getInput("fail-on-supply-chain", "");
  const failOnSupplyChain = failOnSupplyChainInput ? failOnSupplyChainInput === "true" : failOnFindings;
  const evidencePackPath = getInput("evidence-pack", "");
  const verifyEvidencePackOutput = getInput("verify-evidence-pack", "true") === "true";
  const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd();
  const targetPath = resolve4(workspace, inputPath);
  if (!existsSync6(targetPath)) {
    console.log(`::error::AgentShield: Path does not exist: ${targetPath}`);
    process.exitCode = 1;
    return;
  }
  console.log(`AgentShield: Scanning ${targetPath}`);
  console.log(`  min-severity: ${minSeverity}`);
  console.log(`  fail-on-findings: ${failOnFindings}`);
  console.log(`  format: ${format}`);
  if (policyPath) {
    console.log(`  policy: ${policyPath}`);
    console.log(`  fail-on-policy: ${failOnPolicy}`);
  }
  console.log("");
  const result = scan(targetPath);
  const filteredResult = {
    ...result,
    findings: result.findings.filter((f) => isAtOrAboveSeverity(f, minSeverity))
  };
  const report = calculateScore(filteredResult);
  emitAnnotations(filteredResult.findings);
  setOutput("score", String(report.score.numericScore));
  setOutput("grade", report.score.grade);
  setOutput("total-findings", String(report.summary.totalFindings));
  setOutput("critical-count", String(report.summary.critical));
  setOutput("baseline-status", "not-run");
  setOutput("new-findings", "0");
  setOutput("resolved-findings", "0");
  setOutput("unchanged-findings", "0");
  setOutput("score-delta", "0");
  setOutput("policy-status", "not-run");
  setOutput("policy-violations", "0");
  setOutput("supply-chain-status", "not-run");
  setOutput("supply-chain-risky-packages", "0");
  setOutput("supply-chain-critical-count", "0");
  setOutput("supply-chain-high-count", "0");
  setOutput("evidence-pack-status", "not-run");
  setOutput("evidence-pack-digest", "");
  let policyEvaluation = null;
  let shouldFailOnPolicy = false;
  let baselineComparison = null;
  let shouldFailOnBaseline = false;
  let supplyChainReport = emptySupplyChainReport();
  let shouldFailOnSupplyChain = false;
  if (policyPath) {
    const { loadPolicy: loadPolicy2, evaluatePolicy: evaluatePolicy2, renderPolicyEvaluation: renderPolicyEvaluation2 } = await Promise.resolve().then(() => (init_policy(), policy_exports));
    const resolvedPolicyPath = resolve4(workspace, policyPath);
    const policyResult = loadPolicy2(resolvedPolicyPath);
    if (!policyResult.success) {
      setOutput("policy-status", "error");
      console.log(
        `::error::AgentShield policy load failed: ${escapeAnnotation(policyResult.error)}`
      );
      writeJobSummary([
        "",
        "",
        "## AgentShield Organization Policy",
        "",
        "- Status: error",
        `- Error: ${policyResult.error}`,
        ""
      ].join("\n"));
      if (failOnPolicy) {
        shouldFailOnPolicy = true;
      }
    } else {
      policyEvaluation = evaluatePolicy2(
        policyResult.policy,
        filteredResult.findings,
        report.score,
        result.target.files
      );
      const policyStatus = statusForPolicyEvaluation(policyEvaluation);
      setOutput("policy-status", policyStatus);
      setOutput("policy-violations", String(policyEvaluation.violations.length));
      writeJobSummary(renderPolicyJobSummary(policyEvaluation));
      console.log(renderPolicyEvaluation2(policyEvaluation));
      if (!policyEvaluation.passed) {
        for (const violation of policyEvaluation.violations) {
          const message = escapeAnnotation(violation.description);
          console.log(
            `::error::AgentShield policy violation ${violation.rule}: ${message}`
          );
        }
        if (failOnPolicy) {
          shouldFailOnPolicy = true;
        }
      }
    }
  }
  if (format === "sarif") {
    const sarifPath = resolve4(workspace, sarifOutput);
    mkdirSync4(dirname4(sarifPath), { recursive: true });
    writeFileSync4(
      sarifPath,
      renderSarifReport(report, {
        policyEvaluation: policyEvaluation ?? void 0,
        policyUri: policyPath || void 0
      })
    );
    setOutput("sarif-path", sarifPath);
    console.log(`SARIF written to: ${sarifPath}`);
  }
  const markdownSummary = renderMarkdownReport(report);
  writeJobSummary(markdownSummary);
  console.log(`Score: ${report.score.numericScore}/100 (Grade: ${report.score.grade})`);
  console.log(`Findings: ${report.summary.totalFindings} total`);
  console.log(`  Critical: ${report.summary.critical}`);
  console.log(`  High: ${report.summary.high}`);
  console.log(`  Medium: ${report.summary.medium}`);
  console.log(`  Low: ${report.summary.low}`);
  console.log(`  Info: ${report.summary.info}`);
  if (supplyChainRequested || supplyChainOnline || evidencePackPath) {
    try {
      const { extractPackages: extractPackages2, renderSupplyChainReport: renderSupplyChainReport2, verifyPackages: verifyPackages2 } = await Promise.resolve().then(() => (init_supply_chain(), supply_chain_exports));
      const packages = extractPackages2(result.target.files);
      supplyChainReport = await verifyPackages2(packages, {
        online: supplyChainOnline
      });
      const supplyChainStatus = statusForSupplyChainReport(supplyChainReport);
      setOutput("supply-chain-status", supplyChainStatus);
      setOutput("supply-chain-risky-packages", String(supplyChainReport.riskyPackages));
      setOutput("supply-chain-critical-count", String(supplyChainReport.criticalCount));
      setOutput("supply-chain-high-count", String(supplyChainReport.highCount));
      writeJobSummary(renderSupplyChainJobSummary(supplyChainReport, {
        online: supplyChainOnline,
        failOnSupplyChain
      }));
      if (supplyChainRequested || supplyChainOnline) {
        console.log(renderSupplyChainReport2(supplyChainReport));
      } else {
        console.log(
          `Supply-chain verification: ${supplyChainStatus.toUpperCase()} (${supplyChainReport.riskyPackages}/${supplyChainReport.totalPackages} risky packages)`
        );
      }
      if ((supplyChainRequested || supplyChainOnline) && shouldFailForSupplyChain(supplyChainReport, { failOnSupplyChain })) {
        const reason = [
          `${supplyChainReport.criticalCount} critical`,
          `${supplyChainReport.highCount} high`
        ].join(", ");
        console.log(`::error::AgentShield supply-chain gate FAILED: ${reason} package risk(s)`);
        shouldFailOnSupplyChain = true;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setOutput("supply-chain-status", "error");
      console.log(`::error::AgentShield supply-chain verification failed: ${escapeAnnotation(message)}`);
      process.exitCode = 1;
      return;
    }
  }
  if (saveBaselinePath) {
    const { saveBaseline: saveBaseline2 } = await Promise.resolve().then(() => (init_baseline(), baseline_exports));
    const savePath = resolve4(workspace, saveBaselinePath);
    saveBaseline2(filteredResult.findings, report.score, savePath);
    setOutput("baseline-path", savePath);
    console.log(`Baseline saved to: ${savePath}`);
  }
  if (baselinePath) {
    const { loadBaseline: loadBaseline2, compareBaseline: compareBaseline2, evaluateGate: evaluateGate2 } = await Promise.resolve().then(() => (init_baseline(), baseline_exports));
    const baseline = loadBaseline2(resolve4(workspace, baselinePath));
    if (baseline) {
      const comparison = compareBaseline2(baseline, filteredResult.findings, report.score);
      baselineComparison = comparison;
      setOutput("new-findings", String(comparison.newFindings.length));
      setOutput("resolved-findings", String(comparison.resolvedFindings.length));
      setOutput("unchanged-findings", String(comparison.unchangedCount));
      setOutput("score-delta", String(comparison.scoreDelta));
      if (comparison.newFindings.length > 0) {
        console.log("");
        console.log(`Baseline comparison: ${comparison.newFindings.length} new, ${comparison.resolvedFindings.length} resolved`);
        emitAnnotations(comparison.newFindings);
      }
      const gateResult = evaluateGate2(comparison);
      setOutput("baseline-status", statusForBaselineGate(gateResult));
      writeJobSummary(renderBaselineJobSummary(comparison, gateResult));
      if (!gateResult.passed) {
        console.log("");
        console.log(`::error::AgentShield gate FAILED: ${gateResult.reasons.join("; ")}`);
        shouldFailOnBaseline = true;
      } else {
        console.log("Baseline gate: PASSED");
      }
    } else {
      setOutput("baseline-status", "missing");
      writeJobSummary(renderMissingBaselineJobSummary(baselinePath));
      console.log(`::warning::Could not load baseline from ${baselinePath}. Skipping comparison.`);
    }
  }
  if (evidencePackPath) {
    try {
      const packPath = resolve4(workspace, evidencePackPath);
      const pack = writeEvidencePack({
        outputDir: packPath,
        report,
        policyEvaluation: policyEvaluation ?? void 0,
        policyPath: policyPath || void 0,
        baselineComparison: baselineComparison ?? void 0,
        baselinePath: baselinePath || void 0,
        supplyChainReport
      });
      setOutput("evidence-pack-path", pack.outputDir);
      console.log(`Evidence pack written to: ${pack.outputDir}`);
      if (verifyEvidencePackOutput) {
        const verification = verifyEvidencePack(pack.outputDir);
        setOutput("evidence-pack-status", verification.ok ? "passed" : "failed");
        setOutput("evidence-pack-digest", verification.bundleDigest ?? "");
        if (!verification.ok) {
          console.log(`::error::AgentShield evidence pack verification failed: ${escapeAnnotation(verification.errors.join("; "))}`);
          process.exitCode = 1;
          return;
        }
        console.log(`Evidence pack verification: PASSED (${verification.bundleDigest})`);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setOutput("evidence-pack-status", "error");
      console.log(`::error::AgentShield evidence pack failed: ${escapeAnnotation(message)}`);
      process.exitCode = 1;
      return;
    }
  }
  if (shouldFailOnPolicy) {
    process.exitCode = 1;
    return;
  }
  if (shouldFailOnBaseline) {
    process.exitCode = 1;
    return;
  }
  if (shouldFailOnSupplyChain) {
    process.exitCode = 1;
    return;
  }
  if (failOnFindings && filteredResult.findings.length > 0) {
    console.log("");
    console.log(
      `::error::AgentShield found ${filteredResult.findings.length} finding(s) at or above ${minSeverity} severity. Failing the action.`
    );
    process.exitCode = 1;
  }
}
run().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.log(`::error::AgentShield action failed: ${escapeAnnotation(message)}`);
  process.exitCode = 1;
});
