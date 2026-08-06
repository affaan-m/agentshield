import { createRequire as __ecc_createRequire } from 'node:module';
const require = __ecc_createRequire(import.meta.url);
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require2() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

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

// node_modules/yaml/dist/nodes/identity.js
var require_identity = __commonJS({
  "node_modules/yaml/dist/nodes/identity.js"(exports) {
    "use strict";
    var ALIAS = /* @__PURE__ */ Symbol.for("yaml.alias");
    var DOC = /* @__PURE__ */ Symbol.for("yaml.document");
    var MAP = /* @__PURE__ */ Symbol.for("yaml.map");
    var PAIR = /* @__PURE__ */ Symbol.for("yaml.pair");
    var SCALAR = /* @__PURE__ */ Symbol.for("yaml.scalar");
    var SEQ = /* @__PURE__ */ Symbol.for("yaml.seq");
    var NODE_TYPE = /* @__PURE__ */ Symbol.for("yaml.node.type");
    var isAlias = (node) => !!node && typeof node === "object" && node[NODE_TYPE] === ALIAS;
    var isDocument = (node) => !!node && typeof node === "object" && node[NODE_TYPE] === DOC;
    var isMap = (node) => !!node && typeof node === "object" && node[NODE_TYPE] === MAP;
    var isPair = (node) => !!node && typeof node === "object" && node[NODE_TYPE] === PAIR;
    var isScalar = (node) => !!node && typeof node === "object" && node[NODE_TYPE] === SCALAR;
    var isSeq = (node) => !!node && typeof node === "object" && node[NODE_TYPE] === SEQ;
    function isCollection(node) {
      if (node && typeof node === "object")
        switch (node[NODE_TYPE]) {
          case MAP:
          case SEQ:
            return true;
        }
      return false;
    }
    function isNode(node) {
      if (node && typeof node === "object")
        switch (node[NODE_TYPE]) {
          case ALIAS:
          case MAP:
          case SCALAR:
          case SEQ:
            return true;
        }
      return false;
    }
    var hasAnchor = (node) => (isScalar(node) || isCollection(node)) && !!node.anchor;
    exports.ALIAS = ALIAS;
    exports.DOC = DOC;
    exports.MAP = MAP;
    exports.NODE_TYPE = NODE_TYPE;
    exports.PAIR = PAIR;
    exports.SCALAR = SCALAR;
    exports.SEQ = SEQ;
    exports.hasAnchor = hasAnchor;
    exports.isAlias = isAlias;
    exports.isCollection = isCollection;
    exports.isDocument = isDocument;
    exports.isMap = isMap;
    exports.isNode = isNode;
    exports.isPair = isPair;
    exports.isScalar = isScalar;
    exports.isSeq = isSeq;
  }
});

// node_modules/yaml/dist/visit.js
var require_visit = __commonJS({
  "node_modules/yaml/dist/visit.js"(exports) {
    "use strict";
    var identity = require_identity();
    var BREAK = /* @__PURE__ */ Symbol("break visit");
    var SKIP = /* @__PURE__ */ Symbol("skip children");
    var REMOVE = /* @__PURE__ */ Symbol("remove node");
    function visit(node, visitor) {
      const visitor_ = initVisitor(visitor);
      if (identity.isDocument(node)) {
        const cd = visit_(null, node.contents, visitor_, Object.freeze([node]));
        if (cd === REMOVE)
          node.contents = null;
      } else
        visit_(null, node, visitor_, Object.freeze([]));
    }
    visit.BREAK = BREAK;
    visit.SKIP = SKIP;
    visit.REMOVE = REMOVE;
    function visit_(key, node, visitor, path) {
      const ctrl = callVisitor(key, node, visitor, path);
      if (identity.isNode(ctrl) || identity.isPair(ctrl)) {
        replaceNode(key, path, ctrl);
        return visit_(key, ctrl, visitor, path);
      }
      if (typeof ctrl !== "symbol") {
        if (identity.isCollection(node)) {
          path = Object.freeze(path.concat(node));
          for (let i = 0; i < node.items.length; ++i) {
            const ci = visit_(i, node.items[i], visitor, path);
            if (typeof ci === "number")
              i = ci - 1;
            else if (ci === BREAK)
              return BREAK;
            else if (ci === REMOVE) {
              node.items.splice(i, 1);
              i -= 1;
            }
          }
        } else if (identity.isPair(node)) {
          path = Object.freeze(path.concat(node));
          const ck = visit_("key", node.key, visitor, path);
          if (ck === BREAK)
            return BREAK;
          else if (ck === REMOVE)
            node.key = null;
          const cv = visit_("value", node.value, visitor, path);
          if (cv === BREAK)
            return BREAK;
          else if (cv === REMOVE)
            node.value = null;
        }
      }
      return ctrl;
    }
    async function visitAsync(node, visitor) {
      const visitor_ = initVisitor(visitor);
      if (identity.isDocument(node)) {
        const cd = await visitAsync_(null, node.contents, visitor_, Object.freeze([node]));
        if (cd === REMOVE)
          node.contents = null;
      } else
        await visitAsync_(null, node, visitor_, Object.freeze([]));
    }
    visitAsync.BREAK = BREAK;
    visitAsync.SKIP = SKIP;
    visitAsync.REMOVE = REMOVE;
    async function visitAsync_(key, node, visitor, path) {
      const ctrl = await callVisitor(key, node, visitor, path);
      if (identity.isNode(ctrl) || identity.isPair(ctrl)) {
        replaceNode(key, path, ctrl);
        return visitAsync_(key, ctrl, visitor, path);
      }
      if (typeof ctrl !== "symbol") {
        if (identity.isCollection(node)) {
          path = Object.freeze(path.concat(node));
          for (let i = 0; i < node.items.length; ++i) {
            const ci = await visitAsync_(i, node.items[i], visitor, path);
            if (typeof ci === "number")
              i = ci - 1;
            else if (ci === BREAK)
              return BREAK;
            else if (ci === REMOVE) {
              node.items.splice(i, 1);
              i -= 1;
            }
          }
        } else if (identity.isPair(node)) {
          path = Object.freeze(path.concat(node));
          const ck = await visitAsync_("key", node.key, visitor, path);
          if (ck === BREAK)
            return BREAK;
          else if (ck === REMOVE)
            node.key = null;
          const cv = await visitAsync_("value", node.value, visitor, path);
          if (cv === BREAK)
            return BREAK;
          else if (cv === REMOVE)
            node.value = null;
        }
      }
      return ctrl;
    }
    function initVisitor(visitor) {
      if (typeof visitor === "object" && (visitor.Collection || visitor.Node || visitor.Value)) {
        return Object.assign({
          Alias: visitor.Node,
          Map: visitor.Node,
          Scalar: visitor.Node,
          Seq: visitor.Node
        }, visitor.Value && {
          Map: visitor.Value,
          Scalar: visitor.Value,
          Seq: visitor.Value
        }, visitor.Collection && {
          Map: visitor.Collection,
          Seq: visitor.Collection
        }, visitor);
      }
      return visitor;
    }
    function callVisitor(key, node, visitor, path) {
      if (typeof visitor === "function")
        return visitor(key, node, path);
      if (identity.isMap(node))
        return visitor.Map?.(key, node, path);
      if (identity.isSeq(node))
        return visitor.Seq?.(key, node, path);
      if (identity.isPair(node))
        return visitor.Pair?.(key, node, path);
      if (identity.isScalar(node))
        return visitor.Scalar?.(key, node, path);
      if (identity.isAlias(node))
        return visitor.Alias?.(key, node, path);
      return void 0;
    }
    function replaceNode(key, path, node) {
      const parent = path[path.length - 1];
      if (identity.isCollection(parent)) {
        parent.items[key] = node;
      } else if (identity.isPair(parent)) {
        if (key === "key")
          parent.key = node;
        else
          parent.value = node;
      } else if (identity.isDocument(parent)) {
        parent.contents = node;
      } else {
        const pt = identity.isAlias(parent) ? "alias" : "scalar";
        throw new Error(`Cannot replace node with ${pt} parent`);
      }
    }
    exports.visit = visit;
    exports.visitAsync = visitAsync;
  }
});

// node_modules/yaml/dist/doc/directives.js
var require_directives = __commonJS({
  "node_modules/yaml/dist/doc/directives.js"(exports) {
    "use strict";
    var identity = require_identity();
    var visit = require_visit();
    var escapeChars = {
      "!": "%21",
      ",": "%2C",
      "[": "%5B",
      "]": "%5D",
      "{": "%7B",
      "}": "%7D"
    };
    var escapeTagName = (tn) => tn.replace(/[!,[\]{}]/g, (ch) => escapeChars[ch]);
    var Directives = class _Directives {
      constructor(yaml, tags) {
        this.docStart = null;
        this.docEnd = false;
        this.yaml = Object.assign({}, _Directives.defaultYaml, yaml);
        this.tags = Object.assign({}, _Directives.defaultTags, tags);
      }
      clone() {
        const copy = new _Directives(this.yaml, this.tags);
        copy.docStart = this.docStart;
        return copy;
      }
      /**
       * During parsing, get a Directives instance for the current document and
       * update the stream state according to the current version's spec.
       */
      atDocument() {
        const res = new _Directives(this.yaml, this.tags);
        switch (this.yaml.version) {
          case "1.1":
            this.atNextDocument = true;
            break;
          case "1.2":
            this.atNextDocument = false;
            this.yaml = {
              explicit: _Directives.defaultYaml.explicit,
              version: "1.2"
            };
            this.tags = Object.assign({}, _Directives.defaultTags);
            break;
        }
        return res;
      }
      /**
       * @param onError - May be called even if the action was successful
       * @returns `true` on success
       */
      add(line, onError) {
        if (this.atNextDocument) {
          this.yaml = { explicit: _Directives.defaultYaml.explicit, version: "1.1" };
          this.tags = Object.assign({}, _Directives.defaultTags);
          this.atNextDocument = false;
        }
        const parts = line.trim().split(/[ \t]+/);
        const name = parts.shift();
        switch (name) {
          case "%TAG": {
            if (parts.length !== 2) {
              onError(0, "%TAG directive should contain exactly two parts");
              if (parts.length < 2)
                return false;
            }
            const [handle, prefix] = parts;
            this.tags[handle] = prefix;
            return true;
          }
          case "%YAML": {
            this.yaml.explicit = true;
            if (parts.length !== 1) {
              onError(0, "%YAML directive should contain exactly one part");
              return false;
            }
            const [version] = parts;
            if (version === "1.1" || version === "1.2") {
              this.yaml.version = version;
              return true;
            } else {
              const isValid2 = /^\d+\.\d+$/.test(version);
              onError(6, `Unsupported YAML version ${version}`, isValid2);
              return false;
            }
          }
          default:
            onError(0, `Unknown directive ${name}`, true);
            return false;
        }
      }
      /**
       * Resolves a tag, matching handles to those defined in %TAG directives.
       *
       * @returns Resolved tag, which may also be the non-specific tag `'!'` or a
       *   `'!local'` tag, or `null` if unresolvable.
       */
      tagName(source, onError) {
        if (source === "!")
          return "!";
        if (source[0] !== "!") {
          onError(`Not a valid tag: ${source}`);
          return null;
        }
        if (source[1] === "<") {
          const verbatim = source.slice(2, -1);
          if (verbatim === "!" || verbatim === "!!") {
            onError(`Verbatim tags aren't resolved, so ${source} is invalid.`);
            return null;
          }
          if (source[source.length - 1] !== ">")
            onError("Verbatim tags must end with a >");
          return verbatim;
        }
        const [, handle, suffix] = source.match(/^(.*!)([^!]*)$/s);
        if (!suffix)
          onError(`The ${source} tag has no suffix`);
        const prefix = this.tags[handle];
        if (prefix) {
          try {
            return prefix + decodeURIComponent(suffix);
          } catch (error) {
            onError(String(error));
            return null;
          }
        }
        if (handle === "!")
          return source;
        onError(`Could not resolve tag: ${source}`);
        return null;
      }
      /**
       * Given a fully resolved tag, returns its printable string form,
       * taking into account current tag prefixes and defaults.
       */
      tagString(tag) {
        for (const [handle, prefix] of Object.entries(this.tags)) {
          if (tag.startsWith(prefix))
            return handle + escapeTagName(tag.substring(prefix.length));
        }
        return tag[0] === "!" ? tag : `!<${tag}>`;
      }
      toString(doc) {
        const lines = this.yaml.explicit ? [`%YAML ${this.yaml.version || "1.2"}`] : [];
        const tagEntries = Object.entries(this.tags);
        let tagNames;
        if (doc && tagEntries.length > 0 && identity.isNode(doc.contents)) {
          const tags = {};
          visit.visit(doc.contents, (_key, node) => {
            if (identity.isNode(node) && node.tag)
              tags[node.tag] = true;
          });
          tagNames = Object.keys(tags);
        } else
          tagNames = [];
        for (const [handle, prefix] of tagEntries) {
          if (handle === "!!" && prefix === "tag:yaml.org,2002:")
            continue;
          if (!doc || tagNames.some((tn) => tn.startsWith(prefix)))
            lines.push(`%TAG ${handle} ${prefix}`);
        }
        return lines.join("\n");
      }
    };
    Directives.defaultYaml = { explicit: false, version: "1.2" };
    Directives.defaultTags = { "!!": "tag:yaml.org,2002:" };
    exports.Directives = Directives;
  }
});

// node_modules/yaml/dist/doc/anchors.js
var require_anchors = __commonJS({
  "node_modules/yaml/dist/doc/anchors.js"(exports) {
    "use strict";
    var identity = require_identity();
    var visit = require_visit();
    function anchorIsValid(anchor) {
      if (/[\x00-\x19\s,[\]{}]/.test(anchor)) {
        const sa = JSON.stringify(anchor);
        const msg = `Anchor must not contain whitespace or control characters: ${sa}`;
        throw new Error(msg);
      }
      return true;
    }
    function anchorNames(root) {
      const anchors = /* @__PURE__ */ new Set();
      visit.visit(root, {
        Value(_key, node) {
          if (node.anchor)
            anchors.add(node.anchor);
        }
      });
      return anchors;
    }
    function findNewAnchor(prefix, exclude) {
      for (let i = 1; true; ++i) {
        const name = `${prefix}${i}`;
        if (!exclude.has(name))
          return name;
      }
    }
    function createNodeAnchors(doc, prefix) {
      const aliasObjects = [];
      const sourceObjects = /* @__PURE__ */ new Map();
      let prevAnchors = null;
      return {
        onAnchor: (source) => {
          aliasObjects.push(source);
          prevAnchors ?? (prevAnchors = anchorNames(doc));
          const anchor = findNewAnchor(prefix, prevAnchors);
          prevAnchors.add(anchor);
          return anchor;
        },
        /**
         * With circular references, the source node is only resolved after all
         * of its child nodes are. This is why anchors are set only after all of
         * the nodes have been created.
         */
        setAnchors: () => {
          for (const source of aliasObjects) {
            const ref = sourceObjects.get(source);
            if (typeof ref === "object" && ref.anchor && (identity.isScalar(ref.node) || identity.isCollection(ref.node))) {
              ref.node.anchor = ref.anchor;
            } else {
              const error = new Error("Failed to resolve repeated object (this should not happen)");
              error.source = source;
              throw error;
            }
          }
        },
        sourceObjects
      };
    }
    exports.anchorIsValid = anchorIsValid;
    exports.anchorNames = anchorNames;
    exports.createNodeAnchors = createNodeAnchors;
    exports.findNewAnchor = findNewAnchor;
  }
});

// node_modules/yaml/dist/doc/applyReviver.js
var require_applyReviver = __commonJS({
  "node_modules/yaml/dist/doc/applyReviver.js"(exports) {
    "use strict";
    function applyReviver(reviver, obj, key, val) {
      if (val && typeof val === "object") {
        if (Array.isArray(val)) {
          for (let i = 0, len = val.length; i < len; ++i) {
            const v0 = val[i];
            const v1 = applyReviver(reviver, val, String(i), v0);
            if (v1 === void 0)
              delete val[i];
            else if (v1 !== v0)
              val[i] = v1;
          }
        } else if (val instanceof Map) {
          for (const k of Array.from(val.keys())) {
            const v0 = val.get(k);
            const v1 = applyReviver(reviver, val, k, v0);
            if (v1 === void 0)
              val.delete(k);
            else if (v1 !== v0)
              val.set(k, v1);
          }
        } else if (val instanceof Set) {
          for (const v0 of Array.from(val)) {
            const v1 = applyReviver(reviver, val, v0, v0);
            if (v1 === void 0)
              val.delete(v0);
            else if (v1 !== v0) {
              val.delete(v0);
              val.add(v1);
            }
          }
        } else {
          for (const [k, v0] of Object.entries(val)) {
            const v1 = applyReviver(reviver, val, k, v0);
            if (v1 === void 0)
              delete val[k];
            else if (v1 !== v0)
              val[k] = v1;
          }
        }
      }
      return reviver.call(obj, key, val);
    }
    exports.applyReviver = applyReviver;
  }
});

// node_modules/yaml/dist/nodes/toJS.js
var require_toJS = __commonJS({
  "node_modules/yaml/dist/nodes/toJS.js"(exports) {
    "use strict";
    var identity = require_identity();
    function toJS(value, arg, ctx) {
      if (Array.isArray(value))
        return value.map((v, i) => toJS(v, String(i), ctx));
      if (value && typeof value.toJSON === "function") {
        if (!ctx || !identity.hasAnchor(value))
          return value.toJSON(arg, ctx);
        const data = { aliasCount: 0, count: 1, res: void 0 };
        ctx.anchors.set(value, data);
        ctx.onCreate = (res2) => {
          data.res = res2;
          delete ctx.onCreate;
        };
        const res = value.toJSON(arg, ctx);
        if (ctx.onCreate)
          ctx.onCreate(res);
        return res;
      }
      if (typeof value === "bigint" && !ctx?.keep)
        return Number(value);
      return value;
    }
    exports.toJS = toJS;
  }
});

// node_modules/yaml/dist/nodes/Node.js
var require_Node = __commonJS({
  "node_modules/yaml/dist/nodes/Node.js"(exports) {
    "use strict";
    var applyReviver = require_applyReviver();
    var identity = require_identity();
    var toJS = require_toJS();
    var NodeBase = class {
      constructor(type) {
        Object.defineProperty(this, identity.NODE_TYPE, { value: type });
      }
      /** Create a copy of this node.  */
      clone() {
        const copy = Object.create(Object.getPrototypeOf(this), Object.getOwnPropertyDescriptors(this));
        if (this.range)
          copy.range = this.range.slice();
        return copy;
      }
      /** A plain JavaScript representation of this node. */
      toJS(doc, { mapAsMap, maxAliasCount, onAnchor, reviver } = {}) {
        if (!identity.isDocument(doc))
          throw new TypeError("A document argument is required");
        const ctx = {
          anchors: /* @__PURE__ */ new Map(),
          doc,
          keep: true,
          mapAsMap: mapAsMap === true,
          mapKeyWarned: false,
          maxAliasCount: typeof maxAliasCount === "number" ? maxAliasCount : 100
        };
        const res = toJS.toJS(this, "", ctx);
        if (typeof onAnchor === "function")
          for (const { count, res: res2 } of ctx.anchors.values())
            onAnchor(res2, count);
        return typeof reviver === "function" ? applyReviver.applyReviver(reviver, { "": res }, "", res) : res;
      }
    };
    exports.NodeBase = NodeBase;
  }
});

// node_modules/yaml/dist/nodes/Alias.js
var require_Alias = __commonJS({
  "node_modules/yaml/dist/nodes/Alias.js"(exports) {
    "use strict";
    var anchors = require_anchors();
    var visit = require_visit();
    var identity = require_identity();
    var Node = require_Node();
    var toJS = require_toJS();
    var Alias = class extends Node.NodeBase {
      constructor(source) {
        super(identity.ALIAS);
        this.source = source;
        Object.defineProperty(this, "tag", {
          set() {
            throw new Error("Alias nodes cannot have tags");
          }
        });
      }
      /**
       * Resolve the value of this alias within `doc`, finding the last
       * instance of the `source` anchor before this node.
       */
      resolve(doc, ctx) {
        let nodes;
        if (ctx?.aliasResolveCache) {
          nodes = ctx.aliasResolveCache;
        } else {
          nodes = [];
          visit.visit(doc, {
            Node: (_key, node) => {
              if (identity.isAlias(node) || identity.hasAnchor(node))
                nodes.push(node);
            }
          });
          if (ctx)
            ctx.aliasResolveCache = nodes;
        }
        let found = void 0;
        for (const node of nodes) {
          if (node === this)
            break;
          if (node.anchor === this.source)
            found = node;
        }
        return found;
      }
      toJSON(_arg, ctx) {
        if (!ctx)
          return { source: this.source };
        const { anchors: anchors2, doc, maxAliasCount } = ctx;
        const source = this.resolve(doc, ctx);
        if (!source) {
          const msg = `Unresolved alias (the anchor must be set before the alias): ${this.source}`;
          throw new ReferenceError(msg);
        }
        let data = anchors2.get(source);
        if (!data) {
          toJS.toJS(source, null, ctx);
          data = anchors2.get(source);
        }
        if (data?.res === void 0) {
          const msg = "This should not happen: Alias anchor was not resolved?";
          throw new ReferenceError(msg);
        }
        if (maxAliasCount >= 0) {
          data.count += 1;
          if (data.aliasCount === 0)
            data.aliasCount = getAliasCount(doc, source, anchors2);
          if (data.count * data.aliasCount > maxAliasCount) {
            const msg = "Excessive alias count indicates a resource exhaustion attack";
            throw new ReferenceError(msg);
          }
        }
        return data.res;
      }
      toString(ctx, _onComment, _onChompKeep) {
        const src = `*${this.source}`;
        if (ctx) {
          anchors.anchorIsValid(this.source);
          if (ctx.options.verifyAliasOrder && !ctx.anchors.has(this.source)) {
            const msg = `Unresolved alias (the anchor must be set before the alias): ${this.source}`;
            throw new Error(msg);
          }
          if (ctx.implicitKey)
            return `${src} `;
        }
        return src;
      }
    };
    function getAliasCount(doc, node, anchors2) {
      if (identity.isAlias(node)) {
        const source = node.resolve(doc);
        const anchor = anchors2 && source && anchors2.get(source);
        return anchor ? anchor.count * anchor.aliasCount : 0;
      } else if (identity.isCollection(node)) {
        let count = 0;
        for (const item of node.items) {
          const c = getAliasCount(doc, item, anchors2);
          if (c > count)
            count = c;
        }
        return count;
      } else if (identity.isPair(node)) {
        const kc = getAliasCount(doc, node.key, anchors2);
        const vc = getAliasCount(doc, node.value, anchors2);
        return Math.max(kc, vc);
      }
      return 1;
    }
    exports.Alias = Alias;
  }
});

// node_modules/yaml/dist/nodes/Scalar.js
var require_Scalar = __commonJS({
  "node_modules/yaml/dist/nodes/Scalar.js"(exports) {
    "use strict";
    var identity = require_identity();
    var Node = require_Node();
    var toJS = require_toJS();
    var isScalarValue = (value) => !value || typeof value !== "function" && typeof value !== "object";
    var Scalar = class extends Node.NodeBase {
      constructor(value) {
        super(identity.SCALAR);
        this.value = value;
      }
      toJSON(arg, ctx) {
        return ctx?.keep ? this.value : toJS.toJS(this.value, arg, ctx);
      }
      toString() {
        return String(this.value);
      }
    };
    Scalar.BLOCK_FOLDED = "BLOCK_FOLDED";
    Scalar.BLOCK_LITERAL = "BLOCK_LITERAL";
    Scalar.PLAIN = "PLAIN";
    Scalar.QUOTE_DOUBLE = "QUOTE_DOUBLE";
    Scalar.QUOTE_SINGLE = "QUOTE_SINGLE";
    exports.Scalar = Scalar;
    exports.isScalarValue = isScalarValue;
  }
});

// node_modules/yaml/dist/doc/createNode.js
var require_createNode = __commonJS({
  "node_modules/yaml/dist/doc/createNode.js"(exports) {
    "use strict";
    var Alias = require_Alias();
    var identity = require_identity();
    var Scalar = require_Scalar();
    var defaultTagPrefix = "tag:yaml.org,2002:";
    function findTagObject(value, tagName, tags) {
      if (tagName) {
        const match = tags.filter((t) => t.tag === tagName);
        const tagObj = match.find((t) => !t.format) ?? match[0];
        if (!tagObj)
          throw new Error(`Tag ${tagName} not found`);
        return tagObj;
      }
      return tags.find((t) => t.identify?.(value) && !t.format);
    }
    function createNode(value, tagName, ctx) {
      if (identity.isDocument(value))
        value = value.contents;
      if (identity.isNode(value))
        return value;
      if (identity.isPair(value)) {
        const map = ctx.schema[identity.MAP].createNode?.(ctx.schema, null, ctx);
        map.items.push(value);
        return map;
      }
      if (value instanceof String || value instanceof Number || value instanceof Boolean || typeof BigInt !== "undefined" && value instanceof BigInt) {
        value = value.valueOf();
      }
      const { aliasDuplicateObjects, onAnchor, onTagObj, schema, sourceObjects } = ctx;
      let ref = void 0;
      if (aliasDuplicateObjects && value && typeof value === "object") {
        ref = sourceObjects.get(value);
        if (ref) {
          ref.anchor ?? (ref.anchor = onAnchor(value));
          return new Alias.Alias(ref.anchor);
        } else {
          ref = { anchor: null, node: null };
          sourceObjects.set(value, ref);
        }
      }
      if (tagName?.startsWith("!!"))
        tagName = defaultTagPrefix + tagName.slice(2);
      let tagObj = findTagObject(value, tagName, schema.tags);
      if (!tagObj) {
        if (value && typeof value.toJSON === "function") {
          value = value.toJSON();
        }
        if (!value || typeof value !== "object") {
          const node2 = new Scalar.Scalar(value);
          if (ref)
            ref.node = node2;
          return node2;
        }
        tagObj = value instanceof Map ? schema[identity.MAP] : Symbol.iterator in Object(value) ? schema[identity.SEQ] : schema[identity.MAP];
      }
      if (onTagObj) {
        onTagObj(tagObj);
        delete ctx.onTagObj;
      }
      const node = tagObj?.createNode ? tagObj.createNode(ctx.schema, value, ctx) : typeof tagObj?.nodeClass?.from === "function" ? tagObj.nodeClass.from(ctx.schema, value, ctx) : new Scalar.Scalar(value);
      if (tagName)
        node.tag = tagName;
      else if (!tagObj.default)
        node.tag = tagObj.tag;
      if (ref)
        ref.node = node;
      return node;
    }
    exports.createNode = createNode;
  }
});

// node_modules/yaml/dist/nodes/Collection.js
var require_Collection = __commonJS({
  "node_modules/yaml/dist/nodes/Collection.js"(exports) {
    "use strict";
    var createNode = require_createNode();
    var identity = require_identity();
    var Node = require_Node();
    function collectionFromPath(schema, path, value) {
      let v = value;
      for (let i = path.length - 1; i >= 0; --i) {
        const k = path[i];
        if (typeof k === "number" && Number.isInteger(k) && k >= 0) {
          const a = [];
          a[k] = v;
          v = a;
        } else {
          v = /* @__PURE__ */ new Map([[k, v]]);
        }
      }
      return createNode.createNode(v, void 0, {
        aliasDuplicateObjects: false,
        keepUndefined: false,
        onAnchor: () => {
          throw new Error("This should not happen, please report a bug.");
        },
        schema,
        sourceObjects: /* @__PURE__ */ new Map()
      });
    }
    var isEmptyPath = (path) => path == null || typeof path === "object" && !!path[Symbol.iterator]().next().done;
    var Collection = class extends Node.NodeBase {
      constructor(type, schema) {
        super(type);
        Object.defineProperty(this, "schema", {
          value: schema,
          configurable: true,
          enumerable: false,
          writable: true
        });
      }
      /**
       * Create a copy of this collection.
       *
       * @param schema - If defined, overwrites the original's schema
       */
      clone(schema) {
        const copy = Object.create(Object.getPrototypeOf(this), Object.getOwnPropertyDescriptors(this));
        if (schema)
          copy.schema = schema;
        copy.items = copy.items.map((it) => identity.isNode(it) || identity.isPair(it) ? it.clone(schema) : it);
        if (this.range)
          copy.range = this.range.slice();
        return copy;
      }
      /**
       * Adds a value to the collection. For `!!map` and `!!omap` the value must
       * be a Pair instance or a `{ key, value }` object, which may not have a key
       * that already exists in the map.
       */
      addIn(path, value) {
        if (isEmptyPath(path))
          this.add(value);
        else {
          const [key, ...rest] = path;
          const node = this.get(key, true);
          if (identity.isCollection(node))
            node.addIn(rest, value);
          else if (node === void 0 && this.schema)
            this.set(key, collectionFromPath(this.schema, rest, value));
          else
            throw new Error(`Expected YAML collection at ${key}. Remaining path: ${rest}`);
        }
      }
      /**
       * Removes a value from the collection.
       * @returns `true` if the item was found and removed.
       */
      deleteIn(path) {
        const [key, ...rest] = path;
        if (rest.length === 0)
          return this.delete(key);
        const node = this.get(key, true);
        if (identity.isCollection(node))
          return node.deleteIn(rest);
        else
          throw new Error(`Expected YAML collection at ${key}. Remaining path: ${rest}`);
      }
      /**
       * Returns item at `key`, or `undefined` if not found. By default unwraps
       * scalar values from their surrounding node; to disable set `keepScalar` to
       * `true` (collections are always returned intact).
       */
      getIn(path, keepScalar) {
        const [key, ...rest] = path;
        const node = this.get(key, true);
        if (rest.length === 0)
          return !keepScalar && identity.isScalar(node) ? node.value : node;
        else
          return identity.isCollection(node) ? node.getIn(rest, keepScalar) : void 0;
      }
      hasAllNullValues(allowScalar) {
        return this.items.every((node) => {
          if (!identity.isPair(node))
            return false;
          const n = node.value;
          return n == null || allowScalar && identity.isScalar(n) && n.value == null && !n.commentBefore && !n.comment && !n.tag;
        });
      }
      /**
       * Checks if the collection includes a value with the key `key`.
       */
      hasIn(path) {
        const [key, ...rest] = path;
        if (rest.length === 0)
          return this.has(key);
        const node = this.get(key, true);
        return identity.isCollection(node) ? node.hasIn(rest) : false;
      }
      /**
       * Sets a value in this collection. For `!!set`, `value` needs to be a
       * boolean to add/remove the item from the set.
       */
      setIn(path, value) {
        const [key, ...rest] = path;
        if (rest.length === 0) {
          this.set(key, value);
        } else {
          const node = this.get(key, true);
          if (identity.isCollection(node))
            node.setIn(rest, value);
          else if (node === void 0 && this.schema)
            this.set(key, collectionFromPath(this.schema, rest, value));
          else
            throw new Error(`Expected YAML collection at ${key}. Remaining path: ${rest}`);
        }
      }
    };
    exports.Collection = Collection;
    exports.collectionFromPath = collectionFromPath;
    exports.isEmptyPath = isEmptyPath;
  }
});

// node_modules/yaml/dist/stringify/stringifyComment.js
var require_stringifyComment = __commonJS({
  "node_modules/yaml/dist/stringify/stringifyComment.js"(exports) {
    "use strict";
    var stringifyComment = (str) => str.replace(/^(?!$)(?: $)?/gm, "#");
    function indentComment(comment, indent) {
      if (/^\n+$/.test(comment))
        return comment.substring(1);
      return indent ? comment.replace(/^(?! *$)/gm, indent) : comment;
    }
    var lineComment = (str, indent, comment) => str.endsWith("\n") ? indentComment(comment, indent) : comment.includes("\n") ? "\n" + indentComment(comment, indent) : (str.endsWith(" ") ? "" : " ") + comment;
    exports.indentComment = indentComment;
    exports.lineComment = lineComment;
    exports.stringifyComment = stringifyComment;
  }
});

// node_modules/yaml/dist/stringify/foldFlowLines.js
var require_foldFlowLines = __commonJS({
  "node_modules/yaml/dist/stringify/foldFlowLines.js"(exports) {
    "use strict";
    var FOLD_FLOW = "flow";
    var FOLD_BLOCK = "block";
    var FOLD_QUOTED = "quoted";
    function foldFlowLines(text, indent, mode = "flow", { indentAtStart, lineWidth = 80, minContentWidth = 20, onFold, onOverflow } = {}) {
      if (!lineWidth || lineWidth < 0)
        return text;
      if (lineWidth < minContentWidth)
        minContentWidth = 0;
      const endStep = Math.max(1 + minContentWidth, 1 + lineWidth - indent.length);
      if (text.length <= endStep)
        return text;
      const folds = [];
      const escapedFolds = {};
      let end = lineWidth - indent.length;
      if (typeof indentAtStart === "number") {
        if (indentAtStart > lineWidth - Math.max(2, minContentWidth))
          folds.push(0);
        else
          end = lineWidth - indentAtStart;
      }
      let split = void 0;
      let prev = void 0;
      let overflow = false;
      let i = -1;
      let escStart = -1;
      let escEnd = -1;
      if (mode === FOLD_BLOCK) {
        i = consumeMoreIndentedLines(text, i, indent.length);
        if (i !== -1)
          end = i + endStep;
      }
      for (let ch; ch = text[i += 1]; ) {
        if (mode === FOLD_QUOTED && ch === "\\") {
          escStart = i;
          switch (text[i + 1]) {
            case "x":
              i += 3;
              break;
            case "u":
              i += 5;
              break;
            case "U":
              i += 9;
              break;
            default:
              i += 1;
          }
          escEnd = i;
        }
        if (ch === "\n") {
          if (mode === FOLD_BLOCK)
            i = consumeMoreIndentedLines(text, i, indent.length);
          end = i + indent.length + endStep;
          split = void 0;
        } else {
          if (ch === " " && prev && prev !== " " && prev !== "\n" && prev !== "	") {
            const next = text[i + 1];
            if (next && next !== " " && next !== "\n" && next !== "	")
              split = i;
          }
          if (i >= end) {
            if (split) {
              folds.push(split);
              end = split + endStep;
              split = void 0;
            } else if (mode === FOLD_QUOTED) {
              while (prev === " " || prev === "	") {
                prev = ch;
                ch = text[i += 1];
                overflow = true;
              }
              const j = i > escEnd + 1 ? i - 2 : escStart - 1;
              if (escapedFolds[j])
                return text;
              folds.push(j);
              escapedFolds[j] = true;
              end = j + endStep;
              split = void 0;
            } else {
              overflow = true;
            }
          }
        }
        prev = ch;
      }
      if (overflow && onOverflow)
        onOverflow();
      if (folds.length === 0)
        return text;
      if (onFold)
        onFold();
      let res = text.slice(0, folds[0]);
      for (let i2 = 0; i2 < folds.length; ++i2) {
        const fold = folds[i2];
        const end2 = folds[i2 + 1] || text.length;
        if (fold === 0)
          res = `
${indent}${text.slice(0, end2)}`;
        else {
          if (mode === FOLD_QUOTED && escapedFolds[fold])
            res += `${text[fold]}\\`;
          res += `
${indent}${text.slice(fold + 1, end2)}`;
        }
      }
      return res;
    }
    function consumeMoreIndentedLines(text, i, indent) {
      let end = i;
      let start = i + 1;
      let ch = text[start];
      while (ch === " " || ch === "	") {
        if (i < start + indent) {
          ch = text[++i];
        } else {
          do {
            ch = text[++i];
          } while (ch && ch !== "\n");
          end = i;
          start = i + 1;
          ch = text[start];
        }
      }
      return end;
    }
    exports.FOLD_BLOCK = FOLD_BLOCK;
    exports.FOLD_FLOW = FOLD_FLOW;
    exports.FOLD_QUOTED = FOLD_QUOTED;
    exports.foldFlowLines = foldFlowLines;
  }
});

// node_modules/yaml/dist/stringify/stringifyString.js
var require_stringifyString = __commonJS({
  "node_modules/yaml/dist/stringify/stringifyString.js"(exports) {
    "use strict";
    var Scalar = require_Scalar();
    var foldFlowLines = require_foldFlowLines();
    var getFoldOptions = (ctx, isBlock) => ({
      indentAtStart: isBlock ? ctx.indent.length : ctx.indentAtStart,
      lineWidth: ctx.options.lineWidth,
      minContentWidth: ctx.options.minContentWidth
    });
    var containsDocumentMarker = (str) => /^(%|---|\.\.\.)/m.test(str);
    function lineLengthOverLimit(str, lineWidth, indentLength) {
      if (!lineWidth || lineWidth < 0)
        return false;
      const limit = lineWidth - indentLength;
      const strLen = str.length;
      if (strLen <= limit)
        return false;
      for (let i = 0, start = 0; i < strLen; ++i) {
        if (str[i] === "\n") {
          if (i - start > limit)
            return true;
          start = i + 1;
          if (strLen - start <= limit)
            return false;
        }
      }
      return true;
    }
    function doubleQuotedString(value, ctx) {
      const json = JSON.stringify(value);
      if (ctx.options.doubleQuotedAsJSON)
        return json;
      const { implicitKey } = ctx;
      const minMultiLineLength = ctx.options.doubleQuotedMinMultiLineLength;
      const indent = ctx.indent || (containsDocumentMarker(value) ? "  " : "");
      let str = "";
      let start = 0;
      for (let i = 0, ch = json[i]; ch; ch = json[++i]) {
        if (ch === " " && json[i + 1] === "\\" && json[i + 2] === "n") {
          str += json.slice(start, i) + "\\ ";
          i += 1;
          start = i;
          ch = "\\";
        }
        if (ch === "\\")
          switch (json[i + 1]) {
            case "u":
              {
                str += json.slice(start, i);
                const code = json.substr(i + 2, 4);
                switch (code) {
                  case "0000":
                    str += "\\0";
                    break;
                  case "0007":
                    str += "\\a";
                    break;
                  case "000b":
                    str += "\\v";
                    break;
                  case "001b":
                    str += "\\e";
                    break;
                  case "0085":
                    str += "\\N";
                    break;
                  case "00a0":
                    str += "\\_";
                    break;
                  case "2028":
                    str += "\\L";
                    break;
                  case "2029":
                    str += "\\P";
                    break;
                  default:
                    if (code.substr(0, 2) === "00")
                      str += "\\x" + code.substr(2);
                    else
                      str += json.substr(i, 6);
                }
                i += 5;
                start = i + 1;
              }
              break;
            case "n":
              if (implicitKey || json[i + 2] === '"' || json.length < minMultiLineLength) {
                i += 1;
              } else {
                str += json.slice(start, i) + "\n\n";
                while (json[i + 2] === "\\" && json[i + 3] === "n" && json[i + 4] !== '"') {
                  str += "\n";
                  i += 2;
                }
                str += indent;
                if (json[i + 2] === " ")
                  str += "\\";
                i += 1;
                start = i + 1;
              }
              break;
            default:
              i += 1;
          }
      }
      str = start ? str + json.slice(start) : json;
      return implicitKey ? str : foldFlowLines.foldFlowLines(str, indent, foldFlowLines.FOLD_QUOTED, getFoldOptions(ctx, false));
    }
    function singleQuotedString(value, ctx) {
      if (ctx.options.singleQuote === false || ctx.implicitKey && value.includes("\n") || /[ \t]\n|\n[ \t]/.test(value))
        return doubleQuotedString(value, ctx);
      const indent = ctx.indent || (containsDocumentMarker(value) ? "  " : "");
      const res = "'" + value.replace(/'/g, "''").replace(/\n+/g, `$&
${indent}`) + "'";
      return ctx.implicitKey ? res : foldFlowLines.foldFlowLines(res, indent, foldFlowLines.FOLD_FLOW, getFoldOptions(ctx, false));
    }
    function quotedString(value, ctx) {
      const { singleQuote } = ctx.options;
      let qs;
      if (singleQuote === false)
        qs = doubleQuotedString;
      else {
        const hasDouble = value.includes('"');
        const hasSingle = value.includes("'");
        if (hasDouble && !hasSingle)
          qs = singleQuotedString;
        else if (hasSingle && !hasDouble)
          qs = doubleQuotedString;
        else
          qs = singleQuote ? singleQuotedString : doubleQuotedString;
      }
      return qs(value, ctx);
    }
    var blockEndNewlines;
    try {
      blockEndNewlines = new RegExp("(^|(?<!\n))\n+(?!\n|$)", "g");
    } catch {
      blockEndNewlines = /\n+(?!\n|$)/g;
    }
    function blockString({ comment, type, value }, ctx, onComment, onChompKeep) {
      const { blockQuote, commentString, lineWidth } = ctx.options;
      if (!blockQuote || /\n[\t ]+$/.test(value)) {
        return quotedString(value, ctx);
      }
      const indent = ctx.indent || (ctx.forceBlockIndent || containsDocumentMarker(value) ? "  " : "");
      const literal = blockQuote === "literal" ? true : blockQuote === "folded" || type === Scalar.Scalar.BLOCK_FOLDED ? false : type === Scalar.Scalar.BLOCK_LITERAL ? true : !lineLengthOverLimit(value, lineWidth, indent.length);
      if (!value)
        return literal ? "|\n" : ">\n";
      let chomp;
      let endStart;
      for (endStart = value.length; endStart > 0; --endStart) {
        const ch = value[endStart - 1];
        if (ch !== "\n" && ch !== "	" && ch !== " ")
          break;
      }
      let end = value.substring(endStart);
      const endNlPos = end.indexOf("\n");
      if (endNlPos === -1) {
        chomp = "-";
      } else if (value === end || endNlPos !== end.length - 1) {
        chomp = "+";
        if (onChompKeep)
          onChompKeep();
      } else {
        chomp = "";
      }
      if (end) {
        value = value.slice(0, -end.length);
        if (end[end.length - 1] === "\n")
          end = end.slice(0, -1);
        end = end.replace(blockEndNewlines, `$&${indent}`);
      }
      let startWithSpace = false;
      let startEnd;
      let startNlPos = -1;
      for (startEnd = 0; startEnd < value.length; ++startEnd) {
        const ch = value[startEnd];
        if (ch === " ")
          startWithSpace = true;
        else if (ch === "\n")
          startNlPos = startEnd;
        else
          break;
      }
      let start = value.substring(0, startNlPos < startEnd ? startNlPos + 1 : startEnd);
      if (start) {
        value = value.substring(start.length);
        start = start.replace(/\n+/g, `$&${indent}`);
      }
      const indentSize = indent ? "2" : "1";
      let header = (startWithSpace ? indentSize : "") + chomp;
      if (comment) {
        header += " " + commentString(comment.replace(/ ?[\r\n]+/g, " "));
        if (onComment)
          onComment();
      }
      if (!literal) {
        const foldedValue = value.replace(/\n+/g, "\n$&").replace(/(?:^|\n)([\t ].*)(?:([\n\t ]*)\n(?![\n\t ]))?/g, "$1$2").replace(/\n+/g, `$&${indent}`);
        let literalFallback = false;
        const foldOptions = getFoldOptions(ctx, true);
        if (blockQuote !== "folded" && type !== Scalar.Scalar.BLOCK_FOLDED) {
          foldOptions.onOverflow = () => {
            literalFallback = true;
          };
        }
        const body = foldFlowLines.foldFlowLines(`${start}${foldedValue}${end}`, indent, foldFlowLines.FOLD_BLOCK, foldOptions);
        if (!literalFallback)
          return `>${header}
${indent}${body}`;
      }
      value = value.replace(/\n+/g, `$&${indent}`);
      return `|${header}
${indent}${start}${value}${end}`;
    }
    function plainString(item, ctx, onComment, onChompKeep) {
      const { type, value } = item;
      const { actualString, implicitKey, indent, indentStep, inFlow } = ctx;
      if (implicitKey && value.includes("\n") || inFlow && /[[\]{},]/.test(value)) {
        return quotedString(value, ctx);
      }
      if (/^[\n\t ,[\]{}#&*!|>'"%@`]|^[?-]$|^[?-][ \t]|[\n:][ \t]|[ \t]\n|[\n\t ]#|[\n\t :]$/.test(value)) {
        return implicitKey || inFlow || !value.includes("\n") ? quotedString(value, ctx) : blockString(item, ctx, onComment, onChompKeep);
      }
      if (!implicitKey && !inFlow && type !== Scalar.Scalar.PLAIN && value.includes("\n")) {
        return blockString(item, ctx, onComment, onChompKeep);
      }
      if (containsDocumentMarker(value)) {
        if (indent === "") {
          ctx.forceBlockIndent = true;
          return blockString(item, ctx, onComment, onChompKeep);
        } else if (implicitKey && indent === indentStep) {
          return quotedString(value, ctx);
        }
      }
      const str = value.replace(/\n+/g, `$&
${indent}`);
      if (actualString) {
        const test = (tag) => tag.default && tag.tag !== "tag:yaml.org,2002:str" && tag.test?.test(str);
        const { compat, tags } = ctx.doc.schema;
        if (tags.some(test) || compat?.some(test))
          return quotedString(value, ctx);
      }
      return implicitKey ? str : foldFlowLines.foldFlowLines(str, indent, foldFlowLines.FOLD_FLOW, getFoldOptions(ctx, false));
    }
    function stringifyString(item, ctx, onComment, onChompKeep) {
      const { implicitKey, inFlow } = ctx;
      const ss = typeof item.value === "string" ? item : Object.assign({}, item, { value: String(item.value) });
      let { type } = item;
      if (type !== Scalar.Scalar.QUOTE_DOUBLE) {
        if (/[\x00-\x08\x0b-\x1f\x7f-\x9f\u{D800}-\u{DFFF}]/u.test(ss.value))
          type = Scalar.Scalar.QUOTE_DOUBLE;
      }
      const _stringify = (_type) => {
        switch (_type) {
          case Scalar.Scalar.BLOCK_FOLDED:
          case Scalar.Scalar.BLOCK_LITERAL:
            return implicitKey || inFlow ? quotedString(ss.value, ctx) : blockString(ss, ctx, onComment, onChompKeep);
          case Scalar.Scalar.QUOTE_DOUBLE:
            return doubleQuotedString(ss.value, ctx);
          case Scalar.Scalar.QUOTE_SINGLE:
            return singleQuotedString(ss.value, ctx);
          case Scalar.Scalar.PLAIN:
            return plainString(ss, ctx, onComment, onChompKeep);
          default:
            return null;
        }
      };
      let res = _stringify(type);
      if (res === null) {
        const { defaultKeyType, defaultStringType } = ctx.options;
        const t = implicitKey && defaultKeyType || defaultStringType;
        res = _stringify(t);
        if (res === null)
          throw new Error(`Unsupported default string type ${t}`);
      }
      return res;
    }
    exports.stringifyString = stringifyString;
  }
});

// node_modules/yaml/dist/stringify/stringify.js
var require_stringify = __commonJS({
  "node_modules/yaml/dist/stringify/stringify.js"(exports) {
    "use strict";
    var anchors = require_anchors();
    var identity = require_identity();
    var stringifyComment = require_stringifyComment();
    var stringifyString = require_stringifyString();
    function createStringifyContext(doc, options) {
      const opt = Object.assign({
        blockQuote: true,
        commentString: stringifyComment.stringifyComment,
        defaultKeyType: null,
        defaultStringType: "PLAIN",
        directives: null,
        doubleQuotedAsJSON: false,
        doubleQuotedMinMultiLineLength: 40,
        falseStr: "false",
        flowCollectionPadding: true,
        indentSeq: true,
        lineWidth: 80,
        minContentWidth: 20,
        nullStr: "null",
        simpleKeys: false,
        singleQuote: null,
        trailingComma: false,
        trueStr: "true",
        verifyAliasOrder: true
      }, doc.schema.toStringOptions, options);
      let inFlow;
      switch (opt.collectionStyle) {
        case "block":
          inFlow = false;
          break;
        case "flow":
          inFlow = true;
          break;
        default:
          inFlow = null;
      }
      return {
        anchors: /* @__PURE__ */ new Set(),
        doc,
        flowCollectionPadding: opt.flowCollectionPadding ? " " : "",
        indent: "",
        indentStep: typeof opt.indent === "number" ? " ".repeat(opt.indent) : "  ",
        inFlow,
        options: opt
      };
    }
    function getTagObject(tags, item) {
      if (item.tag) {
        const match = tags.filter((t) => t.tag === item.tag);
        if (match.length > 0)
          return match.find((t) => t.format === item.format) ?? match[0];
      }
      let tagObj = void 0;
      let obj;
      if (identity.isScalar(item)) {
        obj = item.value;
        let match = tags.filter((t) => t.identify?.(obj));
        if (match.length > 1) {
          const testMatch = match.filter((t) => t.test);
          if (testMatch.length > 0)
            match = testMatch;
        }
        tagObj = match.find((t) => t.format === item.format) ?? match.find((t) => !t.format);
      } else {
        obj = item;
        tagObj = tags.find((t) => t.nodeClass && obj instanceof t.nodeClass);
      }
      if (!tagObj) {
        const name = obj?.constructor?.name ?? (obj === null ? "null" : typeof obj);
        throw new Error(`Tag not resolved for ${name} value`);
      }
      return tagObj;
    }
    function stringifyProps(node, tagObj, { anchors: anchors$1, doc }) {
      if (!doc.directives)
        return "";
      const props = [];
      const anchor = (identity.isScalar(node) || identity.isCollection(node)) && node.anchor;
      if (anchor && anchors.anchorIsValid(anchor)) {
        anchors$1.add(anchor);
        props.push(`&${anchor}`);
      }
      const tag = node.tag ?? (tagObj.default ? null : tagObj.tag);
      if (tag)
        props.push(doc.directives.tagString(tag));
      return props.join(" ");
    }
    function stringify(item, ctx, onComment, onChompKeep) {
      if (identity.isPair(item))
        return item.toString(ctx, onComment, onChompKeep);
      if (identity.isAlias(item)) {
        if (ctx.doc.directives)
          return item.toString(ctx);
        if (ctx.resolvedAliases?.has(item)) {
          throw new TypeError(`Cannot stringify circular structure without alias nodes`);
        } else {
          if (ctx.resolvedAliases)
            ctx.resolvedAliases.add(item);
          else
            ctx.resolvedAliases = /* @__PURE__ */ new Set([item]);
          item = item.resolve(ctx.doc);
        }
      }
      let tagObj = void 0;
      const node = identity.isNode(item) ? item : ctx.doc.createNode(item, { onTagObj: (o) => tagObj = o });
      tagObj ?? (tagObj = getTagObject(ctx.doc.schema.tags, node));
      const props = stringifyProps(node, tagObj, ctx);
      if (props.length > 0)
        ctx.indentAtStart = (ctx.indentAtStart ?? 0) + props.length + 1;
      const str = typeof tagObj.stringify === "function" ? tagObj.stringify(node, ctx, onComment, onChompKeep) : identity.isScalar(node) ? stringifyString.stringifyString(node, ctx, onComment, onChompKeep) : node.toString(ctx, onComment, onChompKeep);
      if (!props)
        return str;
      return identity.isScalar(node) || str[0] === "{" || str[0] === "[" ? `${props} ${str}` : `${props}
${ctx.indent}${str}`;
    }
    exports.createStringifyContext = createStringifyContext;
    exports.stringify = stringify;
  }
});

// node_modules/yaml/dist/stringify/stringifyPair.js
var require_stringifyPair = __commonJS({
  "node_modules/yaml/dist/stringify/stringifyPair.js"(exports) {
    "use strict";
    var identity = require_identity();
    var Scalar = require_Scalar();
    var stringify = require_stringify();
    var stringifyComment = require_stringifyComment();
    function stringifyPair({ key, value }, ctx, onComment, onChompKeep) {
      const { allNullValues, doc, indent, indentStep, options: { commentString, indentSeq, simpleKeys } } = ctx;
      let keyComment = identity.isNode(key) && key.comment || null;
      if (simpleKeys) {
        if (keyComment) {
          throw new Error("With simple keys, key nodes cannot have comments");
        }
        if (identity.isCollection(key) || !identity.isNode(key) && typeof key === "object") {
          const msg = "With simple keys, collection cannot be used as a key value";
          throw new Error(msg);
        }
      }
      let explicitKey = !simpleKeys && (!key || keyComment && value == null && !ctx.inFlow || identity.isCollection(key) || (identity.isScalar(key) ? key.type === Scalar.Scalar.BLOCK_FOLDED || key.type === Scalar.Scalar.BLOCK_LITERAL : typeof key === "object"));
      ctx = Object.assign({}, ctx, {
        allNullValues: false,
        implicitKey: !explicitKey && (simpleKeys || !allNullValues),
        indent: indent + indentStep
      });
      let keyCommentDone = false;
      let chompKeep = false;
      let str = stringify.stringify(key, ctx, () => keyCommentDone = true, () => chompKeep = true);
      if (!explicitKey && !ctx.inFlow && str.length > 1024) {
        if (simpleKeys)
          throw new Error("With simple keys, single line scalar must not span more than 1024 characters");
        explicitKey = true;
      }
      if (ctx.inFlow) {
        if (allNullValues || value == null) {
          if (keyCommentDone && onComment)
            onComment();
          return str === "" ? "?" : explicitKey ? `? ${str}` : str;
        }
      } else if (allNullValues && !simpleKeys || value == null && explicitKey) {
        str = `? ${str}`;
        if (keyComment && !keyCommentDone) {
          str += stringifyComment.lineComment(str, ctx.indent, commentString(keyComment));
        } else if (chompKeep && onChompKeep)
          onChompKeep();
        return str;
      }
      if (keyCommentDone)
        keyComment = null;
      if (explicitKey) {
        if (keyComment)
          str += stringifyComment.lineComment(str, ctx.indent, commentString(keyComment));
        str = `? ${str}
${indent}:`;
      } else {
        str = `${str}:`;
        if (keyComment)
          str += stringifyComment.lineComment(str, ctx.indent, commentString(keyComment));
      }
      let vsb, vcb, valueComment;
      if (identity.isNode(value)) {
        vsb = !!value.spaceBefore;
        vcb = value.commentBefore;
        valueComment = value.comment;
      } else {
        vsb = false;
        vcb = null;
        valueComment = null;
        if (value && typeof value === "object")
          value = doc.createNode(value);
      }
      ctx.implicitKey = false;
      if (!explicitKey && !keyComment && identity.isScalar(value))
        ctx.indentAtStart = str.length + 1;
      chompKeep = false;
      if (!indentSeq && indentStep.length >= 2 && !ctx.inFlow && !explicitKey && identity.isSeq(value) && !value.flow && !value.tag && !value.anchor) {
        ctx.indent = ctx.indent.substring(2);
      }
      let valueCommentDone = false;
      const valueStr = stringify.stringify(value, ctx, () => valueCommentDone = true, () => chompKeep = true);
      let ws = " ";
      if (keyComment || vsb || vcb) {
        ws = vsb ? "\n" : "";
        if (vcb) {
          const cs = commentString(vcb);
          ws += `
${stringifyComment.indentComment(cs, ctx.indent)}`;
        }
        if (valueStr === "" && !ctx.inFlow) {
          if (ws === "\n" && valueComment)
            ws = "\n\n";
        } else {
          ws += `
${ctx.indent}`;
        }
      } else if (!explicitKey && identity.isCollection(value)) {
        const vs0 = valueStr[0];
        const nl0 = valueStr.indexOf("\n");
        const hasNewline = nl0 !== -1;
        const flow = ctx.inFlow ?? value.flow ?? value.items.length === 0;
        if (hasNewline || !flow) {
          let hasPropsLine = false;
          if (hasNewline && (vs0 === "&" || vs0 === "!")) {
            let sp0 = valueStr.indexOf(" ");
            if (vs0 === "&" && sp0 !== -1 && sp0 < nl0 && valueStr[sp0 + 1] === "!") {
              sp0 = valueStr.indexOf(" ", sp0 + 1);
            }
            if (sp0 === -1 || nl0 < sp0)
              hasPropsLine = true;
          }
          if (!hasPropsLine)
            ws = `
${ctx.indent}`;
        }
      } else if (valueStr === "" || valueStr[0] === "\n") {
        ws = "";
      }
      str += ws + valueStr;
      if (ctx.inFlow) {
        if (valueCommentDone && onComment)
          onComment();
      } else if (valueComment && !valueCommentDone) {
        str += stringifyComment.lineComment(str, ctx.indent, commentString(valueComment));
      } else if (chompKeep && onChompKeep) {
        onChompKeep();
      }
      return str;
    }
    exports.stringifyPair = stringifyPair;
  }
});

// node_modules/yaml/dist/log.js
var require_log = __commonJS({
  "node_modules/yaml/dist/log.js"(exports) {
    "use strict";
    var node_process = __require("process");
    function debug(logLevel, ...messages) {
      if (logLevel === "debug")
        console.log(...messages);
    }
    function warn(logLevel, warning) {
      if (logLevel === "debug" || logLevel === "warn") {
        if (typeof node_process.emitWarning === "function")
          node_process.emitWarning(warning);
        else
          console.warn(warning);
      }
    }
    exports.debug = debug;
    exports.warn = warn;
  }
});

// node_modules/yaml/dist/schema/yaml-1.1/merge.js
var require_merge = __commonJS({
  "node_modules/yaml/dist/schema/yaml-1.1/merge.js"(exports) {
    "use strict";
    var identity = require_identity();
    var Scalar = require_Scalar();
    var MERGE_KEY = "<<";
    var merge = {
      identify: (value) => value === MERGE_KEY || typeof value === "symbol" && value.description === MERGE_KEY,
      default: "key",
      tag: "tag:yaml.org,2002:merge",
      test: /^<<$/,
      resolve: () => Object.assign(new Scalar.Scalar(Symbol(MERGE_KEY)), {
        addToJSMap: addMergeToJSMap
      }),
      stringify: () => MERGE_KEY
    };
    var isMergeKey = (ctx, key) => (merge.identify(key) || identity.isScalar(key) && (!key.type || key.type === Scalar.Scalar.PLAIN) && merge.identify(key.value)) && ctx?.doc.schema.tags.some((tag) => tag.tag === merge.tag && tag.default);
    function addMergeToJSMap(ctx, map, value) {
      value = ctx && identity.isAlias(value) ? value.resolve(ctx.doc) : value;
      if (identity.isSeq(value))
        for (const it of value.items)
          mergeValue(ctx, map, it);
      else if (Array.isArray(value))
        for (const it of value)
          mergeValue(ctx, map, it);
      else
        mergeValue(ctx, map, value);
    }
    function mergeValue(ctx, map, value) {
      const source = ctx && identity.isAlias(value) ? value.resolve(ctx.doc) : value;
      if (!identity.isMap(source))
        throw new Error("Merge sources must be maps or map aliases");
      const srcMap = source.toJSON(null, ctx, Map);
      for (const [key, value2] of srcMap) {
        if (map instanceof Map) {
          if (!map.has(key))
            map.set(key, value2);
        } else if (map instanceof Set) {
          map.add(key);
        } else if (!Object.prototype.hasOwnProperty.call(map, key)) {
          Object.defineProperty(map, key, {
            value: value2,
            writable: true,
            enumerable: true,
            configurable: true
          });
        }
      }
      return map;
    }
    exports.addMergeToJSMap = addMergeToJSMap;
    exports.isMergeKey = isMergeKey;
    exports.merge = merge;
  }
});

// node_modules/yaml/dist/nodes/addPairToJSMap.js
var require_addPairToJSMap = __commonJS({
  "node_modules/yaml/dist/nodes/addPairToJSMap.js"(exports) {
    "use strict";
    var log = require_log();
    var merge = require_merge();
    var stringify = require_stringify();
    var identity = require_identity();
    var toJS = require_toJS();
    function addPairToJSMap(ctx, map, { key, value }) {
      if (identity.isNode(key) && key.addToJSMap)
        key.addToJSMap(ctx, map, value);
      else if (merge.isMergeKey(ctx, key))
        merge.addMergeToJSMap(ctx, map, value);
      else {
        const jsKey = toJS.toJS(key, "", ctx);
        if (map instanceof Map) {
          map.set(jsKey, toJS.toJS(value, jsKey, ctx));
        } else if (map instanceof Set) {
          map.add(jsKey);
        } else {
          const stringKey = stringifyKey(key, jsKey, ctx);
          const jsValue = toJS.toJS(value, stringKey, ctx);
          if (stringKey in map)
            Object.defineProperty(map, stringKey, {
              value: jsValue,
              writable: true,
              enumerable: true,
              configurable: true
            });
          else
            map[stringKey] = jsValue;
        }
      }
      return map;
    }
    function stringifyKey(key, jsKey, ctx) {
      if (jsKey === null)
        return "";
      if (typeof jsKey !== "object")
        return String(jsKey);
      if (identity.isNode(key) && ctx?.doc) {
        const strCtx = stringify.createStringifyContext(ctx.doc, {});
        strCtx.anchors = /* @__PURE__ */ new Set();
        for (const node of ctx.anchors.keys())
          strCtx.anchors.add(node.anchor);
        strCtx.inFlow = true;
        strCtx.inStringifyKey = true;
        const strKey = key.toString(strCtx);
        if (!ctx.mapKeyWarned) {
          let jsonStr = JSON.stringify(strKey);
          if (jsonStr.length > 40)
            jsonStr = jsonStr.substring(0, 36) + '..."';
          log.warn(ctx.doc.options.logLevel, `Keys with collection values will be stringified due to JS Object restrictions: ${jsonStr}. Set mapAsMap: true to use object keys.`);
          ctx.mapKeyWarned = true;
        }
        return strKey;
      }
      return JSON.stringify(jsKey);
    }
    exports.addPairToJSMap = addPairToJSMap;
  }
});

// node_modules/yaml/dist/nodes/Pair.js
var require_Pair = __commonJS({
  "node_modules/yaml/dist/nodes/Pair.js"(exports) {
    "use strict";
    var createNode = require_createNode();
    var stringifyPair = require_stringifyPair();
    var addPairToJSMap = require_addPairToJSMap();
    var identity = require_identity();
    function createPair(key, value, ctx) {
      const k = createNode.createNode(key, void 0, ctx);
      const v = createNode.createNode(value, void 0, ctx);
      return new Pair(k, v);
    }
    var Pair = class _Pair {
      constructor(key, value = null) {
        Object.defineProperty(this, identity.NODE_TYPE, { value: identity.PAIR });
        this.key = key;
        this.value = value;
      }
      clone(schema) {
        let { key, value } = this;
        if (identity.isNode(key))
          key = key.clone(schema);
        if (identity.isNode(value))
          value = value.clone(schema);
        return new _Pair(key, value);
      }
      toJSON(_, ctx) {
        const pair = ctx?.mapAsMap ? /* @__PURE__ */ new Map() : {};
        return addPairToJSMap.addPairToJSMap(ctx, pair, this);
      }
      toString(ctx, onComment, onChompKeep) {
        return ctx?.doc ? stringifyPair.stringifyPair(this, ctx, onComment, onChompKeep) : JSON.stringify(this);
      }
    };
    exports.Pair = Pair;
    exports.createPair = createPair;
  }
});

// node_modules/yaml/dist/stringify/stringifyCollection.js
var require_stringifyCollection = __commonJS({
  "node_modules/yaml/dist/stringify/stringifyCollection.js"(exports) {
    "use strict";
    var identity = require_identity();
    var stringify = require_stringify();
    var stringifyComment = require_stringifyComment();
    function stringifyCollection(collection, ctx, options) {
      const flow = ctx.inFlow ?? collection.flow;
      const stringify2 = flow ? stringifyFlowCollection : stringifyBlockCollection;
      return stringify2(collection, ctx, options);
    }
    function stringifyBlockCollection({ comment, items }, ctx, { blockItemPrefix, flowChars, itemIndent, onChompKeep, onComment }) {
      const { indent, options: { commentString } } = ctx;
      const itemCtx = Object.assign({}, ctx, { indent: itemIndent, type: null });
      let chompKeep = false;
      const lines = [];
      for (let i = 0; i < items.length; ++i) {
        const item = items[i];
        let comment2 = null;
        if (identity.isNode(item)) {
          if (!chompKeep && item.spaceBefore)
            lines.push("");
          addCommentBefore(ctx, lines, item.commentBefore, chompKeep);
          if (item.comment)
            comment2 = item.comment;
        } else if (identity.isPair(item)) {
          const ik = identity.isNode(item.key) ? item.key : null;
          if (ik) {
            if (!chompKeep && ik.spaceBefore)
              lines.push("");
            addCommentBefore(ctx, lines, ik.commentBefore, chompKeep);
          }
        }
        chompKeep = false;
        let str2 = stringify.stringify(item, itemCtx, () => comment2 = null, () => chompKeep = true);
        if (comment2)
          str2 += stringifyComment.lineComment(str2, itemIndent, commentString(comment2));
        if (chompKeep && comment2)
          chompKeep = false;
        lines.push(blockItemPrefix + str2);
      }
      let str;
      if (lines.length === 0) {
        str = flowChars.start + flowChars.end;
      } else {
        str = lines[0];
        for (let i = 1; i < lines.length; ++i) {
          const line = lines[i];
          str += line ? `
${indent}${line}` : "\n";
        }
      }
      if (comment) {
        str += "\n" + stringifyComment.indentComment(commentString(comment), indent);
        if (onComment)
          onComment();
      } else if (chompKeep && onChompKeep)
        onChompKeep();
      return str;
    }
    function stringifyFlowCollection({ items }, ctx, { flowChars, itemIndent }) {
      const { indent, indentStep, flowCollectionPadding: fcPadding, options: { commentString } } = ctx;
      itemIndent += indentStep;
      const itemCtx = Object.assign({}, ctx, {
        indent: itemIndent,
        inFlow: true,
        type: null
      });
      let reqNewline = false;
      let linesAtValue = 0;
      const lines = [];
      for (let i = 0; i < items.length; ++i) {
        const item = items[i];
        let comment = null;
        if (identity.isNode(item)) {
          if (item.spaceBefore)
            lines.push("");
          addCommentBefore(ctx, lines, item.commentBefore, false);
          if (item.comment)
            comment = item.comment;
        } else if (identity.isPair(item)) {
          const ik = identity.isNode(item.key) ? item.key : null;
          if (ik) {
            if (ik.spaceBefore)
              lines.push("");
            addCommentBefore(ctx, lines, ik.commentBefore, false);
            if (ik.comment)
              reqNewline = true;
          }
          const iv = identity.isNode(item.value) ? item.value : null;
          if (iv) {
            if (iv.comment)
              comment = iv.comment;
            if (iv.commentBefore)
              reqNewline = true;
          } else if (item.value == null && ik?.comment) {
            comment = ik.comment;
          }
        }
        if (comment)
          reqNewline = true;
        let str = stringify.stringify(item, itemCtx, () => comment = null);
        reqNewline || (reqNewline = lines.length > linesAtValue || str.includes("\n"));
        if (i < items.length - 1) {
          str += ",";
        } else if (ctx.options.trailingComma) {
          if (ctx.options.lineWidth > 0) {
            reqNewline || (reqNewline = lines.reduce((sum, line) => sum + line.length + 2, 2) + (str.length + 2) > ctx.options.lineWidth);
          }
          if (reqNewline) {
            str += ",";
          }
        }
        if (comment)
          str += stringifyComment.lineComment(str, itemIndent, commentString(comment));
        lines.push(str);
        linesAtValue = lines.length;
      }
      const { start, end } = flowChars;
      if (lines.length === 0) {
        return start + end;
      } else {
        if (!reqNewline) {
          const len = lines.reduce((sum, line) => sum + line.length + 2, 2);
          reqNewline = ctx.options.lineWidth > 0 && len > ctx.options.lineWidth;
        }
        if (reqNewline) {
          let str = start;
          for (const line of lines)
            str += line ? `
${indentStep}${indent}${line}` : "\n";
          return `${str}
${indent}${end}`;
        } else {
          return `${start}${fcPadding}${lines.join(" ")}${fcPadding}${end}`;
        }
      }
    }
    function addCommentBefore({ indent, options: { commentString } }, lines, comment, chompKeep) {
      if (comment && chompKeep)
        comment = comment.replace(/^\n+/, "");
      if (comment) {
        const ic = stringifyComment.indentComment(commentString(comment), indent);
        lines.push(ic.trimStart());
      }
    }
    exports.stringifyCollection = stringifyCollection;
  }
});

// node_modules/yaml/dist/nodes/YAMLMap.js
var require_YAMLMap = __commonJS({
  "node_modules/yaml/dist/nodes/YAMLMap.js"(exports) {
    "use strict";
    var stringifyCollection = require_stringifyCollection();
    var addPairToJSMap = require_addPairToJSMap();
    var Collection = require_Collection();
    var identity = require_identity();
    var Pair = require_Pair();
    var Scalar = require_Scalar();
    function findPair(items, key) {
      const k = identity.isScalar(key) ? key.value : key;
      for (const it of items) {
        if (identity.isPair(it)) {
          if (it.key === key || it.key === k)
            return it;
          if (identity.isScalar(it.key) && it.key.value === k)
            return it;
        }
      }
      return void 0;
    }
    var YAMLMap = class extends Collection.Collection {
      static get tagName() {
        return "tag:yaml.org,2002:map";
      }
      constructor(schema) {
        super(identity.MAP, schema);
        this.items = [];
      }
      /**
       * A generic collection parsing method that can be extended
       * to other node classes that inherit from YAMLMap
       */
      static from(schema, obj, ctx) {
        const { keepUndefined, replacer } = ctx;
        const map = new this(schema);
        const add = (key, value) => {
          if (typeof replacer === "function")
            value = replacer.call(obj, key, value);
          else if (Array.isArray(replacer) && !replacer.includes(key))
            return;
          if (value !== void 0 || keepUndefined)
            map.items.push(Pair.createPair(key, value, ctx));
        };
        if (obj instanceof Map) {
          for (const [key, value] of obj)
            add(key, value);
        } else if (obj && typeof obj === "object") {
          for (const key of Object.keys(obj))
            add(key, obj[key]);
        }
        if (typeof schema.sortMapEntries === "function") {
          map.items.sort(schema.sortMapEntries);
        }
        return map;
      }
      /**
       * Adds a value to the collection.
       *
       * @param overwrite - If not set `true`, using a key that is already in the
       *   collection will throw. Otherwise, overwrites the previous value.
       */
      add(pair, overwrite) {
        let _pair;
        if (identity.isPair(pair))
          _pair = pair;
        else if (!pair || typeof pair !== "object" || !("key" in pair)) {
          _pair = new Pair.Pair(pair, pair?.value);
        } else
          _pair = new Pair.Pair(pair.key, pair.value);
        const prev = findPair(this.items, _pair.key);
        const sortEntries = this.schema?.sortMapEntries;
        if (prev) {
          if (!overwrite)
            throw new Error(`Key ${_pair.key} already set`);
          if (identity.isScalar(prev.value) && Scalar.isScalarValue(_pair.value))
            prev.value.value = _pair.value;
          else
            prev.value = _pair.value;
        } else if (sortEntries) {
          const i = this.items.findIndex((item) => sortEntries(_pair, item) < 0);
          if (i === -1)
            this.items.push(_pair);
          else
            this.items.splice(i, 0, _pair);
        } else {
          this.items.push(_pair);
        }
      }
      delete(key) {
        const it = findPair(this.items, key);
        if (!it)
          return false;
        const del = this.items.splice(this.items.indexOf(it), 1);
        return del.length > 0;
      }
      get(key, keepScalar) {
        const it = findPair(this.items, key);
        const node = it?.value;
        return (!keepScalar && identity.isScalar(node) ? node.value : node) ?? void 0;
      }
      has(key) {
        return !!findPair(this.items, key);
      }
      set(key, value) {
        this.add(new Pair.Pair(key, value), true);
      }
      /**
       * @param ctx - Conversion context, originally set in Document#toJS()
       * @param {Class} Type - If set, forces the returned collection type
       * @returns Instance of Type, Map, or Object
       */
      toJSON(_, ctx, Type) {
        const map = Type ? new Type() : ctx?.mapAsMap ? /* @__PURE__ */ new Map() : {};
        if (ctx?.onCreate)
          ctx.onCreate(map);
        for (const item of this.items)
          addPairToJSMap.addPairToJSMap(ctx, map, item);
        return map;
      }
      toString(ctx, onComment, onChompKeep) {
        if (!ctx)
          return JSON.stringify(this);
        for (const item of this.items) {
          if (!identity.isPair(item))
            throw new Error(`Map items must all be pairs; found ${JSON.stringify(item)} instead`);
        }
        if (!ctx.allNullValues && this.hasAllNullValues(false))
          ctx = Object.assign({}, ctx, { allNullValues: true });
        return stringifyCollection.stringifyCollection(this, ctx, {
          blockItemPrefix: "",
          flowChars: { start: "{", end: "}" },
          itemIndent: ctx.indent || "",
          onChompKeep,
          onComment
        });
      }
    };
    exports.YAMLMap = YAMLMap;
    exports.findPair = findPair;
  }
});

// node_modules/yaml/dist/schema/common/map.js
var require_map = __commonJS({
  "node_modules/yaml/dist/schema/common/map.js"(exports) {
    "use strict";
    var identity = require_identity();
    var YAMLMap = require_YAMLMap();
    var map = {
      collection: "map",
      default: true,
      nodeClass: YAMLMap.YAMLMap,
      tag: "tag:yaml.org,2002:map",
      resolve(map2, onError) {
        if (!identity.isMap(map2))
          onError("Expected a mapping for this tag");
        return map2;
      },
      createNode: (schema, obj, ctx) => YAMLMap.YAMLMap.from(schema, obj, ctx)
    };
    exports.map = map;
  }
});

// node_modules/yaml/dist/nodes/YAMLSeq.js
var require_YAMLSeq = __commonJS({
  "node_modules/yaml/dist/nodes/YAMLSeq.js"(exports) {
    "use strict";
    var createNode = require_createNode();
    var stringifyCollection = require_stringifyCollection();
    var Collection = require_Collection();
    var identity = require_identity();
    var Scalar = require_Scalar();
    var toJS = require_toJS();
    var YAMLSeq = class extends Collection.Collection {
      static get tagName() {
        return "tag:yaml.org,2002:seq";
      }
      constructor(schema) {
        super(identity.SEQ, schema);
        this.items = [];
      }
      add(value) {
        this.items.push(value);
      }
      /**
       * Removes a value from the collection.
       *
       * `key` must contain a representation of an integer for this to succeed.
       * It may be wrapped in a `Scalar`.
       *
       * @returns `true` if the item was found and removed.
       */
      delete(key) {
        const idx = asItemIndex(key);
        if (typeof idx !== "number")
          return false;
        const del = this.items.splice(idx, 1);
        return del.length > 0;
      }
      get(key, keepScalar) {
        const idx = asItemIndex(key);
        if (typeof idx !== "number")
          return void 0;
        const it = this.items[idx];
        return !keepScalar && identity.isScalar(it) ? it.value : it;
      }
      /**
       * Checks if the collection includes a value with the key `key`.
       *
       * `key` must contain a representation of an integer for this to succeed.
       * It may be wrapped in a `Scalar`.
       */
      has(key) {
        const idx = asItemIndex(key);
        return typeof idx === "number" && idx < this.items.length;
      }
      /**
       * Sets a value in this collection. For `!!set`, `value` needs to be a
       * boolean to add/remove the item from the set.
       *
       * If `key` does not contain a representation of an integer, this will throw.
       * It may be wrapped in a `Scalar`.
       */
      set(key, value) {
        const idx = asItemIndex(key);
        if (typeof idx !== "number")
          throw new Error(`Expected a valid index, not ${key}.`);
        const prev = this.items[idx];
        if (identity.isScalar(prev) && Scalar.isScalarValue(value))
          prev.value = value;
        else
          this.items[idx] = value;
      }
      toJSON(_, ctx) {
        const seq = [];
        if (ctx?.onCreate)
          ctx.onCreate(seq);
        let i = 0;
        for (const item of this.items)
          seq.push(toJS.toJS(item, String(i++), ctx));
        return seq;
      }
      toString(ctx, onComment, onChompKeep) {
        if (!ctx)
          return JSON.stringify(this);
        return stringifyCollection.stringifyCollection(this, ctx, {
          blockItemPrefix: "- ",
          flowChars: { start: "[", end: "]" },
          itemIndent: (ctx.indent || "") + "  ",
          onChompKeep,
          onComment
        });
      }
      static from(schema, obj, ctx) {
        const { replacer } = ctx;
        const seq = new this(schema);
        if (obj && Symbol.iterator in Object(obj)) {
          let i = 0;
          for (let it of obj) {
            if (typeof replacer === "function") {
              const key = obj instanceof Set ? it : String(i++);
              it = replacer.call(obj, key, it);
            }
            seq.items.push(createNode.createNode(it, void 0, ctx));
          }
        }
        return seq;
      }
    };
    function asItemIndex(key) {
      let idx = identity.isScalar(key) ? key.value : key;
      if (idx && typeof idx === "string")
        idx = Number(idx);
      return typeof idx === "number" && Number.isInteger(idx) && idx >= 0 ? idx : null;
    }
    exports.YAMLSeq = YAMLSeq;
  }
});

// node_modules/yaml/dist/schema/common/seq.js
var require_seq = __commonJS({
  "node_modules/yaml/dist/schema/common/seq.js"(exports) {
    "use strict";
    var identity = require_identity();
    var YAMLSeq = require_YAMLSeq();
    var seq = {
      collection: "seq",
      default: true,
      nodeClass: YAMLSeq.YAMLSeq,
      tag: "tag:yaml.org,2002:seq",
      resolve(seq2, onError) {
        if (!identity.isSeq(seq2))
          onError("Expected a sequence for this tag");
        return seq2;
      },
      createNode: (schema, obj, ctx) => YAMLSeq.YAMLSeq.from(schema, obj, ctx)
    };
    exports.seq = seq;
  }
});

// node_modules/yaml/dist/schema/common/string.js
var require_string = __commonJS({
  "node_modules/yaml/dist/schema/common/string.js"(exports) {
    "use strict";
    var stringifyString = require_stringifyString();
    var string = {
      identify: (value) => typeof value === "string",
      default: true,
      tag: "tag:yaml.org,2002:str",
      resolve: (str) => str,
      stringify(item, ctx, onComment, onChompKeep) {
        ctx = Object.assign({ actualString: true }, ctx);
        return stringifyString.stringifyString(item, ctx, onComment, onChompKeep);
      }
    };
    exports.string = string;
  }
});

// node_modules/yaml/dist/schema/common/null.js
var require_null = __commonJS({
  "node_modules/yaml/dist/schema/common/null.js"(exports) {
    "use strict";
    var Scalar = require_Scalar();
    var nullTag = {
      identify: (value) => value == null,
      createNode: () => new Scalar.Scalar(null),
      default: true,
      tag: "tag:yaml.org,2002:null",
      test: /^(?:~|[Nn]ull|NULL)?$/,
      resolve: () => new Scalar.Scalar(null),
      stringify: ({ source }, ctx) => typeof source === "string" && nullTag.test.test(source) ? source : ctx.options.nullStr
    };
    exports.nullTag = nullTag;
  }
});

// node_modules/yaml/dist/schema/core/bool.js
var require_bool = __commonJS({
  "node_modules/yaml/dist/schema/core/bool.js"(exports) {
    "use strict";
    var Scalar = require_Scalar();
    var boolTag = {
      identify: (value) => typeof value === "boolean",
      default: true,
      tag: "tag:yaml.org,2002:bool",
      test: /^(?:[Tt]rue|TRUE|[Ff]alse|FALSE)$/,
      resolve: (str) => new Scalar.Scalar(str[0] === "t" || str[0] === "T"),
      stringify({ source, value }, ctx) {
        if (source && boolTag.test.test(source)) {
          const sv = source[0] === "t" || source[0] === "T";
          if (value === sv)
            return source;
        }
        return value ? ctx.options.trueStr : ctx.options.falseStr;
      }
    };
    exports.boolTag = boolTag;
  }
});

// node_modules/yaml/dist/stringify/stringifyNumber.js
var require_stringifyNumber = __commonJS({
  "node_modules/yaml/dist/stringify/stringifyNumber.js"(exports) {
    "use strict";
    function stringifyNumber({ format, minFractionDigits, tag, value }) {
      if (typeof value === "bigint")
        return String(value);
      const num = typeof value === "number" ? value : Number(value);
      if (!isFinite(num))
        return isNaN(num) ? ".nan" : num < 0 ? "-.inf" : ".inf";
      let n = Object.is(value, -0) ? "-0" : JSON.stringify(value);
      if (!format && minFractionDigits && (!tag || tag === "tag:yaml.org,2002:float") && /^\d/.test(n)) {
        let i = n.indexOf(".");
        if (i < 0) {
          i = n.length;
          n += ".";
        }
        let d = minFractionDigits - (n.length - i - 1);
        while (d-- > 0)
          n += "0";
      }
      return n;
    }
    exports.stringifyNumber = stringifyNumber;
  }
});

// node_modules/yaml/dist/schema/core/float.js
var require_float = __commonJS({
  "node_modules/yaml/dist/schema/core/float.js"(exports) {
    "use strict";
    var Scalar = require_Scalar();
    var stringifyNumber = require_stringifyNumber();
    var floatNaN = {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      test: /^(?:[-+]?\.(?:inf|Inf|INF)|\.nan|\.NaN|\.NAN)$/,
      resolve: (str) => str.slice(-3).toLowerCase() === "nan" ? NaN : str[0] === "-" ? Number.NEGATIVE_INFINITY : Number.POSITIVE_INFINITY,
      stringify: stringifyNumber.stringifyNumber
    };
    var floatExp = {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      format: "EXP",
      test: /^[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+$/,
      resolve: (str) => parseFloat(str),
      stringify(node) {
        const num = Number(node.value);
        return isFinite(num) ? num.toExponential() : stringifyNumber.stringifyNumber(node);
      }
    };
    var float = {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      test: /^[-+]?(?:\.[0-9]+|[0-9]+\.[0-9]*)$/,
      resolve(str) {
        const node = new Scalar.Scalar(parseFloat(str));
        const dot = str.indexOf(".");
        if (dot !== -1 && str[str.length - 1] === "0")
          node.minFractionDigits = str.length - dot - 1;
        return node;
      },
      stringify: stringifyNumber.stringifyNumber
    };
    exports.float = float;
    exports.floatExp = floatExp;
    exports.floatNaN = floatNaN;
  }
});

// node_modules/yaml/dist/schema/core/int.js
var require_int = __commonJS({
  "node_modules/yaml/dist/schema/core/int.js"(exports) {
    "use strict";
    var stringifyNumber = require_stringifyNumber();
    var intIdentify = (value) => typeof value === "bigint" || Number.isInteger(value);
    var intResolve = (str, offset, radix, { intAsBigInt }) => intAsBigInt ? BigInt(str) : parseInt(str.substring(offset), radix);
    function intStringify(node, radix, prefix) {
      const { value } = node;
      if (intIdentify(value) && value >= 0)
        return prefix + value.toString(radix);
      return stringifyNumber.stringifyNumber(node);
    }
    var intOct = {
      identify: (value) => intIdentify(value) && value >= 0,
      default: true,
      tag: "tag:yaml.org,2002:int",
      format: "OCT",
      test: /^0o[0-7]+$/,
      resolve: (str, _onError, opt) => intResolve(str, 2, 8, opt),
      stringify: (node) => intStringify(node, 8, "0o")
    };
    var int = {
      identify: intIdentify,
      default: true,
      tag: "tag:yaml.org,2002:int",
      test: /^[-+]?[0-9]+$/,
      resolve: (str, _onError, opt) => intResolve(str, 0, 10, opt),
      stringify: stringifyNumber.stringifyNumber
    };
    var intHex = {
      identify: (value) => intIdentify(value) && value >= 0,
      default: true,
      tag: "tag:yaml.org,2002:int",
      format: "HEX",
      test: /^0x[0-9a-fA-F]+$/,
      resolve: (str, _onError, opt) => intResolve(str, 2, 16, opt),
      stringify: (node) => intStringify(node, 16, "0x")
    };
    exports.int = int;
    exports.intHex = intHex;
    exports.intOct = intOct;
  }
});

// node_modules/yaml/dist/schema/core/schema.js
var require_schema = __commonJS({
  "node_modules/yaml/dist/schema/core/schema.js"(exports) {
    "use strict";
    var map = require_map();
    var _null = require_null();
    var seq = require_seq();
    var string = require_string();
    var bool = require_bool();
    var float = require_float();
    var int = require_int();
    var schema = [
      map.map,
      seq.seq,
      string.string,
      _null.nullTag,
      bool.boolTag,
      int.intOct,
      int.int,
      int.intHex,
      float.floatNaN,
      float.floatExp,
      float.float
    ];
    exports.schema = schema;
  }
});

// node_modules/yaml/dist/schema/json/schema.js
var require_schema2 = __commonJS({
  "node_modules/yaml/dist/schema/json/schema.js"(exports) {
    "use strict";
    var Scalar = require_Scalar();
    var map = require_map();
    var seq = require_seq();
    function intIdentify(value) {
      return typeof value === "bigint" || Number.isInteger(value);
    }
    var stringifyJSON = ({ value }) => JSON.stringify(value);
    var jsonScalars = [
      {
        identify: (value) => typeof value === "string",
        default: true,
        tag: "tag:yaml.org,2002:str",
        resolve: (str) => str,
        stringify: stringifyJSON
      },
      {
        identify: (value) => value == null,
        createNode: () => new Scalar.Scalar(null),
        default: true,
        tag: "tag:yaml.org,2002:null",
        test: /^null$/,
        resolve: () => null,
        stringify: stringifyJSON
      },
      {
        identify: (value) => typeof value === "boolean",
        default: true,
        tag: "tag:yaml.org,2002:bool",
        test: /^true$|^false$/,
        resolve: (str) => str === "true",
        stringify: stringifyJSON
      },
      {
        identify: intIdentify,
        default: true,
        tag: "tag:yaml.org,2002:int",
        test: /^-?(?:0|[1-9][0-9]*)$/,
        resolve: (str, _onError, { intAsBigInt }) => intAsBigInt ? BigInt(str) : parseInt(str, 10),
        stringify: ({ value }) => intIdentify(value) ? value.toString() : JSON.stringify(value)
      },
      {
        identify: (value) => typeof value === "number",
        default: true,
        tag: "tag:yaml.org,2002:float",
        test: /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*)?(?:[eE][-+]?[0-9]+)?$/,
        resolve: (str) => parseFloat(str),
        stringify: stringifyJSON
      }
    ];
    var jsonError = {
      default: true,
      tag: "",
      test: /^/,
      resolve(str, onError) {
        onError(`Unresolved plain scalar ${JSON.stringify(str)}`);
        return str;
      }
    };
    var schema = [map.map, seq.seq].concat(jsonScalars, jsonError);
    exports.schema = schema;
  }
});

// node_modules/yaml/dist/schema/yaml-1.1/binary.js
var require_binary = __commonJS({
  "node_modules/yaml/dist/schema/yaml-1.1/binary.js"(exports) {
    "use strict";
    var node_buffer = __require("buffer");
    var Scalar = require_Scalar();
    var stringifyString = require_stringifyString();
    var binary = {
      identify: (value) => value instanceof Uint8Array,
      // Buffer inherits from Uint8Array
      default: false,
      tag: "tag:yaml.org,2002:binary",
      /**
       * Returns a Buffer in node and an Uint8Array in browsers
       *
       * To use the resulting buffer as an image, you'll want to do something like:
       *
       *   const blob = new Blob([buffer], { type: 'image/jpeg' })
       *   document.querySelector('#photo').src = URL.createObjectURL(blob)
       */
      resolve(src, onError) {
        if (typeof node_buffer.Buffer === "function") {
          return node_buffer.Buffer.from(src, "base64");
        } else if (typeof atob === "function") {
          const str = atob(src.replace(/[\n\r]/g, ""));
          const buffer = new Uint8Array(str.length);
          for (let i = 0; i < str.length; ++i)
            buffer[i] = str.charCodeAt(i);
          return buffer;
        } else {
          onError("This environment does not support reading binary tags; either Buffer or atob is required");
          return src;
        }
      },
      stringify({ comment, type, value }, ctx, onComment, onChompKeep) {
        if (!value)
          return "";
        const buf = value;
        let str;
        if (typeof node_buffer.Buffer === "function") {
          str = buf instanceof node_buffer.Buffer ? buf.toString("base64") : node_buffer.Buffer.from(buf.buffer).toString("base64");
        } else if (typeof btoa === "function") {
          let s = "";
          for (let i = 0; i < buf.length; ++i)
            s += String.fromCharCode(buf[i]);
          str = btoa(s);
        } else {
          throw new Error("This environment does not support writing binary tags; either Buffer or btoa is required");
        }
        type ?? (type = Scalar.Scalar.BLOCK_LITERAL);
        if (type !== Scalar.Scalar.QUOTE_DOUBLE) {
          const lineWidth = Math.max(ctx.options.lineWidth - ctx.indent.length, ctx.options.minContentWidth);
          const n = Math.ceil(str.length / lineWidth);
          const lines = new Array(n);
          for (let i = 0, o = 0; i < n; ++i, o += lineWidth) {
            lines[i] = str.substr(o, lineWidth);
          }
          str = lines.join(type === Scalar.Scalar.BLOCK_LITERAL ? "\n" : " ");
        }
        return stringifyString.stringifyString({ comment, type, value: str }, ctx, onComment, onChompKeep);
      }
    };
    exports.binary = binary;
  }
});

// node_modules/yaml/dist/schema/yaml-1.1/pairs.js
var require_pairs = __commonJS({
  "node_modules/yaml/dist/schema/yaml-1.1/pairs.js"(exports) {
    "use strict";
    var identity = require_identity();
    var Pair = require_Pair();
    var Scalar = require_Scalar();
    var YAMLSeq = require_YAMLSeq();
    function resolvePairs(seq, onError) {
      if (identity.isSeq(seq)) {
        for (let i = 0; i < seq.items.length; ++i) {
          let item = seq.items[i];
          if (identity.isPair(item))
            continue;
          else if (identity.isMap(item)) {
            if (item.items.length > 1)
              onError("Each pair must have its own sequence indicator");
            const pair = item.items[0] || new Pair.Pair(new Scalar.Scalar(null));
            if (item.commentBefore)
              pair.key.commentBefore = pair.key.commentBefore ? `${item.commentBefore}
${pair.key.commentBefore}` : item.commentBefore;
            if (item.comment) {
              const cn = pair.value ?? pair.key;
              cn.comment = cn.comment ? `${item.comment}
${cn.comment}` : item.comment;
            }
            item = pair;
          }
          seq.items[i] = identity.isPair(item) ? item : new Pair.Pair(item);
        }
      } else
        onError("Expected a sequence for this tag");
      return seq;
    }
    function createPairs(schema, iterable, ctx) {
      const { replacer } = ctx;
      const pairs2 = new YAMLSeq.YAMLSeq(schema);
      pairs2.tag = "tag:yaml.org,2002:pairs";
      let i = 0;
      if (iterable && Symbol.iterator in Object(iterable))
        for (let it of iterable) {
          if (typeof replacer === "function")
            it = replacer.call(iterable, String(i++), it);
          let key, value;
          if (Array.isArray(it)) {
            if (it.length === 2) {
              key = it[0];
              value = it[1];
            } else
              throw new TypeError(`Expected [key, value] tuple: ${it}`);
          } else if (it && it instanceof Object) {
            const keys = Object.keys(it);
            if (keys.length === 1) {
              key = keys[0];
              value = it[key];
            } else {
              throw new TypeError(`Expected tuple with one key, not ${keys.length} keys`);
            }
          } else {
            key = it;
          }
          pairs2.items.push(Pair.createPair(key, value, ctx));
        }
      return pairs2;
    }
    var pairs = {
      collection: "seq",
      default: false,
      tag: "tag:yaml.org,2002:pairs",
      resolve: resolvePairs,
      createNode: createPairs
    };
    exports.createPairs = createPairs;
    exports.pairs = pairs;
    exports.resolvePairs = resolvePairs;
  }
});

// node_modules/yaml/dist/schema/yaml-1.1/omap.js
var require_omap = __commonJS({
  "node_modules/yaml/dist/schema/yaml-1.1/omap.js"(exports) {
    "use strict";
    var identity = require_identity();
    var toJS = require_toJS();
    var YAMLMap = require_YAMLMap();
    var YAMLSeq = require_YAMLSeq();
    var pairs = require_pairs();
    var YAMLOMap = class _YAMLOMap extends YAMLSeq.YAMLSeq {
      constructor() {
        super();
        this.add = YAMLMap.YAMLMap.prototype.add.bind(this);
        this.delete = YAMLMap.YAMLMap.prototype.delete.bind(this);
        this.get = YAMLMap.YAMLMap.prototype.get.bind(this);
        this.has = YAMLMap.YAMLMap.prototype.has.bind(this);
        this.set = YAMLMap.YAMLMap.prototype.set.bind(this);
        this.tag = _YAMLOMap.tag;
      }
      /**
       * If `ctx` is given, the return type is actually `Map<unknown, unknown>`,
       * but TypeScript won't allow widening the signature of a child method.
       */
      toJSON(_, ctx) {
        if (!ctx)
          return super.toJSON(_);
        const map = /* @__PURE__ */ new Map();
        if (ctx?.onCreate)
          ctx.onCreate(map);
        for (const pair of this.items) {
          let key, value;
          if (identity.isPair(pair)) {
            key = toJS.toJS(pair.key, "", ctx);
            value = toJS.toJS(pair.value, key, ctx);
          } else {
            key = toJS.toJS(pair, "", ctx);
          }
          if (map.has(key))
            throw new Error("Ordered maps must not include duplicate keys");
          map.set(key, value);
        }
        return map;
      }
      static from(schema, iterable, ctx) {
        const pairs$1 = pairs.createPairs(schema, iterable, ctx);
        const omap2 = new this();
        omap2.items = pairs$1.items;
        return omap2;
      }
    };
    YAMLOMap.tag = "tag:yaml.org,2002:omap";
    var omap = {
      collection: "seq",
      identify: (value) => value instanceof Map,
      nodeClass: YAMLOMap,
      default: false,
      tag: "tag:yaml.org,2002:omap",
      resolve(seq, onError) {
        const pairs$1 = pairs.resolvePairs(seq, onError);
        const seenKeys = [];
        for (const { key } of pairs$1.items) {
          if (identity.isScalar(key)) {
            if (seenKeys.includes(key.value)) {
              onError(`Ordered maps must not include duplicate keys: ${key.value}`);
            } else {
              seenKeys.push(key.value);
            }
          }
        }
        return Object.assign(new YAMLOMap(), pairs$1);
      },
      createNode: (schema, iterable, ctx) => YAMLOMap.from(schema, iterable, ctx)
    };
    exports.YAMLOMap = YAMLOMap;
    exports.omap = omap;
  }
});

// node_modules/yaml/dist/schema/yaml-1.1/bool.js
var require_bool2 = __commonJS({
  "node_modules/yaml/dist/schema/yaml-1.1/bool.js"(exports) {
    "use strict";
    var Scalar = require_Scalar();
    function boolStringify({ value, source }, ctx) {
      const boolObj = value ? trueTag : falseTag;
      if (source && boolObj.test.test(source))
        return source;
      return value ? ctx.options.trueStr : ctx.options.falseStr;
    }
    var trueTag = {
      identify: (value) => value === true,
      default: true,
      tag: "tag:yaml.org,2002:bool",
      test: /^(?:Y|y|[Yy]es|YES|[Tt]rue|TRUE|[Oo]n|ON)$/,
      resolve: () => new Scalar.Scalar(true),
      stringify: boolStringify
    };
    var falseTag = {
      identify: (value) => value === false,
      default: true,
      tag: "tag:yaml.org,2002:bool",
      test: /^(?:N|n|[Nn]o|NO|[Ff]alse|FALSE|[Oo]ff|OFF)$/,
      resolve: () => new Scalar.Scalar(false),
      stringify: boolStringify
    };
    exports.falseTag = falseTag;
    exports.trueTag = trueTag;
  }
});

// node_modules/yaml/dist/schema/yaml-1.1/float.js
var require_float2 = __commonJS({
  "node_modules/yaml/dist/schema/yaml-1.1/float.js"(exports) {
    "use strict";
    var Scalar = require_Scalar();
    var stringifyNumber = require_stringifyNumber();
    var floatNaN = {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      test: /^(?:[-+]?\.(?:inf|Inf|INF)|\.nan|\.NaN|\.NAN)$/,
      resolve: (str) => str.slice(-3).toLowerCase() === "nan" ? NaN : str[0] === "-" ? Number.NEGATIVE_INFINITY : Number.POSITIVE_INFINITY,
      stringify: stringifyNumber.stringifyNumber
    };
    var floatExp = {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      format: "EXP",
      test: /^[-+]?(?:[0-9][0-9_]*)?(?:\.[0-9_]*)?[eE][-+]?[0-9]+$/,
      resolve: (str) => parseFloat(str.replace(/_/g, "")),
      stringify(node) {
        const num = Number(node.value);
        return isFinite(num) ? num.toExponential() : stringifyNumber.stringifyNumber(node);
      }
    };
    var float = {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      test: /^[-+]?(?:[0-9][0-9_]*)?\.[0-9_]*$/,
      resolve(str) {
        const node = new Scalar.Scalar(parseFloat(str.replace(/_/g, "")));
        const dot = str.indexOf(".");
        if (dot !== -1) {
          const f = str.substring(dot + 1).replace(/_/g, "");
          if (f[f.length - 1] === "0")
            node.minFractionDigits = f.length;
        }
        return node;
      },
      stringify: stringifyNumber.stringifyNumber
    };
    exports.float = float;
    exports.floatExp = floatExp;
    exports.floatNaN = floatNaN;
  }
});

// node_modules/yaml/dist/schema/yaml-1.1/int.js
var require_int2 = __commonJS({
  "node_modules/yaml/dist/schema/yaml-1.1/int.js"(exports) {
    "use strict";
    var stringifyNumber = require_stringifyNumber();
    var intIdentify = (value) => typeof value === "bigint" || Number.isInteger(value);
    function intResolve(str, offset, radix, { intAsBigInt }) {
      const sign = str[0];
      if (sign === "-" || sign === "+")
        offset += 1;
      str = str.substring(offset).replace(/_/g, "");
      if (intAsBigInt) {
        switch (radix) {
          case 2:
            str = `0b${str}`;
            break;
          case 8:
            str = `0o${str}`;
            break;
          case 16:
            str = `0x${str}`;
            break;
        }
        const n2 = BigInt(str);
        return sign === "-" ? BigInt(-1) * n2 : n2;
      }
      const n = parseInt(str, radix);
      return sign === "-" ? -1 * n : n;
    }
    function intStringify(node, radix, prefix) {
      const { value } = node;
      if (intIdentify(value)) {
        const str = value.toString(radix);
        return value < 0 ? "-" + prefix + str.substr(1) : prefix + str;
      }
      return stringifyNumber.stringifyNumber(node);
    }
    var intBin = {
      identify: intIdentify,
      default: true,
      tag: "tag:yaml.org,2002:int",
      format: "BIN",
      test: /^[-+]?0b[0-1_]+$/,
      resolve: (str, _onError, opt) => intResolve(str, 2, 2, opt),
      stringify: (node) => intStringify(node, 2, "0b")
    };
    var intOct = {
      identify: intIdentify,
      default: true,
      tag: "tag:yaml.org,2002:int",
      format: "OCT",
      test: /^[-+]?0[0-7_]+$/,
      resolve: (str, _onError, opt) => intResolve(str, 1, 8, opt),
      stringify: (node) => intStringify(node, 8, "0")
    };
    var int = {
      identify: intIdentify,
      default: true,
      tag: "tag:yaml.org,2002:int",
      test: /^[-+]?[0-9][0-9_]*$/,
      resolve: (str, _onError, opt) => intResolve(str, 0, 10, opt),
      stringify: stringifyNumber.stringifyNumber
    };
    var intHex = {
      identify: intIdentify,
      default: true,
      tag: "tag:yaml.org,2002:int",
      format: "HEX",
      test: /^[-+]?0x[0-9a-fA-F_]+$/,
      resolve: (str, _onError, opt) => intResolve(str, 2, 16, opt),
      stringify: (node) => intStringify(node, 16, "0x")
    };
    exports.int = int;
    exports.intBin = intBin;
    exports.intHex = intHex;
    exports.intOct = intOct;
  }
});

// node_modules/yaml/dist/schema/yaml-1.1/set.js
var require_set = __commonJS({
  "node_modules/yaml/dist/schema/yaml-1.1/set.js"(exports) {
    "use strict";
    var identity = require_identity();
    var Pair = require_Pair();
    var YAMLMap = require_YAMLMap();
    var YAMLSet = class _YAMLSet extends YAMLMap.YAMLMap {
      constructor(schema) {
        super(schema);
        this.tag = _YAMLSet.tag;
      }
      add(key) {
        let pair;
        if (identity.isPair(key))
          pair = key;
        else if (key && typeof key === "object" && "key" in key && "value" in key && key.value === null)
          pair = new Pair.Pair(key.key, null);
        else
          pair = new Pair.Pair(key, null);
        const prev = YAMLMap.findPair(this.items, pair.key);
        if (!prev)
          this.items.push(pair);
      }
      /**
       * If `keepPair` is `true`, returns the Pair matching `key`.
       * Otherwise, returns the value of that Pair's key.
       */
      get(key, keepPair) {
        const pair = YAMLMap.findPair(this.items, key);
        return !keepPair && identity.isPair(pair) ? identity.isScalar(pair.key) ? pair.key.value : pair.key : pair;
      }
      set(key, value) {
        if (typeof value !== "boolean")
          throw new Error(`Expected boolean value for set(key, value) in a YAML set, not ${typeof value}`);
        const prev = YAMLMap.findPair(this.items, key);
        if (prev && !value) {
          this.items.splice(this.items.indexOf(prev), 1);
        } else if (!prev && value) {
          this.items.push(new Pair.Pair(key));
        }
      }
      toJSON(_, ctx) {
        return super.toJSON(_, ctx, Set);
      }
      toString(ctx, onComment, onChompKeep) {
        if (!ctx)
          return JSON.stringify(this);
        if (this.hasAllNullValues(true))
          return super.toString(Object.assign({}, ctx, { allNullValues: true }), onComment, onChompKeep);
        else
          throw new Error("Set items must all have null values");
      }
      static from(schema, iterable, ctx) {
        const { replacer } = ctx;
        const set2 = new this(schema);
        if (iterable && Symbol.iterator in Object(iterable))
          for (let value of iterable) {
            if (typeof replacer === "function")
              value = replacer.call(iterable, value, value);
            set2.items.push(Pair.createPair(value, null, ctx));
          }
        return set2;
      }
    };
    YAMLSet.tag = "tag:yaml.org,2002:set";
    var set = {
      collection: "map",
      identify: (value) => value instanceof Set,
      nodeClass: YAMLSet,
      default: false,
      tag: "tag:yaml.org,2002:set",
      createNode: (schema, iterable, ctx) => YAMLSet.from(schema, iterable, ctx),
      resolve(map, onError) {
        if (identity.isMap(map)) {
          if (map.hasAllNullValues(true))
            return Object.assign(new YAMLSet(), map);
          else
            onError("Set items must all have null values");
        } else
          onError("Expected a mapping for this tag");
        return map;
      }
    };
    exports.YAMLSet = YAMLSet;
    exports.set = set;
  }
});

// node_modules/yaml/dist/schema/yaml-1.1/timestamp.js
var require_timestamp = __commonJS({
  "node_modules/yaml/dist/schema/yaml-1.1/timestamp.js"(exports) {
    "use strict";
    var stringifyNumber = require_stringifyNumber();
    function parseSexagesimal(str, asBigInt) {
      const sign = str[0];
      const parts = sign === "-" || sign === "+" ? str.substring(1) : str;
      const num = (n) => asBigInt ? BigInt(n) : Number(n);
      const res = parts.replace(/_/g, "").split(":").reduce((res2, p) => res2 * num(60) + num(p), num(0));
      return sign === "-" ? num(-1) * res : res;
    }
    function stringifySexagesimal(node) {
      let { value } = node;
      let num = (n) => n;
      if (typeof value === "bigint")
        num = (n) => BigInt(n);
      else if (isNaN(value) || !isFinite(value))
        return stringifyNumber.stringifyNumber(node);
      let sign = "";
      if (value < 0) {
        sign = "-";
        value *= num(-1);
      }
      const _60 = num(60);
      const parts = [value % _60];
      if (value < 60) {
        parts.unshift(0);
      } else {
        value = (value - parts[0]) / _60;
        parts.unshift(value % _60);
        if (value >= 60) {
          value = (value - parts[0]) / _60;
          parts.unshift(value);
        }
      }
      return sign + parts.map((n) => String(n).padStart(2, "0")).join(":").replace(/000000\d*$/, "");
    }
    var intTime = {
      identify: (value) => typeof value === "bigint" || Number.isInteger(value),
      default: true,
      tag: "tag:yaml.org,2002:int",
      format: "TIME",
      test: /^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+$/,
      resolve: (str, _onError, { intAsBigInt }) => parseSexagesimal(str, intAsBigInt),
      stringify: stringifySexagesimal
    };
    var floatTime = {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      format: "TIME",
      test: /^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*$/,
      resolve: (str) => parseSexagesimal(str, false),
      stringify: stringifySexagesimal
    };
    var timestamp = {
      identify: (value) => value instanceof Date,
      default: true,
      tag: "tag:yaml.org,2002:timestamp",
      // If the time zone is omitted, the timestamp is assumed to be specified in UTC. The time part
      // may be omitted altogether, resulting in a date format. In such a case, the time part is
      // assumed to be 00:00:00Z (start of day, UTC).
      test: RegExp("^([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})(?:(?:t|T|[ \\t]+)([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2}(\\.[0-9]+)?)(?:[ \\t]*(Z|[-+][012]?[0-9](?::[0-9]{2})?))?)?$"),
      resolve(str) {
        const match = str.match(timestamp.test);
        if (!match)
          throw new Error("!!timestamp expects a date, starting with yyyy-mm-dd");
        const [, year, month, day, hour, minute, second] = match.map(Number);
        const millisec = match[7] ? Number((match[7] + "00").substr(1, 3)) : 0;
        let date = Date.UTC(year, month - 1, day, hour || 0, minute || 0, second || 0, millisec);
        const tz = match[8];
        if (tz && tz !== "Z") {
          let d = parseSexagesimal(tz, false);
          if (Math.abs(d) < 30)
            d *= 60;
          date -= 6e4 * d;
        }
        return new Date(date);
      },
      stringify: ({ value }) => value?.toISOString().replace(/(T00:00:00)?\.000Z$/, "") ?? ""
    };
    exports.floatTime = floatTime;
    exports.intTime = intTime;
    exports.timestamp = timestamp;
  }
});

// node_modules/yaml/dist/schema/yaml-1.1/schema.js
var require_schema3 = __commonJS({
  "node_modules/yaml/dist/schema/yaml-1.1/schema.js"(exports) {
    "use strict";
    var map = require_map();
    var _null = require_null();
    var seq = require_seq();
    var string = require_string();
    var binary = require_binary();
    var bool = require_bool2();
    var float = require_float2();
    var int = require_int2();
    var merge = require_merge();
    var omap = require_omap();
    var pairs = require_pairs();
    var set = require_set();
    var timestamp = require_timestamp();
    var schema = [
      map.map,
      seq.seq,
      string.string,
      _null.nullTag,
      bool.trueTag,
      bool.falseTag,
      int.intBin,
      int.intOct,
      int.int,
      int.intHex,
      float.floatNaN,
      float.floatExp,
      float.float,
      binary.binary,
      merge.merge,
      omap.omap,
      pairs.pairs,
      set.set,
      timestamp.intTime,
      timestamp.floatTime,
      timestamp.timestamp
    ];
    exports.schema = schema;
  }
});

// node_modules/yaml/dist/schema/tags.js
var require_tags = __commonJS({
  "node_modules/yaml/dist/schema/tags.js"(exports) {
    "use strict";
    var map = require_map();
    var _null = require_null();
    var seq = require_seq();
    var string = require_string();
    var bool = require_bool();
    var float = require_float();
    var int = require_int();
    var schema = require_schema();
    var schema$1 = require_schema2();
    var binary = require_binary();
    var merge = require_merge();
    var omap = require_omap();
    var pairs = require_pairs();
    var schema$2 = require_schema3();
    var set = require_set();
    var timestamp = require_timestamp();
    var schemas = /* @__PURE__ */ new Map([
      ["core", schema.schema],
      ["failsafe", [map.map, seq.seq, string.string]],
      ["json", schema$1.schema],
      ["yaml11", schema$2.schema],
      ["yaml-1.1", schema$2.schema]
    ]);
    var tagsByName = {
      binary: binary.binary,
      bool: bool.boolTag,
      float: float.float,
      floatExp: float.floatExp,
      floatNaN: float.floatNaN,
      floatTime: timestamp.floatTime,
      int: int.int,
      intHex: int.intHex,
      intOct: int.intOct,
      intTime: timestamp.intTime,
      map: map.map,
      merge: merge.merge,
      null: _null.nullTag,
      omap: omap.omap,
      pairs: pairs.pairs,
      seq: seq.seq,
      set: set.set,
      timestamp: timestamp.timestamp
    };
    var coreKnownTags = {
      "tag:yaml.org,2002:binary": binary.binary,
      "tag:yaml.org,2002:merge": merge.merge,
      "tag:yaml.org,2002:omap": omap.omap,
      "tag:yaml.org,2002:pairs": pairs.pairs,
      "tag:yaml.org,2002:set": set.set,
      "tag:yaml.org,2002:timestamp": timestamp.timestamp
    };
    function getTags(customTags, schemaName, addMergeTag) {
      const schemaTags = schemas.get(schemaName);
      if (schemaTags && !customTags) {
        return addMergeTag && !schemaTags.includes(merge.merge) ? schemaTags.concat(merge.merge) : schemaTags.slice();
      }
      let tags = schemaTags;
      if (!tags) {
        if (Array.isArray(customTags))
          tags = [];
        else {
          const keys = Array.from(schemas.keys()).filter((key) => key !== "yaml11").map((key) => JSON.stringify(key)).join(", ");
          throw new Error(`Unknown schema "${schemaName}"; use one of ${keys} or define customTags array`);
        }
      }
      if (Array.isArray(customTags)) {
        for (const tag of customTags)
          tags = tags.concat(tag);
      } else if (typeof customTags === "function") {
        tags = customTags(tags.slice());
      }
      if (addMergeTag)
        tags = tags.concat(merge.merge);
      return tags.reduce((tags2, tag) => {
        const tagObj = typeof tag === "string" ? tagsByName[tag] : tag;
        if (!tagObj) {
          const tagName = JSON.stringify(tag);
          const keys = Object.keys(tagsByName).map((key) => JSON.stringify(key)).join(", ");
          throw new Error(`Unknown custom tag ${tagName}; use one of ${keys}`);
        }
        if (!tags2.includes(tagObj))
          tags2.push(tagObj);
        return tags2;
      }, []);
    }
    exports.coreKnownTags = coreKnownTags;
    exports.getTags = getTags;
  }
});

// node_modules/yaml/dist/schema/Schema.js
var require_Schema = __commonJS({
  "node_modules/yaml/dist/schema/Schema.js"(exports) {
    "use strict";
    var identity = require_identity();
    var map = require_map();
    var seq = require_seq();
    var string = require_string();
    var tags = require_tags();
    var sortMapEntriesByKey = (a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
    var Schema = class _Schema {
      constructor({ compat, customTags, merge, resolveKnownTags, schema, sortMapEntries, toStringDefaults }) {
        this.compat = Array.isArray(compat) ? tags.getTags(compat, "compat") : compat ? tags.getTags(null, compat) : null;
        this.name = typeof schema === "string" && schema || "core";
        this.knownTags = resolveKnownTags ? tags.coreKnownTags : {};
        this.tags = tags.getTags(customTags, this.name, merge);
        this.toStringOptions = toStringDefaults ?? null;
        Object.defineProperty(this, identity.MAP, { value: map.map });
        Object.defineProperty(this, identity.SCALAR, { value: string.string });
        Object.defineProperty(this, identity.SEQ, { value: seq.seq });
        this.sortMapEntries = typeof sortMapEntries === "function" ? sortMapEntries : sortMapEntries === true ? sortMapEntriesByKey : null;
      }
      clone() {
        const copy = Object.create(_Schema.prototype, Object.getOwnPropertyDescriptors(this));
        copy.tags = this.tags.slice();
        return copy;
      }
    };
    exports.Schema = Schema;
  }
});

// node_modules/yaml/dist/stringify/stringifyDocument.js
var require_stringifyDocument = __commonJS({
  "node_modules/yaml/dist/stringify/stringifyDocument.js"(exports) {
    "use strict";
    var identity = require_identity();
    var stringify = require_stringify();
    var stringifyComment = require_stringifyComment();
    function stringifyDocument(doc, options) {
      const lines = [];
      let hasDirectives = options.directives === true;
      if (options.directives !== false && doc.directives) {
        const dir = doc.directives.toString(doc);
        if (dir) {
          lines.push(dir);
          hasDirectives = true;
        } else if (doc.directives.docStart)
          hasDirectives = true;
      }
      if (hasDirectives)
        lines.push("---");
      const ctx = stringify.createStringifyContext(doc, options);
      const { commentString } = ctx.options;
      if (doc.commentBefore) {
        if (lines.length !== 1)
          lines.unshift("");
        const cs = commentString(doc.commentBefore);
        lines.unshift(stringifyComment.indentComment(cs, ""));
      }
      let chompKeep = false;
      let contentComment = null;
      if (doc.contents) {
        if (identity.isNode(doc.contents)) {
          if (doc.contents.spaceBefore && hasDirectives)
            lines.push("");
          if (doc.contents.commentBefore) {
            const cs = commentString(doc.contents.commentBefore);
            lines.push(stringifyComment.indentComment(cs, ""));
          }
          ctx.forceBlockIndent = !!doc.comment;
          contentComment = doc.contents.comment;
        }
        const onChompKeep = contentComment ? void 0 : () => chompKeep = true;
        let body = stringify.stringify(doc.contents, ctx, () => contentComment = null, onChompKeep);
        if (contentComment)
          body += stringifyComment.lineComment(body, "", commentString(contentComment));
        if ((body[0] === "|" || body[0] === ">") && lines[lines.length - 1] === "---") {
          lines[lines.length - 1] = `--- ${body}`;
        } else
          lines.push(body);
      } else {
        lines.push(stringify.stringify(doc.contents, ctx));
      }
      if (doc.directives?.docEnd) {
        if (doc.comment) {
          const cs = commentString(doc.comment);
          if (cs.includes("\n")) {
            lines.push("...");
            lines.push(stringifyComment.indentComment(cs, ""));
          } else {
            lines.push(`... ${cs}`);
          }
        } else {
          lines.push("...");
        }
      } else {
        let dc = doc.comment;
        if (dc && chompKeep)
          dc = dc.replace(/^\n+/, "");
        if (dc) {
          if ((!chompKeep || contentComment) && lines[lines.length - 1] !== "")
            lines.push("");
          lines.push(stringifyComment.indentComment(commentString(dc), ""));
        }
      }
      return lines.join("\n") + "\n";
    }
    exports.stringifyDocument = stringifyDocument;
  }
});

// node_modules/yaml/dist/doc/Document.js
var require_Document = __commonJS({
  "node_modules/yaml/dist/doc/Document.js"(exports) {
    "use strict";
    var Alias = require_Alias();
    var Collection = require_Collection();
    var identity = require_identity();
    var Pair = require_Pair();
    var toJS = require_toJS();
    var Schema = require_Schema();
    var stringifyDocument = require_stringifyDocument();
    var anchors = require_anchors();
    var applyReviver = require_applyReviver();
    var createNode = require_createNode();
    var directives = require_directives();
    var Document = class _Document {
      constructor(value, replacer, options) {
        this.commentBefore = null;
        this.comment = null;
        this.errors = [];
        this.warnings = [];
        Object.defineProperty(this, identity.NODE_TYPE, { value: identity.DOC });
        let _replacer = null;
        if (typeof replacer === "function" || Array.isArray(replacer)) {
          _replacer = replacer;
        } else if (options === void 0 && replacer) {
          options = replacer;
          replacer = void 0;
        }
        const opt = Object.assign({
          intAsBigInt: false,
          keepSourceTokens: false,
          logLevel: "warn",
          prettyErrors: true,
          strict: true,
          stringKeys: false,
          uniqueKeys: true,
          version: "1.2"
        }, options);
        this.options = opt;
        let { version } = opt;
        if (options?._directives) {
          this.directives = options._directives.atDocument();
          if (this.directives.yaml.explicit)
            version = this.directives.yaml.version;
        } else
          this.directives = new directives.Directives({ version });
        this.setSchema(version, options);
        this.contents = value === void 0 ? null : this.createNode(value, _replacer, options);
      }
      /**
       * Create a deep copy of this Document and its contents.
       *
       * Custom Node values that inherit from `Object` still refer to their original instances.
       */
      clone() {
        const copy = Object.create(_Document.prototype, {
          [identity.NODE_TYPE]: { value: identity.DOC }
        });
        copy.commentBefore = this.commentBefore;
        copy.comment = this.comment;
        copy.errors = this.errors.slice();
        copy.warnings = this.warnings.slice();
        copy.options = Object.assign({}, this.options);
        if (this.directives)
          copy.directives = this.directives.clone();
        copy.schema = this.schema.clone();
        copy.contents = identity.isNode(this.contents) ? this.contents.clone(copy.schema) : this.contents;
        if (this.range)
          copy.range = this.range.slice();
        return copy;
      }
      /** Adds a value to the document. */
      add(value) {
        if (assertCollection(this.contents))
          this.contents.add(value);
      }
      /** Adds a value to the document. */
      addIn(path, value) {
        if (assertCollection(this.contents))
          this.contents.addIn(path, value);
      }
      /**
       * Create a new `Alias` node, ensuring that the target `node` has the required anchor.
       *
       * If `node` already has an anchor, `name` is ignored.
       * Otherwise, the `node.anchor` value will be set to `name`,
       * or if an anchor with that name is already present in the document,
       * `name` will be used as a prefix for a new unique anchor.
       * If `name` is undefined, the generated anchor will use 'a' as a prefix.
       */
      createAlias(node, name) {
        if (!node.anchor) {
          const prev = anchors.anchorNames(this);
          node.anchor = // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
          !name || prev.has(name) ? anchors.findNewAnchor(name || "a", prev) : name;
        }
        return new Alias.Alias(node.anchor);
      }
      createNode(value, replacer, options) {
        let _replacer = void 0;
        if (typeof replacer === "function") {
          value = replacer.call({ "": value }, "", value);
          _replacer = replacer;
        } else if (Array.isArray(replacer)) {
          const keyToStr = (v) => typeof v === "number" || v instanceof String || v instanceof Number;
          const asStr = replacer.filter(keyToStr).map(String);
          if (asStr.length > 0)
            replacer = replacer.concat(asStr);
          _replacer = replacer;
        } else if (options === void 0 && replacer) {
          options = replacer;
          replacer = void 0;
        }
        const { aliasDuplicateObjects, anchorPrefix, flow, keepUndefined, onTagObj, tag } = options ?? {};
        const { onAnchor, setAnchors, sourceObjects } = anchors.createNodeAnchors(
          this,
          // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
          anchorPrefix || "a"
        );
        const ctx = {
          aliasDuplicateObjects: aliasDuplicateObjects ?? true,
          keepUndefined: keepUndefined ?? false,
          onAnchor,
          onTagObj,
          replacer: _replacer,
          schema: this.schema,
          sourceObjects
        };
        const node = createNode.createNode(value, tag, ctx);
        if (flow && identity.isCollection(node))
          node.flow = true;
        setAnchors();
        return node;
      }
      /**
       * Convert a key and a value into a `Pair` using the current schema,
       * recursively wrapping all values as `Scalar` or `Collection` nodes.
       */
      createPair(key, value, options = {}) {
        const k = this.createNode(key, null, options);
        const v = this.createNode(value, null, options);
        return new Pair.Pair(k, v);
      }
      /**
       * Removes a value from the document.
       * @returns `true` if the item was found and removed.
       */
      delete(key) {
        return assertCollection(this.contents) ? this.contents.delete(key) : false;
      }
      /**
       * Removes a value from the document.
       * @returns `true` if the item was found and removed.
       */
      deleteIn(path) {
        if (Collection.isEmptyPath(path)) {
          if (this.contents == null)
            return false;
          this.contents = null;
          return true;
        }
        return assertCollection(this.contents) ? this.contents.deleteIn(path) : false;
      }
      /**
       * Returns item at `key`, or `undefined` if not found. By default unwraps
       * scalar values from their surrounding node; to disable set `keepScalar` to
       * `true` (collections are always returned intact).
       */
      get(key, keepScalar) {
        return identity.isCollection(this.contents) ? this.contents.get(key, keepScalar) : void 0;
      }
      /**
       * Returns item at `path`, or `undefined` if not found. By default unwraps
       * scalar values from their surrounding node; to disable set `keepScalar` to
       * `true` (collections are always returned intact).
       */
      getIn(path, keepScalar) {
        if (Collection.isEmptyPath(path))
          return !keepScalar && identity.isScalar(this.contents) ? this.contents.value : this.contents;
        return identity.isCollection(this.contents) ? this.contents.getIn(path, keepScalar) : void 0;
      }
      /**
       * Checks if the document includes a value with the key `key`.
       */
      has(key) {
        return identity.isCollection(this.contents) ? this.contents.has(key) : false;
      }
      /**
       * Checks if the document includes a value at `path`.
       */
      hasIn(path) {
        if (Collection.isEmptyPath(path))
          return this.contents !== void 0;
        return identity.isCollection(this.contents) ? this.contents.hasIn(path) : false;
      }
      /**
       * Sets a value in this document. For `!!set`, `value` needs to be a
       * boolean to add/remove the item from the set.
       */
      set(key, value) {
        if (this.contents == null) {
          this.contents = Collection.collectionFromPath(this.schema, [key], value);
        } else if (assertCollection(this.contents)) {
          this.contents.set(key, value);
        }
      }
      /**
       * Sets a value in this document. For `!!set`, `value` needs to be a
       * boolean to add/remove the item from the set.
       */
      setIn(path, value) {
        if (Collection.isEmptyPath(path)) {
          this.contents = value;
        } else if (this.contents == null) {
          this.contents = Collection.collectionFromPath(this.schema, Array.from(path), value);
        } else if (assertCollection(this.contents)) {
          this.contents.setIn(path, value);
        }
      }
      /**
       * Change the YAML version and schema used by the document.
       * A `null` version disables support for directives, explicit tags, anchors, and aliases.
       * It also requires the `schema` option to be given as a `Schema` instance value.
       *
       * Overrides all previously set schema options.
       */
      setSchema(version, options = {}) {
        if (typeof version === "number")
          version = String(version);
        let opt;
        switch (version) {
          case "1.1":
            if (this.directives)
              this.directives.yaml.version = "1.1";
            else
              this.directives = new directives.Directives({ version: "1.1" });
            opt = { resolveKnownTags: false, schema: "yaml-1.1" };
            break;
          case "1.2":
          case "next":
            if (this.directives)
              this.directives.yaml.version = version;
            else
              this.directives = new directives.Directives({ version });
            opt = { resolveKnownTags: true, schema: "core" };
            break;
          case null:
            if (this.directives)
              delete this.directives;
            opt = null;
            break;
          default: {
            const sv = JSON.stringify(version);
            throw new Error(`Expected '1.1', '1.2' or null as first argument, but found: ${sv}`);
          }
        }
        if (options.schema instanceof Object)
          this.schema = options.schema;
        else if (opt)
          this.schema = new Schema.Schema(Object.assign(opt, options));
        else
          throw new Error(`With a null YAML version, the { schema: Schema } option is required`);
      }
      // json & jsonArg are only used from toJSON()
      toJS({ json, jsonArg, mapAsMap, maxAliasCount, onAnchor, reviver } = {}) {
        const ctx = {
          anchors: /* @__PURE__ */ new Map(),
          doc: this,
          keep: !json,
          mapAsMap: mapAsMap === true,
          mapKeyWarned: false,
          maxAliasCount: typeof maxAliasCount === "number" ? maxAliasCount : 100
        };
        const res = toJS.toJS(this.contents, jsonArg ?? "", ctx);
        if (typeof onAnchor === "function")
          for (const { count, res: res2 } of ctx.anchors.values())
            onAnchor(res2, count);
        return typeof reviver === "function" ? applyReviver.applyReviver(reviver, { "": res }, "", res) : res;
      }
      /**
       * A JSON representation of the document `contents`.
       *
       * @param jsonArg Used by `JSON.stringify` to indicate the array index or
       *   property name.
       */
      toJSON(jsonArg, onAnchor) {
        return this.toJS({ json: true, jsonArg, mapAsMap: false, onAnchor });
      }
      /** A YAML representation of the document. */
      toString(options = {}) {
        if (this.errors.length > 0)
          throw new Error("Document with errors cannot be stringified");
        if ("indent" in options && (!Number.isInteger(options.indent) || Number(options.indent) <= 0)) {
          const s = JSON.stringify(options.indent);
          throw new Error(`"indent" option must be a positive integer, not ${s}`);
        }
        return stringifyDocument.stringifyDocument(this, options);
      }
    };
    function assertCollection(contents) {
      if (identity.isCollection(contents))
        return true;
      throw new Error("Expected a YAML collection as document contents");
    }
    exports.Document = Document;
  }
});

// node_modules/yaml/dist/errors.js
var require_errors = __commonJS({
  "node_modules/yaml/dist/errors.js"(exports) {
    "use strict";
    var YAMLError = class extends Error {
      constructor(name, pos, code, message) {
        super();
        this.name = name;
        this.code = code;
        this.message = message;
        this.pos = pos;
      }
    };
    var YAMLParseError = class extends YAMLError {
      constructor(pos, code, message) {
        super("YAMLParseError", pos, code, message);
      }
    };
    var YAMLWarning = class extends YAMLError {
      constructor(pos, code, message) {
        super("YAMLWarning", pos, code, message);
      }
    };
    var prettifyError = (src, lc) => (error) => {
      if (error.pos[0] === -1)
        return;
      error.linePos = error.pos.map((pos) => lc.linePos(pos));
      const { line, col } = error.linePos[0];
      error.message += ` at line ${line}, column ${col}`;
      let ci = col - 1;
      let lineStr = src.substring(lc.lineStarts[line - 1], lc.lineStarts[line]).replace(/[\n\r]+$/, "");
      if (ci >= 60 && lineStr.length > 80) {
        const trimStart = Math.min(ci - 39, lineStr.length - 79);
        lineStr = "\u2026" + lineStr.substring(trimStart);
        ci -= trimStart - 1;
      }
      if (lineStr.length > 80)
        lineStr = lineStr.substring(0, 79) + "\u2026";
      if (line > 1 && /^ *$/.test(lineStr.substring(0, ci))) {
        let prev = src.substring(lc.lineStarts[line - 2], lc.lineStarts[line - 1]);
        if (prev.length > 80)
          prev = prev.substring(0, 79) + "\u2026\n";
        lineStr = prev + lineStr;
      }
      if (/[^ ]/.test(lineStr)) {
        let count = 1;
        const end = error.linePos[1];
        if (end?.line === line && end.col > col) {
          count = Math.max(1, Math.min(end.col - col, 80 - ci));
        }
        const pointer = " ".repeat(ci) + "^".repeat(count);
        error.message += `:

${lineStr}
${pointer}
`;
      }
    };
    exports.YAMLError = YAMLError;
    exports.YAMLParseError = YAMLParseError;
    exports.YAMLWarning = YAMLWarning;
    exports.prettifyError = prettifyError;
  }
});

// node_modules/yaml/dist/compose/resolve-props.js
var require_resolve_props = __commonJS({
  "node_modules/yaml/dist/compose/resolve-props.js"(exports) {
    "use strict";
    function resolveProps(tokens, { flow, indicator, next, offset, onError, parentIndent, startOnNewline }) {
      let spaceBefore = false;
      let atNewline = startOnNewline;
      let hasSpace = startOnNewline;
      let comment = "";
      let commentSep = "";
      let hasNewline = false;
      let reqSpace = false;
      let tab = null;
      let anchor = null;
      let tag = null;
      let newlineAfterProp = null;
      let comma = null;
      let found = null;
      let start = null;
      for (const token of tokens) {
        if (reqSpace) {
          if (token.type !== "space" && token.type !== "newline" && token.type !== "comma")
            onError(token.offset, "MISSING_CHAR", "Tags and anchors must be separated from the next token by white space");
          reqSpace = false;
        }
        if (tab) {
          if (atNewline && token.type !== "comment" && token.type !== "newline") {
            onError(tab, "TAB_AS_INDENT", "Tabs are not allowed as indentation");
          }
          tab = null;
        }
        switch (token.type) {
          case "space":
            if (!flow && (indicator !== "doc-start" || next?.type !== "flow-collection") && token.source.includes("	")) {
              tab = token;
            }
            hasSpace = true;
            break;
          case "comment": {
            if (!hasSpace)
              onError(token, "MISSING_CHAR", "Comments must be separated from other tokens by white space characters");
            const cb = token.source.substring(1) || " ";
            if (!comment)
              comment = cb;
            else
              comment += commentSep + cb;
            commentSep = "";
            atNewline = false;
            break;
          }
          case "newline":
            if (atNewline) {
              if (comment)
                comment += token.source;
              else if (!found || indicator !== "seq-item-ind")
                spaceBefore = true;
            } else
              commentSep += token.source;
            atNewline = true;
            hasNewline = true;
            if (anchor || tag)
              newlineAfterProp = token;
            hasSpace = true;
            break;
          case "anchor":
            if (anchor)
              onError(token, "MULTIPLE_ANCHORS", "A node can have at most one anchor");
            if (token.source.endsWith(":"))
              onError(token.offset + token.source.length - 1, "BAD_ALIAS", "Anchor ending in : is ambiguous", true);
            anchor = token;
            start ?? (start = token.offset);
            atNewline = false;
            hasSpace = false;
            reqSpace = true;
            break;
          case "tag": {
            if (tag)
              onError(token, "MULTIPLE_TAGS", "A node can have at most one tag");
            tag = token;
            start ?? (start = token.offset);
            atNewline = false;
            hasSpace = false;
            reqSpace = true;
            break;
          }
          case indicator:
            if (anchor || tag)
              onError(token, "BAD_PROP_ORDER", `Anchors and tags must be after the ${token.source} indicator`);
            if (found)
              onError(token, "UNEXPECTED_TOKEN", `Unexpected ${token.source} in ${flow ?? "collection"}`);
            found = token;
            atNewline = indicator === "seq-item-ind" || indicator === "explicit-key-ind";
            hasSpace = false;
            break;
          case "comma":
            if (flow) {
              if (comma)
                onError(token, "UNEXPECTED_TOKEN", `Unexpected , in ${flow}`);
              comma = token;
              atNewline = false;
              hasSpace = false;
              break;
            }
          // else fallthrough
          default:
            onError(token, "UNEXPECTED_TOKEN", `Unexpected ${token.type} token`);
            atNewline = false;
            hasSpace = false;
        }
      }
      const last = tokens[tokens.length - 1];
      const end = last ? last.offset + last.source.length : offset;
      if (reqSpace && next && next.type !== "space" && next.type !== "newline" && next.type !== "comma" && (next.type !== "scalar" || next.source !== "")) {
        onError(next.offset, "MISSING_CHAR", "Tags and anchors must be separated from the next token by white space");
      }
      if (tab && (atNewline && tab.indent <= parentIndent || next?.type === "block-map" || next?.type === "block-seq"))
        onError(tab, "TAB_AS_INDENT", "Tabs are not allowed as indentation");
      return {
        comma,
        found,
        spaceBefore,
        comment,
        hasNewline,
        anchor,
        tag,
        newlineAfterProp,
        end,
        start: start ?? end
      };
    }
    exports.resolveProps = resolveProps;
  }
});

// node_modules/yaml/dist/compose/util-contains-newline.js
var require_util_contains_newline = __commonJS({
  "node_modules/yaml/dist/compose/util-contains-newline.js"(exports) {
    "use strict";
    function containsNewline(key) {
      if (!key)
        return null;
      switch (key.type) {
        case "alias":
        case "scalar":
        case "double-quoted-scalar":
        case "single-quoted-scalar":
          if (key.source.includes("\n"))
            return true;
          if (key.end) {
            for (const st of key.end)
              if (st.type === "newline")
                return true;
          }
          return false;
        case "flow-collection":
          for (const it of key.items) {
            for (const st of it.start)
              if (st.type === "newline")
                return true;
            if (it.sep) {
              for (const st of it.sep)
                if (st.type === "newline")
                  return true;
            }
            if (containsNewline(it.key) || containsNewline(it.value))
              return true;
          }
          return false;
        default:
          return true;
      }
    }
    exports.containsNewline = containsNewline;
  }
});

// node_modules/yaml/dist/compose/util-flow-indent-check.js
var require_util_flow_indent_check = __commonJS({
  "node_modules/yaml/dist/compose/util-flow-indent-check.js"(exports) {
    "use strict";
    var utilContainsNewline = require_util_contains_newline();
    function flowIndentCheck(indent, fc, onError) {
      if (fc?.type === "flow-collection") {
        const end = fc.end[0];
        if (end.indent === indent && (end.source === "]" || end.source === "}") && utilContainsNewline.containsNewline(fc)) {
          const msg = "Flow end indicator should be more indented than parent";
          onError(end, "BAD_INDENT", msg, true);
        }
      }
    }
    exports.flowIndentCheck = flowIndentCheck;
  }
});

// node_modules/yaml/dist/compose/util-map-includes.js
var require_util_map_includes = __commonJS({
  "node_modules/yaml/dist/compose/util-map-includes.js"(exports) {
    "use strict";
    var identity = require_identity();
    function mapIncludes(ctx, items, search) {
      const { uniqueKeys } = ctx.options;
      if (uniqueKeys === false)
        return false;
      const isEqual = typeof uniqueKeys === "function" ? uniqueKeys : (a, b) => a === b || identity.isScalar(a) && identity.isScalar(b) && a.value === b.value;
      return items.some((pair) => isEqual(pair.key, search));
    }
    exports.mapIncludes = mapIncludes;
  }
});

// node_modules/yaml/dist/compose/resolve-block-map.js
var require_resolve_block_map = __commonJS({
  "node_modules/yaml/dist/compose/resolve-block-map.js"(exports) {
    "use strict";
    var Pair = require_Pair();
    var YAMLMap = require_YAMLMap();
    var resolveProps = require_resolve_props();
    var utilContainsNewline = require_util_contains_newline();
    var utilFlowIndentCheck = require_util_flow_indent_check();
    var utilMapIncludes = require_util_map_includes();
    var startColMsg = "All mapping items must start at the same column";
    function resolveBlockMap({ composeNode, composeEmptyNode }, ctx, bm, onError, tag) {
      const NodeClass = tag?.nodeClass ?? YAMLMap.YAMLMap;
      const map = new NodeClass(ctx.schema);
      if (ctx.atRoot)
        ctx.atRoot = false;
      let offset = bm.offset;
      let commentEnd = null;
      for (const collItem of bm.items) {
        const { start, key, sep, value } = collItem;
        const keyProps = resolveProps.resolveProps(start, {
          indicator: "explicit-key-ind",
          next: key ?? sep?.[0],
          offset,
          onError,
          parentIndent: bm.indent,
          startOnNewline: true
        });
        const implicitKey = !keyProps.found;
        if (implicitKey) {
          if (key) {
            if (key.type === "block-seq")
              onError(offset, "BLOCK_AS_IMPLICIT_KEY", "A block sequence may not be used as an implicit map key");
            else if ("indent" in key && key.indent !== bm.indent)
              onError(offset, "BAD_INDENT", startColMsg);
          }
          if (!keyProps.anchor && !keyProps.tag && !sep) {
            commentEnd = keyProps.end;
            if (keyProps.comment) {
              if (map.comment)
                map.comment += "\n" + keyProps.comment;
              else
                map.comment = keyProps.comment;
            }
            continue;
          }
          if (keyProps.newlineAfterProp || utilContainsNewline.containsNewline(key)) {
            onError(key ?? start[start.length - 1], "MULTILINE_IMPLICIT_KEY", "Implicit keys need to be on a single line");
          }
        } else if (keyProps.found?.indent !== bm.indent) {
          onError(offset, "BAD_INDENT", startColMsg);
        }
        ctx.atKey = true;
        const keyStart = keyProps.end;
        const keyNode = key ? composeNode(ctx, key, keyProps, onError) : composeEmptyNode(ctx, keyStart, start, null, keyProps, onError);
        if (ctx.schema.compat)
          utilFlowIndentCheck.flowIndentCheck(bm.indent, key, onError);
        ctx.atKey = false;
        if (utilMapIncludes.mapIncludes(ctx, map.items, keyNode))
          onError(keyStart, "DUPLICATE_KEY", "Map keys must be unique");
        const valueProps = resolveProps.resolveProps(sep ?? [], {
          indicator: "map-value-ind",
          next: value,
          offset: keyNode.range[2],
          onError,
          parentIndent: bm.indent,
          startOnNewline: !key || key.type === "block-scalar"
        });
        offset = valueProps.end;
        if (valueProps.found) {
          if (implicitKey) {
            if (value?.type === "block-map" && !valueProps.hasNewline)
              onError(offset, "BLOCK_AS_IMPLICIT_KEY", "Nested mappings are not allowed in compact mappings");
            if (ctx.options.strict && keyProps.start < valueProps.found.offset - 1024)
              onError(keyNode.range, "KEY_OVER_1024_CHARS", "The : indicator must be at most 1024 chars after the start of an implicit block mapping key");
          }
          const valueNode = value ? composeNode(ctx, value, valueProps, onError) : composeEmptyNode(ctx, offset, sep, null, valueProps, onError);
          if (ctx.schema.compat)
            utilFlowIndentCheck.flowIndentCheck(bm.indent, value, onError);
          offset = valueNode.range[2];
          const pair = new Pair.Pair(keyNode, valueNode);
          if (ctx.options.keepSourceTokens)
            pair.srcToken = collItem;
          map.items.push(pair);
        } else {
          if (implicitKey)
            onError(keyNode.range, "MISSING_CHAR", "Implicit map keys need to be followed by map values");
          if (valueProps.comment) {
            if (keyNode.comment)
              keyNode.comment += "\n" + valueProps.comment;
            else
              keyNode.comment = valueProps.comment;
          }
          const pair = new Pair.Pair(keyNode);
          if (ctx.options.keepSourceTokens)
            pair.srcToken = collItem;
          map.items.push(pair);
        }
      }
      if (commentEnd && commentEnd < offset)
        onError(commentEnd, "IMPOSSIBLE", "Map comment with trailing content");
      map.range = [bm.offset, offset, commentEnd ?? offset];
      return map;
    }
    exports.resolveBlockMap = resolveBlockMap;
  }
});

// node_modules/yaml/dist/compose/resolve-block-seq.js
var require_resolve_block_seq = __commonJS({
  "node_modules/yaml/dist/compose/resolve-block-seq.js"(exports) {
    "use strict";
    var YAMLSeq = require_YAMLSeq();
    var resolveProps = require_resolve_props();
    var utilFlowIndentCheck = require_util_flow_indent_check();
    function resolveBlockSeq({ composeNode, composeEmptyNode }, ctx, bs, onError, tag) {
      const NodeClass = tag?.nodeClass ?? YAMLSeq.YAMLSeq;
      const seq = new NodeClass(ctx.schema);
      if (ctx.atRoot)
        ctx.atRoot = false;
      if (ctx.atKey)
        ctx.atKey = false;
      let offset = bs.offset;
      let commentEnd = null;
      for (const { start, value } of bs.items) {
        const props = resolveProps.resolveProps(start, {
          indicator: "seq-item-ind",
          next: value,
          offset,
          onError,
          parentIndent: bs.indent,
          startOnNewline: true
        });
        if (!props.found) {
          if (props.anchor || props.tag || value) {
            if (value?.type === "block-seq")
              onError(props.end, "BAD_INDENT", "All sequence items must start at the same column");
            else
              onError(offset, "MISSING_CHAR", "Sequence item without - indicator");
          } else {
            commentEnd = props.end;
            if (props.comment)
              seq.comment = props.comment;
            continue;
          }
        }
        const node = value ? composeNode(ctx, value, props, onError) : composeEmptyNode(ctx, props.end, start, null, props, onError);
        if (ctx.schema.compat)
          utilFlowIndentCheck.flowIndentCheck(bs.indent, value, onError);
        offset = node.range[2];
        seq.items.push(node);
      }
      seq.range = [bs.offset, offset, commentEnd ?? offset];
      return seq;
    }
    exports.resolveBlockSeq = resolveBlockSeq;
  }
});

// node_modules/yaml/dist/compose/resolve-end.js
var require_resolve_end = __commonJS({
  "node_modules/yaml/dist/compose/resolve-end.js"(exports) {
    "use strict";
    function resolveEnd(end, offset, reqSpace, onError) {
      let comment = "";
      if (end) {
        let hasSpace = false;
        let sep = "";
        for (const token of end) {
          const { source, type } = token;
          switch (type) {
            case "space":
              hasSpace = true;
              break;
            case "comment": {
              if (reqSpace && !hasSpace)
                onError(token, "MISSING_CHAR", "Comments must be separated from other tokens by white space characters");
              const cb = source.substring(1) || " ";
              if (!comment)
                comment = cb;
              else
                comment += sep + cb;
              sep = "";
              break;
            }
            case "newline":
              if (comment)
                sep += source;
              hasSpace = true;
              break;
            default:
              onError(token, "UNEXPECTED_TOKEN", `Unexpected ${type} at node end`);
          }
          offset += source.length;
        }
      }
      return { comment, offset };
    }
    exports.resolveEnd = resolveEnd;
  }
});

// node_modules/yaml/dist/compose/resolve-flow-collection.js
var require_resolve_flow_collection = __commonJS({
  "node_modules/yaml/dist/compose/resolve-flow-collection.js"(exports) {
    "use strict";
    var identity = require_identity();
    var Pair = require_Pair();
    var YAMLMap = require_YAMLMap();
    var YAMLSeq = require_YAMLSeq();
    var resolveEnd = require_resolve_end();
    var resolveProps = require_resolve_props();
    var utilContainsNewline = require_util_contains_newline();
    var utilMapIncludes = require_util_map_includes();
    var blockMsg = "Block collections are not allowed within flow collections";
    var isBlock = (token) => token && (token.type === "block-map" || token.type === "block-seq");
    function resolveFlowCollection({ composeNode, composeEmptyNode }, ctx, fc, onError, tag) {
      const isMap = fc.start.source === "{";
      const fcName = isMap ? "flow map" : "flow sequence";
      const NodeClass = tag?.nodeClass ?? (isMap ? YAMLMap.YAMLMap : YAMLSeq.YAMLSeq);
      const coll = new NodeClass(ctx.schema);
      coll.flow = true;
      const atRoot = ctx.atRoot;
      if (atRoot)
        ctx.atRoot = false;
      if (ctx.atKey)
        ctx.atKey = false;
      let offset = fc.offset + fc.start.source.length;
      for (let i = 0; i < fc.items.length; ++i) {
        const collItem = fc.items[i];
        const { start, key, sep, value } = collItem;
        const props = resolveProps.resolveProps(start, {
          flow: fcName,
          indicator: "explicit-key-ind",
          next: key ?? sep?.[0],
          offset,
          onError,
          parentIndent: fc.indent,
          startOnNewline: false
        });
        if (!props.found) {
          if (!props.anchor && !props.tag && !sep && !value) {
            if (i === 0 && props.comma)
              onError(props.comma, "UNEXPECTED_TOKEN", `Unexpected , in ${fcName}`);
            else if (i < fc.items.length - 1)
              onError(props.start, "UNEXPECTED_TOKEN", `Unexpected empty item in ${fcName}`);
            if (props.comment) {
              if (coll.comment)
                coll.comment += "\n" + props.comment;
              else
                coll.comment = props.comment;
            }
            offset = props.end;
            continue;
          }
          if (!isMap && ctx.options.strict && utilContainsNewline.containsNewline(key))
            onError(
              key,
              // checked by containsNewline()
              "MULTILINE_IMPLICIT_KEY",
              "Implicit keys of flow sequence pairs need to be on a single line"
            );
        }
        if (i === 0) {
          if (props.comma)
            onError(props.comma, "UNEXPECTED_TOKEN", `Unexpected , in ${fcName}`);
        } else {
          if (!props.comma)
            onError(props.start, "MISSING_CHAR", `Missing , between ${fcName} items`);
          if (props.comment) {
            let prevItemComment = "";
            loop: for (const st of start) {
              switch (st.type) {
                case "comma":
                case "space":
                  break;
                case "comment":
                  prevItemComment = st.source.substring(1);
                  break loop;
                default:
                  break loop;
              }
            }
            if (prevItemComment) {
              let prev = coll.items[coll.items.length - 1];
              if (identity.isPair(prev))
                prev = prev.value ?? prev.key;
              if (prev.comment)
                prev.comment += "\n" + prevItemComment;
              else
                prev.comment = prevItemComment;
              props.comment = props.comment.substring(prevItemComment.length + 1);
            }
          }
        }
        if (!isMap && !sep && !props.found) {
          const valueNode = value ? composeNode(ctx, value, props, onError) : composeEmptyNode(ctx, props.end, sep, null, props, onError);
          coll.items.push(valueNode);
          offset = valueNode.range[2];
          if (isBlock(value))
            onError(valueNode.range, "BLOCK_IN_FLOW", blockMsg);
        } else {
          ctx.atKey = true;
          const keyStart = props.end;
          const keyNode = key ? composeNode(ctx, key, props, onError) : composeEmptyNode(ctx, keyStart, start, null, props, onError);
          if (isBlock(key))
            onError(keyNode.range, "BLOCK_IN_FLOW", blockMsg);
          ctx.atKey = false;
          const valueProps = resolveProps.resolveProps(sep ?? [], {
            flow: fcName,
            indicator: "map-value-ind",
            next: value,
            offset: keyNode.range[2],
            onError,
            parentIndent: fc.indent,
            startOnNewline: false
          });
          if (valueProps.found) {
            if (!isMap && !props.found && ctx.options.strict) {
              if (sep)
                for (const st of sep) {
                  if (st === valueProps.found)
                    break;
                  if (st.type === "newline") {
                    onError(st, "MULTILINE_IMPLICIT_KEY", "Implicit keys of flow sequence pairs need to be on a single line");
                    break;
                  }
                }
              if (props.start < valueProps.found.offset - 1024)
                onError(valueProps.found, "KEY_OVER_1024_CHARS", "The : indicator must be at most 1024 chars after the start of an implicit flow sequence key");
            }
          } else if (value) {
            if ("source" in value && value.source?.[0] === ":")
              onError(value, "MISSING_CHAR", `Missing space after : in ${fcName}`);
            else
              onError(valueProps.start, "MISSING_CHAR", `Missing , or : between ${fcName} items`);
          }
          const valueNode = value ? composeNode(ctx, value, valueProps, onError) : valueProps.found ? composeEmptyNode(ctx, valueProps.end, sep, null, valueProps, onError) : null;
          if (valueNode) {
            if (isBlock(value))
              onError(valueNode.range, "BLOCK_IN_FLOW", blockMsg);
          } else if (valueProps.comment) {
            if (keyNode.comment)
              keyNode.comment += "\n" + valueProps.comment;
            else
              keyNode.comment = valueProps.comment;
          }
          const pair = new Pair.Pair(keyNode, valueNode);
          if (ctx.options.keepSourceTokens)
            pair.srcToken = collItem;
          if (isMap) {
            const map = coll;
            if (utilMapIncludes.mapIncludes(ctx, map.items, keyNode))
              onError(keyStart, "DUPLICATE_KEY", "Map keys must be unique");
            map.items.push(pair);
          } else {
            const map = new YAMLMap.YAMLMap(ctx.schema);
            map.flow = true;
            map.items.push(pair);
            const endRange = (valueNode ?? keyNode).range;
            map.range = [keyNode.range[0], endRange[1], endRange[2]];
            coll.items.push(map);
          }
          offset = valueNode ? valueNode.range[2] : valueProps.end;
        }
      }
      const expectedEnd = isMap ? "}" : "]";
      const [ce, ...ee] = fc.end;
      let cePos = offset;
      if (ce?.source === expectedEnd)
        cePos = ce.offset + ce.source.length;
      else {
        const name = fcName[0].toUpperCase() + fcName.substring(1);
        const msg = atRoot ? `${name} must end with a ${expectedEnd}` : `${name} in block collection must be sufficiently indented and end with a ${expectedEnd}`;
        onError(offset, atRoot ? "MISSING_CHAR" : "BAD_INDENT", msg);
        if (ce && ce.source.length !== 1)
          ee.unshift(ce);
      }
      if (ee.length > 0) {
        const end = resolveEnd.resolveEnd(ee, cePos, ctx.options.strict, onError);
        if (end.comment) {
          if (coll.comment)
            coll.comment += "\n" + end.comment;
          else
            coll.comment = end.comment;
        }
        coll.range = [fc.offset, cePos, end.offset];
      } else {
        coll.range = [fc.offset, cePos, cePos];
      }
      return coll;
    }
    exports.resolveFlowCollection = resolveFlowCollection;
  }
});

// node_modules/yaml/dist/compose/compose-collection.js
var require_compose_collection = __commonJS({
  "node_modules/yaml/dist/compose/compose-collection.js"(exports) {
    "use strict";
    var identity = require_identity();
    var Scalar = require_Scalar();
    var YAMLMap = require_YAMLMap();
    var YAMLSeq = require_YAMLSeq();
    var resolveBlockMap = require_resolve_block_map();
    var resolveBlockSeq = require_resolve_block_seq();
    var resolveFlowCollection = require_resolve_flow_collection();
    function resolveCollection(CN, ctx, token, onError, tagName, tag) {
      const coll = token.type === "block-map" ? resolveBlockMap.resolveBlockMap(CN, ctx, token, onError, tag) : token.type === "block-seq" ? resolveBlockSeq.resolveBlockSeq(CN, ctx, token, onError, tag) : resolveFlowCollection.resolveFlowCollection(CN, ctx, token, onError, tag);
      const Coll = coll.constructor;
      if (tagName === "!" || tagName === Coll.tagName) {
        coll.tag = Coll.tagName;
        return coll;
      }
      if (tagName)
        coll.tag = tagName;
      return coll;
    }
    function composeCollection(CN, ctx, token, props, onError) {
      const tagToken = props.tag;
      const tagName = !tagToken ? null : ctx.directives.tagName(tagToken.source, (msg) => onError(tagToken, "TAG_RESOLVE_FAILED", msg));
      if (token.type === "block-seq") {
        const { anchor, newlineAfterProp: nl } = props;
        const lastProp = anchor && tagToken ? anchor.offset > tagToken.offset ? anchor : tagToken : anchor ?? tagToken;
        if (lastProp && (!nl || nl.offset < lastProp.offset)) {
          const message = "Missing newline after block sequence props";
          onError(lastProp, "MISSING_CHAR", message);
        }
      }
      const expType = token.type === "block-map" ? "map" : token.type === "block-seq" ? "seq" : token.start.source === "{" ? "map" : "seq";
      if (!tagToken || !tagName || tagName === "!" || tagName === YAMLMap.YAMLMap.tagName && expType === "map" || tagName === YAMLSeq.YAMLSeq.tagName && expType === "seq") {
        return resolveCollection(CN, ctx, token, onError, tagName);
      }
      let tag = ctx.schema.tags.find((t) => t.tag === tagName && t.collection === expType);
      if (!tag) {
        const kt = ctx.schema.knownTags[tagName];
        if (kt?.collection === expType) {
          ctx.schema.tags.push(Object.assign({}, kt, { default: false }));
          tag = kt;
        } else {
          if (kt) {
            onError(tagToken, "BAD_COLLECTION_TYPE", `${kt.tag} used for ${expType} collection, but expects ${kt.collection ?? "scalar"}`, true);
          } else {
            onError(tagToken, "TAG_RESOLVE_FAILED", `Unresolved tag: ${tagName}`, true);
          }
          return resolveCollection(CN, ctx, token, onError, tagName);
        }
      }
      const coll = resolveCollection(CN, ctx, token, onError, tagName, tag);
      const res = tag.resolve?.(coll, (msg) => onError(tagToken, "TAG_RESOLVE_FAILED", msg), ctx.options) ?? coll;
      const node = identity.isNode(res) ? res : new Scalar.Scalar(res);
      node.range = coll.range;
      node.tag = tagName;
      if (tag?.format)
        node.format = tag.format;
      return node;
    }
    exports.composeCollection = composeCollection;
  }
});

// node_modules/yaml/dist/compose/resolve-block-scalar.js
var require_resolve_block_scalar = __commonJS({
  "node_modules/yaml/dist/compose/resolve-block-scalar.js"(exports) {
    "use strict";
    var Scalar = require_Scalar();
    function resolveBlockScalar(ctx, scalar, onError) {
      const start = scalar.offset;
      const header = parseBlockScalarHeader(scalar, ctx.options.strict, onError);
      if (!header)
        return { value: "", type: null, comment: "", range: [start, start, start] };
      const type = header.mode === ">" ? Scalar.Scalar.BLOCK_FOLDED : Scalar.Scalar.BLOCK_LITERAL;
      const lines = scalar.source ? splitLines(scalar.source) : [];
      let chompStart = lines.length;
      for (let i = lines.length - 1; i >= 0; --i) {
        const content = lines[i][1];
        if (content === "" || content === "\r")
          chompStart = i;
        else
          break;
      }
      if (chompStart === 0) {
        const value2 = header.chomp === "+" && lines.length > 0 ? "\n".repeat(Math.max(1, lines.length - 1)) : "";
        let end2 = start + header.length;
        if (scalar.source)
          end2 += scalar.source.length;
        return { value: value2, type, comment: header.comment, range: [start, end2, end2] };
      }
      let trimIndent = scalar.indent + header.indent;
      let offset = scalar.offset + header.length;
      let contentStart = 0;
      for (let i = 0; i < chompStart; ++i) {
        const [indent, content] = lines[i];
        if (content === "" || content === "\r") {
          if (header.indent === 0 && indent.length > trimIndent)
            trimIndent = indent.length;
        } else {
          if (indent.length < trimIndent) {
            const message = "Block scalars with more-indented leading empty lines must use an explicit indentation indicator";
            onError(offset + indent.length, "MISSING_CHAR", message);
          }
          if (header.indent === 0)
            trimIndent = indent.length;
          contentStart = i;
          if (trimIndent === 0 && !ctx.atRoot) {
            const message = "Block scalar values in collections must be indented";
            onError(offset, "BAD_INDENT", message);
          }
          break;
        }
        offset += indent.length + content.length + 1;
      }
      for (let i = lines.length - 1; i >= chompStart; --i) {
        if (lines[i][0].length > trimIndent)
          chompStart = i + 1;
      }
      let value = "";
      let sep = "";
      let prevMoreIndented = false;
      for (let i = 0; i < contentStart; ++i)
        value += lines[i][0].slice(trimIndent) + "\n";
      for (let i = contentStart; i < chompStart; ++i) {
        let [indent, content] = lines[i];
        offset += indent.length + content.length + 1;
        const crlf = content[content.length - 1] === "\r";
        if (crlf)
          content = content.slice(0, -1);
        if (content && indent.length < trimIndent) {
          const src = header.indent ? "explicit indentation indicator" : "first line";
          const message = `Block scalar lines must not be less indented than their ${src}`;
          onError(offset - content.length - (crlf ? 2 : 1), "BAD_INDENT", message);
          indent = "";
        }
        if (type === Scalar.Scalar.BLOCK_LITERAL) {
          value += sep + indent.slice(trimIndent) + content;
          sep = "\n";
        } else if (indent.length > trimIndent || content[0] === "	") {
          if (sep === " ")
            sep = "\n";
          else if (!prevMoreIndented && sep === "\n")
            sep = "\n\n";
          value += sep + indent.slice(trimIndent) + content;
          sep = "\n";
          prevMoreIndented = true;
        } else if (content === "") {
          if (sep === "\n")
            value += "\n";
          else
            sep = "\n";
        } else {
          value += sep + content;
          sep = " ";
          prevMoreIndented = false;
        }
      }
      switch (header.chomp) {
        case "-":
          break;
        case "+":
          for (let i = chompStart; i < lines.length; ++i)
            value += "\n" + lines[i][0].slice(trimIndent);
          if (value[value.length - 1] !== "\n")
            value += "\n";
          break;
        default:
          value += "\n";
      }
      const end = start + header.length + scalar.source.length;
      return { value, type, comment: header.comment, range: [start, end, end] };
    }
    function parseBlockScalarHeader({ offset, props }, strict, onError) {
      if (props[0].type !== "block-scalar-header") {
        onError(props[0], "IMPOSSIBLE", "Block scalar header not found");
        return null;
      }
      const { source } = props[0];
      const mode = source[0];
      let indent = 0;
      let chomp = "";
      let error = -1;
      for (let i = 1; i < source.length; ++i) {
        const ch = source[i];
        if (!chomp && (ch === "-" || ch === "+"))
          chomp = ch;
        else {
          const n = Number(ch);
          if (!indent && n)
            indent = n;
          else if (error === -1)
            error = offset + i;
        }
      }
      if (error !== -1)
        onError(error, "UNEXPECTED_TOKEN", `Block scalar header includes extra characters: ${source}`);
      let hasSpace = false;
      let comment = "";
      let length = source.length;
      for (let i = 1; i < props.length; ++i) {
        const token = props[i];
        switch (token.type) {
          case "space":
            hasSpace = true;
          // fallthrough
          case "newline":
            length += token.source.length;
            break;
          case "comment":
            if (strict && !hasSpace) {
              const message = "Comments must be separated from other tokens by white space characters";
              onError(token, "MISSING_CHAR", message);
            }
            length += token.source.length;
            comment = token.source.substring(1);
            break;
          case "error":
            onError(token, "UNEXPECTED_TOKEN", token.message);
            length += token.source.length;
            break;
          /* istanbul ignore next should not happen */
          default: {
            const message = `Unexpected token in block scalar header: ${token.type}`;
            onError(token, "UNEXPECTED_TOKEN", message);
            const ts = token.source;
            if (ts && typeof ts === "string")
              length += ts.length;
          }
        }
      }
      return { mode, indent, chomp, comment, length };
    }
    function splitLines(source) {
      const split = source.split(/\n( *)/);
      const first = split[0];
      const m = first.match(/^( *)/);
      const line0 = m?.[1] ? [m[1], first.slice(m[1].length)] : ["", first];
      const lines = [line0];
      for (let i = 1; i < split.length; i += 2)
        lines.push([split[i], split[i + 1]]);
      return lines;
    }
    exports.resolveBlockScalar = resolveBlockScalar;
  }
});

// node_modules/yaml/dist/compose/resolve-flow-scalar.js
var require_resolve_flow_scalar = __commonJS({
  "node_modules/yaml/dist/compose/resolve-flow-scalar.js"(exports) {
    "use strict";
    var Scalar = require_Scalar();
    var resolveEnd = require_resolve_end();
    function resolveFlowScalar(scalar, strict, onError) {
      const { offset, type, source, end } = scalar;
      let _type;
      let value;
      const _onError = (rel, code, msg) => onError(offset + rel, code, msg);
      switch (type) {
        case "scalar":
          _type = Scalar.Scalar.PLAIN;
          value = plainValue(source, _onError);
          break;
        case "single-quoted-scalar":
          _type = Scalar.Scalar.QUOTE_SINGLE;
          value = singleQuotedValue(source, _onError);
          break;
        case "double-quoted-scalar":
          _type = Scalar.Scalar.QUOTE_DOUBLE;
          value = doubleQuotedValue(source, _onError);
          break;
        /* istanbul ignore next should not happen */
        default:
          onError(scalar, "UNEXPECTED_TOKEN", `Expected a flow scalar value, but found: ${type}`);
          return {
            value: "",
            type: null,
            comment: "",
            range: [offset, offset + source.length, offset + source.length]
          };
      }
      const valueEnd = offset + source.length;
      const re = resolveEnd.resolveEnd(end, valueEnd, strict, onError);
      return {
        value,
        type: _type,
        comment: re.comment,
        range: [offset, valueEnd, re.offset]
      };
    }
    function plainValue(source, onError) {
      let badChar = "";
      switch (source[0]) {
        /* istanbul ignore next should not happen */
        case "	":
          badChar = "a tab character";
          break;
        case ",":
          badChar = "flow indicator character ,";
          break;
        case "%":
          badChar = "directive indicator character %";
          break;
        case "|":
        case ">": {
          badChar = `block scalar indicator ${source[0]}`;
          break;
        }
        case "@":
        case "`": {
          badChar = `reserved character ${source[0]}`;
          break;
        }
      }
      if (badChar)
        onError(0, "BAD_SCALAR_START", `Plain value cannot start with ${badChar}`);
      return foldLines(source);
    }
    function singleQuotedValue(source, onError) {
      if (source[source.length - 1] !== "'" || source.length === 1)
        onError(source.length, "MISSING_CHAR", "Missing closing 'quote");
      return foldLines(source.slice(1, -1)).replace(/''/g, "'");
    }
    function foldLines(source) {
      let first, line;
      try {
        first = new RegExp("(.*?)(?<![ 	])[ 	]*\r?\n", "sy");
        line = new RegExp("[ 	]*(.*?)(?:(?<![ 	])[ 	]*)?\r?\n", "sy");
      } catch {
        first = /(.*?)[ \t]*\r?\n/sy;
        line = /[ \t]*(.*?)[ \t]*\r?\n/sy;
      }
      let match = first.exec(source);
      if (!match)
        return source;
      let res = match[1];
      let sep = " ";
      let pos = first.lastIndex;
      line.lastIndex = pos;
      while (match = line.exec(source)) {
        if (match[1] === "") {
          if (sep === "\n")
            res += sep;
          else
            sep = "\n";
        } else {
          res += sep + match[1];
          sep = " ";
        }
        pos = line.lastIndex;
      }
      const last = /[ \t]*(.*)/sy;
      last.lastIndex = pos;
      match = last.exec(source);
      return res + sep + (match?.[1] ?? "");
    }
    function doubleQuotedValue(source, onError) {
      let res = "";
      for (let i = 1; i < source.length - 1; ++i) {
        const ch = source[i];
        if (ch === "\r" && source[i + 1] === "\n")
          continue;
        if (ch === "\n") {
          const { fold, offset } = foldNewline(source, i);
          res += fold;
          i = offset;
        } else if (ch === "\\") {
          let next = source[++i];
          const cc = escapeCodes[next];
          if (cc)
            res += cc;
          else if (next === "\n") {
            next = source[i + 1];
            while (next === " " || next === "	")
              next = source[++i + 1];
          } else if (next === "\r" && source[i + 1] === "\n") {
            next = source[++i + 1];
            while (next === " " || next === "	")
              next = source[++i + 1];
          } else if (next === "x" || next === "u" || next === "U") {
            const length = { x: 2, u: 4, U: 8 }[next];
            res += parseCharCode(source, i + 1, length, onError);
            i += length;
          } else {
            const raw = source.substr(i - 1, 2);
            onError(i - 1, "BAD_DQ_ESCAPE", `Invalid escape sequence ${raw}`);
            res += raw;
          }
        } else if (ch === " " || ch === "	") {
          const wsStart = i;
          let next = source[i + 1];
          while (next === " " || next === "	")
            next = source[++i + 1];
          if (next !== "\n" && !(next === "\r" && source[i + 2] === "\n"))
            res += i > wsStart ? source.slice(wsStart, i + 1) : ch;
        } else {
          res += ch;
        }
      }
      if (source[source.length - 1] !== '"' || source.length === 1)
        onError(source.length, "MISSING_CHAR", 'Missing closing "quote');
      return res;
    }
    function foldNewline(source, offset) {
      let fold = "";
      let ch = source[offset + 1];
      while (ch === " " || ch === "	" || ch === "\n" || ch === "\r") {
        if (ch === "\r" && source[offset + 2] !== "\n")
          break;
        if (ch === "\n")
          fold += "\n";
        offset += 1;
        ch = source[offset + 1];
      }
      if (!fold)
        fold = " ";
      return { fold, offset };
    }
    var escapeCodes = {
      "0": "\0",
      // null character
      a: "\x07",
      // bell character
      b: "\b",
      // backspace
      e: "\x1B",
      // escape character
      f: "\f",
      // form feed
      n: "\n",
      // line feed
      r: "\r",
      // carriage return
      t: "	",
      // horizontal tab
      v: "\v",
      // vertical tab
      N: "\x85",
      // Unicode next line
      _: "\xA0",
      // Unicode non-breaking space
      L: "\u2028",
      // Unicode line separator
      P: "\u2029",
      // Unicode paragraph separator
      " ": " ",
      '"': '"',
      "/": "/",
      "\\": "\\",
      "	": "	"
    };
    function parseCharCode(source, offset, length, onError) {
      const cc = source.substr(offset, length);
      const ok = cc.length === length && /^[0-9a-fA-F]+$/.test(cc);
      const code = ok ? parseInt(cc, 16) : NaN;
      if (isNaN(code)) {
        const raw = source.substr(offset - 2, length + 2);
        onError(offset - 2, "BAD_DQ_ESCAPE", `Invalid escape sequence ${raw}`);
        return raw;
      }
      return String.fromCodePoint(code);
    }
    exports.resolveFlowScalar = resolveFlowScalar;
  }
});

// node_modules/yaml/dist/compose/compose-scalar.js
var require_compose_scalar = __commonJS({
  "node_modules/yaml/dist/compose/compose-scalar.js"(exports) {
    "use strict";
    var identity = require_identity();
    var Scalar = require_Scalar();
    var resolveBlockScalar = require_resolve_block_scalar();
    var resolveFlowScalar = require_resolve_flow_scalar();
    function composeScalar(ctx, token, tagToken, onError) {
      const { value, type, comment, range } = token.type === "block-scalar" ? resolveBlockScalar.resolveBlockScalar(ctx, token, onError) : resolveFlowScalar.resolveFlowScalar(token, ctx.options.strict, onError);
      const tagName = tagToken ? ctx.directives.tagName(tagToken.source, (msg) => onError(tagToken, "TAG_RESOLVE_FAILED", msg)) : null;
      let tag;
      if (ctx.options.stringKeys && ctx.atKey) {
        tag = ctx.schema[identity.SCALAR];
      } else if (tagName)
        tag = findScalarTagByName(ctx.schema, value, tagName, tagToken, onError);
      else if (token.type === "scalar")
        tag = findScalarTagByTest(ctx, value, token, onError);
      else
        tag = ctx.schema[identity.SCALAR];
      let scalar;
      try {
        const res = tag.resolve(value, (msg) => onError(tagToken ?? token, "TAG_RESOLVE_FAILED", msg), ctx.options);
        scalar = identity.isScalar(res) ? res : new Scalar.Scalar(res);
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        onError(tagToken ?? token, "TAG_RESOLVE_FAILED", msg);
        scalar = new Scalar.Scalar(value);
      }
      scalar.range = range;
      scalar.source = value;
      if (type)
        scalar.type = type;
      if (tagName)
        scalar.tag = tagName;
      if (tag.format)
        scalar.format = tag.format;
      if (comment)
        scalar.comment = comment;
      return scalar;
    }
    function findScalarTagByName(schema, value, tagName, tagToken, onError) {
      if (tagName === "!")
        return schema[identity.SCALAR];
      const matchWithTest = [];
      for (const tag of schema.tags) {
        if (!tag.collection && tag.tag === tagName) {
          if (tag.default && tag.test)
            matchWithTest.push(tag);
          else
            return tag;
        }
      }
      for (const tag of matchWithTest)
        if (tag.test?.test(value))
          return tag;
      const kt = schema.knownTags[tagName];
      if (kt && !kt.collection) {
        schema.tags.push(Object.assign({}, kt, { default: false, test: void 0 }));
        return kt;
      }
      onError(tagToken, "TAG_RESOLVE_FAILED", `Unresolved tag: ${tagName}`, tagName !== "tag:yaml.org,2002:str");
      return schema[identity.SCALAR];
    }
    function findScalarTagByTest({ atKey, directives, schema }, value, token, onError) {
      const tag = schema.tags.find((tag2) => (tag2.default === true || atKey && tag2.default === "key") && tag2.test?.test(value)) || schema[identity.SCALAR];
      if (schema.compat) {
        const compat = schema.compat.find((tag2) => tag2.default && tag2.test?.test(value)) ?? schema[identity.SCALAR];
        if (tag.tag !== compat.tag) {
          const ts = directives.tagString(tag.tag);
          const cs = directives.tagString(compat.tag);
          const msg = `Value may be parsed as either ${ts} or ${cs}`;
          onError(token, "TAG_RESOLVE_FAILED", msg, true);
        }
      }
      return tag;
    }
    exports.composeScalar = composeScalar;
  }
});

// node_modules/yaml/dist/compose/util-empty-scalar-position.js
var require_util_empty_scalar_position = __commonJS({
  "node_modules/yaml/dist/compose/util-empty-scalar-position.js"(exports) {
    "use strict";
    function emptyScalarPosition(offset, before, pos) {
      if (before) {
        pos ?? (pos = before.length);
        for (let i = pos - 1; i >= 0; --i) {
          let st = before[i];
          switch (st.type) {
            case "space":
            case "comment":
            case "newline":
              offset -= st.source.length;
              continue;
          }
          st = before[++i];
          while (st?.type === "space") {
            offset += st.source.length;
            st = before[++i];
          }
          break;
        }
      }
      return offset;
    }
    exports.emptyScalarPosition = emptyScalarPosition;
  }
});

// node_modules/yaml/dist/compose/compose-node.js
var require_compose_node = __commonJS({
  "node_modules/yaml/dist/compose/compose-node.js"(exports) {
    "use strict";
    var Alias = require_Alias();
    var identity = require_identity();
    var composeCollection = require_compose_collection();
    var composeScalar = require_compose_scalar();
    var resolveEnd = require_resolve_end();
    var utilEmptyScalarPosition = require_util_empty_scalar_position();
    var CN = { composeNode, composeEmptyNode };
    function composeNode(ctx, token, props, onError) {
      const atKey = ctx.atKey;
      const { spaceBefore, comment, anchor, tag } = props;
      let node;
      let isSrcToken = true;
      switch (token.type) {
        case "alias":
          node = composeAlias(ctx, token, onError);
          if (anchor || tag)
            onError(token, "ALIAS_PROPS", "An alias node must not specify any properties");
          break;
        case "scalar":
        case "single-quoted-scalar":
        case "double-quoted-scalar":
        case "block-scalar":
          node = composeScalar.composeScalar(ctx, token, tag, onError);
          if (anchor)
            node.anchor = anchor.source.substring(1);
          break;
        case "block-map":
        case "block-seq":
        case "flow-collection":
          try {
            node = composeCollection.composeCollection(CN, ctx, token, props, onError);
            if (anchor)
              node.anchor = anchor.source.substring(1);
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            onError(token, "RESOURCE_EXHAUSTION", message);
          }
          break;
        default: {
          const message = token.type === "error" ? token.message : `Unsupported token (type: ${token.type})`;
          onError(token, "UNEXPECTED_TOKEN", message);
          isSrcToken = false;
        }
      }
      node ?? (node = composeEmptyNode(ctx, token.offset, void 0, null, props, onError));
      if (anchor && node.anchor === "")
        onError(anchor, "BAD_ALIAS", "Anchor cannot be an empty string");
      if (atKey && ctx.options.stringKeys && (!identity.isScalar(node) || typeof node.value !== "string" || node.tag && node.tag !== "tag:yaml.org,2002:str")) {
        const msg = "With stringKeys, all keys must be strings";
        onError(tag ?? token, "NON_STRING_KEY", msg);
      }
      if (spaceBefore)
        node.spaceBefore = true;
      if (comment) {
        if (token.type === "scalar" && token.source === "")
          node.comment = comment;
        else
          node.commentBefore = comment;
      }
      if (ctx.options.keepSourceTokens && isSrcToken)
        node.srcToken = token;
      return node;
    }
    function composeEmptyNode(ctx, offset, before, pos, { spaceBefore, comment, anchor, tag, end }, onError) {
      const token = {
        type: "scalar",
        offset: utilEmptyScalarPosition.emptyScalarPosition(offset, before, pos),
        indent: -1,
        source: ""
      };
      const node = composeScalar.composeScalar(ctx, token, tag, onError);
      if (anchor) {
        node.anchor = anchor.source.substring(1);
        if (node.anchor === "")
          onError(anchor, "BAD_ALIAS", "Anchor cannot be an empty string");
      }
      if (spaceBefore)
        node.spaceBefore = true;
      if (comment) {
        node.comment = comment;
        node.range[2] = end;
      }
      return node;
    }
    function composeAlias({ options }, { offset, source, end }, onError) {
      const alias = new Alias.Alias(source.substring(1));
      if (alias.source === "")
        onError(offset, "BAD_ALIAS", "Alias cannot be an empty string");
      if (alias.source.endsWith(":"))
        onError(offset + source.length - 1, "BAD_ALIAS", "Alias ending in : is ambiguous", true);
      const valueEnd = offset + source.length;
      const re = resolveEnd.resolveEnd(end, valueEnd, options.strict, onError);
      alias.range = [offset, valueEnd, re.offset];
      if (re.comment)
        alias.comment = re.comment;
      return alias;
    }
    exports.composeEmptyNode = composeEmptyNode;
    exports.composeNode = composeNode;
  }
});

// node_modules/yaml/dist/compose/compose-doc.js
var require_compose_doc = __commonJS({
  "node_modules/yaml/dist/compose/compose-doc.js"(exports) {
    "use strict";
    var Document = require_Document();
    var composeNode = require_compose_node();
    var resolveEnd = require_resolve_end();
    var resolveProps = require_resolve_props();
    function composeDoc(options, directives, { offset, start, value, end }, onError) {
      const opts = Object.assign({ _directives: directives }, options);
      const doc = new Document.Document(void 0, opts);
      const ctx = {
        atKey: false,
        atRoot: true,
        directives: doc.directives,
        options: doc.options,
        schema: doc.schema
      };
      const props = resolveProps.resolveProps(start, {
        indicator: "doc-start",
        next: value ?? end?.[0],
        offset,
        onError,
        parentIndent: 0,
        startOnNewline: true
      });
      if (props.found) {
        doc.directives.docStart = true;
        if (value && (value.type === "block-map" || value.type === "block-seq") && !props.hasNewline)
          onError(props.end, "MISSING_CHAR", "Block collection cannot start on same line with directives-end marker");
      }
      doc.contents = value ? composeNode.composeNode(ctx, value, props, onError) : composeNode.composeEmptyNode(ctx, props.end, start, null, props, onError);
      const contentEnd = doc.contents.range[2];
      const re = resolveEnd.resolveEnd(end, contentEnd, false, onError);
      if (re.comment)
        doc.comment = re.comment;
      doc.range = [offset, contentEnd, re.offset];
      return doc;
    }
    exports.composeDoc = composeDoc;
  }
});

// node_modules/yaml/dist/compose/composer.js
var require_composer = __commonJS({
  "node_modules/yaml/dist/compose/composer.js"(exports) {
    "use strict";
    var node_process = __require("process");
    var directives = require_directives();
    var Document = require_Document();
    var errors = require_errors();
    var identity = require_identity();
    var composeDoc = require_compose_doc();
    var resolveEnd = require_resolve_end();
    function getErrorPos(src) {
      if (typeof src === "number")
        return [src, src + 1];
      if (Array.isArray(src))
        return src.length === 2 ? src : [src[0], src[1]];
      const { offset, source } = src;
      return [offset, offset + (typeof source === "string" ? source.length : 1)];
    }
    function parsePrelude(prelude) {
      let comment = "";
      let atComment = false;
      let afterEmptyLine = false;
      for (let i = 0; i < prelude.length; ++i) {
        const source = prelude[i];
        switch (source[0]) {
          case "#":
            comment += (comment === "" ? "" : afterEmptyLine ? "\n\n" : "\n") + (source.substring(1) || " ");
            atComment = true;
            afterEmptyLine = false;
            break;
          case "%":
            if (prelude[i + 1]?.[0] !== "#")
              i += 1;
            atComment = false;
            break;
          default:
            if (!atComment)
              afterEmptyLine = true;
            atComment = false;
        }
      }
      return { comment, afterEmptyLine };
    }
    var Composer = class {
      constructor(options = {}) {
        this.doc = null;
        this.atDirectives = false;
        this.prelude = [];
        this.errors = [];
        this.warnings = [];
        this.onError = (source, code, message, warning) => {
          const pos = getErrorPos(source);
          if (warning)
            this.warnings.push(new errors.YAMLWarning(pos, code, message));
          else
            this.errors.push(new errors.YAMLParseError(pos, code, message));
        };
        this.directives = new directives.Directives({ version: options.version || "1.2" });
        this.options = options;
      }
      decorate(doc, afterDoc) {
        const { comment, afterEmptyLine } = parsePrelude(this.prelude);
        if (comment) {
          const dc = doc.contents;
          if (afterDoc) {
            doc.comment = doc.comment ? `${doc.comment}
${comment}` : comment;
          } else if (afterEmptyLine || doc.directives.docStart || !dc) {
            doc.commentBefore = comment;
          } else if (identity.isCollection(dc) && !dc.flow && dc.items.length > 0) {
            let it = dc.items[0];
            if (identity.isPair(it))
              it = it.key;
            const cb = it.commentBefore;
            it.commentBefore = cb ? `${comment}
${cb}` : comment;
          } else {
            const cb = dc.commentBefore;
            dc.commentBefore = cb ? `${comment}
${cb}` : comment;
          }
        }
        if (afterDoc) {
          Array.prototype.push.apply(doc.errors, this.errors);
          Array.prototype.push.apply(doc.warnings, this.warnings);
        } else {
          doc.errors = this.errors;
          doc.warnings = this.warnings;
        }
        this.prelude = [];
        this.errors = [];
        this.warnings = [];
      }
      /**
       * Current stream status information.
       *
       * Mostly useful at the end of input for an empty stream.
       */
      streamInfo() {
        return {
          comment: parsePrelude(this.prelude).comment,
          directives: this.directives,
          errors: this.errors,
          warnings: this.warnings
        };
      }
      /**
       * Compose tokens into documents.
       *
       * @param forceDoc - If the stream contains no document, still emit a final document including any comments and directives that would be applied to a subsequent document.
       * @param endOffset - Should be set if `forceDoc` is also set, to set the document range end and to indicate errors correctly.
       */
      *compose(tokens, forceDoc = false, endOffset = -1) {
        for (const token of tokens)
          yield* this.next(token);
        yield* this.end(forceDoc, endOffset);
      }
      /** Advance the composer by one CST token. */
      *next(token) {
        if (node_process.env.LOG_STREAM)
          console.dir(token, { depth: null });
        switch (token.type) {
          case "directive":
            this.directives.add(token.source, (offset, message, warning) => {
              const pos = getErrorPos(token);
              pos[0] += offset;
              this.onError(pos, "BAD_DIRECTIVE", message, warning);
            });
            this.prelude.push(token.source);
            this.atDirectives = true;
            break;
          case "document": {
            const doc = composeDoc.composeDoc(this.options, this.directives, token, this.onError);
            if (this.atDirectives && !doc.directives.docStart)
              this.onError(token, "MISSING_CHAR", "Missing directives-end/doc-start indicator line");
            this.decorate(doc, false);
            if (this.doc)
              yield this.doc;
            this.doc = doc;
            this.atDirectives = false;
            break;
          }
          case "byte-order-mark":
          case "space":
            break;
          case "comment":
          case "newline":
            this.prelude.push(token.source);
            break;
          case "error": {
            const msg = token.source ? `${token.message}: ${JSON.stringify(token.source)}` : token.message;
            const error = new errors.YAMLParseError(getErrorPos(token), "UNEXPECTED_TOKEN", msg);
            if (this.atDirectives || !this.doc)
              this.errors.push(error);
            else
              this.doc.errors.push(error);
            break;
          }
          case "doc-end": {
            if (!this.doc) {
              const msg = "Unexpected doc-end without preceding document";
              this.errors.push(new errors.YAMLParseError(getErrorPos(token), "UNEXPECTED_TOKEN", msg));
              break;
            }
            this.doc.directives.docEnd = true;
            const end = resolveEnd.resolveEnd(token.end, token.offset + token.source.length, this.doc.options.strict, this.onError);
            this.decorate(this.doc, true);
            if (end.comment) {
              const dc = this.doc.comment;
              this.doc.comment = dc ? `${dc}
${end.comment}` : end.comment;
            }
            this.doc.range[2] = end.offset;
            break;
          }
          default:
            this.errors.push(new errors.YAMLParseError(getErrorPos(token), "UNEXPECTED_TOKEN", `Unsupported token ${token.type}`));
        }
      }
      /**
       * Call at end of input to yield any remaining document.
       *
       * @param forceDoc - If the stream contains no document, still emit a final document including any comments and directives that would be applied to a subsequent document.
       * @param endOffset - Should be set if `forceDoc` is also set, to set the document range end and to indicate errors correctly.
       */
      *end(forceDoc = false, endOffset = -1) {
        if (this.doc) {
          this.decorate(this.doc, true);
          yield this.doc;
          this.doc = null;
        } else if (forceDoc) {
          const opts = Object.assign({ _directives: this.directives }, this.options);
          const doc = new Document.Document(void 0, opts);
          if (this.atDirectives)
            this.onError(endOffset, "MISSING_CHAR", "Missing directives-end indicator line");
          doc.range = [0, endOffset, endOffset];
          this.decorate(doc, false);
          yield doc;
        }
      }
    };
    exports.Composer = Composer;
  }
});

// node_modules/yaml/dist/parse/cst-scalar.js
var require_cst_scalar = __commonJS({
  "node_modules/yaml/dist/parse/cst-scalar.js"(exports) {
    "use strict";
    var resolveBlockScalar = require_resolve_block_scalar();
    var resolveFlowScalar = require_resolve_flow_scalar();
    var errors = require_errors();
    var stringifyString = require_stringifyString();
    function resolveAsScalar(token, strict = true, onError) {
      if (token) {
        const _onError = (pos, code, message) => {
          const offset = typeof pos === "number" ? pos : Array.isArray(pos) ? pos[0] : pos.offset;
          if (onError)
            onError(offset, code, message);
          else
            throw new errors.YAMLParseError([offset, offset + 1], code, message);
        };
        switch (token.type) {
          case "scalar":
          case "single-quoted-scalar":
          case "double-quoted-scalar":
            return resolveFlowScalar.resolveFlowScalar(token, strict, _onError);
          case "block-scalar":
            return resolveBlockScalar.resolveBlockScalar({ options: { strict } }, token, _onError);
        }
      }
      return null;
    }
    function createScalarToken(value, context) {
      const { implicitKey = false, indent, inFlow = false, offset = -1, type = "PLAIN" } = context;
      const source = stringifyString.stringifyString({ type, value }, {
        implicitKey,
        indent: indent > 0 ? " ".repeat(indent) : "",
        inFlow,
        options: { blockQuote: true, lineWidth: -1 }
      });
      const end = context.end ?? [
        { type: "newline", offset: -1, indent, source: "\n" }
      ];
      switch (source[0]) {
        case "|":
        case ">": {
          const he = source.indexOf("\n");
          const head = source.substring(0, he);
          const body = source.substring(he + 1) + "\n";
          const props = [
            { type: "block-scalar-header", offset, indent, source: head }
          ];
          if (!addEndtoBlockProps(props, end))
            props.push({ type: "newline", offset: -1, indent, source: "\n" });
          return { type: "block-scalar", offset, indent, props, source: body };
        }
        case '"':
          return { type: "double-quoted-scalar", offset, indent, source, end };
        case "'":
          return { type: "single-quoted-scalar", offset, indent, source, end };
        default:
          return { type: "scalar", offset, indent, source, end };
      }
    }
    function setScalarValue(token, value, context = {}) {
      let { afterKey = false, implicitKey = false, inFlow = false, type } = context;
      let indent = "indent" in token ? token.indent : null;
      if (afterKey && typeof indent === "number")
        indent += 2;
      if (!type)
        switch (token.type) {
          case "single-quoted-scalar":
            type = "QUOTE_SINGLE";
            break;
          case "double-quoted-scalar":
            type = "QUOTE_DOUBLE";
            break;
          case "block-scalar": {
            const header = token.props[0];
            if (header.type !== "block-scalar-header")
              throw new Error("Invalid block scalar header");
            type = header.source[0] === ">" ? "BLOCK_FOLDED" : "BLOCK_LITERAL";
            break;
          }
          default:
            type = "PLAIN";
        }
      const source = stringifyString.stringifyString({ type, value }, {
        implicitKey: implicitKey || indent === null,
        indent: indent !== null && indent > 0 ? " ".repeat(indent) : "",
        inFlow,
        options: { blockQuote: true, lineWidth: -1 }
      });
      switch (source[0]) {
        case "|":
        case ">":
          setBlockScalarValue(token, source);
          break;
        case '"':
          setFlowScalarValue(token, source, "double-quoted-scalar");
          break;
        case "'":
          setFlowScalarValue(token, source, "single-quoted-scalar");
          break;
        default:
          setFlowScalarValue(token, source, "scalar");
      }
    }
    function setBlockScalarValue(token, source) {
      const he = source.indexOf("\n");
      const head = source.substring(0, he);
      const body = source.substring(he + 1) + "\n";
      if (token.type === "block-scalar") {
        const header = token.props[0];
        if (header.type !== "block-scalar-header")
          throw new Error("Invalid block scalar header");
        header.source = head;
        token.source = body;
      } else {
        const { offset } = token;
        const indent = "indent" in token ? token.indent : -1;
        const props = [
          { type: "block-scalar-header", offset, indent, source: head }
        ];
        if (!addEndtoBlockProps(props, "end" in token ? token.end : void 0))
          props.push({ type: "newline", offset: -1, indent, source: "\n" });
        for (const key of Object.keys(token))
          if (key !== "type" && key !== "offset")
            delete token[key];
        Object.assign(token, { type: "block-scalar", indent, props, source: body });
      }
    }
    function addEndtoBlockProps(props, end) {
      if (end)
        for (const st of end)
          switch (st.type) {
            case "space":
            case "comment":
              props.push(st);
              break;
            case "newline":
              props.push(st);
              return true;
          }
      return false;
    }
    function setFlowScalarValue(token, source, type) {
      switch (token.type) {
        case "scalar":
        case "double-quoted-scalar":
        case "single-quoted-scalar":
          token.type = type;
          token.source = source;
          break;
        case "block-scalar": {
          const end = token.props.slice(1);
          let oa = source.length;
          if (token.props[0].type === "block-scalar-header")
            oa -= token.props[0].source.length;
          for (const tok of end)
            tok.offset += oa;
          delete token.props;
          Object.assign(token, { type, source, end });
          break;
        }
        case "block-map":
        case "block-seq": {
          const offset = token.offset + source.length;
          const nl = { type: "newline", offset, indent: token.indent, source: "\n" };
          delete token.items;
          Object.assign(token, { type, source, end: [nl] });
          break;
        }
        default: {
          const indent = "indent" in token ? token.indent : -1;
          const end = "end" in token && Array.isArray(token.end) ? token.end.filter((st) => st.type === "space" || st.type === "comment" || st.type === "newline") : [];
          for (const key of Object.keys(token))
            if (key !== "type" && key !== "offset")
              delete token[key];
          Object.assign(token, { type, indent, source, end });
        }
      }
    }
    exports.createScalarToken = createScalarToken;
    exports.resolveAsScalar = resolveAsScalar;
    exports.setScalarValue = setScalarValue;
  }
});

// node_modules/yaml/dist/parse/cst-stringify.js
var require_cst_stringify = __commonJS({
  "node_modules/yaml/dist/parse/cst-stringify.js"(exports) {
    "use strict";
    var stringify = (cst) => "type" in cst ? stringifyToken(cst) : stringifyItem(cst);
    function stringifyToken(token) {
      switch (token.type) {
        case "block-scalar": {
          let res = "";
          for (const tok of token.props)
            res += stringifyToken(tok);
          return res + token.source;
        }
        case "block-map":
        case "block-seq": {
          let res = "";
          for (const item of token.items)
            res += stringifyItem(item);
          return res;
        }
        case "flow-collection": {
          let res = token.start.source;
          for (const item of token.items)
            res += stringifyItem(item);
          for (const st of token.end)
            res += st.source;
          return res;
        }
        case "document": {
          let res = stringifyItem(token);
          if (token.end)
            for (const st of token.end)
              res += st.source;
          return res;
        }
        default: {
          let res = token.source;
          if ("end" in token && token.end)
            for (const st of token.end)
              res += st.source;
          return res;
        }
      }
    }
    function stringifyItem({ start, key, sep, value }) {
      let res = "";
      for (const st of start)
        res += st.source;
      if (key)
        res += stringifyToken(key);
      if (sep)
        for (const st of sep)
          res += st.source;
      if (value)
        res += stringifyToken(value);
      return res;
    }
    exports.stringify = stringify;
  }
});

// node_modules/yaml/dist/parse/cst-visit.js
var require_cst_visit = __commonJS({
  "node_modules/yaml/dist/parse/cst-visit.js"(exports) {
    "use strict";
    var BREAK = /* @__PURE__ */ Symbol("break visit");
    var SKIP = /* @__PURE__ */ Symbol("skip children");
    var REMOVE = /* @__PURE__ */ Symbol("remove item");
    function visit(cst, visitor) {
      if ("type" in cst && cst.type === "document")
        cst = { start: cst.start, value: cst.value };
      _visit(Object.freeze([]), cst, visitor);
    }
    visit.BREAK = BREAK;
    visit.SKIP = SKIP;
    visit.REMOVE = REMOVE;
    visit.itemAtPath = (cst, path) => {
      let item = cst;
      for (const [field, index] of path) {
        const tok = item?.[field];
        if (tok && "items" in tok) {
          item = tok.items[index];
        } else
          return void 0;
      }
      return item;
    };
    visit.parentCollection = (cst, path) => {
      const parent = visit.itemAtPath(cst, path.slice(0, -1));
      const field = path[path.length - 1][0];
      const coll = parent?.[field];
      if (coll && "items" in coll)
        return coll;
      throw new Error("Parent collection not found");
    };
    function _visit(path, item, visitor) {
      let ctrl = visitor(item, path);
      if (typeof ctrl === "symbol")
        return ctrl;
      for (const field of ["key", "value"]) {
        const token = item[field];
        if (token && "items" in token) {
          for (let i = 0; i < token.items.length; ++i) {
            const ci = _visit(Object.freeze(path.concat([[field, i]])), token.items[i], visitor);
            if (typeof ci === "number")
              i = ci - 1;
            else if (ci === BREAK)
              return BREAK;
            else if (ci === REMOVE) {
              token.items.splice(i, 1);
              i -= 1;
            }
          }
          if (typeof ctrl === "function" && field === "key")
            ctrl = ctrl(item, path);
        }
      }
      return typeof ctrl === "function" ? ctrl(item, path) : ctrl;
    }
    exports.visit = visit;
  }
});

// node_modules/yaml/dist/parse/cst.js
var require_cst = __commonJS({
  "node_modules/yaml/dist/parse/cst.js"(exports) {
    "use strict";
    var cstScalar = require_cst_scalar();
    var cstStringify = require_cst_stringify();
    var cstVisit = require_cst_visit();
    var BOM = "\uFEFF";
    var DOCUMENT = "";
    var FLOW_END = "";
    var SCALAR = "";
    var isCollection = (token) => !!token && "items" in token;
    var isScalar = (token) => !!token && (token.type === "scalar" || token.type === "single-quoted-scalar" || token.type === "double-quoted-scalar" || token.type === "block-scalar");
    function prettyToken(token) {
      switch (token) {
        case BOM:
          return "<BOM>";
        case DOCUMENT:
          return "<DOC>";
        case FLOW_END:
          return "<FLOW_END>";
        case SCALAR:
          return "<SCALAR>";
        default:
          return JSON.stringify(token);
      }
    }
    function tokenType(source) {
      switch (source) {
        case BOM:
          return "byte-order-mark";
        case DOCUMENT:
          return "doc-mode";
        case FLOW_END:
          return "flow-error-end";
        case SCALAR:
          return "scalar";
        case "---":
          return "doc-start";
        case "...":
          return "doc-end";
        case "":
        case "\n":
        case "\r\n":
          return "newline";
        case "-":
          return "seq-item-ind";
        case "?":
          return "explicit-key-ind";
        case ":":
          return "map-value-ind";
        case "{":
          return "flow-map-start";
        case "}":
          return "flow-map-end";
        case "[":
          return "flow-seq-start";
        case "]":
          return "flow-seq-end";
        case ",":
          return "comma";
      }
      switch (source[0]) {
        case " ":
        case "	":
          return "space";
        case "#":
          return "comment";
        case "%":
          return "directive-line";
        case "*":
          return "alias";
        case "&":
          return "anchor";
        case "!":
          return "tag";
        case "'":
          return "single-quoted-scalar";
        case '"':
          return "double-quoted-scalar";
        case "|":
        case ">":
          return "block-scalar-header";
      }
      return null;
    }
    exports.createScalarToken = cstScalar.createScalarToken;
    exports.resolveAsScalar = cstScalar.resolveAsScalar;
    exports.setScalarValue = cstScalar.setScalarValue;
    exports.stringify = cstStringify.stringify;
    exports.visit = cstVisit.visit;
    exports.BOM = BOM;
    exports.DOCUMENT = DOCUMENT;
    exports.FLOW_END = FLOW_END;
    exports.SCALAR = SCALAR;
    exports.isCollection = isCollection;
    exports.isScalar = isScalar;
    exports.prettyToken = prettyToken;
    exports.tokenType = tokenType;
  }
});

// node_modules/yaml/dist/parse/lexer.js
var require_lexer = __commonJS({
  "node_modules/yaml/dist/parse/lexer.js"(exports) {
    "use strict";
    var cst = require_cst();
    function isEmpty(ch) {
      switch (ch) {
        case void 0:
        case " ":
        case "\n":
        case "\r":
        case "	":
          return true;
        default:
          return false;
      }
    }
    var hexDigits = new Set("0123456789ABCDEFabcdef");
    var tagChars = new Set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-#;/?:@&=+$_.!~*'()");
    var flowIndicatorChars = new Set(",[]{}");
    var invalidAnchorChars = new Set(" ,[]{}\n\r	");
    var isNotAnchorChar = (ch) => !ch || invalidAnchorChars.has(ch);
    var Lexer = class {
      constructor() {
        this.atEnd = false;
        this.blockScalarIndent = -1;
        this.blockScalarKeep = false;
        this.buffer = "";
        this.flowKey = false;
        this.flowLevel = 0;
        this.indentNext = 0;
        this.indentValue = 0;
        this.lineEndPos = null;
        this.next = null;
        this.pos = 0;
      }
      /**
       * Generate YAML tokens from the `source` string. If `incomplete`,
       * a part of the last line may be left as a buffer for the next call.
       *
       * @returns A generator of lexical tokens
       */
      *lex(source, incomplete = false) {
        if (source) {
          if (typeof source !== "string")
            throw TypeError("source is not a string");
          this.buffer = this.buffer ? this.buffer + source : source;
          this.lineEndPos = null;
        }
        this.atEnd = !incomplete;
        let next = this.next ?? "stream";
        while (next && (incomplete || this.hasChars(1)))
          next = yield* this.parseNext(next);
      }
      atLineEnd() {
        let i = this.pos;
        let ch = this.buffer[i];
        while (ch === " " || ch === "	")
          ch = this.buffer[++i];
        if (!ch || ch === "#" || ch === "\n")
          return true;
        if (ch === "\r")
          return this.buffer[i + 1] === "\n";
        return false;
      }
      charAt(n) {
        return this.buffer[this.pos + n];
      }
      continueScalar(offset) {
        let ch = this.buffer[offset];
        if (this.indentNext > 0) {
          let indent = 0;
          while (ch === " ")
            ch = this.buffer[++indent + offset];
          if (ch === "\r") {
            const next = this.buffer[indent + offset + 1];
            if (next === "\n" || !next && !this.atEnd)
              return offset + indent + 1;
          }
          return ch === "\n" || indent >= this.indentNext || !ch && !this.atEnd ? offset + indent : -1;
        }
        if (ch === "-" || ch === ".") {
          const dt = this.buffer.substr(offset, 3);
          if ((dt === "---" || dt === "...") && isEmpty(this.buffer[offset + 3]))
            return -1;
        }
        return offset;
      }
      getLine() {
        let end = this.lineEndPos;
        if (typeof end !== "number" || end !== -1 && end < this.pos) {
          end = this.buffer.indexOf("\n", this.pos);
          this.lineEndPos = end;
        }
        if (end === -1)
          return this.atEnd ? this.buffer.substring(this.pos) : null;
        if (this.buffer[end - 1] === "\r")
          end -= 1;
        return this.buffer.substring(this.pos, end);
      }
      hasChars(n) {
        return this.pos + n <= this.buffer.length;
      }
      setNext(state) {
        this.buffer = this.buffer.substring(this.pos);
        this.pos = 0;
        this.lineEndPos = null;
        this.next = state;
        return null;
      }
      peek(n) {
        return this.buffer.substr(this.pos, n);
      }
      *parseNext(next) {
        switch (next) {
          case "stream":
            return yield* this.parseStream();
          case "line-start":
            return yield* this.parseLineStart();
          case "block-start":
            return yield* this.parseBlockStart();
          case "doc":
            return yield* this.parseDocument();
          case "flow":
            return yield* this.parseFlowCollection();
          case "quoted-scalar":
            return yield* this.parseQuotedScalar();
          case "block-scalar":
            return yield* this.parseBlockScalar();
          case "plain-scalar":
            return yield* this.parsePlainScalar();
        }
      }
      *parseStream() {
        let line = this.getLine();
        if (line === null)
          return this.setNext("stream");
        if (line[0] === cst.BOM) {
          yield* this.pushCount(1);
          line = line.substring(1);
        }
        if (line[0] === "%") {
          let dirEnd = line.length;
          let cs = line.indexOf("#");
          while (cs !== -1) {
            const ch = line[cs - 1];
            if (ch === " " || ch === "	") {
              dirEnd = cs - 1;
              break;
            } else {
              cs = line.indexOf("#", cs + 1);
            }
          }
          while (true) {
            const ch = line[dirEnd - 1];
            if (ch === " " || ch === "	")
              dirEnd -= 1;
            else
              break;
          }
          const n = (yield* this.pushCount(dirEnd)) + (yield* this.pushSpaces(true));
          yield* this.pushCount(line.length - n);
          this.pushNewline();
          return "stream";
        }
        if (this.atLineEnd()) {
          const sp = yield* this.pushSpaces(true);
          yield* this.pushCount(line.length - sp);
          yield* this.pushNewline();
          return "stream";
        }
        yield cst.DOCUMENT;
        return yield* this.parseLineStart();
      }
      *parseLineStart() {
        const ch = this.charAt(0);
        if (!ch && !this.atEnd)
          return this.setNext("line-start");
        if (ch === "-" || ch === ".") {
          if (!this.atEnd && !this.hasChars(4))
            return this.setNext("line-start");
          const s = this.peek(3);
          if ((s === "---" || s === "...") && isEmpty(this.charAt(3))) {
            yield* this.pushCount(3);
            this.indentValue = 0;
            this.indentNext = 0;
            return s === "---" ? "doc" : "stream";
          }
        }
        this.indentValue = yield* this.pushSpaces(false);
        if (this.indentNext > this.indentValue && !isEmpty(this.charAt(1)))
          this.indentNext = this.indentValue;
        return yield* this.parseBlockStart();
      }
      *parseBlockStart() {
        const [ch0, ch1] = this.peek(2);
        if (!ch1 && !this.atEnd)
          return this.setNext("block-start");
        if ((ch0 === "-" || ch0 === "?" || ch0 === ":") && isEmpty(ch1)) {
          const n = (yield* this.pushCount(1)) + (yield* this.pushSpaces(true));
          this.indentNext = this.indentValue + 1;
          this.indentValue += n;
          return yield* this.parseBlockStart();
        }
        return "doc";
      }
      *parseDocument() {
        yield* this.pushSpaces(true);
        const line = this.getLine();
        if (line === null)
          return this.setNext("doc");
        let n = yield* this.pushIndicators();
        switch (line[n]) {
          case "#":
            yield* this.pushCount(line.length - n);
          // fallthrough
          case void 0:
            yield* this.pushNewline();
            return yield* this.parseLineStart();
          case "{":
          case "[":
            yield* this.pushCount(1);
            this.flowKey = false;
            this.flowLevel = 1;
            return "flow";
          case "}":
          case "]":
            yield* this.pushCount(1);
            return "doc";
          case "*":
            yield* this.pushUntil(isNotAnchorChar);
            return "doc";
          case '"':
          case "'":
            return yield* this.parseQuotedScalar();
          case "|":
          case ">":
            n += yield* this.parseBlockScalarHeader();
            n += yield* this.pushSpaces(true);
            yield* this.pushCount(line.length - n);
            yield* this.pushNewline();
            return yield* this.parseBlockScalar();
          default:
            return yield* this.parsePlainScalar();
        }
      }
      *parseFlowCollection() {
        let nl, sp;
        let indent = -1;
        do {
          nl = yield* this.pushNewline();
          if (nl > 0) {
            sp = yield* this.pushSpaces(false);
            this.indentValue = indent = sp;
          } else {
            sp = 0;
          }
          sp += yield* this.pushSpaces(true);
        } while (nl + sp > 0);
        const line = this.getLine();
        if (line === null)
          return this.setNext("flow");
        if (indent !== -1 && indent < this.indentNext && line[0] !== "#" || indent === 0 && (line.startsWith("---") || line.startsWith("...")) && isEmpty(line[3])) {
          const atFlowEndMarker = indent === this.indentNext - 1 && this.flowLevel === 1 && (line[0] === "]" || line[0] === "}");
          if (!atFlowEndMarker) {
            this.flowLevel = 0;
            yield cst.FLOW_END;
            return yield* this.parseLineStart();
          }
        }
        let n = 0;
        while (line[n] === ",") {
          n += yield* this.pushCount(1);
          n += yield* this.pushSpaces(true);
          this.flowKey = false;
        }
        n += yield* this.pushIndicators();
        switch (line[n]) {
          case void 0:
            return "flow";
          case "#":
            yield* this.pushCount(line.length - n);
            return "flow";
          case "{":
          case "[":
            yield* this.pushCount(1);
            this.flowKey = false;
            this.flowLevel += 1;
            return "flow";
          case "}":
          case "]":
            yield* this.pushCount(1);
            this.flowKey = true;
            this.flowLevel -= 1;
            return this.flowLevel ? "flow" : "doc";
          case "*":
            yield* this.pushUntil(isNotAnchorChar);
            return "flow";
          case '"':
          case "'":
            this.flowKey = true;
            return yield* this.parseQuotedScalar();
          case ":": {
            const next = this.charAt(1);
            if (this.flowKey || isEmpty(next) || next === ",") {
              this.flowKey = false;
              yield* this.pushCount(1);
              yield* this.pushSpaces(true);
              return "flow";
            }
          }
          // fallthrough
          default:
            this.flowKey = false;
            return yield* this.parsePlainScalar();
        }
      }
      *parseQuotedScalar() {
        const quote = this.charAt(0);
        let end = this.buffer.indexOf(quote, this.pos + 1);
        if (quote === "'") {
          while (end !== -1 && this.buffer[end + 1] === "'")
            end = this.buffer.indexOf("'", end + 2);
        } else {
          while (end !== -1) {
            let n = 0;
            while (this.buffer[end - 1 - n] === "\\")
              n += 1;
            if (n % 2 === 0)
              break;
            end = this.buffer.indexOf('"', end + 1);
          }
        }
        const qb = this.buffer.substring(0, end);
        let nl = qb.indexOf("\n", this.pos);
        if (nl !== -1) {
          while (nl !== -1) {
            const cs = this.continueScalar(nl + 1);
            if (cs === -1)
              break;
            nl = qb.indexOf("\n", cs);
          }
          if (nl !== -1) {
            end = nl - (qb[nl - 1] === "\r" ? 2 : 1);
          }
        }
        if (end === -1) {
          if (!this.atEnd)
            return this.setNext("quoted-scalar");
          end = this.buffer.length;
        }
        yield* this.pushToIndex(end + 1, false);
        return this.flowLevel ? "flow" : "doc";
      }
      *parseBlockScalarHeader() {
        this.blockScalarIndent = -1;
        this.blockScalarKeep = false;
        let i = this.pos;
        while (true) {
          const ch = this.buffer[++i];
          if (ch === "+")
            this.blockScalarKeep = true;
          else if (ch > "0" && ch <= "9")
            this.blockScalarIndent = Number(ch) - 1;
          else if (ch !== "-")
            break;
        }
        return yield* this.pushUntil((ch) => isEmpty(ch) || ch === "#");
      }
      *parseBlockScalar() {
        let nl = this.pos - 1;
        let indent = 0;
        let ch;
        loop: for (let i2 = this.pos; ch = this.buffer[i2]; ++i2) {
          switch (ch) {
            case " ":
              indent += 1;
              break;
            case "\n":
              nl = i2;
              indent = 0;
              break;
            case "\r": {
              const next = this.buffer[i2 + 1];
              if (!next && !this.atEnd)
                return this.setNext("block-scalar");
              if (next === "\n")
                break;
            }
            // fallthrough
            default:
              break loop;
          }
        }
        if (!ch && !this.atEnd)
          return this.setNext("block-scalar");
        if (indent >= this.indentNext) {
          if (this.blockScalarIndent === -1)
            this.indentNext = indent;
          else {
            this.indentNext = this.blockScalarIndent + (this.indentNext === 0 ? 1 : this.indentNext);
          }
          do {
            const cs = this.continueScalar(nl + 1);
            if (cs === -1)
              break;
            nl = this.buffer.indexOf("\n", cs);
          } while (nl !== -1);
          if (nl === -1) {
            if (!this.atEnd)
              return this.setNext("block-scalar");
            nl = this.buffer.length;
          }
        }
        let i = nl + 1;
        ch = this.buffer[i];
        while (ch === " ")
          ch = this.buffer[++i];
        if (ch === "	") {
          while (ch === "	" || ch === " " || ch === "\r" || ch === "\n")
            ch = this.buffer[++i];
          nl = i - 1;
        } else if (!this.blockScalarKeep) {
          do {
            let i2 = nl - 1;
            let ch2 = this.buffer[i2];
            if (ch2 === "\r")
              ch2 = this.buffer[--i2];
            const lastChar = i2;
            while (ch2 === " ")
              ch2 = this.buffer[--i2];
            if (ch2 === "\n" && i2 >= this.pos && i2 + 1 + indent > lastChar)
              nl = i2;
            else
              break;
          } while (true);
        }
        yield cst.SCALAR;
        yield* this.pushToIndex(nl + 1, true);
        return yield* this.parseLineStart();
      }
      *parsePlainScalar() {
        const inFlow = this.flowLevel > 0;
        let end = this.pos - 1;
        let i = this.pos - 1;
        let ch;
        while (ch = this.buffer[++i]) {
          if (ch === ":") {
            const next = this.buffer[i + 1];
            if (isEmpty(next) || inFlow && flowIndicatorChars.has(next))
              break;
            end = i;
          } else if (isEmpty(ch)) {
            let next = this.buffer[i + 1];
            if (ch === "\r") {
              if (next === "\n") {
                i += 1;
                ch = "\n";
                next = this.buffer[i + 1];
              } else
                end = i;
            }
            if (next === "#" || inFlow && flowIndicatorChars.has(next))
              break;
            if (ch === "\n") {
              const cs = this.continueScalar(i + 1);
              if (cs === -1)
                break;
              i = Math.max(i, cs - 2);
            }
          } else {
            if (inFlow && flowIndicatorChars.has(ch))
              break;
            end = i;
          }
        }
        if (!ch && !this.atEnd)
          return this.setNext("plain-scalar");
        yield cst.SCALAR;
        yield* this.pushToIndex(end + 1, true);
        return inFlow ? "flow" : "doc";
      }
      *pushCount(n) {
        if (n > 0) {
          yield this.buffer.substr(this.pos, n);
          this.pos += n;
          return n;
        }
        return 0;
      }
      *pushToIndex(i, allowEmpty) {
        const s = this.buffer.slice(this.pos, i);
        if (s) {
          yield s;
          this.pos += s.length;
          return s.length;
        } else if (allowEmpty)
          yield "";
        return 0;
      }
      *pushIndicators() {
        switch (this.charAt(0)) {
          case "!":
            return (yield* this.pushTag()) + (yield* this.pushSpaces(true)) + (yield* this.pushIndicators());
          case "&":
            return (yield* this.pushUntil(isNotAnchorChar)) + (yield* this.pushSpaces(true)) + (yield* this.pushIndicators());
          case "-":
          // this is an error
          case "?":
          // this is an error outside flow collections
          case ":": {
            const inFlow = this.flowLevel > 0;
            const ch1 = this.charAt(1);
            if (isEmpty(ch1) || inFlow && flowIndicatorChars.has(ch1)) {
              if (!inFlow)
                this.indentNext = this.indentValue + 1;
              else if (this.flowKey)
                this.flowKey = false;
              return (yield* this.pushCount(1)) + (yield* this.pushSpaces(true)) + (yield* this.pushIndicators());
            }
          }
        }
        return 0;
      }
      *pushTag() {
        if (this.charAt(1) === "<") {
          let i = this.pos + 2;
          let ch = this.buffer[i];
          while (!isEmpty(ch) && ch !== ">")
            ch = this.buffer[++i];
          return yield* this.pushToIndex(ch === ">" ? i + 1 : i, false);
        } else {
          let i = this.pos + 1;
          let ch = this.buffer[i];
          while (ch) {
            if (tagChars.has(ch))
              ch = this.buffer[++i];
            else if (ch === "%" && hexDigits.has(this.buffer[i + 1]) && hexDigits.has(this.buffer[i + 2])) {
              ch = this.buffer[i += 3];
            } else
              break;
          }
          return yield* this.pushToIndex(i, false);
        }
      }
      *pushNewline() {
        const ch = this.buffer[this.pos];
        if (ch === "\n")
          return yield* this.pushCount(1);
        else if (ch === "\r" && this.charAt(1) === "\n")
          return yield* this.pushCount(2);
        else
          return 0;
      }
      *pushSpaces(allowTabs) {
        let i = this.pos - 1;
        let ch;
        do {
          ch = this.buffer[++i];
        } while (ch === " " || allowTabs && ch === "	");
        const n = i - this.pos;
        if (n > 0) {
          yield this.buffer.substr(this.pos, n);
          this.pos = i;
        }
        return n;
      }
      *pushUntil(test) {
        let i = this.pos;
        let ch = this.buffer[i];
        while (!test(ch))
          ch = this.buffer[++i];
        return yield* this.pushToIndex(i, false);
      }
    };
    exports.Lexer = Lexer;
  }
});

// node_modules/yaml/dist/parse/line-counter.js
var require_line_counter = __commonJS({
  "node_modules/yaml/dist/parse/line-counter.js"(exports) {
    "use strict";
    var LineCounter = class {
      constructor() {
        this.lineStarts = [];
        this.addNewLine = (offset) => this.lineStarts.push(offset);
        this.linePos = (offset) => {
          let low = 0;
          let high = this.lineStarts.length;
          while (low < high) {
            const mid = low + high >> 1;
            if (this.lineStarts[mid] < offset)
              low = mid + 1;
            else
              high = mid;
          }
          if (this.lineStarts[low] === offset)
            return { line: low + 1, col: 1 };
          if (low === 0)
            return { line: 0, col: offset };
          const start = this.lineStarts[low - 1];
          return { line: low, col: offset - start + 1 };
        };
      }
    };
    exports.LineCounter = LineCounter;
  }
});

// node_modules/yaml/dist/parse/parser.js
var require_parser = __commonJS({
  "node_modules/yaml/dist/parse/parser.js"(exports) {
    "use strict";
    var node_process = __require("process");
    var cst = require_cst();
    var lexer = require_lexer();
    function includesToken(list, type) {
      for (let i = 0; i < list.length; ++i)
        if (list[i].type === type)
          return true;
      return false;
    }
    function findNonEmptyIndex(list) {
      for (let i = 0; i < list.length; ++i) {
        switch (list[i].type) {
          case "space":
          case "comment":
          case "newline":
            break;
          default:
            return i;
        }
      }
      return -1;
    }
    function isFlowToken(token) {
      switch (token?.type) {
        case "alias":
        case "scalar":
        case "single-quoted-scalar":
        case "double-quoted-scalar":
        case "flow-collection":
          return true;
        default:
          return false;
      }
    }
    function getPrevProps(parent) {
      switch (parent.type) {
        case "document":
          return parent.start;
        case "block-map": {
          const it = parent.items[parent.items.length - 1];
          return it.sep ?? it.start;
        }
        case "block-seq":
          return parent.items[parent.items.length - 1].start;
        /* istanbul ignore next should not happen */
        default:
          return [];
      }
    }
    function getFirstKeyStartProps(prev) {
      if (prev.length === 0)
        return [];
      let i = prev.length;
      loop: while (--i >= 0) {
        switch (prev[i].type) {
          case "doc-start":
          case "explicit-key-ind":
          case "map-value-ind":
          case "seq-item-ind":
          case "newline":
            break loop;
        }
      }
      while (prev[++i]?.type === "space") {
      }
      return prev.splice(i, prev.length);
    }
    function fixFlowSeqItems(fc) {
      if (fc.start.type === "flow-seq-start") {
        for (const it of fc.items) {
          if (it.sep && !it.value && !includesToken(it.start, "explicit-key-ind") && !includesToken(it.sep, "map-value-ind")) {
            if (it.key)
              it.value = it.key;
            delete it.key;
            if (isFlowToken(it.value)) {
              if (it.value.end)
                Array.prototype.push.apply(it.value.end, it.sep);
              else
                it.value.end = it.sep;
            } else
              Array.prototype.push.apply(it.start, it.sep);
            delete it.sep;
          }
        }
      }
    }
    var Parser = class {
      /**
       * @param onNewLine - If defined, called separately with the start position of
       *   each new line (in `parse()`, including the start of input).
       */
      constructor(onNewLine) {
        this.atNewLine = true;
        this.atScalar = false;
        this.indent = 0;
        this.offset = 0;
        this.onKeyLine = false;
        this.stack = [];
        this.source = "";
        this.type = "";
        this.lexer = new lexer.Lexer();
        this.onNewLine = onNewLine;
      }
      /**
       * Parse `source` as a YAML stream.
       * If `incomplete`, a part of the last line may be left as a buffer for the next call.
       *
       * Errors are not thrown, but yielded as `{ type: 'error', message }` tokens.
       *
       * @returns A generator of tokens representing each directive, document, and other structure.
       */
      *parse(source, incomplete = false) {
        if (this.onNewLine && this.offset === 0)
          this.onNewLine(0);
        for (const lexeme of this.lexer.lex(source, incomplete))
          yield* this.next(lexeme);
        if (!incomplete)
          yield* this.end();
      }
      /**
       * Advance the parser by the `source` of one lexical token.
       */
      *next(source) {
        this.source = source;
        if (node_process.env.LOG_TOKENS)
          console.log("|", cst.prettyToken(source));
        if (this.atScalar) {
          this.atScalar = false;
          yield* this.step();
          this.offset += source.length;
          return;
        }
        const type = cst.tokenType(source);
        if (!type) {
          const message = `Not a YAML token: ${source}`;
          yield* this.pop({ type: "error", offset: this.offset, message, source });
          this.offset += source.length;
        } else if (type === "scalar") {
          this.atNewLine = false;
          this.atScalar = true;
          this.type = "scalar";
        } else {
          this.type = type;
          yield* this.step();
          switch (type) {
            case "newline":
              this.atNewLine = true;
              this.indent = 0;
              if (this.onNewLine)
                this.onNewLine(this.offset + source.length);
              break;
            case "space":
              if (this.atNewLine && source[0] === " ")
                this.indent += source.length;
              break;
            case "explicit-key-ind":
            case "map-value-ind":
            case "seq-item-ind":
              if (this.atNewLine)
                this.indent += source.length;
              break;
            case "doc-mode":
            case "flow-error-end":
              return;
            default:
              this.atNewLine = false;
          }
          this.offset += source.length;
        }
      }
      /** Call at end of input to push out any remaining constructions */
      *end() {
        while (this.stack.length > 0)
          yield* this.pop();
      }
      get sourceToken() {
        const st = {
          type: this.type,
          offset: this.offset,
          indent: this.indent,
          source: this.source
        };
        return st;
      }
      *step() {
        const top = this.peek(1);
        if (this.type === "doc-end" && top?.type !== "doc-end") {
          while (this.stack.length > 0)
            yield* this.pop();
          this.stack.push({
            type: "doc-end",
            offset: this.offset,
            source: this.source
          });
          return;
        }
        if (!top)
          return yield* this.stream();
        switch (top.type) {
          case "document":
            return yield* this.document(top);
          case "alias":
          case "scalar":
          case "single-quoted-scalar":
          case "double-quoted-scalar":
            return yield* this.scalar(top);
          case "block-scalar":
            return yield* this.blockScalar(top);
          case "block-map":
            return yield* this.blockMap(top);
          case "block-seq":
            return yield* this.blockSequence(top);
          case "flow-collection":
            return yield* this.flowCollection(top);
          case "doc-end":
            return yield* this.documentEnd(top);
        }
        yield* this.pop();
      }
      peek(n) {
        return this.stack[this.stack.length - n];
      }
      *pop(error) {
        const token = error ?? this.stack.pop();
        if (!token) {
          const message = "Tried to pop an empty stack";
          yield { type: "error", offset: this.offset, source: "", message };
        } else if (this.stack.length === 0) {
          yield token;
        } else {
          const top = this.peek(1);
          if (token.type === "block-scalar") {
            token.indent = "indent" in top ? top.indent : 0;
          } else if (token.type === "flow-collection" && top.type === "document") {
            token.indent = 0;
          }
          if (token.type === "flow-collection")
            fixFlowSeqItems(token);
          switch (top.type) {
            case "document":
              top.value = token;
              break;
            case "block-scalar":
              top.props.push(token);
              break;
            case "block-map": {
              const it = top.items[top.items.length - 1];
              if (it.value) {
                top.items.push({ start: [], key: token, sep: [] });
                this.onKeyLine = true;
                return;
              } else if (it.sep) {
                it.value = token;
              } else {
                Object.assign(it, { key: token, sep: [] });
                this.onKeyLine = !it.explicitKey;
                return;
              }
              break;
            }
            case "block-seq": {
              const it = top.items[top.items.length - 1];
              if (it.value)
                top.items.push({ start: [], value: token });
              else
                it.value = token;
              break;
            }
            case "flow-collection": {
              const it = top.items[top.items.length - 1];
              if (!it || it.value)
                top.items.push({ start: [], key: token, sep: [] });
              else if (it.sep)
                it.value = token;
              else
                Object.assign(it, { key: token, sep: [] });
              return;
            }
            /* istanbul ignore next should not happen */
            default:
              yield* this.pop();
              yield* this.pop(token);
          }
          if ((top.type === "document" || top.type === "block-map" || top.type === "block-seq") && (token.type === "block-map" || token.type === "block-seq")) {
            const last = token.items[token.items.length - 1];
            if (last && !last.sep && !last.value && last.start.length > 0 && findNonEmptyIndex(last.start) === -1 && (token.indent === 0 || last.start.every((st) => st.type !== "comment" || st.indent < token.indent))) {
              if (top.type === "document")
                top.end = last.start;
              else
                top.items.push({ start: last.start });
              token.items.splice(-1, 1);
            }
          }
        }
      }
      *stream() {
        switch (this.type) {
          case "directive-line":
            yield { type: "directive", offset: this.offset, source: this.source };
            return;
          case "byte-order-mark":
          case "space":
          case "comment":
          case "newline":
            yield this.sourceToken;
            return;
          case "doc-mode":
          case "doc-start": {
            const doc = {
              type: "document",
              offset: this.offset,
              start: []
            };
            if (this.type === "doc-start")
              doc.start.push(this.sourceToken);
            this.stack.push(doc);
            return;
          }
        }
        yield {
          type: "error",
          offset: this.offset,
          message: `Unexpected ${this.type} token in YAML stream`,
          source: this.source
        };
      }
      *document(doc) {
        if (doc.value)
          return yield* this.lineEnd(doc);
        switch (this.type) {
          case "doc-start": {
            if (findNonEmptyIndex(doc.start) !== -1) {
              yield* this.pop();
              yield* this.step();
            } else
              doc.start.push(this.sourceToken);
            return;
          }
          case "anchor":
          case "tag":
          case "space":
          case "comment":
          case "newline":
            doc.start.push(this.sourceToken);
            return;
        }
        const bv = this.startBlockValue(doc);
        if (bv)
          this.stack.push(bv);
        else {
          yield {
            type: "error",
            offset: this.offset,
            message: `Unexpected ${this.type} token in YAML document`,
            source: this.source
          };
        }
      }
      *scalar(scalar) {
        if (this.type === "map-value-ind") {
          const prev = getPrevProps(this.peek(2));
          const start = getFirstKeyStartProps(prev);
          let sep;
          if (scalar.end) {
            sep = scalar.end;
            sep.push(this.sourceToken);
            delete scalar.end;
          } else
            sep = [this.sourceToken];
          const map = {
            type: "block-map",
            offset: scalar.offset,
            indent: scalar.indent,
            items: [{ start, key: scalar, sep }]
          };
          this.onKeyLine = true;
          this.stack[this.stack.length - 1] = map;
        } else
          yield* this.lineEnd(scalar);
      }
      *blockScalar(scalar) {
        switch (this.type) {
          case "space":
          case "comment":
          case "newline":
            scalar.props.push(this.sourceToken);
            return;
          case "scalar":
            scalar.source = this.source;
            this.atNewLine = true;
            this.indent = 0;
            if (this.onNewLine) {
              let nl = this.source.indexOf("\n") + 1;
              while (nl !== 0) {
                this.onNewLine(this.offset + nl);
                nl = this.source.indexOf("\n", nl) + 1;
              }
            }
            yield* this.pop();
            break;
          /* istanbul ignore next should not happen */
          default:
            yield* this.pop();
            yield* this.step();
        }
      }
      *blockMap(map) {
        const it = map.items[map.items.length - 1];
        switch (this.type) {
          case "newline":
            this.onKeyLine = false;
            if (it.value) {
              const end = "end" in it.value ? it.value.end : void 0;
              const last = Array.isArray(end) ? end[end.length - 1] : void 0;
              if (last?.type === "comment")
                end?.push(this.sourceToken);
              else
                map.items.push({ start: [this.sourceToken] });
            } else if (it.sep) {
              it.sep.push(this.sourceToken);
            } else {
              it.start.push(this.sourceToken);
            }
            return;
          case "space":
          case "comment":
            if (it.value) {
              map.items.push({ start: [this.sourceToken] });
            } else if (it.sep) {
              it.sep.push(this.sourceToken);
            } else {
              if (this.atIndentedComment(it.start, map.indent)) {
                const prev = map.items[map.items.length - 2];
                const end = prev?.value?.end;
                if (Array.isArray(end)) {
                  Array.prototype.push.apply(end, it.start);
                  end.push(this.sourceToken);
                  map.items.pop();
                  return;
                }
              }
              it.start.push(this.sourceToken);
            }
            return;
        }
        if (this.indent >= map.indent) {
          const atMapIndent = !this.onKeyLine && this.indent === map.indent;
          const atNextItem = atMapIndent && (it.sep || it.explicitKey) && this.type !== "seq-item-ind";
          let start = [];
          if (atNextItem && it.sep && !it.value) {
            const nl = [];
            for (let i = 0; i < it.sep.length; ++i) {
              const st = it.sep[i];
              switch (st.type) {
                case "newline":
                  nl.push(i);
                  break;
                case "space":
                  break;
                case "comment":
                  if (st.indent > map.indent)
                    nl.length = 0;
                  break;
                default:
                  nl.length = 0;
              }
            }
            if (nl.length >= 2)
              start = it.sep.splice(nl[1]);
          }
          switch (this.type) {
            case "anchor":
            case "tag":
              if (atNextItem || it.value) {
                start.push(this.sourceToken);
                map.items.push({ start });
                this.onKeyLine = true;
              } else if (it.sep) {
                it.sep.push(this.sourceToken);
              } else {
                it.start.push(this.sourceToken);
              }
              return;
            case "explicit-key-ind":
              if (!it.sep && !it.explicitKey) {
                it.start.push(this.sourceToken);
                it.explicitKey = true;
              } else if (atNextItem || it.value) {
                start.push(this.sourceToken);
                map.items.push({ start, explicitKey: true });
              } else {
                this.stack.push({
                  type: "block-map",
                  offset: this.offset,
                  indent: this.indent,
                  items: [{ start: [this.sourceToken], explicitKey: true }]
                });
              }
              this.onKeyLine = true;
              return;
            case "map-value-ind":
              if (it.explicitKey) {
                if (!it.sep) {
                  if (includesToken(it.start, "newline")) {
                    Object.assign(it, { key: null, sep: [this.sourceToken] });
                  } else {
                    const start2 = getFirstKeyStartProps(it.start);
                    this.stack.push({
                      type: "block-map",
                      offset: this.offset,
                      indent: this.indent,
                      items: [{ start: start2, key: null, sep: [this.sourceToken] }]
                    });
                  }
                } else if (it.value) {
                  map.items.push({ start: [], key: null, sep: [this.sourceToken] });
                } else if (includesToken(it.sep, "map-value-ind")) {
                  this.stack.push({
                    type: "block-map",
                    offset: this.offset,
                    indent: this.indent,
                    items: [{ start, key: null, sep: [this.sourceToken] }]
                  });
                } else if (isFlowToken(it.key) && !includesToken(it.sep, "newline")) {
                  const start2 = getFirstKeyStartProps(it.start);
                  const key = it.key;
                  const sep = it.sep;
                  sep.push(this.sourceToken);
                  delete it.key;
                  delete it.sep;
                  this.stack.push({
                    type: "block-map",
                    offset: this.offset,
                    indent: this.indent,
                    items: [{ start: start2, key, sep }]
                  });
                } else if (start.length > 0) {
                  it.sep = it.sep.concat(start, this.sourceToken);
                } else {
                  it.sep.push(this.sourceToken);
                }
              } else {
                if (!it.sep) {
                  Object.assign(it, { key: null, sep: [this.sourceToken] });
                } else if (it.value || atNextItem) {
                  map.items.push({ start, key: null, sep: [this.sourceToken] });
                } else if (includesToken(it.sep, "map-value-ind")) {
                  this.stack.push({
                    type: "block-map",
                    offset: this.offset,
                    indent: this.indent,
                    items: [{ start: [], key: null, sep: [this.sourceToken] }]
                  });
                } else {
                  it.sep.push(this.sourceToken);
                }
              }
              this.onKeyLine = true;
              return;
            case "alias":
            case "scalar":
            case "single-quoted-scalar":
            case "double-quoted-scalar": {
              const fs = this.flowScalar(this.type);
              if (atNextItem || it.value) {
                map.items.push({ start, key: fs, sep: [] });
                this.onKeyLine = true;
              } else if (it.sep) {
                this.stack.push(fs);
              } else {
                Object.assign(it, { key: fs, sep: [] });
                this.onKeyLine = true;
              }
              return;
            }
            default: {
              const bv = this.startBlockValue(map);
              if (bv) {
                if (bv.type === "block-seq") {
                  if (!it.explicitKey && it.sep && !includesToken(it.sep, "newline")) {
                    yield* this.pop({
                      type: "error",
                      offset: this.offset,
                      message: "Unexpected block-seq-ind on same line with key",
                      source: this.source
                    });
                    return;
                  }
                } else if (atMapIndent) {
                  map.items.push({ start });
                }
                this.stack.push(bv);
                return;
              }
            }
          }
        }
        yield* this.pop();
        yield* this.step();
      }
      *blockSequence(seq) {
        const it = seq.items[seq.items.length - 1];
        switch (this.type) {
          case "newline":
            if (it.value) {
              const end = "end" in it.value ? it.value.end : void 0;
              const last = Array.isArray(end) ? end[end.length - 1] : void 0;
              if (last?.type === "comment")
                end?.push(this.sourceToken);
              else
                seq.items.push({ start: [this.sourceToken] });
            } else
              it.start.push(this.sourceToken);
            return;
          case "space":
          case "comment":
            if (it.value)
              seq.items.push({ start: [this.sourceToken] });
            else {
              if (this.atIndentedComment(it.start, seq.indent)) {
                const prev = seq.items[seq.items.length - 2];
                const end = prev?.value?.end;
                if (Array.isArray(end)) {
                  Array.prototype.push.apply(end, it.start);
                  end.push(this.sourceToken);
                  seq.items.pop();
                  return;
                }
              }
              it.start.push(this.sourceToken);
            }
            return;
          case "anchor":
          case "tag":
            if (it.value || this.indent <= seq.indent)
              break;
            it.start.push(this.sourceToken);
            return;
          case "seq-item-ind":
            if (this.indent !== seq.indent)
              break;
            if (it.value || includesToken(it.start, "seq-item-ind"))
              seq.items.push({ start: [this.sourceToken] });
            else
              it.start.push(this.sourceToken);
            return;
        }
        if (this.indent > seq.indent) {
          const bv = this.startBlockValue(seq);
          if (bv) {
            this.stack.push(bv);
            return;
          }
        }
        yield* this.pop();
        yield* this.step();
      }
      *flowCollection(fc) {
        const it = fc.items[fc.items.length - 1];
        if (this.type === "flow-error-end") {
          let top;
          do {
            yield* this.pop();
            top = this.peek(1);
          } while (top?.type === "flow-collection");
        } else if (fc.end.length === 0) {
          switch (this.type) {
            case "comma":
            case "explicit-key-ind":
              if (!it || it.sep)
                fc.items.push({ start: [this.sourceToken] });
              else
                it.start.push(this.sourceToken);
              return;
            case "map-value-ind":
              if (!it || it.value)
                fc.items.push({ start: [], key: null, sep: [this.sourceToken] });
              else if (it.sep)
                it.sep.push(this.sourceToken);
              else
                Object.assign(it, { key: null, sep: [this.sourceToken] });
              return;
            case "space":
            case "comment":
            case "newline":
            case "anchor":
            case "tag":
              if (!it || it.value)
                fc.items.push({ start: [this.sourceToken] });
              else if (it.sep)
                it.sep.push(this.sourceToken);
              else
                it.start.push(this.sourceToken);
              return;
            case "alias":
            case "scalar":
            case "single-quoted-scalar":
            case "double-quoted-scalar": {
              const fs = this.flowScalar(this.type);
              if (!it || it.value)
                fc.items.push({ start: [], key: fs, sep: [] });
              else if (it.sep)
                this.stack.push(fs);
              else
                Object.assign(it, { key: fs, sep: [] });
              return;
            }
            case "flow-map-end":
            case "flow-seq-end":
              fc.end.push(this.sourceToken);
              return;
          }
          const bv = this.startBlockValue(fc);
          if (bv)
            this.stack.push(bv);
          else {
            yield* this.pop();
            yield* this.step();
          }
        } else {
          const parent = this.peek(2);
          if (parent.type === "block-map" && (this.type === "map-value-ind" && parent.indent === fc.indent || this.type === "newline" && !parent.items[parent.items.length - 1].sep)) {
            yield* this.pop();
            yield* this.step();
          } else if (this.type === "map-value-ind" && parent.type !== "flow-collection") {
            const prev = getPrevProps(parent);
            const start = getFirstKeyStartProps(prev);
            fixFlowSeqItems(fc);
            const sep = fc.end.splice(1, fc.end.length);
            sep.push(this.sourceToken);
            const map = {
              type: "block-map",
              offset: fc.offset,
              indent: fc.indent,
              items: [{ start, key: fc, sep }]
            };
            this.onKeyLine = true;
            this.stack[this.stack.length - 1] = map;
          } else {
            yield* this.lineEnd(fc);
          }
        }
      }
      flowScalar(type) {
        if (this.onNewLine) {
          let nl = this.source.indexOf("\n") + 1;
          while (nl !== 0) {
            this.onNewLine(this.offset + nl);
            nl = this.source.indexOf("\n", nl) + 1;
          }
        }
        return {
          type,
          offset: this.offset,
          indent: this.indent,
          source: this.source
        };
      }
      startBlockValue(parent) {
        switch (this.type) {
          case "alias":
          case "scalar":
          case "single-quoted-scalar":
          case "double-quoted-scalar":
            return this.flowScalar(this.type);
          case "block-scalar-header":
            return {
              type: "block-scalar",
              offset: this.offset,
              indent: this.indent,
              props: [this.sourceToken],
              source: ""
            };
          case "flow-map-start":
          case "flow-seq-start":
            return {
              type: "flow-collection",
              offset: this.offset,
              indent: this.indent,
              start: this.sourceToken,
              items: [],
              end: []
            };
          case "seq-item-ind":
            return {
              type: "block-seq",
              offset: this.offset,
              indent: this.indent,
              items: [{ start: [this.sourceToken] }]
            };
          case "explicit-key-ind": {
            this.onKeyLine = true;
            const prev = getPrevProps(parent);
            const start = getFirstKeyStartProps(prev);
            start.push(this.sourceToken);
            return {
              type: "block-map",
              offset: this.offset,
              indent: this.indent,
              items: [{ start, explicitKey: true }]
            };
          }
          case "map-value-ind": {
            this.onKeyLine = true;
            const prev = getPrevProps(parent);
            const start = getFirstKeyStartProps(prev);
            return {
              type: "block-map",
              offset: this.offset,
              indent: this.indent,
              items: [{ start, key: null, sep: [this.sourceToken] }]
            };
          }
        }
        return null;
      }
      atIndentedComment(start, indent) {
        if (this.type !== "comment")
          return false;
        if (this.indent <= indent)
          return false;
        return start.every((st) => st.type === "newline" || st.type === "space");
      }
      *documentEnd(docEnd) {
        if (this.type !== "doc-mode") {
          if (docEnd.end)
            docEnd.end.push(this.sourceToken);
          else
            docEnd.end = [this.sourceToken];
          if (this.type === "newline")
            yield* this.pop();
        }
      }
      *lineEnd(token) {
        switch (this.type) {
          case "comma":
          case "doc-start":
          case "doc-end":
          case "flow-seq-end":
          case "flow-map-end":
          case "map-value-ind":
            yield* this.pop();
            yield* this.step();
            break;
          case "newline":
            this.onKeyLine = false;
          // fallthrough
          case "space":
          case "comment":
          default:
            if (token.end)
              token.end.push(this.sourceToken);
            else
              token.end = [this.sourceToken];
            if (this.type === "newline")
              yield* this.pop();
        }
      }
    };
    exports.Parser = Parser;
  }
});

// node_modules/yaml/dist/public-api.js
var require_public_api = __commonJS({
  "node_modules/yaml/dist/public-api.js"(exports) {
    "use strict";
    var composer = require_composer();
    var Document = require_Document();
    var errors = require_errors();
    var log = require_log();
    var identity = require_identity();
    var lineCounter = require_line_counter();
    var parser = require_parser();
    function parseOptions(options) {
      const prettyErrors = options.prettyErrors !== false;
      const lineCounter$1 = options.lineCounter || prettyErrors && new lineCounter.LineCounter() || null;
      return { lineCounter: lineCounter$1, prettyErrors };
    }
    function parseAllDocuments(source, options = {}) {
      const { lineCounter: lineCounter2, prettyErrors } = parseOptions(options);
      const parser$1 = new parser.Parser(lineCounter2?.addNewLine);
      const composer$1 = new composer.Composer(options);
      const docs = Array.from(composer$1.compose(parser$1.parse(source)));
      if (prettyErrors && lineCounter2)
        for (const doc of docs) {
          doc.errors.forEach(errors.prettifyError(source, lineCounter2));
          doc.warnings.forEach(errors.prettifyError(source, lineCounter2));
        }
      if (docs.length > 0)
        return docs;
      return Object.assign([], { empty: true }, composer$1.streamInfo());
    }
    function parseDocument(source, options = {}) {
      const { lineCounter: lineCounter2, prettyErrors } = parseOptions(options);
      const parser$1 = new parser.Parser(lineCounter2?.addNewLine);
      const composer$1 = new composer.Composer(options);
      let doc = null;
      for (const _doc of composer$1.compose(parser$1.parse(source), true, source.length)) {
        if (!doc)
          doc = _doc;
        else if (doc.options.logLevel !== "silent") {
          doc.errors.push(new errors.YAMLParseError(_doc.range.slice(0, 2), "MULTIPLE_DOCS", "Source contains multiple documents; please use YAML.parseAllDocuments()"));
          break;
        }
      }
      if (prettyErrors && lineCounter2) {
        doc.errors.forEach(errors.prettifyError(source, lineCounter2));
        doc.warnings.forEach(errors.prettifyError(source, lineCounter2));
      }
      return doc;
    }
    function parse(src, reviver, options) {
      let _reviver = void 0;
      if (typeof reviver === "function") {
        _reviver = reviver;
      } else if (options === void 0 && reviver && typeof reviver === "object") {
        options = reviver;
      }
      const doc = parseDocument(src, options);
      if (!doc)
        return null;
      doc.warnings.forEach((warning) => log.warn(doc.options.logLevel, warning));
      if (doc.errors.length > 0) {
        if (doc.options.logLevel !== "silent")
          throw doc.errors[0];
        else
          doc.errors = [];
      }
      return doc.toJS(Object.assign({ reviver: _reviver }, options));
    }
    function stringify(value, replacer, options) {
      let _replacer = null;
      if (typeof replacer === "function" || Array.isArray(replacer)) {
        _replacer = replacer;
      } else if (options === void 0 && replacer) {
        options = replacer;
      }
      if (typeof options === "string")
        options = options.length;
      if (typeof options === "number") {
        const indent = Math.round(options);
        options = indent < 1 ? void 0 : indent > 8 ? { indent: 8 } : { indent };
      }
      if (value === void 0) {
        const { keepUndefined } = options ?? replacer ?? {};
        if (!keepUndefined)
          return void 0;
      }
      if (identity.isDocument(value) && !_replacer)
        return value.toString(options);
      return new Document.Document(value, _replacer, options).toString(options);
    }
    exports.parse = parse;
    exports.parseAllDocuments = parseAllDocuments;
    exports.parseDocument = parseDocument;
    exports.stringify = stringify;
  }
});

// node_modules/yaml/dist/index.js
var require_dist = __commonJS({
  "node_modules/yaml/dist/index.js"(exports) {
    "use strict";
    var composer = require_composer();
    var Document = require_Document();
    var Schema = require_Schema();
    var errors = require_errors();
    var Alias = require_Alias();
    var identity = require_identity();
    var Pair = require_Pair();
    var Scalar = require_Scalar();
    var YAMLMap = require_YAMLMap();
    var YAMLSeq = require_YAMLSeq();
    var cst = require_cst();
    var lexer = require_lexer();
    var lineCounter = require_line_counter();
    var parser = require_parser();
    var publicApi = require_public_api();
    var visit = require_visit();
    exports.Composer = composer.Composer;
    exports.Document = Document.Document;
    exports.Schema = Schema.Schema;
    exports.YAMLError = errors.YAMLError;
    exports.YAMLParseError = errors.YAMLParseError;
    exports.YAMLWarning = errors.YAMLWarning;
    exports.Alias = Alias.Alias;
    exports.isAlias = identity.isAlias;
    exports.isCollection = identity.isCollection;
    exports.isDocument = identity.isDocument;
    exports.isMap = identity.isMap;
    exports.isNode = identity.isNode;
    exports.isPair = identity.isPair;
    exports.isScalar = identity.isScalar;
    exports.isSeq = identity.isSeq;
    exports.Pair = Pair.Pair;
    exports.Scalar = Scalar.Scalar;
    exports.YAMLMap = YAMLMap.YAMLMap;
    exports.YAMLSeq = YAMLSeq.YAMLSeq;
    exports.CST = cst;
    exports.Lexer = lexer.Lexer;
    exports.LineCounter = lineCounter.LineCounter;
    exports.Parser = parser.Parser;
    exports.parse = publicApi.parse;
    exports.parseAllDocuments = publicApi.parseAllDocuments;
    exports.parseDocument = publicApi.parseDocument;
    exports.stringify = publicApi.stringify;
    exports.visit = visit.visit;
    exports.visitAsync = visit.visitAsync;
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

// node_modules/zod/v3/helpers/util.js
var util, objectUtil, ZodParsedType, getParsedType;
var init_util = __esm({
  "node_modules/zod/v3/helpers/util.js"() {
    "use strict";
    (function(util2) {
      util2.assertEqual = (_) => {
      };
      function assertIs(_arg) {
      }
      util2.assertIs = assertIs;
      function assertNever(_x) {
        throw new Error();
      }
      util2.assertNever = assertNever;
      util2.arrayToEnum = (items) => {
        const obj = {};
        for (const item of items) {
          obj[item] = item;
        }
        return obj;
      };
      util2.getValidEnumValues = (obj) => {
        const validKeys = util2.objectKeys(obj).filter((k) => typeof obj[obj[k]] !== "number");
        const filtered = {};
        for (const k of validKeys) {
          filtered[k] = obj[k];
        }
        return util2.objectValues(filtered);
      };
      util2.objectValues = (obj) => {
        return util2.objectKeys(obj).map(function(e) {
          return obj[e];
        });
      };
      util2.objectKeys = typeof Object.keys === "function" ? (obj) => Object.keys(obj) : (object) => {
        const keys = [];
        for (const key in object) {
          if (Object.prototype.hasOwnProperty.call(object, key)) {
            keys.push(key);
          }
        }
        return keys;
      };
      util2.find = (arr, checker) => {
        for (const item of arr) {
          if (checker(item))
            return item;
        }
        return void 0;
      };
      util2.isInteger = typeof Number.isInteger === "function" ? (val) => Number.isInteger(val) : (val) => typeof val === "number" && Number.isFinite(val) && Math.floor(val) === val;
      function joinValues(array, separator = " | ") {
        return array.map((val) => typeof val === "string" ? `'${val}'` : val).join(separator);
      }
      util2.joinValues = joinValues;
      util2.jsonStringifyReplacer = (_, value) => {
        if (typeof value === "bigint") {
          return value.toString();
        }
        return value;
      };
    })(util || (util = {}));
    (function(objectUtil2) {
      objectUtil2.mergeShapes = (first, second) => {
        return {
          ...first,
          ...second
          // second overwrites first
        };
      };
    })(objectUtil || (objectUtil = {}));
    ZodParsedType = util.arrayToEnum([
      "string",
      "nan",
      "number",
      "integer",
      "float",
      "boolean",
      "date",
      "bigint",
      "symbol",
      "function",
      "undefined",
      "null",
      "array",
      "object",
      "unknown",
      "promise",
      "void",
      "never",
      "map",
      "set"
    ]);
    getParsedType = (data) => {
      const t = typeof data;
      switch (t) {
        case "undefined":
          return ZodParsedType.undefined;
        case "string":
          return ZodParsedType.string;
        case "number":
          return Number.isNaN(data) ? ZodParsedType.nan : ZodParsedType.number;
        case "boolean":
          return ZodParsedType.boolean;
        case "function":
          return ZodParsedType.function;
        case "bigint":
          return ZodParsedType.bigint;
        case "symbol":
          return ZodParsedType.symbol;
        case "object":
          if (Array.isArray(data)) {
            return ZodParsedType.array;
          }
          if (data === null) {
            return ZodParsedType.null;
          }
          if (data.then && typeof data.then === "function" && data.catch && typeof data.catch === "function") {
            return ZodParsedType.promise;
          }
          if (typeof Map !== "undefined" && data instanceof Map) {
            return ZodParsedType.map;
          }
          if (typeof Set !== "undefined" && data instanceof Set) {
            return ZodParsedType.set;
          }
          if (typeof Date !== "undefined" && data instanceof Date) {
            return ZodParsedType.date;
          }
          return ZodParsedType.object;
        default:
          return ZodParsedType.unknown;
      }
    };
  }
});

// node_modules/zod/v3/ZodError.js
var ZodIssueCode, quotelessJson, ZodError;
var init_ZodError = __esm({
  "node_modules/zod/v3/ZodError.js"() {
    "use strict";
    init_util();
    ZodIssueCode = util.arrayToEnum([
      "invalid_type",
      "invalid_literal",
      "custom",
      "invalid_union",
      "invalid_union_discriminator",
      "invalid_enum_value",
      "unrecognized_keys",
      "invalid_arguments",
      "invalid_return_type",
      "invalid_date",
      "invalid_string",
      "too_small",
      "too_big",
      "invalid_intersection_types",
      "not_multiple_of",
      "not_finite"
    ]);
    quotelessJson = (obj) => {
      const json = JSON.stringify(obj, null, 2);
      return json.replace(/"([^"]+)":/g, "$1:");
    };
    ZodError = class _ZodError extends Error {
      get errors() {
        return this.issues;
      }
      constructor(issues) {
        super();
        this.issues = [];
        this.addIssue = (sub) => {
          this.issues = [...this.issues, sub];
        };
        this.addIssues = (subs = []) => {
          this.issues = [...this.issues, ...subs];
        };
        const actualProto = new.target.prototype;
        if (Object.setPrototypeOf) {
          Object.setPrototypeOf(this, actualProto);
        } else {
          this.__proto__ = actualProto;
        }
        this.name = "ZodError";
        this.issues = issues;
      }
      format(_mapper) {
        const mapper = _mapper || function(issue) {
          return issue.message;
        };
        const fieldErrors = { _errors: [] };
        const processError = (error) => {
          for (const issue of error.issues) {
            if (issue.code === "invalid_union") {
              issue.unionErrors.map(processError);
            } else if (issue.code === "invalid_return_type") {
              processError(issue.returnTypeError);
            } else if (issue.code === "invalid_arguments") {
              processError(issue.argumentsError);
            } else if (issue.path.length === 0) {
              fieldErrors._errors.push(mapper(issue));
            } else {
              let curr = fieldErrors;
              let i = 0;
              while (i < issue.path.length) {
                const el = issue.path[i];
                const terminal = i === issue.path.length - 1;
                if (!terminal) {
                  curr[el] = curr[el] || { _errors: [] };
                } else {
                  curr[el] = curr[el] || { _errors: [] };
                  curr[el]._errors.push(mapper(issue));
                }
                curr = curr[el];
                i++;
              }
            }
          }
        };
        processError(this);
        return fieldErrors;
      }
      static assert(value) {
        if (!(value instanceof _ZodError)) {
          throw new Error(`Not a ZodError: ${value}`);
        }
      }
      toString() {
        return this.message;
      }
      get message() {
        return JSON.stringify(this.issues, util.jsonStringifyReplacer, 2);
      }
      get isEmpty() {
        return this.issues.length === 0;
      }
      flatten(mapper = (issue) => issue.message) {
        const fieldErrors = {};
        const formErrors = [];
        for (const sub of this.issues) {
          if (sub.path.length > 0) {
            const firstEl = sub.path[0];
            fieldErrors[firstEl] = fieldErrors[firstEl] || [];
            fieldErrors[firstEl].push(mapper(sub));
          } else {
            formErrors.push(mapper(sub));
          }
        }
        return { formErrors, fieldErrors };
      }
      get formErrors() {
        return this.flatten();
      }
    };
    ZodError.create = (issues) => {
      const error = new ZodError(issues);
      return error;
    };
  }
});

// node_modules/zod/v3/locales/en.js
var errorMap, en_default;
var init_en = __esm({
  "node_modules/zod/v3/locales/en.js"() {
    "use strict";
    init_ZodError();
    init_util();
    errorMap = (issue, _ctx) => {
      let message;
      switch (issue.code) {
        case ZodIssueCode.invalid_type:
          if (issue.received === ZodParsedType.undefined) {
            message = "Required";
          } else {
            message = `Expected ${issue.expected}, received ${issue.received}`;
          }
          break;
        case ZodIssueCode.invalid_literal:
          message = `Invalid literal value, expected ${JSON.stringify(issue.expected, util.jsonStringifyReplacer)}`;
          break;
        case ZodIssueCode.unrecognized_keys:
          message = `Unrecognized key(s) in object: ${util.joinValues(issue.keys, ", ")}`;
          break;
        case ZodIssueCode.invalid_union:
          message = `Invalid input`;
          break;
        case ZodIssueCode.invalid_union_discriminator:
          message = `Invalid discriminator value. Expected ${util.joinValues(issue.options)}`;
          break;
        case ZodIssueCode.invalid_enum_value:
          message = `Invalid enum value. Expected ${util.joinValues(issue.options)}, received '${issue.received}'`;
          break;
        case ZodIssueCode.invalid_arguments:
          message = `Invalid function arguments`;
          break;
        case ZodIssueCode.invalid_return_type:
          message = `Invalid function return type`;
          break;
        case ZodIssueCode.invalid_date:
          message = `Invalid date`;
          break;
        case ZodIssueCode.invalid_string:
          if (typeof issue.validation === "object") {
            if ("includes" in issue.validation) {
              message = `Invalid input: must include "${issue.validation.includes}"`;
              if (typeof issue.validation.position === "number") {
                message = `${message} at one or more positions greater than or equal to ${issue.validation.position}`;
              }
            } else if ("startsWith" in issue.validation) {
              message = `Invalid input: must start with "${issue.validation.startsWith}"`;
            } else if ("endsWith" in issue.validation) {
              message = `Invalid input: must end with "${issue.validation.endsWith}"`;
            } else {
              util.assertNever(issue.validation);
            }
          } else if (issue.validation !== "regex") {
            message = `Invalid ${issue.validation}`;
          } else {
            message = "Invalid";
          }
          break;
        case ZodIssueCode.too_small:
          if (issue.type === "array")
            message = `Array must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `more than`} ${issue.minimum} element(s)`;
          else if (issue.type === "string")
            message = `String must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `over`} ${issue.minimum} character(s)`;
          else if (issue.type === "number")
            message = `Number must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${issue.minimum}`;
          else if (issue.type === "bigint")
            message = `Number must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${issue.minimum}`;
          else if (issue.type === "date")
            message = `Date must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${new Date(Number(issue.minimum))}`;
          else
            message = "Invalid input";
          break;
        case ZodIssueCode.too_big:
          if (issue.type === "array")
            message = `Array must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `less than`} ${issue.maximum} element(s)`;
          else if (issue.type === "string")
            message = `String must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `under`} ${issue.maximum} character(s)`;
          else if (issue.type === "number")
            message = `Number must be ${issue.exact ? `exactly` : issue.inclusive ? `less than or equal to` : `less than`} ${issue.maximum}`;
          else if (issue.type === "bigint")
            message = `BigInt must be ${issue.exact ? `exactly` : issue.inclusive ? `less than or equal to` : `less than`} ${issue.maximum}`;
          else if (issue.type === "date")
            message = `Date must be ${issue.exact ? `exactly` : issue.inclusive ? `smaller than or equal to` : `smaller than`} ${new Date(Number(issue.maximum))}`;
          else
            message = "Invalid input";
          break;
        case ZodIssueCode.custom:
          message = `Invalid input`;
          break;
        case ZodIssueCode.invalid_intersection_types:
          message = `Intersection results could not be merged`;
          break;
        case ZodIssueCode.not_multiple_of:
          message = `Number must be a multiple of ${issue.multipleOf}`;
          break;
        case ZodIssueCode.not_finite:
          message = "Number must be finite";
          break;
        default:
          message = _ctx.defaultError;
          util.assertNever(issue);
      }
      return { message };
    };
    en_default = errorMap;
  }
});

// node_modules/zod/v3/errors.js
function setErrorMap(map) {
  overrideErrorMap = map;
}
function getErrorMap() {
  return overrideErrorMap;
}
var overrideErrorMap;
var init_errors = __esm({
  "node_modules/zod/v3/errors.js"() {
    "use strict";
    init_en();
    overrideErrorMap = en_default;
  }
});

// node_modules/zod/v3/helpers/parseUtil.js
function addIssueToContext(ctx, issueData) {
  const overrideMap = getErrorMap();
  const issue = makeIssue({
    issueData,
    data: ctx.data,
    path: ctx.path,
    errorMaps: [
      ctx.common.contextualErrorMap,
      // contextual error map is first priority
      ctx.schemaErrorMap,
      // then schema-bound map if available
      overrideMap,
      // then global override map
      overrideMap === en_default ? void 0 : en_default
      // then global default map
    ].filter((x) => !!x)
  });
  ctx.common.issues.push(issue);
}
var makeIssue, EMPTY_PATH, ParseStatus, INVALID, DIRTY, OK, isAborted, isDirty, isValid, isAsync;
var init_parseUtil = __esm({
  "node_modules/zod/v3/helpers/parseUtil.js"() {
    "use strict";
    init_errors();
    init_en();
    makeIssue = (params) => {
      const { data, path, errorMaps, issueData } = params;
      const fullPath = [...path, ...issueData.path || []];
      const fullIssue = {
        ...issueData,
        path: fullPath
      };
      if (issueData.message !== void 0) {
        return {
          ...issueData,
          path: fullPath,
          message: issueData.message
        };
      }
      let errorMessage = "";
      const maps = errorMaps.filter((m) => !!m).slice().reverse();
      for (const map of maps) {
        errorMessage = map(fullIssue, { data, defaultError: errorMessage }).message;
      }
      return {
        ...issueData,
        path: fullPath,
        message: errorMessage
      };
    };
    EMPTY_PATH = [];
    ParseStatus = class _ParseStatus {
      constructor() {
        this.value = "valid";
      }
      dirty() {
        if (this.value === "valid")
          this.value = "dirty";
      }
      abort() {
        if (this.value !== "aborted")
          this.value = "aborted";
      }
      static mergeArray(status, results) {
        const arrayValue = [];
        for (const s of results) {
          if (s.status === "aborted")
            return INVALID;
          if (s.status === "dirty")
            status.dirty();
          arrayValue.push(s.value);
        }
        return { status: status.value, value: arrayValue };
      }
      static async mergeObjectAsync(status, pairs) {
        const syncPairs = [];
        for (const pair of pairs) {
          const key = await pair.key;
          const value = await pair.value;
          syncPairs.push({
            key,
            value
          });
        }
        return _ParseStatus.mergeObjectSync(status, syncPairs);
      }
      static mergeObjectSync(status, pairs) {
        const finalObject = {};
        for (const pair of pairs) {
          const { key, value } = pair;
          if (key.status === "aborted")
            return INVALID;
          if (value.status === "aborted")
            return INVALID;
          if (key.status === "dirty")
            status.dirty();
          if (value.status === "dirty")
            status.dirty();
          if (key.value !== "__proto__" && (typeof value.value !== "undefined" || pair.alwaysSet)) {
            finalObject[key.value] = value.value;
          }
        }
        return { status: status.value, value: finalObject };
      }
    };
    INVALID = Object.freeze({
      status: "aborted"
    });
    DIRTY = (value) => ({ status: "dirty", value });
    OK = (value) => ({ status: "valid", value });
    isAborted = (x) => x.status === "aborted";
    isDirty = (x) => x.status === "dirty";
    isValid = (x) => x.status === "valid";
    isAsync = (x) => typeof Promise !== "undefined" && x instanceof Promise;
  }
});

// node_modules/zod/v3/helpers/typeAliases.js
var init_typeAliases = __esm({
  "node_modules/zod/v3/helpers/typeAliases.js"() {
    "use strict";
  }
});

// node_modules/zod/v3/helpers/errorUtil.js
var errorUtil;
var init_errorUtil = __esm({
  "node_modules/zod/v3/helpers/errorUtil.js"() {
    "use strict";
    (function(errorUtil2) {
      errorUtil2.errToObj = (message) => typeof message === "string" ? { message } : message || {};
      errorUtil2.toString = (message) => typeof message === "string" ? message : message?.message;
    })(errorUtil || (errorUtil = {}));
  }
});

// node_modules/zod/v3/types.js
function processCreateParams(params) {
  if (!params)
    return {};
  const { errorMap: errorMap2, invalid_type_error, required_error, description } = params;
  if (errorMap2 && (invalid_type_error || required_error)) {
    throw new Error(`Can't use "invalid_type_error" or "required_error" in conjunction with custom error map.`);
  }
  if (errorMap2)
    return { errorMap: errorMap2, description };
  const customMap = (iss, ctx) => {
    const { message } = params;
    if (iss.code === "invalid_enum_value") {
      return { message: message ?? ctx.defaultError };
    }
    if (typeof ctx.data === "undefined") {
      return { message: message ?? required_error ?? ctx.defaultError };
    }
    if (iss.code !== "invalid_type")
      return { message: ctx.defaultError };
    return { message: message ?? invalid_type_error ?? ctx.defaultError };
  };
  return { errorMap: customMap, description };
}
function timeRegexSource(args) {
  let secondsRegexSource = `[0-5]\\d`;
  if (args.precision) {
    secondsRegexSource = `${secondsRegexSource}\\.\\d{${args.precision}}`;
  } else if (args.precision == null) {
    secondsRegexSource = `${secondsRegexSource}(\\.\\d+)?`;
  }
  const secondsQuantifier = args.precision ? "+" : "?";
  return `([01]\\d|2[0-3]):[0-5]\\d(:${secondsRegexSource})${secondsQuantifier}`;
}
function timeRegex(args) {
  return new RegExp(`^${timeRegexSource(args)}$`);
}
function datetimeRegex(args) {
  let regex = `${dateRegexSource}T${timeRegexSource(args)}`;
  const opts = [];
  opts.push(args.local ? `Z?` : `Z`);
  if (args.offset)
    opts.push(`([+-]\\d{2}:?\\d{2})`);
  regex = `${regex}(${opts.join("|")})`;
  return new RegExp(`^${regex}$`);
}
function isValidIP(ip, version) {
  if ((version === "v4" || !version) && ipv4Regex.test(ip)) {
    return true;
  }
  if ((version === "v6" || !version) && ipv6Regex.test(ip)) {
    return true;
  }
  return false;
}
function isValidJWT(jwt, alg) {
  if (!jwtRegex.test(jwt))
    return false;
  try {
    const [header] = jwt.split(".");
    if (!header)
      return false;
    const base64 = header.replace(/-/g, "+").replace(/_/g, "/").padEnd(header.length + (4 - header.length % 4) % 4, "=");
    const decoded = JSON.parse(atob(base64));
    if (typeof decoded !== "object" || decoded === null)
      return false;
    if ("typ" in decoded && decoded?.typ !== "JWT")
      return false;
    if (!decoded.alg)
      return false;
    if (alg && decoded.alg !== alg)
      return false;
    return true;
  } catch {
    return false;
  }
}
function isValidCidr(ip, version) {
  if ((version === "v4" || !version) && ipv4CidrRegex.test(ip)) {
    return true;
  }
  if ((version === "v6" || !version) && ipv6CidrRegex.test(ip)) {
    return true;
  }
  return false;
}
function floatSafeRemainder(val, step) {
  const valDecCount = (val.toString().split(".")[1] || "").length;
  const stepDecCount = (step.toString().split(".")[1] || "").length;
  const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;
  const valInt = Number.parseInt(val.toFixed(decCount).replace(".", ""));
  const stepInt = Number.parseInt(step.toFixed(decCount).replace(".", ""));
  return valInt % stepInt / 10 ** decCount;
}
function deepPartialify(schema) {
  if (schema instanceof ZodObject) {
    const newShape = {};
    for (const key in schema.shape) {
      const fieldSchema = schema.shape[key];
      newShape[key] = ZodOptional.create(deepPartialify(fieldSchema));
    }
    return new ZodObject({
      ...schema._def,
      shape: () => newShape
    });
  } else if (schema instanceof ZodArray) {
    return new ZodArray({
      ...schema._def,
      type: deepPartialify(schema.element)
    });
  } else if (schema instanceof ZodOptional) {
    return ZodOptional.create(deepPartialify(schema.unwrap()));
  } else if (schema instanceof ZodNullable) {
    return ZodNullable.create(deepPartialify(schema.unwrap()));
  } else if (schema instanceof ZodTuple) {
    return ZodTuple.create(schema.items.map((item) => deepPartialify(item)));
  } else {
    return schema;
  }
}
function mergeValues(a, b) {
  const aType = getParsedType(a);
  const bType = getParsedType(b);
  if (a === b) {
    return { valid: true, data: a };
  } else if (aType === ZodParsedType.object && bType === ZodParsedType.object) {
    const bKeys = util.objectKeys(b);
    const sharedKeys = util.objectKeys(a).filter((key) => bKeys.indexOf(key) !== -1);
    const newObj = { ...a, ...b };
    for (const key of sharedKeys) {
      const sharedValue = mergeValues(a[key], b[key]);
      if (!sharedValue.valid) {
        return { valid: false };
      }
      newObj[key] = sharedValue.data;
    }
    return { valid: true, data: newObj };
  } else if (aType === ZodParsedType.array && bType === ZodParsedType.array) {
    if (a.length !== b.length) {
      return { valid: false };
    }
    const newArray = [];
    for (let index = 0; index < a.length; index++) {
      const itemA = a[index];
      const itemB = b[index];
      const sharedValue = mergeValues(itemA, itemB);
      if (!sharedValue.valid) {
        return { valid: false };
      }
      newArray.push(sharedValue.data);
    }
    return { valid: true, data: newArray };
  } else if (aType === ZodParsedType.date && bType === ZodParsedType.date && +a === +b) {
    return { valid: true, data: a };
  } else {
    return { valid: false };
  }
}
function createZodEnum(values, params) {
  return new ZodEnum({
    values,
    typeName: ZodFirstPartyTypeKind.ZodEnum,
    ...processCreateParams(params)
  });
}
function cleanParams(params, data) {
  const p = typeof params === "function" ? params(data) : typeof params === "string" ? { message: params } : params;
  const p2 = typeof p === "string" ? { message: p } : p;
  return p2;
}
function custom(check, _params = {}, fatal) {
  if (check)
    return ZodAny.create().superRefine((data, ctx) => {
      const r = check(data);
      if (r instanceof Promise) {
        return r.then((r2) => {
          if (!r2) {
            const params = cleanParams(_params, data);
            const _fatal = params.fatal ?? fatal ?? true;
            ctx.addIssue({ code: "custom", ...params, fatal: _fatal });
          }
        });
      }
      if (!r) {
        const params = cleanParams(_params, data);
        const _fatal = params.fatal ?? fatal ?? true;
        ctx.addIssue({ code: "custom", ...params, fatal: _fatal });
      }
      return;
    });
  return ZodAny.create();
}
var ParseInputLazyPath, handleResult, ZodType, cuidRegex, cuid2Regex, ulidRegex, uuidRegex, nanoidRegex, jwtRegex, durationRegex, emailRegex, _emojiRegex, emojiRegex, ipv4Regex, ipv4CidrRegex, ipv6Regex, ipv6CidrRegex, base64Regex, base64urlRegex, dateRegexSource, dateRegex, ZodString, ZodNumber, ZodBigInt, ZodBoolean, ZodDate, ZodSymbol, ZodUndefined, ZodNull, ZodAny, ZodUnknown, ZodNever, ZodVoid, ZodArray, ZodObject, ZodUnion, getDiscriminator, ZodDiscriminatedUnion, ZodIntersection, ZodTuple, ZodRecord, ZodMap, ZodSet, ZodFunction, ZodLazy, ZodLiteral, ZodEnum, ZodNativeEnum, ZodPromise, ZodEffects, ZodOptional, ZodNullable, ZodDefault, ZodCatch, ZodNaN, BRAND, ZodBranded, ZodPipeline, ZodReadonly, late, ZodFirstPartyTypeKind, instanceOfType, stringType, numberType, nanType, bigIntType, booleanType, dateType, symbolType, undefinedType, nullType, anyType, unknownType, neverType, voidType, arrayType, objectType, strictObjectType, unionType, discriminatedUnionType, intersectionType, tupleType, recordType, mapType, setType, functionType, lazyType, literalType, enumType, nativeEnumType, promiseType, effectsType, optionalType, nullableType, preprocessType, pipelineType, ostring, onumber, oboolean, coerce, NEVER;
var init_types = __esm({
  "node_modules/zod/v3/types.js"() {
    "use strict";
    init_ZodError();
    init_errors();
    init_errorUtil();
    init_parseUtil();
    init_util();
    ParseInputLazyPath = class {
      constructor(parent, value, path, key) {
        this._cachedPath = [];
        this.parent = parent;
        this.data = value;
        this._path = path;
        this._key = key;
      }
      get path() {
        if (!this._cachedPath.length) {
          if (Array.isArray(this._key)) {
            this._cachedPath.push(...this._path, ...this._key);
          } else {
            this._cachedPath.push(...this._path, this._key);
          }
        }
        return this._cachedPath;
      }
    };
    handleResult = (ctx, result) => {
      if (isValid(result)) {
        return { success: true, data: result.value };
      } else {
        if (!ctx.common.issues.length) {
          throw new Error("Validation failed but no issues detected.");
        }
        return {
          success: false,
          get error() {
            if (this._error)
              return this._error;
            const error = new ZodError(ctx.common.issues);
            this._error = error;
            return this._error;
          }
        };
      }
    };
    ZodType = class {
      get description() {
        return this._def.description;
      }
      _getType(input) {
        return getParsedType(input.data);
      }
      _getOrReturnCtx(input, ctx) {
        return ctx || {
          common: input.parent.common,
          data: input.data,
          parsedType: getParsedType(input.data),
          schemaErrorMap: this._def.errorMap,
          path: input.path,
          parent: input.parent
        };
      }
      _processInputParams(input) {
        return {
          status: new ParseStatus(),
          ctx: {
            common: input.parent.common,
            data: input.data,
            parsedType: getParsedType(input.data),
            schemaErrorMap: this._def.errorMap,
            path: input.path,
            parent: input.parent
          }
        };
      }
      _parseSync(input) {
        const result = this._parse(input);
        if (isAsync(result)) {
          throw new Error("Synchronous parse encountered promise.");
        }
        return result;
      }
      _parseAsync(input) {
        const result = this._parse(input);
        return Promise.resolve(result);
      }
      parse(data, params) {
        const result = this.safeParse(data, params);
        if (result.success)
          return result.data;
        throw result.error;
      }
      safeParse(data, params) {
        const ctx = {
          common: {
            issues: [],
            async: params?.async ?? false,
            contextualErrorMap: params?.errorMap
          },
          path: params?.path || [],
          schemaErrorMap: this._def.errorMap,
          parent: null,
          data,
          parsedType: getParsedType(data)
        };
        const result = this._parseSync({ data, path: ctx.path, parent: ctx });
        return handleResult(ctx, result);
      }
      "~validate"(data) {
        const ctx = {
          common: {
            issues: [],
            async: !!this["~standard"].async
          },
          path: [],
          schemaErrorMap: this._def.errorMap,
          parent: null,
          data,
          parsedType: getParsedType(data)
        };
        if (!this["~standard"].async) {
          try {
            const result = this._parseSync({ data, path: [], parent: ctx });
            return isValid(result) ? {
              value: result.value
            } : {
              issues: ctx.common.issues
            };
          } catch (err) {
            if (err?.message?.toLowerCase()?.includes("encountered")) {
              this["~standard"].async = true;
            }
            ctx.common = {
              issues: [],
              async: true
            };
          }
        }
        return this._parseAsync({ data, path: [], parent: ctx }).then((result) => isValid(result) ? {
          value: result.value
        } : {
          issues: ctx.common.issues
        });
      }
      async parseAsync(data, params) {
        const result = await this.safeParseAsync(data, params);
        if (result.success)
          return result.data;
        throw result.error;
      }
      async safeParseAsync(data, params) {
        const ctx = {
          common: {
            issues: [],
            contextualErrorMap: params?.errorMap,
            async: true
          },
          path: params?.path || [],
          schemaErrorMap: this._def.errorMap,
          parent: null,
          data,
          parsedType: getParsedType(data)
        };
        const maybeAsyncResult = this._parse({ data, path: ctx.path, parent: ctx });
        const result = await (isAsync(maybeAsyncResult) ? maybeAsyncResult : Promise.resolve(maybeAsyncResult));
        return handleResult(ctx, result);
      }
      refine(check, message) {
        const getIssueProperties = (val) => {
          if (typeof message === "string" || typeof message === "undefined") {
            return { message };
          } else if (typeof message === "function") {
            return message(val);
          } else {
            return message;
          }
        };
        return this._refinement((val, ctx) => {
          const result = check(val);
          const setError = () => ctx.addIssue({
            code: ZodIssueCode.custom,
            ...getIssueProperties(val)
          });
          if (typeof Promise !== "undefined" && result instanceof Promise) {
            return result.then((data) => {
              if (!data) {
                setError();
                return false;
              } else {
                return true;
              }
            });
          }
          if (!result) {
            setError();
            return false;
          } else {
            return true;
          }
        });
      }
      refinement(check, refinementData) {
        return this._refinement((val, ctx) => {
          if (!check(val)) {
            ctx.addIssue(typeof refinementData === "function" ? refinementData(val, ctx) : refinementData);
            return false;
          } else {
            return true;
          }
        });
      }
      _refinement(refinement) {
        return new ZodEffects({
          schema: this,
          typeName: ZodFirstPartyTypeKind.ZodEffects,
          effect: { type: "refinement", refinement }
        });
      }
      superRefine(refinement) {
        return this._refinement(refinement);
      }
      constructor(def) {
        this.spa = this.safeParseAsync;
        this._def = def;
        this.parse = this.parse.bind(this);
        this.safeParse = this.safeParse.bind(this);
        this.parseAsync = this.parseAsync.bind(this);
        this.safeParseAsync = this.safeParseAsync.bind(this);
        this.spa = this.spa.bind(this);
        this.refine = this.refine.bind(this);
        this.refinement = this.refinement.bind(this);
        this.superRefine = this.superRefine.bind(this);
        this.optional = this.optional.bind(this);
        this.nullable = this.nullable.bind(this);
        this.nullish = this.nullish.bind(this);
        this.array = this.array.bind(this);
        this.promise = this.promise.bind(this);
        this.or = this.or.bind(this);
        this.and = this.and.bind(this);
        this.transform = this.transform.bind(this);
        this.brand = this.brand.bind(this);
        this.default = this.default.bind(this);
        this.catch = this.catch.bind(this);
        this.describe = this.describe.bind(this);
        this.pipe = this.pipe.bind(this);
        this.readonly = this.readonly.bind(this);
        this.isNullable = this.isNullable.bind(this);
        this.isOptional = this.isOptional.bind(this);
        this["~standard"] = {
          version: 1,
          vendor: "zod",
          validate: (data) => this["~validate"](data)
        };
      }
      optional() {
        return ZodOptional.create(this, this._def);
      }
      nullable() {
        return ZodNullable.create(this, this._def);
      }
      nullish() {
        return this.nullable().optional();
      }
      array() {
        return ZodArray.create(this);
      }
      promise() {
        return ZodPromise.create(this, this._def);
      }
      or(option) {
        return ZodUnion.create([this, option], this._def);
      }
      and(incoming) {
        return ZodIntersection.create(this, incoming, this._def);
      }
      transform(transform) {
        return new ZodEffects({
          ...processCreateParams(this._def),
          schema: this,
          typeName: ZodFirstPartyTypeKind.ZodEffects,
          effect: { type: "transform", transform }
        });
      }
      default(def) {
        const defaultValueFunc = typeof def === "function" ? def : () => def;
        return new ZodDefault({
          ...processCreateParams(this._def),
          innerType: this,
          defaultValue: defaultValueFunc,
          typeName: ZodFirstPartyTypeKind.ZodDefault
        });
      }
      brand() {
        return new ZodBranded({
          typeName: ZodFirstPartyTypeKind.ZodBranded,
          type: this,
          ...processCreateParams(this._def)
        });
      }
      catch(def) {
        const catchValueFunc = typeof def === "function" ? def : () => def;
        return new ZodCatch({
          ...processCreateParams(this._def),
          innerType: this,
          catchValue: catchValueFunc,
          typeName: ZodFirstPartyTypeKind.ZodCatch
        });
      }
      describe(description) {
        const This = this.constructor;
        return new This({
          ...this._def,
          description
        });
      }
      pipe(target) {
        return ZodPipeline.create(this, target);
      }
      readonly() {
        return ZodReadonly.create(this);
      }
      isOptional() {
        return this.safeParse(void 0).success;
      }
      isNullable() {
        return this.safeParse(null).success;
      }
    };
    cuidRegex = /^c[^\s-]{8,}$/i;
    cuid2Regex = /^[0-9a-z]+$/;
    ulidRegex = /^[0-9A-HJKMNP-TV-Z]{26}$/i;
    uuidRegex = /^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$/i;
    nanoidRegex = /^[a-z0-9_-]{21}$/i;
    jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/;
    durationRegex = /^[-+]?P(?!$)(?:(?:[-+]?\d+Y)|(?:[-+]?\d+[.,]\d+Y$))?(?:(?:[-+]?\d+M)|(?:[-+]?\d+[.,]\d+M$))?(?:(?:[-+]?\d+W)|(?:[-+]?\d+[.,]\d+W$))?(?:(?:[-+]?\d+D)|(?:[-+]?\d+[.,]\d+D$))?(?:T(?=[\d+-])(?:(?:[-+]?\d+H)|(?:[-+]?\d+[.,]\d+H$))?(?:(?:[-+]?\d+M)|(?:[-+]?\d+[.,]\d+M$))?(?:[-+]?\d+(?:[.,]\d+)?S)?)??$/;
    emailRegex = /^(?!\.)(?!.*\.\.)([A-Z0-9_'+\-\.]*)[A-Z0-9_+-]@([A-Z0-9][A-Z0-9\-]*\.)+[A-Z]{2,}$/i;
    _emojiRegex = `^(\\p{Extended_Pictographic}|\\p{Emoji_Component})+$`;
    ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
    ipv4CidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\/(3[0-2]|[12]?[0-9])$/;
    ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
    ipv6CidrRegex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$/;
    base64Regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;
    base64urlRegex = /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}(=)?))?$/;
    dateRegexSource = `((\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-((0[13578]|1[02])-(0[1-9]|[12]\\d|3[01])|(0[469]|11)-(0[1-9]|[12]\\d|30)|(02)-(0[1-9]|1\\d|2[0-8])))`;
    dateRegex = new RegExp(`^${dateRegexSource}$`);
    ZodString = class _ZodString extends ZodType {
      _parse(input) {
        if (this._def.coerce) {
          input.data = String(input.data);
        }
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.string) {
          const ctx2 = this._getOrReturnCtx(input);
          addIssueToContext(ctx2, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.string,
            received: ctx2.parsedType
          });
          return INVALID;
        }
        const status = new ParseStatus();
        let ctx = void 0;
        for (const check of this._def.checks) {
          if (check.kind === "min") {
            if (input.data.length < check.value) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.too_small,
                minimum: check.value,
                type: "string",
                inclusive: true,
                exact: false,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "max") {
            if (input.data.length > check.value) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.too_big,
                maximum: check.value,
                type: "string",
                inclusive: true,
                exact: false,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "length") {
            const tooBig = input.data.length > check.value;
            const tooSmall = input.data.length < check.value;
            if (tooBig || tooSmall) {
              ctx = this._getOrReturnCtx(input, ctx);
              if (tooBig) {
                addIssueToContext(ctx, {
                  code: ZodIssueCode.too_big,
                  maximum: check.value,
                  type: "string",
                  inclusive: true,
                  exact: true,
                  message: check.message
                });
              } else if (tooSmall) {
                addIssueToContext(ctx, {
                  code: ZodIssueCode.too_small,
                  minimum: check.value,
                  type: "string",
                  inclusive: true,
                  exact: true,
                  message: check.message
                });
              }
              status.dirty();
            }
          } else if (check.kind === "email") {
            if (!emailRegex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "email",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "emoji") {
            if (!emojiRegex) {
              emojiRegex = new RegExp(_emojiRegex, "u");
            }
            if (!emojiRegex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "emoji",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "uuid") {
            if (!uuidRegex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "uuid",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "nanoid") {
            if (!nanoidRegex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "nanoid",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "cuid") {
            if (!cuidRegex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "cuid",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "cuid2") {
            if (!cuid2Regex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "cuid2",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "ulid") {
            if (!ulidRegex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "ulid",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "url") {
            try {
              new URL(input.data);
            } catch {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "url",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "regex") {
            check.regex.lastIndex = 0;
            const testResult = check.regex.test(input.data);
            if (!testResult) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "regex",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "trim") {
            input.data = input.data.trim();
          } else if (check.kind === "includes") {
            if (!input.data.includes(check.value, check.position)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_string,
                validation: { includes: check.value, position: check.position },
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "toLowerCase") {
            input.data = input.data.toLowerCase();
          } else if (check.kind === "toUpperCase") {
            input.data = input.data.toUpperCase();
          } else if (check.kind === "startsWith") {
            if (!input.data.startsWith(check.value)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_string,
                validation: { startsWith: check.value },
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "endsWith") {
            if (!input.data.endsWith(check.value)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_string,
                validation: { endsWith: check.value },
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "datetime") {
            const regex = datetimeRegex(check);
            if (!regex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_string,
                validation: "datetime",
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "date") {
            const regex = dateRegex;
            if (!regex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_string,
                validation: "date",
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "time") {
            const regex = timeRegex(check);
            if (!regex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_string,
                validation: "time",
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "duration") {
            if (!durationRegex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "duration",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "ip") {
            if (!isValidIP(input.data, check.version)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "ip",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "jwt") {
            if (!isValidJWT(input.data, check.alg)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "jwt",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "cidr") {
            if (!isValidCidr(input.data, check.version)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "cidr",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "base64") {
            if (!base64Regex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "base64",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "base64url") {
            if (!base64urlRegex.test(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                validation: "base64url",
                code: ZodIssueCode.invalid_string,
                message: check.message
              });
              status.dirty();
            }
          } else {
            util.assertNever(check);
          }
        }
        return { status: status.value, value: input.data };
      }
      _regex(regex, validation, message) {
        return this.refinement((data) => regex.test(data), {
          validation,
          code: ZodIssueCode.invalid_string,
          ...errorUtil.errToObj(message)
        });
      }
      _addCheck(check) {
        return new _ZodString({
          ...this._def,
          checks: [...this._def.checks, check]
        });
      }
      email(message) {
        return this._addCheck({ kind: "email", ...errorUtil.errToObj(message) });
      }
      url(message) {
        return this._addCheck({ kind: "url", ...errorUtil.errToObj(message) });
      }
      emoji(message) {
        return this._addCheck({ kind: "emoji", ...errorUtil.errToObj(message) });
      }
      uuid(message) {
        return this._addCheck({ kind: "uuid", ...errorUtil.errToObj(message) });
      }
      nanoid(message) {
        return this._addCheck({ kind: "nanoid", ...errorUtil.errToObj(message) });
      }
      cuid(message) {
        return this._addCheck({ kind: "cuid", ...errorUtil.errToObj(message) });
      }
      cuid2(message) {
        return this._addCheck({ kind: "cuid2", ...errorUtil.errToObj(message) });
      }
      ulid(message) {
        return this._addCheck({ kind: "ulid", ...errorUtil.errToObj(message) });
      }
      base64(message) {
        return this._addCheck({ kind: "base64", ...errorUtil.errToObj(message) });
      }
      base64url(message) {
        return this._addCheck({
          kind: "base64url",
          ...errorUtil.errToObj(message)
        });
      }
      jwt(options) {
        return this._addCheck({ kind: "jwt", ...errorUtil.errToObj(options) });
      }
      ip(options) {
        return this._addCheck({ kind: "ip", ...errorUtil.errToObj(options) });
      }
      cidr(options) {
        return this._addCheck({ kind: "cidr", ...errorUtil.errToObj(options) });
      }
      datetime(options) {
        if (typeof options === "string") {
          return this._addCheck({
            kind: "datetime",
            precision: null,
            offset: false,
            local: false,
            message: options
          });
        }
        return this._addCheck({
          kind: "datetime",
          precision: typeof options?.precision === "undefined" ? null : options?.precision,
          offset: options?.offset ?? false,
          local: options?.local ?? false,
          ...errorUtil.errToObj(options?.message)
        });
      }
      date(message) {
        return this._addCheck({ kind: "date", message });
      }
      time(options) {
        if (typeof options === "string") {
          return this._addCheck({
            kind: "time",
            precision: null,
            message: options
          });
        }
        return this._addCheck({
          kind: "time",
          precision: typeof options?.precision === "undefined" ? null : options?.precision,
          ...errorUtil.errToObj(options?.message)
        });
      }
      duration(message) {
        return this._addCheck({ kind: "duration", ...errorUtil.errToObj(message) });
      }
      regex(regex, message) {
        return this._addCheck({
          kind: "regex",
          regex,
          ...errorUtil.errToObj(message)
        });
      }
      includes(value, options) {
        return this._addCheck({
          kind: "includes",
          value,
          position: options?.position,
          ...errorUtil.errToObj(options?.message)
        });
      }
      startsWith(value, message) {
        return this._addCheck({
          kind: "startsWith",
          value,
          ...errorUtil.errToObj(message)
        });
      }
      endsWith(value, message) {
        return this._addCheck({
          kind: "endsWith",
          value,
          ...errorUtil.errToObj(message)
        });
      }
      min(minLength, message) {
        return this._addCheck({
          kind: "min",
          value: minLength,
          ...errorUtil.errToObj(message)
        });
      }
      max(maxLength, message) {
        return this._addCheck({
          kind: "max",
          value: maxLength,
          ...errorUtil.errToObj(message)
        });
      }
      length(len, message) {
        return this._addCheck({
          kind: "length",
          value: len,
          ...errorUtil.errToObj(message)
        });
      }
      /**
       * Equivalent to `.min(1)`
       */
      nonempty(message) {
        return this.min(1, errorUtil.errToObj(message));
      }
      trim() {
        return new _ZodString({
          ...this._def,
          checks: [...this._def.checks, { kind: "trim" }]
        });
      }
      toLowerCase() {
        return new _ZodString({
          ...this._def,
          checks: [...this._def.checks, { kind: "toLowerCase" }]
        });
      }
      toUpperCase() {
        return new _ZodString({
          ...this._def,
          checks: [...this._def.checks, { kind: "toUpperCase" }]
        });
      }
      get isDatetime() {
        return !!this._def.checks.find((ch) => ch.kind === "datetime");
      }
      get isDate() {
        return !!this._def.checks.find((ch) => ch.kind === "date");
      }
      get isTime() {
        return !!this._def.checks.find((ch) => ch.kind === "time");
      }
      get isDuration() {
        return !!this._def.checks.find((ch) => ch.kind === "duration");
      }
      get isEmail() {
        return !!this._def.checks.find((ch) => ch.kind === "email");
      }
      get isURL() {
        return !!this._def.checks.find((ch) => ch.kind === "url");
      }
      get isEmoji() {
        return !!this._def.checks.find((ch) => ch.kind === "emoji");
      }
      get isUUID() {
        return !!this._def.checks.find((ch) => ch.kind === "uuid");
      }
      get isNANOID() {
        return !!this._def.checks.find((ch) => ch.kind === "nanoid");
      }
      get isCUID() {
        return !!this._def.checks.find((ch) => ch.kind === "cuid");
      }
      get isCUID2() {
        return !!this._def.checks.find((ch) => ch.kind === "cuid2");
      }
      get isULID() {
        return !!this._def.checks.find((ch) => ch.kind === "ulid");
      }
      get isIP() {
        return !!this._def.checks.find((ch) => ch.kind === "ip");
      }
      get isCIDR() {
        return !!this._def.checks.find((ch) => ch.kind === "cidr");
      }
      get isBase64() {
        return !!this._def.checks.find((ch) => ch.kind === "base64");
      }
      get isBase64url() {
        return !!this._def.checks.find((ch) => ch.kind === "base64url");
      }
      get minLength() {
        let min = null;
        for (const ch of this._def.checks) {
          if (ch.kind === "min") {
            if (min === null || ch.value > min)
              min = ch.value;
          }
        }
        return min;
      }
      get maxLength() {
        let max = null;
        for (const ch of this._def.checks) {
          if (ch.kind === "max") {
            if (max === null || ch.value < max)
              max = ch.value;
          }
        }
        return max;
      }
    };
    ZodString.create = (params) => {
      return new ZodString({
        checks: [],
        typeName: ZodFirstPartyTypeKind.ZodString,
        coerce: params?.coerce ?? false,
        ...processCreateParams(params)
      });
    };
    ZodNumber = class _ZodNumber extends ZodType {
      constructor() {
        super(...arguments);
        this.min = this.gte;
        this.max = this.lte;
        this.step = this.multipleOf;
      }
      _parse(input) {
        if (this._def.coerce) {
          input.data = Number(input.data);
        }
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.number) {
          const ctx2 = this._getOrReturnCtx(input);
          addIssueToContext(ctx2, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.number,
            received: ctx2.parsedType
          });
          return INVALID;
        }
        let ctx = void 0;
        const status = new ParseStatus();
        for (const check of this._def.checks) {
          if (check.kind === "int") {
            if (!util.isInteger(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: "integer",
                received: "float",
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "min") {
            const tooSmall = check.inclusive ? input.data < check.value : input.data <= check.value;
            if (tooSmall) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.too_small,
                minimum: check.value,
                type: "number",
                inclusive: check.inclusive,
                exact: false,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "max") {
            const tooBig = check.inclusive ? input.data > check.value : input.data >= check.value;
            if (tooBig) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.too_big,
                maximum: check.value,
                type: "number",
                inclusive: check.inclusive,
                exact: false,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "multipleOf") {
            if (floatSafeRemainder(input.data, check.value) !== 0) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.not_multiple_of,
                multipleOf: check.value,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "finite") {
            if (!Number.isFinite(input.data)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.not_finite,
                message: check.message
              });
              status.dirty();
            }
          } else {
            util.assertNever(check);
          }
        }
        return { status: status.value, value: input.data };
      }
      gte(value, message) {
        return this.setLimit("min", value, true, errorUtil.toString(message));
      }
      gt(value, message) {
        return this.setLimit("min", value, false, errorUtil.toString(message));
      }
      lte(value, message) {
        return this.setLimit("max", value, true, errorUtil.toString(message));
      }
      lt(value, message) {
        return this.setLimit("max", value, false, errorUtil.toString(message));
      }
      setLimit(kind, value, inclusive, message) {
        return new _ZodNumber({
          ...this._def,
          checks: [
            ...this._def.checks,
            {
              kind,
              value,
              inclusive,
              message: errorUtil.toString(message)
            }
          ]
        });
      }
      _addCheck(check) {
        return new _ZodNumber({
          ...this._def,
          checks: [...this._def.checks, check]
        });
      }
      int(message) {
        return this._addCheck({
          kind: "int",
          message: errorUtil.toString(message)
        });
      }
      positive(message) {
        return this._addCheck({
          kind: "min",
          value: 0,
          inclusive: false,
          message: errorUtil.toString(message)
        });
      }
      negative(message) {
        return this._addCheck({
          kind: "max",
          value: 0,
          inclusive: false,
          message: errorUtil.toString(message)
        });
      }
      nonpositive(message) {
        return this._addCheck({
          kind: "max",
          value: 0,
          inclusive: true,
          message: errorUtil.toString(message)
        });
      }
      nonnegative(message) {
        return this._addCheck({
          kind: "min",
          value: 0,
          inclusive: true,
          message: errorUtil.toString(message)
        });
      }
      multipleOf(value, message) {
        return this._addCheck({
          kind: "multipleOf",
          value,
          message: errorUtil.toString(message)
        });
      }
      finite(message) {
        return this._addCheck({
          kind: "finite",
          message: errorUtil.toString(message)
        });
      }
      safe(message) {
        return this._addCheck({
          kind: "min",
          inclusive: true,
          value: Number.MIN_SAFE_INTEGER,
          message: errorUtil.toString(message)
        })._addCheck({
          kind: "max",
          inclusive: true,
          value: Number.MAX_SAFE_INTEGER,
          message: errorUtil.toString(message)
        });
      }
      get minValue() {
        let min = null;
        for (const ch of this._def.checks) {
          if (ch.kind === "min") {
            if (min === null || ch.value > min)
              min = ch.value;
          }
        }
        return min;
      }
      get maxValue() {
        let max = null;
        for (const ch of this._def.checks) {
          if (ch.kind === "max") {
            if (max === null || ch.value < max)
              max = ch.value;
          }
        }
        return max;
      }
      get isInt() {
        return !!this._def.checks.find((ch) => ch.kind === "int" || ch.kind === "multipleOf" && util.isInteger(ch.value));
      }
      get isFinite() {
        let max = null;
        let min = null;
        for (const ch of this._def.checks) {
          if (ch.kind === "finite" || ch.kind === "int" || ch.kind === "multipleOf") {
            return true;
          } else if (ch.kind === "min") {
            if (min === null || ch.value > min)
              min = ch.value;
          } else if (ch.kind === "max") {
            if (max === null || ch.value < max)
              max = ch.value;
          }
        }
        return Number.isFinite(min) && Number.isFinite(max);
      }
    };
    ZodNumber.create = (params) => {
      return new ZodNumber({
        checks: [],
        typeName: ZodFirstPartyTypeKind.ZodNumber,
        coerce: params?.coerce || false,
        ...processCreateParams(params)
      });
    };
    ZodBigInt = class _ZodBigInt extends ZodType {
      constructor() {
        super(...arguments);
        this.min = this.gte;
        this.max = this.lte;
      }
      _parse(input) {
        if (this._def.coerce) {
          try {
            input.data = BigInt(input.data);
          } catch {
            return this._getInvalidInput(input);
          }
        }
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.bigint) {
          return this._getInvalidInput(input);
        }
        let ctx = void 0;
        const status = new ParseStatus();
        for (const check of this._def.checks) {
          if (check.kind === "min") {
            const tooSmall = check.inclusive ? input.data < check.value : input.data <= check.value;
            if (tooSmall) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.too_small,
                type: "bigint",
                minimum: check.value,
                inclusive: check.inclusive,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "max") {
            const tooBig = check.inclusive ? input.data > check.value : input.data >= check.value;
            if (tooBig) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.too_big,
                type: "bigint",
                maximum: check.value,
                inclusive: check.inclusive,
                message: check.message
              });
              status.dirty();
            }
          } else if (check.kind === "multipleOf") {
            if (input.data % check.value !== BigInt(0)) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.not_multiple_of,
                multipleOf: check.value,
                message: check.message
              });
              status.dirty();
            }
          } else {
            util.assertNever(check);
          }
        }
        return { status: status.value, value: input.data };
      }
      _getInvalidInput(input) {
        const ctx = this._getOrReturnCtx(input);
        addIssueToContext(ctx, {
          code: ZodIssueCode.invalid_type,
          expected: ZodParsedType.bigint,
          received: ctx.parsedType
        });
        return INVALID;
      }
      gte(value, message) {
        return this.setLimit("min", value, true, errorUtil.toString(message));
      }
      gt(value, message) {
        return this.setLimit("min", value, false, errorUtil.toString(message));
      }
      lte(value, message) {
        return this.setLimit("max", value, true, errorUtil.toString(message));
      }
      lt(value, message) {
        return this.setLimit("max", value, false, errorUtil.toString(message));
      }
      setLimit(kind, value, inclusive, message) {
        return new _ZodBigInt({
          ...this._def,
          checks: [
            ...this._def.checks,
            {
              kind,
              value,
              inclusive,
              message: errorUtil.toString(message)
            }
          ]
        });
      }
      _addCheck(check) {
        return new _ZodBigInt({
          ...this._def,
          checks: [...this._def.checks, check]
        });
      }
      positive(message) {
        return this._addCheck({
          kind: "min",
          value: BigInt(0),
          inclusive: false,
          message: errorUtil.toString(message)
        });
      }
      negative(message) {
        return this._addCheck({
          kind: "max",
          value: BigInt(0),
          inclusive: false,
          message: errorUtil.toString(message)
        });
      }
      nonpositive(message) {
        return this._addCheck({
          kind: "max",
          value: BigInt(0),
          inclusive: true,
          message: errorUtil.toString(message)
        });
      }
      nonnegative(message) {
        return this._addCheck({
          kind: "min",
          value: BigInt(0),
          inclusive: true,
          message: errorUtil.toString(message)
        });
      }
      multipleOf(value, message) {
        return this._addCheck({
          kind: "multipleOf",
          value,
          message: errorUtil.toString(message)
        });
      }
      get minValue() {
        let min = null;
        for (const ch of this._def.checks) {
          if (ch.kind === "min") {
            if (min === null || ch.value > min)
              min = ch.value;
          }
        }
        return min;
      }
      get maxValue() {
        let max = null;
        for (const ch of this._def.checks) {
          if (ch.kind === "max") {
            if (max === null || ch.value < max)
              max = ch.value;
          }
        }
        return max;
      }
    };
    ZodBigInt.create = (params) => {
      return new ZodBigInt({
        checks: [],
        typeName: ZodFirstPartyTypeKind.ZodBigInt,
        coerce: params?.coerce ?? false,
        ...processCreateParams(params)
      });
    };
    ZodBoolean = class extends ZodType {
      _parse(input) {
        if (this._def.coerce) {
          input.data = Boolean(input.data);
        }
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.boolean) {
          const ctx = this._getOrReturnCtx(input);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.boolean,
            received: ctx.parsedType
          });
          return INVALID;
        }
        return OK(input.data);
      }
    };
    ZodBoolean.create = (params) => {
      return new ZodBoolean({
        typeName: ZodFirstPartyTypeKind.ZodBoolean,
        coerce: params?.coerce || false,
        ...processCreateParams(params)
      });
    };
    ZodDate = class _ZodDate extends ZodType {
      _parse(input) {
        if (this._def.coerce) {
          input.data = new Date(input.data);
        }
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.date) {
          const ctx2 = this._getOrReturnCtx(input);
          addIssueToContext(ctx2, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.date,
            received: ctx2.parsedType
          });
          return INVALID;
        }
        if (Number.isNaN(input.data.getTime())) {
          const ctx2 = this._getOrReturnCtx(input);
          addIssueToContext(ctx2, {
            code: ZodIssueCode.invalid_date
          });
          return INVALID;
        }
        const status = new ParseStatus();
        let ctx = void 0;
        for (const check of this._def.checks) {
          if (check.kind === "min") {
            if (input.data.getTime() < check.value) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.too_small,
                message: check.message,
                inclusive: true,
                exact: false,
                minimum: check.value,
                type: "date"
              });
              status.dirty();
            }
          } else if (check.kind === "max") {
            if (input.data.getTime() > check.value) {
              ctx = this._getOrReturnCtx(input, ctx);
              addIssueToContext(ctx, {
                code: ZodIssueCode.too_big,
                message: check.message,
                inclusive: true,
                exact: false,
                maximum: check.value,
                type: "date"
              });
              status.dirty();
            }
          } else {
            util.assertNever(check);
          }
        }
        return {
          status: status.value,
          value: new Date(input.data.getTime())
        };
      }
      _addCheck(check) {
        return new _ZodDate({
          ...this._def,
          checks: [...this._def.checks, check]
        });
      }
      min(minDate, message) {
        return this._addCheck({
          kind: "min",
          value: minDate.getTime(),
          message: errorUtil.toString(message)
        });
      }
      max(maxDate, message) {
        return this._addCheck({
          kind: "max",
          value: maxDate.getTime(),
          message: errorUtil.toString(message)
        });
      }
      get minDate() {
        let min = null;
        for (const ch of this._def.checks) {
          if (ch.kind === "min") {
            if (min === null || ch.value > min)
              min = ch.value;
          }
        }
        return min != null ? new Date(min) : null;
      }
      get maxDate() {
        let max = null;
        for (const ch of this._def.checks) {
          if (ch.kind === "max") {
            if (max === null || ch.value < max)
              max = ch.value;
          }
        }
        return max != null ? new Date(max) : null;
      }
    };
    ZodDate.create = (params) => {
      return new ZodDate({
        checks: [],
        coerce: params?.coerce || false,
        typeName: ZodFirstPartyTypeKind.ZodDate,
        ...processCreateParams(params)
      });
    };
    ZodSymbol = class extends ZodType {
      _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.symbol) {
          const ctx = this._getOrReturnCtx(input);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.symbol,
            received: ctx.parsedType
          });
          return INVALID;
        }
        return OK(input.data);
      }
    };
    ZodSymbol.create = (params) => {
      return new ZodSymbol({
        typeName: ZodFirstPartyTypeKind.ZodSymbol,
        ...processCreateParams(params)
      });
    };
    ZodUndefined = class extends ZodType {
      _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.undefined) {
          const ctx = this._getOrReturnCtx(input);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.undefined,
            received: ctx.parsedType
          });
          return INVALID;
        }
        return OK(input.data);
      }
    };
    ZodUndefined.create = (params) => {
      return new ZodUndefined({
        typeName: ZodFirstPartyTypeKind.ZodUndefined,
        ...processCreateParams(params)
      });
    };
    ZodNull = class extends ZodType {
      _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.null) {
          const ctx = this._getOrReturnCtx(input);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.null,
            received: ctx.parsedType
          });
          return INVALID;
        }
        return OK(input.data);
      }
    };
    ZodNull.create = (params) => {
      return new ZodNull({
        typeName: ZodFirstPartyTypeKind.ZodNull,
        ...processCreateParams(params)
      });
    };
    ZodAny = class extends ZodType {
      constructor() {
        super(...arguments);
        this._any = true;
      }
      _parse(input) {
        return OK(input.data);
      }
    };
    ZodAny.create = (params) => {
      return new ZodAny({
        typeName: ZodFirstPartyTypeKind.ZodAny,
        ...processCreateParams(params)
      });
    };
    ZodUnknown = class extends ZodType {
      constructor() {
        super(...arguments);
        this._unknown = true;
      }
      _parse(input) {
        return OK(input.data);
      }
    };
    ZodUnknown.create = (params) => {
      return new ZodUnknown({
        typeName: ZodFirstPartyTypeKind.ZodUnknown,
        ...processCreateParams(params)
      });
    };
    ZodNever = class extends ZodType {
      _parse(input) {
        const ctx = this._getOrReturnCtx(input);
        addIssueToContext(ctx, {
          code: ZodIssueCode.invalid_type,
          expected: ZodParsedType.never,
          received: ctx.parsedType
        });
        return INVALID;
      }
    };
    ZodNever.create = (params) => {
      return new ZodNever({
        typeName: ZodFirstPartyTypeKind.ZodNever,
        ...processCreateParams(params)
      });
    };
    ZodVoid = class extends ZodType {
      _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.undefined) {
          const ctx = this._getOrReturnCtx(input);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.void,
            received: ctx.parsedType
          });
          return INVALID;
        }
        return OK(input.data);
      }
    };
    ZodVoid.create = (params) => {
      return new ZodVoid({
        typeName: ZodFirstPartyTypeKind.ZodVoid,
        ...processCreateParams(params)
      });
    };
    ZodArray = class _ZodArray extends ZodType {
      _parse(input) {
        const { ctx, status } = this._processInputParams(input);
        const def = this._def;
        if (ctx.parsedType !== ZodParsedType.array) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.array,
            received: ctx.parsedType
          });
          return INVALID;
        }
        if (def.exactLength !== null) {
          const tooBig = ctx.data.length > def.exactLength.value;
          const tooSmall = ctx.data.length < def.exactLength.value;
          if (tooBig || tooSmall) {
            addIssueToContext(ctx, {
              code: tooBig ? ZodIssueCode.too_big : ZodIssueCode.too_small,
              minimum: tooSmall ? def.exactLength.value : void 0,
              maximum: tooBig ? def.exactLength.value : void 0,
              type: "array",
              inclusive: true,
              exact: true,
              message: def.exactLength.message
            });
            status.dirty();
          }
        }
        if (def.minLength !== null) {
          if (ctx.data.length < def.minLength.value) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_small,
              minimum: def.minLength.value,
              type: "array",
              inclusive: true,
              exact: false,
              message: def.minLength.message
            });
            status.dirty();
          }
        }
        if (def.maxLength !== null) {
          if (ctx.data.length > def.maxLength.value) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_big,
              maximum: def.maxLength.value,
              type: "array",
              inclusive: true,
              exact: false,
              message: def.maxLength.message
            });
            status.dirty();
          }
        }
        if (ctx.common.async) {
          return Promise.all([...ctx.data].map((item, i) => {
            return def.type._parseAsync(new ParseInputLazyPath(ctx, item, ctx.path, i));
          })).then((result2) => {
            return ParseStatus.mergeArray(status, result2);
          });
        }
        const result = [...ctx.data].map((item, i) => {
          return def.type._parseSync(new ParseInputLazyPath(ctx, item, ctx.path, i));
        });
        return ParseStatus.mergeArray(status, result);
      }
      get element() {
        return this._def.type;
      }
      min(minLength, message) {
        return new _ZodArray({
          ...this._def,
          minLength: { value: minLength, message: errorUtil.toString(message) }
        });
      }
      max(maxLength, message) {
        return new _ZodArray({
          ...this._def,
          maxLength: { value: maxLength, message: errorUtil.toString(message) }
        });
      }
      length(len, message) {
        return new _ZodArray({
          ...this._def,
          exactLength: { value: len, message: errorUtil.toString(message) }
        });
      }
      nonempty(message) {
        return this.min(1, message);
      }
    };
    ZodArray.create = (schema, params) => {
      return new ZodArray({
        type: schema,
        minLength: null,
        maxLength: null,
        exactLength: null,
        typeName: ZodFirstPartyTypeKind.ZodArray,
        ...processCreateParams(params)
      });
    };
    ZodObject = class _ZodObject extends ZodType {
      constructor() {
        super(...arguments);
        this._cached = null;
        this.nonstrict = this.passthrough;
        this.augment = this.extend;
      }
      _getCached() {
        if (this._cached !== null)
          return this._cached;
        const shape = this._def.shape();
        const keys = util.objectKeys(shape);
        this._cached = { shape, keys };
        return this._cached;
      }
      _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.object) {
          const ctx2 = this._getOrReturnCtx(input);
          addIssueToContext(ctx2, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.object,
            received: ctx2.parsedType
          });
          return INVALID;
        }
        const { status, ctx } = this._processInputParams(input);
        const { shape, keys: shapeKeys } = this._getCached();
        const extraKeys = [];
        if (!(this._def.catchall instanceof ZodNever && this._def.unknownKeys === "strip")) {
          for (const key in ctx.data) {
            if (!shapeKeys.includes(key)) {
              extraKeys.push(key);
            }
          }
        }
        const pairs = [];
        for (const key of shapeKeys) {
          const keyValidator = shape[key];
          const value = ctx.data[key];
          pairs.push({
            key: { status: "valid", value: key },
            value: keyValidator._parse(new ParseInputLazyPath(ctx, value, ctx.path, key)),
            alwaysSet: key in ctx.data
          });
        }
        if (this._def.catchall instanceof ZodNever) {
          const unknownKeys = this._def.unknownKeys;
          if (unknownKeys === "passthrough") {
            for (const key of extraKeys) {
              pairs.push({
                key: { status: "valid", value: key },
                value: { status: "valid", value: ctx.data[key] }
              });
            }
          } else if (unknownKeys === "strict") {
            if (extraKeys.length > 0) {
              addIssueToContext(ctx, {
                code: ZodIssueCode.unrecognized_keys,
                keys: extraKeys
              });
              status.dirty();
            }
          } else if (unknownKeys === "strip") {
          } else {
            throw new Error(`Internal ZodObject error: invalid unknownKeys value.`);
          }
        } else {
          const catchall = this._def.catchall;
          for (const key of extraKeys) {
            const value = ctx.data[key];
            pairs.push({
              key: { status: "valid", value: key },
              value: catchall._parse(
                new ParseInputLazyPath(ctx, value, ctx.path, key)
                //, ctx.child(key), value, getParsedType(value)
              ),
              alwaysSet: key in ctx.data
            });
          }
        }
        if (ctx.common.async) {
          return Promise.resolve().then(async () => {
            const syncPairs = [];
            for (const pair of pairs) {
              const key = await pair.key;
              const value = await pair.value;
              syncPairs.push({
                key,
                value,
                alwaysSet: pair.alwaysSet
              });
            }
            return syncPairs;
          }).then((syncPairs) => {
            return ParseStatus.mergeObjectSync(status, syncPairs);
          });
        } else {
          return ParseStatus.mergeObjectSync(status, pairs);
        }
      }
      get shape() {
        return this._def.shape();
      }
      strict(message) {
        errorUtil.errToObj;
        return new _ZodObject({
          ...this._def,
          unknownKeys: "strict",
          ...message !== void 0 ? {
            errorMap: (issue, ctx) => {
              const defaultError = this._def.errorMap?.(issue, ctx).message ?? ctx.defaultError;
              if (issue.code === "unrecognized_keys")
                return {
                  message: errorUtil.errToObj(message).message ?? defaultError
                };
              return {
                message: defaultError
              };
            }
          } : {}
        });
      }
      strip() {
        return new _ZodObject({
          ...this._def,
          unknownKeys: "strip"
        });
      }
      passthrough() {
        return new _ZodObject({
          ...this._def,
          unknownKeys: "passthrough"
        });
      }
      // const AugmentFactory =
      //   <Def extends ZodObjectDef>(def: Def) =>
      //   <Augmentation extends ZodRawShape>(
      //     augmentation: Augmentation
      //   ): ZodObject<
      //     extendShape<ReturnType<Def["shape"]>, Augmentation>,
      //     Def["unknownKeys"],
      //     Def["catchall"]
      //   > => {
      //     return new ZodObject({
      //       ...def,
      //       shape: () => ({
      //         ...def.shape(),
      //         ...augmentation,
      //       }),
      //     }) as any;
      //   };
      extend(augmentation) {
        return new _ZodObject({
          ...this._def,
          shape: () => ({
            ...this._def.shape(),
            ...augmentation
          })
        });
      }
      /**
       * Prior to zod@1.0.12 there was a bug in the
       * inferred type of merged objects. Please
       * upgrade if you are experiencing issues.
       */
      merge(merging) {
        const merged = new _ZodObject({
          unknownKeys: merging._def.unknownKeys,
          catchall: merging._def.catchall,
          shape: () => ({
            ...this._def.shape(),
            ...merging._def.shape()
          }),
          typeName: ZodFirstPartyTypeKind.ZodObject
        });
        return merged;
      }
      // merge<
      //   Incoming extends AnyZodObject,
      //   Augmentation extends Incoming["shape"],
      //   NewOutput extends {
      //     [k in keyof Augmentation | keyof Output]: k extends keyof Augmentation
      //       ? Augmentation[k]["_output"]
      //       : k extends keyof Output
      //       ? Output[k]
      //       : never;
      //   },
      //   NewInput extends {
      //     [k in keyof Augmentation | keyof Input]: k extends keyof Augmentation
      //       ? Augmentation[k]["_input"]
      //       : k extends keyof Input
      //       ? Input[k]
      //       : never;
      //   }
      // >(
      //   merging: Incoming
      // ): ZodObject<
      //   extendShape<T, ReturnType<Incoming["_def"]["shape"]>>,
      //   Incoming["_def"]["unknownKeys"],
      //   Incoming["_def"]["catchall"],
      //   NewOutput,
      //   NewInput
      // > {
      //   const merged: any = new ZodObject({
      //     unknownKeys: merging._def.unknownKeys,
      //     catchall: merging._def.catchall,
      //     shape: () =>
      //       objectUtil.mergeShapes(this._def.shape(), merging._def.shape()),
      //     typeName: ZodFirstPartyTypeKind.ZodObject,
      //   }) as any;
      //   return merged;
      // }
      setKey(key, schema) {
        return this.augment({ [key]: schema });
      }
      // merge<Incoming extends AnyZodObject>(
      //   merging: Incoming
      // ): //ZodObject<T & Incoming["_shape"], UnknownKeys, Catchall> = (merging) => {
      // ZodObject<
      //   extendShape<T, ReturnType<Incoming["_def"]["shape"]>>,
      //   Incoming["_def"]["unknownKeys"],
      //   Incoming["_def"]["catchall"]
      // > {
      //   // const mergedShape = objectUtil.mergeShapes(
      //   //   this._def.shape(),
      //   //   merging._def.shape()
      //   // );
      //   const merged: any = new ZodObject({
      //     unknownKeys: merging._def.unknownKeys,
      //     catchall: merging._def.catchall,
      //     shape: () =>
      //       objectUtil.mergeShapes(this._def.shape(), merging._def.shape()),
      //     typeName: ZodFirstPartyTypeKind.ZodObject,
      //   }) as any;
      //   return merged;
      // }
      catchall(index) {
        return new _ZodObject({
          ...this._def,
          catchall: index
        });
      }
      pick(mask) {
        const shape = {};
        for (const key of util.objectKeys(mask)) {
          if (mask[key] && this.shape[key]) {
            shape[key] = this.shape[key];
          }
        }
        return new _ZodObject({
          ...this._def,
          shape: () => shape
        });
      }
      omit(mask) {
        const shape = {};
        for (const key of util.objectKeys(this.shape)) {
          if (!mask[key]) {
            shape[key] = this.shape[key];
          }
        }
        return new _ZodObject({
          ...this._def,
          shape: () => shape
        });
      }
      /**
       * @deprecated
       */
      deepPartial() {
        return deepPartialify(this);
      }
      partial(mask) {
        const newShape = {};
        for (const key of util.objectKeys(this.shape)) {
          const fieldSchema = this.shape[key];
          if (mask && !mask[key]) {
            newShape[key] = fieldSchema;
          } else {
            newShape[key] = fieldSchema.optional();
          }
        }
        return new _ZodObject({
          ...this._def,
          shape: () => newShape
        });
      }
      required(mask) {
        const newShape = {};
        for (const key of util.objectKeys(this.shape)) {
          if (mask && !mask[key]) {
            newShape[key] = this.shape[key];
          } else {
            const fieldSchema = this.shape[key];
            let newField = fieldSchema;
            while (newField instanceof ZodOptional) {
              newField = newField._def.innerType;
            }
            newShape[key] = newField;
          }
        }
        return new _ZodObject({
          ...this._def,
          shape: () => newShape
        });
      }
      keyof() {
        return createZodEnum(util.objectKeys(this.shape));
      }
    };
    ZodObject.create = (shape, params) => {
      return new ZodObject({
        shape: () => shape,
        unknownKeys: "strip",
        catchall: ZodNever.create(),
        typeName: ZodFirstPartyTypeKind.ZodObject,
        ...processCreateParams(params)
      });
    };
    ZodObject.strictCreate = (shape, params) => {
      return new ZodObject({
        shape: () => shape,
        unknownKeys: "strict",
        catchall: ZodNever.create(),
        typeName: ZodFirstPartyTypeKind.ZodObject,
        ...processCreateParams(params)
      });
    };
    ZodObject.lazycreate = (shape, params) => {
      return new ZodObject({
        shape,
        unknownKeys: "strip",
        catchall: ZodNever.create(),
        typeName: ZodFirstPartyTypeKind.ZodObject,
        ...processCreateParams(params)
      });
    };
    ZodUnion = class extends ZodType {
      _parse(input) {
        const { ctx } = this._processInputParams(input);
        const options = this._def.options;
        function handleResults(results) {
          for (const result of results) {
            if (result.result.status === "valid") {
              return result.result;
            }
          }
          for (const result of results) {
            if (result.result.status === "dirty") {
              ctx.common.issues.push(...result.ctx.common.issues);
              return result.result;
            }
          }
          const unionErrors = results.map((result) => new ZodError(result.ctx.common.issues));
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_union,
            unionErrors
          });
          return INVALID;
        }
        if (ctx.common.async) {
          return Promise.all(options.map(async (option) => {
            const childCtx = {
              ...ctx,
              common: {
                ...ctx.common,
                issues: []
              },
              parent: null
            };
            return {
              result: await option._parseAsync({
                data: ctx.data,
                path: ctx.path,
                parent: childCtx
              }),
              ctx: childCtx
            };
          })).then(handleResults);
        } else {
          let dirty = void 0;
          const issues = [];
          for (const option of options) {
            const childCtx = {
              ...ctx,
              common: {
                ...ctx.common,
                issues: []
              },
              parent: null
            };
            const result = option._parseSync({
              data: ctx.data,
              path: ctx.path,
              parent: childCtx
            });
            if (result.status === "valid") {
              return result;
            } else if (result.status === "dirty" && !dirty) {
              dirty = { result, ctx: childCtx };
            }
            if (childCtx.common.issues.length) {
              issues.push(childCtx.common.issues);
            }
          }
          if (dirty) {
            ctx.common.issues.push(...dirty.ctx.common.issues);
            return dirty.result;
          }
          const unionErrors = issues.map((issues2) => new ZodError(issues2));
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_union,
            unionErrors
          });
          return INVALID;
        }
      }
      get options() {
        return this._def.options;
      }
    };
    ZodUnion.create = (types, params) => {
      return new ZodUnion({
        options: types,
        typeName: ZodFirstPartyTypeKind.ZodUnion,
        ...processCreateParams(params)
      });
    };
    getDiscriminator = (type) => {
      if (type instanceof ZodLazy) {
        return getDiscriminator(type.schema);
      } else if (type instanceof ZodEffects) {
        return getDiscriminator(type.innerType());
      } else if (type instanceof ZodLiteral) {
        return [type.value];
      } else if (type instanceof ZodEnum) {
        return type.options;
      } else if (type instanceof ZodNativeEnum) {
        return util.objectValues(type.enum);
      } else if (type instanceof ZodDefault) {
        return getDiscriminator(type._def.innerType);
      } else if (type instanceof ZodUndefined) {
        return [void 0];
      } else if (type instanceof ZodNull) {
        return [null];
      } else if (type instanceof ZodOptional) {
        return [void 0, ...getDiscriminator(type.unwrap())];
      } else if (type instanceof ZodNullable) {
        return [null, ...getDiscriminator(type.unwrap())];
      } else if (type instanceof ZodBranded) {
        return getDiscriminator(type.unwrap());
      } else if (type instanceof ZodReadonly) {
        return getDiscriminator(type.unwrap());
      } else if (type instanceof ZodCatch) {
        return getDiscriminator(type._def.innerType);
      } else {
        return [];
      }
    };
    ZodDiscriminatedUnion = class _ZodDiscriminatedUnion extends ZodType {
      _parse(input) {
        const { ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.object) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.object,
            received: ctx.parsedType
          });
          return INVALID;
        }
        const discriminator = this.discriminator;
        const discriminatorValue = ctx.data[discriminator];
        const option = this.optionsMap.get(discriminatorValue);
        if (!option) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_union_discriminator,
            options: Array.from(this.optionsMap.keys()),
            path: [discriminator]
          });
          return INVALID;
        }
        if (ctx.common.async) {
          return option._parseAsync({
            data: ctx.data,
            path: ctx.path,
            parent: ctx
          });
        } else {
          return option._parseSync({
            data: ctx.data,
            path: ctx.path,
            parent: ctx
          });
        }
      }
      get discriminator() {
        return this._def.discriminator;
      }
      get options() {
        return this._def.options;
      }
      get optionsMap() {
        return this._def.optionsMap;
      }
      /**
       * The constructor of the discriminated union schema. Its behaviour is very similar to that of the normal z.union() constructor.
       * However, it only allows a union of objects, all of which need to share a discriminator property. This property must
       * have a different value for each object in the union.
       * @param discriminator the name of the discriminator property
       * @param types an array of object schemas
       * @param params
       */
      static create(discriminator, options, params) {
        const optionsMap = /* @__PURE__ */ new Map();
        for (const type of options) {
          const discriminatorValues = getDiscriminator(type.shape[discriminator]);
          if (!discriminatorValues.length) {
            throw new Error(`A discriminator value for key \`${discriminator}\` could not be extracted from all schema options`);
          }
          for (const value of discriminatorValues) {
            if (optionsMap.has(value)) {
              throw new Error(`Discriminator property ${String(discriminator)} has duplicate value ${String(value)}`);
            }
            optionsMap.set(value, type);
          }
        }
        return new _ZodDiscriminatedUnion({
          typeName: ZodFirstPartyTypeKind.ZodDiscriminatedUnion,
          discriminator,
          options,
          optionsMap,
          ...processCreateParams(params)
        });
      }
    };
    ZodIntersection = class extends ZodType {
      _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        const handleParsed = (parsedLeft, parsedRight) => {
          if (isAborted(parsedLeft) || isAborted(parsedRight)) {
            return INVALID;
          }
          const merged = mergeValues(parsedLeft.value, parsedRight.value);
          if (!merged.valid) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.invalid_intersection_types
            });
            return INVALID;
          }
          if (isDirty(parsedLeft) || isDirty(parsedRight)) {
            status.dirty();
          }
          return { status: status.value, value: merged.data };
        };
        if (ctx.common.async) {
          return Promise.all([
            this._def.left._parseAsync({
              data: ctx.data,
              path: ctx.path,
              parent: ctx
            }),
            this._def.right._parseAsync({
              data: ctx.data,
              path: ctx.path,
              parent: ctx
            })
          ]).then(([left, right]) => handleParsed(left, right));
        } else {
          return handleParsed(this._def.left._parseSync({
            data: ctx.data,
            path: ctx.path,
            parent: ctx
          }), this._def.right._parseSync({
            data: ctx.data,
            path: ctx.path,
            parent: ctx
          }));
        }
      }
    };
    ZodIntersection.create = (left, right, params) => {
      return new ZodIntersection({
        left,
        right,
        typeName: ZodFirstPartyTypeKind.ZodIntersection,
        ...processCreateParams(params)
      });
    };
    ZodTuple = class _ZodTuple extends ZodType {
      _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.array) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.array,
            received: ctx.parsedType
          });
          return INVALID;
        }
        if (ctx.data.length < this._def.items.length) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            minimum: this._def.items.length,
            inclusive: true,
            exact: false,
            type: "array"
          });
          return INVALID;
        }
        const rest = this._def.rest;
        if (!rest && ctx.data.length > this._def.items.length) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            maximum: this._def.items.length,
            inclusive: true,
            exact: false,
            type: "array"
          });
          status.dirty();
        }
        const items = [...ctx.data].map((item, itemIndex) => {
          const schema = this._def.items[itemIndex] || this._def.rest;
          if (!schema)
            return null;
          return schema._parse(new ParseInputLazyPath(ctx, item, ctx.path, itemIndex));
        }).filter((x) => !!x);
        if (ctx.common.async) {
          return Promise.all(items).then((results) => {
            return ParseStatus.mergeArray(status, results);
          });
        } else {
          return ParseStatus.mergeArray(status, items);
        }
      }
      get items() {
        return this._def.items;
      }
      rest(rest) {
        return new _ZodTuple({
          ...this._def,
          rest
        });
      }
    };
    ZodTuple.create = (schemas, params) => {
      if (!Array.isArray(schemas)) {
        throw new Error("You must pass an array of schemas to z.tuple([ ... ])");
      }
      return new ZodTuple({
        items: schemas,
        typeName: ZodFirstPartyTypeKind.ZodTuple,
        rest: null,
        ...processCreateParams(params)
      });
    };
    ZodRecord = class _ZodRecord extends ZodType {
      get keySchema() {
        return this._def.keyType;
      }
      get valueSchema() {
        return this._def.valueType;
      }
      _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.object) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.object,
            received: ctx.parsedType
          });
          return INVALID;
        }
        const pairs = [];
        const keyType = this._def.keyType;
        const valueType = this._def.valueType;
        for (const key in ctx.data) {
          pairs.push({
            key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, key)),
            value: valueType._parse(new ParseInputLazyPath(ctx, ctx.data[key], ctx.path, key)),
            alwaysSet: key in ctx.data
          });
        }
        if (ctx.common.async) {
          return ParseStatus.mergeObjectAsync(status, pairs);
        } else {
          return ParseStatus.mergeObjectSync(status, pairs);
        }
      }
      get element() {
        return this._def.valueType;
      }
      static create(first, second, third) {
        if (second instanceof ZodType) {
          return new _ZodRecord({
            keyType: first,
            valueType: second,
            typeName: ZodFirstPartyTypeKind.ZodRecord,
            ...processCreateParams(third)
          });
        }
        return new _ZodRecord({
          keyType: ZodString.create(),
          valueType: first,
          typeName: ZodFirstPartyTypeKind.ZodRecord,
          ...processCreateParams(second)
        });
      }
    };
    ZodMap = class extends ZodType {
      get keySchema() {
        return this._def.keyType;
      }
      get valueSchema() {
        return this._def.valueType;
      }
      _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.map) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.map,
            received: ctx.parsedType
          });
          return INVALID;
        }
        const keyType = this._def.keyType;
        const valueType = this._def.valueType;
        const pairs = [...ctx.data.entries()].map(([key, value], index) => {
          return {
            key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, [index, "key"])),
            value: valueType._parse(new ParseInputLazyPath(ctx, value, ctx.path, [index, "value"]))
          };
        });
        if (ctx.common.async) {
          const finalMap = /* @__PURE__ */ new Map();
          return Promise.resolve().then(async () => {
            for (const pair of pairs) {
              const key = await pair.key;
              const value = await pair.value;
              if (key.status === "aborted" || value.status === "aborted") {
                return INVALID;
              }
              if (key.status === "dirty" || value.status === "dirty") {
                status.dirty();
              }
              finalMap.set(key.value, value.value);
            }
            return { status: status.value, value: finalMap };
          });
        } else {
          const finalMap = /* @__PURE__ */ new Map();
          for (const pair of pairs) {
            const key = pair.key;
            const value = pair.value;
            if (key.status === "aborted" || value.status === "aborted") {
              return INVALID;
            }
            if (key.status === "dirty" || value.status === "dirty") {
              status.dirty();
            }
            finalMap.set(key.value, value.value);
          }
          return { status: status.value, value: finalMap };
        }
      }
    };
    ZodMap.create = (keyType, valueType, params) => {
      return new ZodMap({
        valueType,
        keyType,
        typeName: ZodFirstPartyTypeKind.ZodMap,
        ...processCreateParams(params)
      });
    };
    ZodSet = class _ZodSet extends ZodType {
      _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.set) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.set,
            received: ctx.parsedType
          });
          return INVALID;
        }
        const def = this._def;
        if (def.minSize !== null) {
          if (ctx.data.size < def.minSize.value) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_small,
              minimum: def.minSize.value,
              type: "set",
              inclusive: true,
              exact: false,
              message: def.minSize.message
            });
            status.dirty();
          }
        }
        if (def.maxSize !== null) {
          if (ctx.data.size > def.maxSize.value) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_big,
              maximum: def.maxSize.value,
              type: "set",
              inclusive: true,
              exact: false,
              message: def.maxSize.message
            });
            status.dirty();
          }
        }
        const valueType = this._def.valueType;
        function finalizeSet(elements2) {
          const parsedSet = /* @__PURE__ */ new Set();
          for (const element of elements2) {
            if (element.status === "aborted")
              return INVALID;
            if (element.status === "dirty")
              status.dirty();
            parsedSet.add(element.value);
          }
          return { status: status.value, value: parsedSet };
        }
        const elements = [...ctx.data.values()].map((item, i) => valueType._parse(new ParseInputLazyPath(ctx, item, ctx.path, i)));
        if (ctx.common.async) {
          return Promise.all(elements).then((elements2) => finalizeSet(elements2));
        } else {
          return finalizeSet(elements);
        }
      }
      min(minSize, message) {
        return new _ZodSet({
          ...this._def,
          minSize: { value: minSize, message: errorUtil.toString(message) }
        });
      }
      max(maxSize, message) {
        return new _ZodSet({
          ...this._def,
          maxSize: { value: maxSize, message: errorUtil.toString(message) }
        });
      }
      size(size, message) {
        return this.min(size, message).max(size, message);
      }
      nonempty(message) {
        return this.min(1, message);
      }
    };
    ZodSet.create = (valueType, params) => {
      return new ZodSet({
        valueType,
        minSize: null,
        maxSize: null,
        typeName: ZodFirstPartyTypeKind.ZodSet,
        ...processCreateParams(params)
      });
    };
    ZodFunction = class _ZodFunction extends ZodType {
      constructor() {
        super(...arguments);
        this.validate = this.implement;
      }
      _parse(input) {
        const { ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.function) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.function,
            received: ctx.parsedType
          });
          return INVALID;
        }
        function makeArgsIssue(args, error) {
          return makeIssue({
            data: args,
            path: ctx.path,
            errorMaps: [ctx.common.contextualErrorMap, ctx.schemaErrorMap, getErrorMap(), en_default].filter((x) => !!x),
            issueData: {
              code: ZodIssueCode.invalid_arguments,
              argumentsError: error
            }
          });
        }
        function makeReturnsIssue(returns, error) {
          return makeIssue({
            data: returns,
            path: ctx.path,
            errorMaps: [ctx.common.contextualErrorMap, ctx.schemaErrorMap, getErrorMap(), en_default].filter((x) => !!x),
            issueData: {
              code: ZodIssueCode.invalid_return_type,
              returnTypeError: error
            }
          });
        }
        const params = { errorMap: ctx.common.contextualErrorMap };
        const fn = ctx.data;
        if (this._def.returns instanceof ZodPromise) {
          const me = this;
          return OK(async function(...args) {
            const error = new ZodError([]);
            const parsedArgs = await me._def.args.parseAsync(args, params).catch((e) => {
              error.addIssue(makeArgsIssue(args, e));
              throw error;
            });
            const result = await Reflect.apply(fn, this, parsedArgs);
            const parsedReturns = await me._def.returns._def.type.parseAsync(result, params).catch((e) => {
              error.addIssue(makeReturnsIssue(result, e));
              throw error;
            });
            return parsedReturns;
          });
        } else {
          const me = this;
          return OK(function(...args) {
            const parsedArgs = me._def.args.safeParse(args, params);
            if (!parsedArgs.success) {
              throw new ZodError([makeArgsIssue(args, parsedArgs.error)]);
            }
            const result = Reflect.apply(fn, this, parsedArgs.data);
            const parsedReturns = me._def.returns.safeParse(result, params);
            if (!parsedReturns.success) {
              throw new ZodError([makeReturnsIssue(result, parsedReturns.error)]);
            }
            return parsedReturns.data;
          });
        }
      }
      parameters() {
        return this._def.args;
      }
      returnType() {
        return this._def.returns;
      }
      args(...items) {
        return new _ZodFunction({
          ...this._def,
          args: ZodTuple.create(items).rest(ZodUnknown.create())
        });
      }
      returns(returnType) {
        return new _ZodFunction({
          ...this._def,
          returns: returnType
        });
      }
      implement(func) {
        const validatedFunc = this.parse(func);
        return validatedFunc;
      }
      strictImplement(func) {
        const validatedFunc = this.parse(func);
        return validatedFunc;
      }
      static create(args, returns, params) {
        return new _ZodFunction({
          args: args ? args : ZodTuple.create([]).rest(ZodUnknown.create()),
          returns: returns || ZodUnknown.create(),
          typeName: ZodFirstPartyTypeKind.ZodFunction,
          ...processCreateParams(params)
        });
      }
    };
    ZodLazy = class extends ZodType {
      get schema() {
        return this._def.getter();
      }
      _parse(input) {
        const { ctx } = this._processInputParams(input);
        const lazySchema = this._def.getter();
        return lazySchema._parse({ data: ctx.data, path: ctx.path, parent: ctx });
      }
    };
    ZodLazy.create = (getter, params) => {
      return new ZodLazy({
        getter,
        typeName: ZodFirstPartyTypeKind.ZodLazy,
        ...processCreateParams(params)
      });
    };
    ZodLiteral = class extends ZodType {
      _parse(input) {
        if (input.data !== this._def.value) {
          const ctx = this._getOrReturnCtx(input);
          addIssueToContext(ctx, {
            received: ctx.data,
            code: ZodIssueCode.invalid_literal,
            expected: this._def.value
          });
          return INVALID;
        }
        return { status: "valid", value: input.data };
      }
      get value() {
        return this._def.value;
      }
    };
    ZodLiteral.create = (value, params) => {
      return new ZodLiteral({
        value,
        typeName: ZodFirstPartyTypeKind.ZodLiteral,
        ...processCreateParams(params)
      });
    };
    ZodEnum = class _ZodEnum extends ZodType {
      _parse(input) {
        if (typeof input.data !== "string") {
          const ctx = this._getOrReturnCtx(input);
          const expectedValues = this._def.values;
          addIssueToContext(ctx, {
            expected: util.joinValues(expectedValues),
            received: ctx.parsedType,
            code: ZodIssueCode.invalid_type
          });
          return INVALID;
        }
        if (!this._cache) {
          this._cache = new Set(this._def.values);
        }
        if (!this._cache.has(input.data)) {
          const ctx = this._getOrReturnCtx(input);
          const expectedValues = this._def.values;
          addIssueToContext(ctx, {
            received: ctx.data,
            code: ZodIssueCode.invalid_enum_value,
            options: expectedValues
          });
          return INVALID;
        }
        return OK(input.data);
      }
      get options() {
        return this._def.values;
      }
      get enum() {
        const enumValues = {};
        for (const val of this._def.values) {
          enumValues[val] = val;
        }
        return enumValues;
      }
      get Values() {
        const enumValues = {};
        for (const val of this._def.values) {
          enumValues[val] = val;
        }
        return enumValues;
      }
      get Enum() {
        const enumValues = {};
        for (const val of this._def.values) {
          enumValues[val] = val;
        }
        return enumValues;
      }
      extract(values, newDef = this._def) {
        return _ZodEnum.create(values, {
          ...this._def,
          ...newDef
        });
      }
      exclude(values, newDef = this._def) {
        return _ZodEnum.create(this.options.filter((opt) => !values.includes(opt)), {
          ...this._def,
          ...newDef
        });
      }
    };
    ZodEnum.create = createZodEnum;
    ZodNativeEnum = class extends ZodType {
      _parse(input) {
        const nativeEnumValues = util.getValidEnumValues(this._def.values);
        const ctx = this._getOrReturnCtx(input);
        if (ctx.parsedType !== ZodParsedType.string && ctx.parsedType !== ZodParsedType.number) {
          const expectedValues = util.objectValues(nativeEnumValues);
          addIssueToContext(ctx, {
            expected: util.joinValues(expectedValues),
            received: ctx.parsedType,
            code: ZodIssueCode.invalid_type
          });
          return INVALID;
        }
        if (!this._cache) {
          this._cache = new Set(util.getValidEnumValues(this._def.values));
        }
        if (!this._cache.has(input.data)) {
          const expectedValues = util.objectValues(nativeEnumValues);
          addIssueToContext(ctx, {
            received: ctx.data,
            code: ZodIssueCode.invalid_enum_value,
            options: expectedValues
          });
          return INVALID;
        }
        return OK(input.data);
      }
      get enum() {
        return this._def.values;
      }
    };
    ZodNativeEnum.create = (values, params) => {
      return new ZodNativeEnum({
        values,
        typeName: ZodFirstPartyTypeKind.ZodNativeEnum,
        ...processCreateParams(params)
      });
    };
    ZodPromise = class extends ZodType {
      unwrap() {
        return this._def.type;
      }
      _parse(input) {
        const { ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.promise && ctx.common.async === false) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.promise,
            received: ctx.parsedType
          });
          return INVALID;
        }
        const promisified = ctx.parsedType === ZodParsedType.promise ? ctx.data : Promise.resolve(ctx.data);
        return OK(promisified.then((data) => {
          return this._def.type.parseAsync(data, {
            path: ctx.path,
            errorMap: ctx.common.contextualErrorMap
          });
        }));
      }
    };
    ZodPromise.create = (schema, params) => {
      return new ZodPromise({
        type: schema,
        typeName: ZodFirstPartyTypeKind.ZodPromise,
        ...processCreateParams(params)
      });
    };
    ZodEffects = class extends ZodType {
      innerType() {
        return this._def.schema;
      }
      sourceType() {
        return this._def.schema._def.typeName === ZodFirstPartyTypeKind.ZodEffects ? this._def.schema.sourceType() : this._def.schema;
      }
      _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        const effect = this._def.effect || null;
        const checkCtx = {
          addIssue: (arg) => {
            addIssueToContext(ctx, arg);
            if (arg.fatal) {
              status.abort();
            } else {
              status.dirty();
            }
          },
          get path() {
            return ctx.path;
          }
        };
        checkCtx.addIssue = checkCtx.addIssue.bind(checkCtx);
        if (effect.type === "preprocess") {
          const processed = effect.transform(ctx.data, checkCtx);
          if (ctx.common.async) {
            return Promise.resolve(processed).then(async (processed2) => {
              if (status.value === "aborted")
                return INVALID;
              const result = await this._def.schema._parseAsync({
                data: processed2,
                path: ctx.path,
                parent: ctx
              });
              if (result.status === "aborted")
                return INVALID;
              if (result.status === "dirty")
                return DIRTY(result.value);
              if (status.value === "dirty")
                return DIRTY(result.value);
              return result;
            });
          } else {
            if (status.value === "aborted")
              return INVALID;
            const result = this._def.schema._parseSync({
              data: processed,
              path: ctx.path,
              parent: ctx
            });
            if (result.status === "aborted")
              return INVALID;
            if (result.status === "dirty")
              return DIRTY(result.value);
            if (status.value === "dirty")
              return DIRTY(result.value);
            return result;
          }
        }
        if (effect.type === "refinement") {
          const executeRefinement = (acc) => {
            const result = effect.refinement(acc, checkCtx);
            if (ctx.common.async) {
              return Promise.resolve(result);
            }
            if (result instanceof Promise) {
              throw new Error("Async refinement encountered during synchronous parse operation. Use .parseAsync instead.");
            }
            return acc;
          };
          if (ctx.common.async === false) {
            const inner = this._def.schema._parseSync({
              data: ctx.data,
              path: ctx.path,
              parent: ctx
            });
            if (inner.status === "aborted")
              return INVALID;
            if (inner.status === "dirty")
              status.dirty();
            executeRefinement(inner.value);
            return { status: status.value, value: inner.value };
          } else {
            return this._def.schema._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx }).then((inner) => {
              if (inner.status === "aborted")
                return INVALID;
              if (inner.status === "dirty")
                status.dirty();
              return executeRefinement(inner.value).then(() => {
                return { status: status.value, value: inner.value };
              });
            });
          }
        }
        if (effect.type === "transform") {
          if (ctx.common.async === false) {
            const base = this._def.schema._parseSync({
              data: ctx.data,
              path: ctx.path,
              parent: ctx
            });
            if (!isValid(base))
              return INVALID;
            const result = effect.transform(base.value, checkCtx);
            if (result instanceof Promise) {
              throw new Error(`Asynchronous transform encountered during synchronous parse operation. Use .parseAsync instead.`);
            }
            return { status: status.value, value: result };
          } else {
            return this._def.schema._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx }).then((base) => {
              if (!isValid(base))
                return INVALID;
              return Promise.resolve(effect.transform(base.value, checkCtx)).then((result) => ({
                status: status.value,
                value: result
              }));
            });
          }
        }
        util.assertNever(effect);
      }
    };
    ZodEffects.create = (schema, effect, params) => {
      return new ZodEffects({
        schema,
        typeName: ZodFirstPartyTypeKind.ZodEffects,
        effect,
        ...processCreateParams(params)
      });
    };
    ZodEffects.createWithPreprocess = (preprocess, schema, params) => {
      return new ZodEffects({
        schema,
        effect: { type: "preprocess", transform: preprocess },
        typeName: ZodFirstPartyTypeKind.ZodEffects,
        ...processCreateParams(params)
      });
    };
    ZodOptional = class extends ZodType {
      _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType === ZodParsedType.undefined) {
          return OK(void 0);
        }
        return this._def.innerType._parse(input);
      }
      unwrap() {
        return this._def.innerType;
      }
    };
    ZodOptional.create = (type, params) => {
      return new ZodOptional({
        innerType: type,
        typeName: ZodFirstPartyTypeKind.ZodOptional,
        ...processCreateParams(params)
      });
    };
    ZodNullable = class extends ZodType {
      _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType === ZodParsedType.null) {
          return OK(null);
        }
        return this._def.innerType._parse(input);
      }
      unwrap() {
        return this._def.innerType;
      }
    };
    ZodNullable.create = (type, params) => {
      return new ZodNullable({
        innerType: type,
        typeName: ZodFirstPartyTypeKind.ZodNullable,
        ...processCreateParams(params)
      });
    };
    ZodDefault = class extends ZodType {
      _parse(input) {
        const { ctx } = this._processInputParams(input);
        let data = ctx.data;
        if (ctx.parsedType === ZodParsedType.undefined) {
          data = this._def.defaultValue();
        }
        return this._def.innerType._parse({
          data,
          path: ctx.path,
          parent: ctx
        });
      }
      removeDefault() {
        return this._def.innerType;
      }
    };
    ZodDefault.create = (type, params) => {
      return new ZodDefault({
        innerType: type,
        typeName: ZodFirstPartyTypeKind.ZodDefault,
        defaultValue: typeof params.default === "function" ? params.default : () => params.default,
        ...processCreateParams(params)
      });
    };
    ZodCatch = class extends ZodType {
      _parse(input) {
        const { ctx } = this._processInputParams(input);
        const newCtx = {
          ...ctx,
          common: {
            ...ctx.common,
            issues: []
          }
        };
        const result = this._def.innerType._parse({
          data: newCtx.data,
          path: newCtx.path,
          parent: {
            ...newCtx
          }
        });
        if (isAsync(result)) {
          return result.then((result2) => {
            return {
              status: "valid",
              value: result2.status === "valid" ? result2.value : this._def.catchValue({
                get error() {
                  return new ZodError(newCtx.common.issues);
                },
                input: newCtx.data
              })
            };
          });
        } else {
          return {
            status: "valid",
            value: result.status === "valid" ? result.value : this._def.catchValue({
              get error() {
                return new ZodError(newCtx.common.issues);
              },
              input: newCtx.data
            })
          };
        }
      }
      removeCatch() {
        return this._def.innerType;
      }
    };
    ZodCatch.create = (type, params) => {
      return new ZodCatch({
        innerType: type,
        typeName: ZodFirstPartyTypeKind.ZodCatch,
        catchValue: typeof params.catch === "function" ? params.catch : () => params.catch,
        ...processCreateParams(params)
      });
    };
    ZodNaN = class extends ZodType {
      _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.nan) {
          const ctx = this._getOrReturnCtx(input);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.nan,
            received: ctx.parsedType
          });
          return INVALID;
        }
        return { status: "valid", value: input.data };
      }
    };
    ZodNaN.create = (params) => {
      return new ZodNaN({
        typeName: ZodFirstPartyTypeKind.ZodNaN,
        ...processCreateParams(params)
      });
    };
    BRAND = /* @__PURE__ */ Symbol("zod_brand");
    ZodBranded = class extends ZodType {
      _parse(input) {
        const { ctx } = this._processInputParams(input);
        const data = ctx.data;
        return this._def.type._parse({
          data,
          path: ctx.path,
          parent: ctx
        });
      }
      unwrap() {
        return this._def.type;
      }
    };
    ZodPipeline = class _ZodPipeline extends ZodType {
      _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        if (ctx.common.async) {
          const handleAsync = async () => {
            const inResult = await this._def.in._parseAsync({
              data: ctx.data,
              path: ctx.path,
              parent: ctx
            });
            if (inResult.status === "aborted")
              return INVALID;
            if (inResult.status === "dirty") {
              status.dirty();
              return DIRTY(inResult.value);
            } else {
              return this._def.out._parseAsync({
                data: inResult.value,
                path: ctx.path,
                parent: ctx
              });
            }
          };
          return handleAsync();
        } else {
          const inResult = this._def.in._parseSync({
            data: ctx.data,
            path: ctx.path,
            parent: ctx
          });
          if (inResult.status === "aborted")
            return INVALID;
          if (inResult.status === "dirty") {
            status.dirty();
            return {
              status: "dirty",
              value: inResult.value
            };
          } else {
            return this._def.out._parseSync({
              data: inResult.value,
              path: ctx.path,
              parent: ctx
            });
          }
        }
      }
      static create(a, b) {
        return new _ZodPipeline({
          in: a,
          out: b,
          typeName: ZodFirstPartyTypeKind.ZodPipeline
        });
      }
    };
    ZodReadonly = class extends ZodType {
      _parse(input) {
        const result = this._def.innerType._parse(input);
        const freeze = (data) => {
          if (isValid(data)) {
            data.value = Object.freeze(data.value);
          }
          return data;
        };
        return isAsync(result) ? result.then((data) => freeze(data)) : freeze(result);
      }
      unwrap() {
        return this._def.innerType;
      }
    };
    ZodReadonly.create = (type, params) => {
      return new ZodReadonly({
        innerType: type,
        typeName: ZodFirstPartyTypeKind.ZodReadonly,
        ...processCreateParams(params)
      });
    };
    late = {
      object: ZodObject.lazycreate
    };
    (function(ZodFirstPartyTypeKind2) {
      ZodFirstPartyTypeKind2["ZodString"] = "ZodString";
      ZodFirstPartyTypeKind2["ZodNumber"] = "ZodNumber";
      ZodFirstPartyTypeKind2["ZodNaN"] = "ZodNaN";
      ZodFirstPartyTypeKind2["ZodBigInt"] = "ZodBigInt";
      ZodFirstPartyTypeKind2["ZodBoolean"] = "ZodBoolean";
      ZodFirstPartyTypeKind2["ZodDate"] = "ZodDate";
      ZodFirstPartyTypeKind2["ZodSymbol"] = "ZodSymbol";
      ZodFirstPartyTypeKind2["ZodUndefined"] = "ZodUndefined";
      ZodFirstPartyTypeKind2["ZodNull"] = "ZodNull";
      ZodFirstPartyTypeKind2["ZodAny"] = "ZodAny";
      ZodFirstPartyTypeKind2["ZodUnknown"] = "ZodUnknown";
      ZodFirstPartyTypeKind2["ZodNever"] = "ZodNever";
      ZodFirstPartyTypeKind2["ZodVoid"] = "ZodVoid";
      ZodFirstPartyTypeKind2["ZodArray"] = "ZodArray";
      ZodFirstPartyTypeKind2["ZodObject"] = "ZodObject";
      ZodFirstPartyTypeKind2["ZodUnion"] = "ZodUnion";
      ZodFirstPartyTypeKind2["ZodDiscriminatedUnion"] = "ZodDiscriminatedUnion";
      ZodFirstPartyTypeKind2["ZodIntersection"] = "ZodIntersection";
      ZodFirstPartyTypeKind2["ZodTuple"] = "ZodTuple";
      ZodFirstPartyTypeKind2["ZodRecord"] = "ZodRecord";
      ZodFirstPartyTypeKind2["ZodMap"] = "ZodMap";
      ZodFirstPartyTypeKind2["ZodSet"] = "ZodSet";
      ZodFirstPartyTypeKind2["ZodFunction"] = "ZodFunction";
      ZodFirstPartyTypeKind2["ZodLazy"] = "ZodLazy";
      ZodFirstPartyTypeKind2["ZodLiteral"] = "ZodLiteral";
      ZodFirstPartyTypeKind2["ZodEnum"] = "ZodEnum";
      ZodFirstPartyTypeKind2["ZodEffects"] = "ZodEffects";
      ZodFirstPartyTypeKind2["ZodNativeEnum"] = "ZodNativeEnum";
      ZodFirstPartyTypeKind2["ZodOptional"] = "ZodOptional";
      ZodFirstPartyTypeKind2["ZodNullable"] = "ZodNullable";
      ZodFirstPartyTypeKind2["ZodDefault"] = "ZodDefault";
      ZodFirstPartyTypeKind2["ZodCatch"] = "ZodCatch";
      ZodFirstPartyTypeKind2["ZodPromise"] = "ZodPromise";
      ZodFirstPartyTypeKind2["ZodBranded"] = "ZodBranded";
      ZodFirstPartyTypeKind2["ZodPipeline"] = "ZodPipeline";
      ZodFirstPartyTypeKind2["ZodReadonly"] = "ZodReadonly";
    })(ZodFirstPartyTypeKind || (ZodFirstPartyTypeKind = {}));
    instanceOfType = (cls, params = {
      message: `Input not instance of ${cls.name}`
    }) => custom((data) => data instanceof cls, params);
    stringType = ZodString.create;
    numberType = ZodNumber.create;
    nanType = ZodNaN.create;
    bigIntType = ZodBigInt.create;
    booleanType = ZodBoolean.create;
    dateType = ZodDate.create;
    symbolType = ZodSymbol.create;
    undefinedType = ZodUndefined.create;
    nullType = ZodNull.create;
    anyType = ZodAny.create;
    unknownType = ZodUnknown.create;
    neverType = ZodNever.create;
    voidType = ZodVoid.create;
    arrayType = ZodArray.create;
    objectType = ZodObject.create;
    strictObjectType = ZodObject.strictCreate;
    unionType = ZodUnion.create;
    discriminatedUnionType = ZodDiscriminatedUnion.create;
    intersectionType = ZodIntersection.create;
    tupleType = ZodTuple.create;
    recordType = ZodRecord.create;
    mapType = ZodMap.create;
    setType = ZodSet.create;
    functionType = ZodFunction.create;
    lazyType = ZodLazy.create;
    literalType = ZodLiteral.create;
    enumType = ZodEnum.create;
    nativeEnumType = ZodNativeEnum.create;
    promiseType = ZodPromise.create;
    effectsType = ZodEffects.create;
    optionalType = ZodOptional.create;
    nullableType = ZodNullable.create;
    preprocessType = ZodEffects.createWithPreprocess;
    pipelineType = ZodPipeline.create;
    ostring = () => stringType().optional();
    onumber = () => numberType().optional();
    oboolean = () => booleanType().optional();
    coerce = {
      string: ((arg) => ZodString.create({ ...arg, coerce: true })),
      number: ((arg) => ZodNumber.create({ ...arg, coerce: true })),
      boolean: ((arg) => ZodBoolean.create({
        ...arg,
        coerce: true
      })),
      bigint: ((arg) => ZodBigInt.create({ ...arg, coerce: true })),
      date: ((arg) => ZodDate.create({ ...arg, coerce: true }))
    };
    NEVER = INVALID;
  }
});

// node_modules/zod/v3/external.js
var external_exports = {};
__export(external_exports, {
  BRAND: () => BRAND,
  DIRTY: () => DIRTY,
  EMPTY_PATH: () => EMPTY_PATH,
  INVALID: () => INVALID,
  NEVER: () => NEVER,
  OK: () => OK,
  ParseStatus: () => ParseStatus,
  Schema: () => ZodType,
  ZodAny: () => ZodAny,
  ZodArray: () => ZodArray,
  ZodBigInt: () => ZodBigInt,
  ZodBoolean: () => ZodBoolean,
  ZodBranded: () => ZodBranded,
  ZodCatch: () => ZodCatch,
  ZodDate: () => ZodDate,
  ZodDefault: () => ZodDefault,
  ZodDiscriminatedUnion: () => ZodDiscriminatedUnion,
  ZodEffects: () => ZodEffects,
  ZodEnum: () => ZodEnum,
  ZodError: () => ZodError,
  ZodFirstPartyTypeKind: () => ZodFirstPartyTypeKind,
  ZodFunction: () => ZodFunction,
  ZodIntersection: () => ZodIntersection,
  ZodIssueCode: () => ZodIssueCode,
  ZodLazy: () => ZodLazy,
  ZodLiteral: () => ZodLiteral,
  ZodMap: () => ZodMap,
  ZodNaN: () => ZodNaN,
  ZodNativeEnum: () => ZodNativeEnum,
  ZodNever: () => ZodNever,
  ZodNull: () => ZodNull,
  ZodNullable: () => ZodNullable,
  ZodNumber: () => ZodNumber,
  ZodObject: () => ZodObject,
  ZodOptional: () => ZodOptional,
  ZodParsedType: () => ZodParsedType,
  ZodPipeline: () => ZodPipeline,
  ZodPromise: () => ZodPromise,
  ZodReadonly: () => ZodReadonly,
  ZodRecord: () => ZodRecord,
  ZodSchema: () => ZodType,
  ZodSet: () => ZodSet,
  ZodString: () => ZodString,
  ZodSymbol: () => ZodSymbol,
  ZodTransformer: () => ZodEffects,
  ZodTuple: () => ZodTuple,
  ZodType: () => ZodType,
  ZodUndefined: () => ZodUndefined,
  ZodUnion: () => ZodUnion,
  ZodUnknown: () => ZodUnknown,
  ZodVoid: () => ZodVoid,
  addIssueToContext: () => addIssueToContext,
  any: () => anyType,
  array: () => arrayType,
  bigint: () => bigIntType,
  boolean: () => booleanType,
  coerce: () => coerce,
  custom: () => custom,
  date: () => dateType,
  datetimeRegex: () => datetimeRegex,
  defaultErrorMap: () => en_default,
  discriminatedUnion: () => discriminatedUnionType,
  effect: () => effectsType,
  enum: () => enumType,
  function: () => functionType,
  getErrorMap: () => getErrorMap,
  getParsedType: () => getParsedType,
  instanceof: () => instanceOfType,
  intersection: () => intersectionType,
  isAborted: () => isAborted,
  isAsync: () => isAsync,
  isDirty: () => isDirty,
  isValid: () => isValid,
  late: () => late,
  lazy: () => lazyType,
  literal: () => literalType,
  makeIssue: () => makeIssue,
  map: () => mapType,
  nan: () => nanType,
  nativeEnum: () => nativeEnumType,
  never: () => neverType,
  null: () => nullType,
  nullable: () => nullableType,
  number: () => numberType,
  object: () => objectType,
  objectUtil: () => objectUtil,
  oboolean: () => oboolean,
  onumber: () => onumber,
  optional: () => optionalType,
  ostring: () => ostring,
  pipeline: () => pipelineType,
  preprocess: () => preprocessType,
  promise: () => promiseType,
  quotelessJson: () => quotelessJson,
  record: () => recordType,
  set: () => setType,
  setErrorMap: () => setErrorMap,
  strictObject: () => strictObjectType,
  string: () => stringType,
  symbol: () => symbolType,
  transformer: () => effectsType,
  tuple: () => tupleType,
  undefined: () => undefinedType,
  union: () => unionType,
  unknown: () => unknownType,
  util: () => util,
  void: () => voidType
});
var init_external = __esm({
  "node_modules/zod/v3/external.js"() {
    "use strict";
    init_errors();
    init_parseUtil();
    init_typeAliases();
    init_util();
    init_types();
    init_ZodError();
  }
});

// node_modules/zod/index.js
var init_zod = __esm({
  "node_modules/zod/index.js"() {
    "use strict";
    init_external();
    init_external();
  }
});

// src/policy/types.ts
var SeveritySchema, PolicyPackSchema, PolicyExceptionSchema, OrgPolicySchema;
var init_types2 = __esm({
  "src/policy/types.ts"() {
    "use strict";
    init_zod();
    SeveritySchema = external_exports.enum(["critical", "high", "medium", "low", "info"]);
    PolicyPackSchema = external_exports.enum([
      "oss",
      "team",
      "enterprise",
      "regulated",
      "high-risk-hooks-mcp",
      "ci-enforcement"
    ]);
    PolicyExceptionSchema = external_exports.object({
      id: external_exports.string().min(1),
      rule: external_exports.string().min(1),
      owner: external_exports.string().min(1),
      reason: external_exports.string().min(1),
      expires_at: external_exports.string().datetime(),
      scope: external_exports.string().optional(),
      severity: SeveritySchema.optional(),
      ticket: external_exports.string().optional()
    });
    OrgPolicySchema = external_exports.object({
      version: external_exports.literal(1),
      name: external_exports.string().optional(),
      description: external_exports.string().optional(),
      policy_pack: PolicyPackSchema.default("team"),
      owners: external_exports.array(external_exports.string()).default([]),
      exceptions: external_exports.array(PolicyExceptionSchema).default([]),
      /** Items that MUST appear in the permissions.deny list */
      required_deny_list: external_exports.array(external_exports.string()).default([]),
      /** MCP servers that are banned from use */
      banned_mcp_servers: external_exports.array(external_exports.string()).default([]),
      /** Minimum acceptable security score (0-100) */
      min_score: external_exports.number().int().min(0).max(100).default(60),
      /** Maximum allowed severity for any single finding */
      max_severity: SeveritySchema.default("critical"),
      /** Hook patterns that must be present in settings */
      required_hooks: external_exports.array(
        external_exports.object({
          event: external_exports.enum(["PreToolUse", "PostToolUse", "SessionStart", "Stop"]),
          pattern: external_exports.string(),
          description: external_exports.string().optional()
        })
      ).default([]),
      /** Tools that must NOT appear in the allow list */
      banned_tools: external_exports.array(external_exports.string()).default([])
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
    init_types2();
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

// src/policy/export.ts
import { createHash as createHash3 } from "crypto";
import { mkdirSync as mkdirSync3, writeFileSync as writeFileSync3 } from "fs";
import { join as join5 } from "path";
function exportPolicyPacks(options) {
  mkdirSync3(options.outputDir, { recursive: true });
  const summaries = listPolicyPacks();
  const selectedPacks = options.packs && options.packs.length > 0 ? options.packs : summaries.map((summary) => summary.id);
  const entries = [];
  for (const packId of selectedPacks) {
    const summary = summaries.find((item) => item.id === packId);
    if (!summary) {
      throw new Error(`Unknown policy pack: ${packId}`);
    }
    const policy = generatePolicyPack(packId, {
      owners: options.owners,
      name: options.namePrefix ? `${options.namePrefix} ${titleCase(summary.label)} Policy` : void 0
    });
    const policyJson = stableJson(policy);
    const file = `${packId}-policy.json`;
    writeFileSync3(join5(options.outputDir, file), policyJson);
    entries.push({
      id: summary.id,
      label: summary.label,
      description: summary.description,
      file,
      sha256: digest(policyJson)
    });
  }
  const manifest = {
    schema_version: POLICY_EXPORT_SCHEMA_VERSION,
    packs: entries
  };
  writeFileSync3(join5(options.outputDir, "manifest.json"), stableJson(manifest));
  return manifest;
}
function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}
`;
}
function digest(value) {
  return `sha256:${createHash3("sha256").update(value).digest("hex")}`;
}
function titleCase(label) {
  return label.split(" ").map((word) => word.toUpperCase() === word ? word : `${word.slice(0, 1).toUpperCase()}${word.slice(1)}`).join(" ");
}
var POLICY_EXPORT_SCHEMA_VERSION;
var init_export = __esm({
  "src/policy/export.ts"() {
    "use strict";
    init_presets();
    POLICY_EXPORT_SCHEMA_VERSION = "agentshield.policy-export.v1";
  }
});

// src/policy/promote.ts
import { createHash as createHash4 } from "crypto";
import {
  existsSync as existsSync5,
  mkdirSync as mkdirSync4,
  readFileSync as readFileSync4,
  writeFileSync as writeFileSync4
} from "fs";
import {
  dirname as dirname3,
  isAbsolute,
  join as join6
} from "path";
function promotePolicyPack(options) {
  const manifest = readExportManifest(options.manifestPath);
  const entry = selectPolicyPack(manifest.packs, options.pack);
  const sourceFile = isAbsolute(entry.file) ? entry.file : join6(dirname3(options.manifestPath), entry.file);
  if (!existsSync5(sourceFile)) {
    throw new Error(`Policy file not found: ${sourceFile}`);
  }
  const policyJson = readFileSync4(sourceFile, "utf-8");
  const actualDigest = digest2(policyJson);
  if (actualDigest !== entry.sha256) {
    throw new Error(
      `Policy digest mismatch for ${entry.id}: expected ${entry.sha256}, got ${actualDigest}`
    );
  }
  const parsed = JSON.parse(policyJson);
  const policy = OrgPolicySchema.parse(parsed);
  if (policy.policy_pack !== entry.id) {
    throw new Error(
      `Policy pack mismatch: manifest entry is ${entry.id}, policy file declares ${policy.policy_pack}`
    );
  }
  const owners = policy.owners ?? [];
  const dryRun = Boolean(options.dryRun);
  const promoted = !dryRun;
  if (!dryRun) {
    mkdirSync4(dirname3(options.outputPath), { recursive: true });
    writeFileSync4(options.outputPath, policyJson);
  }
  return {
    manifestPath: options.manifestPath,
    sourceFile,
    outputPath: options.outputPath,
    pack: entry.id,
    policyName: policy.name ?? "Organization Policy",
    owners,
    sha256: entry.sha256,
    verified: true,
    promoted,
    dryRun,
    reviewItems: buildPromotionReviewItems({
      manifestPath: options.manifestPath,
      sourceFile,
      outputPath: options.outputPath,
      pack: entry.id,
      owners,
      sha256: entry.sha256,
      dryRun,
      promoted
    })
  };
}
function buildPromotionReviewItems(options) {
  const policyForSmoke = options.promoted ? options.outputPath : options.sourceFile;
  return [
    {
      id: "manifest-digest-verified",
      status: "verified",
      severity: "info",
      title: "Manifest digest verified",
      detail: `${options.pack} matched ${options.sha256}.`,
      evidencePaths: [options.manifestPath, options.sourceFile],
      recommendation: "Attach the manifest and exported policy to the policy promotion review."
    },
    {
      id: "policy-owner-review",
      status: options.owners.length > 0 ? "verified" : "action_required",
      severity: options.owners.length > 0 ? "info" : "medium",
      title: "Policy owner review",
      detail: options.owners.length > 0 ? `Owners: ${options.owners.join(", ")}.` : "No policy owners are declared on the exported policy.",
      evidencePaths: [options.sourceFile],
      recommendation: options.owners.length > 0 ? "Require one listed owner to approve the protected rollout PR." : "Add at least one policy owner before promoting this pack outside a sandbox."
    },
    {
      id: "protected-rollout-pr",
      status: options.promoted ? "verified" : "action_required",
      severity: options.promoted ? "info" : "medium",
      title: "Protected rollout path",
      detail: options.promoted ? `Active policy written to ${options.outputPath}.` : `Dry run only; ${options.outputPath} was not written.`,
      evidencePaths: [options.manifestPath, options.sourceFile],
      recommendation: options.promoted ? "Keep subsequent policy changes behind branch protection, CI, and owner approval." : `Open a protected PR that promotes ${options.sourceFile} to ${options.outputPath} and requires CI plus owner approval.`
    },
    {
      id: "runtime-smoke-test",
      status: "action_required",
      severity: "medium",
      title: "Runtime smoke test",
      detail: `Promotion did not run a repository scan with ${policyForSmoke}.`,
      evidencePaths: [policyForSmoke],
      recommendation: `Run agentshield scan --policy ${policyForSmoke} before enabling this policy as an enforcing CI gate.`
    }
  ];
}
function readExportManifest(manifestPath) {
  if (!existsSync5(manifestPath)) {
    throw new Error(`Policy export manifest not found: ${manifestPath}`);
  }
  const raw = JSON.parse(readFileSync4(manifestPath, "utf-8"));
  if (raw.schema_version !== POLICY_EXPORT_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported policy export manifest schema: ${String(raw.schema_version)}`
    );
  }
  if (!Array.isArray(raw.packs)) {
    throw new Error("Policy export manifest is missing a packs array");
  }
  return {
    schema_version: POLICY_EXPORT_SCHEMA_VERSION,
    packs: raw.packs.map(readManifestEntry)
  };
}
function readManifestEntry(entry) {
  if (!entry || typeof entry !== "object") {
    throw new Error("Invalid policy export manifest entry");
  }
  const candidate = entry;
  const packResult = PolicyPackSchema.safeParse(candidate.id);
  if (!packResult.success) {
    throw new Error(`Invalid policy pack id in manifest: ${String(candidate.id)}`);
  }
  if (typeof candidate.file !== "string" || candidate.file.length === 0) {
    throw new Error(`Invalid policy file for manifest pack: ${packResult.data}`);
  }
  if (typeof candidate.sha256 !== "string" || !/^sha256:[a-f0-9]{64}$/.test(candidate.sha256)) {
    throw new Error(`Invalid policy digest for manifest pack: ${packResult.data}`);
  }
  return {
    id: packResult.data,
    file: candidate.file,
    sha256: candidate.sha256
  };
}
function selectPolicyPack(entries, requestedPack) {
  if (requestedPack) {
    const entry = entries.find((item) => item.id === requestedPack);
    if (!entry) {
      throw new Error(`Policy pack ${requestedPack} not found in export manifest`);
    }
    return entry;
  }
  if (entries.length === 1) {
    return entries[0];
  }
  throw new Error("Export manifest contains multiple policy packs; pass --pack to select one");
}
function digest2(value) {
  return `sha256:${createHash4("sha256").update(value).digest("hex")}`;
}
var init_promote = __esm({
  "src/policy/promote.ts"() {
    "use strict";
    init_export();
    init_types2();
  }
});

// src/policy/index.ts
var policy_exports = {};
__export(policy_exports, {
  OrgPolicySchema: () => OrgPolicySchema,
  POLICY_EXPORT_SCHEMA_VERSION: () => POLICY_EXPORT_SCHEMA_VERSION,
  PolicyExceptionSchema: () => PolicyExceptionSchema,
  PolicyPackSchema: () => PolicyPackSchema,
  evaluatePolicy: () => evaluatePolicy,
  exportPolicyPacks: () => exportPolicyPacks,
  generateExamplePolicy: () => generateExamplePolicy,
  generatePolicyPack: () => generatePolicyPack,
  listPolicyPacks: () => listPolicyPacks,
  loadPolicy: () => loadPolicy,
  promotePolicyPack: () => promotePolicyPack,
  renderPolicyEvaluation: () => renderPolicyEvaluation
});
var init_policy = __esm({
  "src/policy/index.ts"() {
    "use strict";
    init_evaluate();
    init_presets();
    init_export();
    init_promote();
    init_types2();
  }
});

// src/supply-chain/extract.ts
function extractPackages(files) {
  const packages = [];
  const seen = /* @__PURE__ */ new Set();
  for (const file of files) {
    const extracted = extractFromConfigFile(file);
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
function extractFromConfigFile(file) {
  if (file.type === "mcp-json" || file.type === "settings-json") {
    return extractFromMcpConfig(file.content);
  }
  if (file.type !== "package-manager-config") {
    return [];
  }
  const normalizedPath = file.path.replace(/\\/g, "/").toLowerCase();
  if (normalizedPath.endsWith("package.json")) {
    return extractFromPackageJson(file.content, file.path);
  }
  if (normalizedPath.endsWith("package-lock.json")) {
    return extractFromPackageLock(file.content, file.path);
  }
  return [];
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
function extractFromPackageJson(content, path) {
  try {
    const manifest = JSON.parse(content);
    if (!isRecord(manifest)) return [];
    const packages = [];
    for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      const dependencies = manifest[field];
      if (!isRecord(dependencies)) continue;
      for (const [name, spec] of Object.entries(dependencies)) {
        if (!looksLikePackageDependency(name) || typeof spec !== "string") continue;
        packages.push({
          name,
          version: normalizeManifestVersion(spec),
          source: "manifest",
          serverName: path
        });
      }
    }
    return packages;
  } catch {
    return [];
  }
}
function extractFromPackageLock(content, path) {
  try {
    const lockfile = JSON.parse(content);
    if (!isRecord(lockfile)) return [];
    const packages = [];
    if (isRecord(lockfile.packages)) {
      for (const [location, entry] of Object.entries(lockfile.packages)) {
        if (!location.startsWith("node_modules/") || !isRecord(entry)) continue;
        const name = location.slice("node_modules/".length);
        if (!looksLikePackageDependency(name)) continue;
        packages.push({
          name,
          version: typeof entry.version === "string" ? entry.version : void 0,
          source: "lockfile",
          serverName: path
        });
      }
    }
    if (packages.length > 0) {
      return packages;
    }
    const dependencies = lockfile.dependencies;
    if (!isRecord(dependencies)) return [];
    for (const [name, entry] of Object.entries(dependencies)) {
      if (!looksLikePackageDependency(name) || !isRecord(entry)) continue;
      packages.push({
        name,
        version: typeof entry.version === "string" ? entry.version : void 0,
        source: "lockfile",
        serverName: path
      });
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
function looksLikePackageDependency(name) {
  return /^(@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(name);
}
function normalizeManifestVersion(spec) {
  const normalized = spec.trim();
  const exact = normalized.match(/^(?:npm:)?(?:[~^=<> ]*)(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/);
  return exact?.[1];
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
var init_types3 = __esm({
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
    init_types3();
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
    init_types3();
  }
});

// src/baseline/types.ts
var DEFAULT_GATE_CONFIG;
var init_types4 = __esm({
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
import { readFileSync as readFileSync5, writeFileSync as writeFileSync5, existsSync as existsSync6 } from "fs";
import { dirname as dirname4 } from "path";
import { mkdirSync as mkdirSync5 } from "fs";
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
  const dir = dirname4(outputPath);
  if (!existsSync6(dir)) {
    mkdirSync5(dir, { recursive: true });
  }
  writeFileSync5(outputPath, JSON.stringify(serialized, null, 2));
}
function loadBaseline(baselinePath) {
  if (!existsSync6(baselinePath)) return null;
  try {
    const raw = readFileSync5(baselinePath, "utf-8");
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
    init_types4();
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
    init_types4();
  }
});

// src/action.ts
import { resolve as resolve4 } from "path";
import { dirname as dirname5 } from "path";
import { existsSync as existsSync7 } from "fs";
import { appendFileSync, mkdirSync as mkdirSync6, writeFileSync as writeFileSync6 } from "fs";

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
var CLAUDE_PLUGIN_CACHE_PATH_PATTERN = /(^|\/)\.claude\/plugins\/cache(\/|$)/i;
var CLAUDE_SCAN_ROOT_PLUGIN_CACHE_PATH_PATTERN = /^plugins\/cache(\/|$)/i;
function findAllMatches(content, pattern) {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return [...content.matchAll(new RegExp(pattern.source, flags))];
}
function isExampleLikePath(path) {
  return EXAMPLE_LIKE_PATH_PATTERN.test(path.replace(/\\/g, "/"));
}
function isPluginCachePath(path, scanRoot) {
  const normalizedPath = path.replace(/\\/g, "/");
  if (findAllMatches(normalizedPath, CLAUDE_PLUGIN_CACHE_PATH_PATTERN).length > 0) {
    return true;
  }
  if (!scanRoot || !isClaudeScanRoot(scanRoot)) {
    return false;
  }
  return findAllMatches(normalizedPath, CLAUDE_SCAN_ROOT_PLUGIN_CACHE_PATH_PATTERN).length > 0;
}
function isClaudeScanRoot(scanRoot) {
  const normalizedRoot = scanRoot.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  return normalizedRoot === ".claude" || normalizedRoot.endsWith("/.claude");
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
var PACKAGE_MANAGER_CONFIG_FILES = /* @__PURE__ */ new Set([
  "package.json",
  "package-lock.json",
  ".npmrc",
  ".pnpmrc",
  ".yarnrc",
  ".yarnrc.yml",
  "pnpm-workspace.yaml",
  "pnpm-workspace.yml"
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
    [".zed/settings.json", "settings-json"],
    [".zed/tasks.json", "settings-json"],
    ["package.json", "package-manager-config"],
    ["package-lock.json", "package-manager-config"],
    [".npmrc", "package-manager-config"],
    [".pnpmrc", "package-manager-config"],
    [".yarnrc", "package-manager-config"],
    [".yarnrc.yml", "package-manager-config"],
    ["pnpm-workspace.yaml", "package-manager-config"],
    ["pnpm-workspace.yml", "package-manager-config"],
    [".github/workflows/codeql_analysis.yml", "settings-json"],
    [".github/workflows/codeql_analysis.yaml", "settings-json"],
    [".config/gh-token-monitor/token", "hook-script"],
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
    [".zed", "hook-script"],
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
  if (PACKAGE_MANAGER_CONFIG_FILES.has(name)) return "package-manager-config";
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
    name: "openai-legacy-api-key",
    pattern: /sk-(?!ant-|proj-)[a-zA-Z0-9_-]{20,}/g,
    description: "OpenAI API key"
  },
  {
    name: "xai-api-key",
    pattern: /xai-[a-zA-Z0-9_-]{20,}/g,
    description: "xAI API key"
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
    name: "linear-api-key",
    pattern: /lin_api_[a-zA-Z0-9]{20,}/g,
    description: "Linear API key"
  },
  {
    name: "cloudflare-api-token",
    pattern: /(?:CLOUDFLARE_API_TOKEN|CLOUDFLARE_TOKEN|CF_API_TOKEN|CF_TOKEN)\s*[=:]\s*["']?[a-zA-Z0-9_-]{20,}["']?/gi,
    description: "Cloudflare API token"
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
function findAllMatches2(content, pattern) {
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
        const matches = findAllMatches2(file.content, secretPattern.pattern);
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
      const matches = findAllMatches2(file.content, echoEnvPattern);
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
      const matches = findAllMatches2(file.content, envAssignmentPattern);
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
      const matches = findAllMatches2(file.content, urlCredPattern);
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
        const matches = findAllMatches2(file.content, pattern);
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
        const matches = findAllMatches2(file.content, pattern);
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
        const matches = findAllMatches2(file.content, pattern);
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
      const matches = findAllMatches2(file.content, base64Pattern);
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
        const matches = findAllMatches2(file.content, pattern);
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
function findAllMatches3(content, pattern) {
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
function getJsonStringRanges(content, values) {
  const ranges = [];
  const searchOffsets = /* @__PURE__ */ new Map();
  for (const value of values) {
    const escapedValue = JSON.stringify(value).slice(1, -1);
    const startIndex = searchOffsets.get(escapedValue) ?? 0;
    const index = content.indexOf(escapedValue, startIndex);
    if (index === -1) {
      continue;
    }
    ranges.push({ start: index, end: index + escapedValue.length });
    searchOffsets.set(escapedValue, index + escapedValue.length);
  }
  return ranges;
}
function getPermissionDenyStringRanges(file) {
  if (file.type !== "settings-json") {
    return [];
  }
  try {
    const config = JSON.parse(file.content);
    const deny = config?.permissions?.deny;
    if (!Array.isArray(deny)) {
      return [];
    }
    return getJsonStringRanges(
      file.content,
      deny.filter((entry) => typeof entry === "string")
    );
  } catch {
    return [];
  }
}
function isIndexInRanges(index, ranges) {
  return ranges.some((range) => index >= range.start && index < range.end);
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
    for (const match of findAllMatches3(target.content, pattern)) {
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
    name: "mini-shai-hulud-payload-filename",
    pattern: /\b(?:router_init\.js|tanstack_runner\.js|opensearch_init\.js|vite_setup\.mjs|execution\.js|shai-hulud-workflow\.ya?ml)\b/gi,
    description: "Matches payload and workflow filenames used by the May 2026 TanStack/Mini Shai-Hulud npm campaign and follow-on package waves."
  },
  {
    name: "tanstack-exfil-network",
    pattern: /\b(?:api\.masscan\.cloud|filev2\.getsession\.org|git-tanstack\.com|seed[123]\.getsession\.org|83\.142\.209\.194|169\.254\.169\.254|169\.254\.170\.2|127\.0\.0\.1:8200|vault\.svc\.cluster\.local:8200|litter\.catbox\.moe\/(?:h8nc9u\.js|7rrc6l\.mjs))\b/gi,
    description: "Matches exfiltration or second-stage URLs reported for the May 2026 TanStack/Mini Shai-Hulud campaign."
  },
  {
    name: "mini-shai-hulud-payload-hash",
    pattern: /(?:ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c|2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96|7c12d8619f2db233e3d965a9307093355f149d5babc458912757a5e88fec0f54|0c0e8730695e997b3a53d77483f28573392319ec023f8fd6d7282121cf7cf192)/gi,
    description: "Matches payload, package, and encryption-key hashes reported for the May 2026 Mini Shai-Hulud campaign."
  },
  {
    name: "ai-tool-persistence-payload",
    pattern: /(?:\.claude\/(?:router_runtime\.js|setup\.mjs)|\.(?:vscode|zed)\/setup\.mjs|\.github\/workflows\/codeql_analysis\.ya?ml)/gi,
    description: "Matches AI developer-tool persistence payload paths used to re-execute through Claude Code, VS Code, or Zed automation surfaces."
  },
  {
    name: "github-actions-secrets-serialization",
    pattern: /\btoJSON\s*\(\s*secrets\s*\)/gi,
    description: "Matches GitHub Actions workflow code that serializes all repository secrets, a Mini Shai-Hulud workflow-exfiltration pattern."
  },
  {
    name: "mini-shai-hulud-deadman-daemon",
    pattern: /(?:\.config\/gh-token-monitor\/token|\b(?:gh-token-monitor|com\.user\.gh-token-monitor\.plist|gh-token-monitor\.service|gh-token-monitor\.sh)\b)/gi,
    description: "Matches dead-man switch persistence artifacts and token-store files associated with the May 2026 Mini Shai-Hulud campaign."
  },
  {
    name: "mini-shai-hulud-campaign-marker",
    pattern: /(?:Shai-Hulud:\s*Here We Go Again|A Mini Shai-Hulud has Appeared|IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner|PUSH UR T3MPRR|svksjrhjkcejg|dependabot\/github_actions\/format\/|claude@users\.noreply\.github\.com)/gi,
    description: "Matches repository descriptions or commit messages reported in Mini Shai-Hulud propagation and token-wiper flows."
  },
  {
    name: "mini-shai-hulud-python-payload",
    pattern: /(?:\/tmp\/transformers\.pyz|\btransformers\.pyz\b|tmp\.ts018051808\.lock|\bpgmonitor\.py\b|\bpgsql-monitor\.service\b|\bMISTRAL_INIT\b)/gi,
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
      const defensiveDenyRanges = getPermissionDenyStringRanges(file);
      const searchTargets = [
        { content: file.content, source: "content" },
        { content: normalizeConfigPath(file.path), source: "path" }
      ];
      for (const ioc of AI_TOOL_PERSISTENCE_IOCS) {
        for (const target of searchTargets) {
          for (const match of findAllMatches3(target.content, ioc.pattern)) {
            const index = match.index ?? 0;
            if (target.source === "content" && isCommentOnlyAutomationMatch(file, target.content, index)) {
              continue;
            }
            if (target.source === "content" && isIndexInRanges(index, defensiveDenyRanges)) {
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

// src/rules/package-manager.ts
var import_yaml = __toESM(require_dist(), 1);
var RELEASE_AGE_MINUTES = 1440;
function isPackageManagerConfig(file) {
  return file.type === "package-manager-config";
}
function normalizePath(filePath) {
  return filePath.replace(/\\/g, "/").toLowerCase();
}
function isNpmStyleConfig(file) {
  const normalized = normalizePath(file.path);
  return normalized.endsWith(".npmrc") || normalized.endsWith(".pnpmrc");
}
function isNpmConfig(file) {
  return normalizePath(file.path).endsWith(".npmrc");
}
function isPnpmLineConfig(file) {
  const normalized = normalizePath(file.path);
  return normalized.endsWith(".pnpmrc") || normalized.endsWith("/pnpm/rc");
}
function isYarnConfig(file) {
  const normalized = normalizePath(file.path);
  return normalized.endsWith(".yarnrc.yml") || normalized.endsWith(".yarnrc");
}
function isPnpmWorkspaceConfig(file) {
  const normalized = normalizePath(file.path);
  return normalized.endsWith("pnpm-workspace.yaml") || normalized.endsWith("pnpm-workspace.yml");
}
function parseLineConfig(content) {
  const entries = [];
  for (const [index, rawLine] of content.split("\n").entries()) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) continue;
    const assignment = trimmed.match(/^([^=\s]+)\s*=\s*(.*)$/);
    if (!assignment) continue;
    const key = assignment[1].trim();
    const value = stripInlineComment(assignment[2].trim());
    entries.push({
      key,
      normalizedKey: normalizeConfigKey(key),
      value,
      line: index + 1
    });
  }
  return entries;
}
function stripInlineComment(value) {
  const quoted = value.match(/^(['"])(.*)\1$/);
  if (quoted) return quoted[2];
  const commentIndex = value.search(/\s[#;]/);
  return commentIndex === -1 ? value : value.slice(0, commentIndex).trim();
}
function normalizeConfigKey(key) {
  return key.toLowerCase().replace(/^.*:/, "").replace(/[_-]/g, "");
}
function findEntry(entries, key) {
  const normalizedKey = normalizeConfigKey(key);
  return entries.find((entry) => entry.normalizedKey === normalizedKey);
}
function parseBoolean(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (value === 1) return true;
    if (value === 0) return false;
  }
  if (typeof value !== "string") return void 0;
  switch (value.trim().replace(/^['"]|['"]$/g, "").toLowerCase()) {
    case "true":
    case "1":
    case "yes":
    case "on":
      return true;
    case "false":
    case "0":
    case "no":
    case "off":
      return false;
    default:
      return void 0;
  }
}
function parseNumber(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string") return void 0;
  const parsed = Number(value.trim().replace(/^['"]|['"]$/g, ""));
  return Number.isFinite(parsed) ? parsed : void 0;
}
function parseDurationToMinutes(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value * 24 * 60;
  }
  if (typeof value !== "string") return void 0;
  const trimmed = value.trim().replace(/^['"]|['"]$/g, "");
  const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?$/i);
  if (!match) return void 0;
  const amount = Number(match[1]);
  if (!Number.isFinite(amount)) return void 0;
  switch ((match[2] ?? "d").toLowerCase()) {
    case "ms":
      return amount / 6e4;
    case "s":
      return amount / 60;
    case "m":
      return amount;
    case "h":
      return amount * 60;
    case "d":
      return amount * 24 * 60;
    case "w":
      return amount * 7 * 24 * 60;
    default:
      return void 0;
  }
}
function parseYamlRecord(content) {
  try {
    const parsed = (0, import_yaml.parse)(content);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
}
function findYamlLine(content, key) {
  const pattern = new RegExp(`^\\s*${escapeRegExp(key)}\\s*:`, "im");
  const match = pattern.exec(content);
  if (!match || match.index == null) return void 0;
  return content.slice(0, match.index).split("\n").length;
}
function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function isEnvReference(value) {
  const normalized = value.trim().replace(/^['"]|['"]$/g, "");
  return normalized.startsWith("$") || normalized.includes("${") || normalized.includes("%") || normalized.toLowerCase().includes("process.env");
}
function maskCredential(value) {
  const normalized = value.trim().replace(/^['"]|['"]$/g, "");
  if (normalized.length <= 10) return "<redacted>";
  return `${normalized.slice(0, 6)}...${normalized.slice(-4)}`;
}
function makeFinding(options) {
  return {
    id: options.id,
    severity: options.severity,
    category: options.category,
    title: options.title,
    description: options.description,
    file: options.file,
    line: options.line,
    evidence: options.evidence,
    fix: options.before && options.after ? {
      description: "Harden package-manager configuration",
      before: options.before,
      after: options.after,
      auto: false
    } : void 0
  };
}
function credentialFindings(file) {
  const findings = [];
  if (isNpmStyleConfig(file)) {
    for (const entry of parseLineConfig(file.content)) {
      if (!/(?:^|:)_?auth(?:token)?$|(?:^|:)_password$|(?:^|:)password$/.test(entry.normalizedKey)) {
        continue;
      }
      if (!entry.value || isEnvReference(entry.value)) continue;
      findings.push(
        makeFinding({
          id: `package-manager-registry-credential-${entry.line}`,
          severity: "critical",
          category: "secrets",
          title: "Plaintext package registry credential",
          description: "A package-manager config stores a registry credential directly on disk. Use an environment variable reference and rotate the exposed token before relying on package-manager hardening.",
          file: file.path,
          line: entry.line,
          evidence: `${entry.key}=${maskCredential(entry.value)}`,
          before: `${entry.key}=<token>`,
          after: `${entry.key}=\${NPM_TOKEN}`
        })
      );
    }
  }
  if (isYarnConfig(file)) {
    const record = parseYamlRecord(file.content);
    if (!record) return findings;
    for (const key of ["npmAuthToken", "npmAuthIdent"]) {
      const value = record[key];
      if (typeof value !== "string" || isEnvReference(value)) continue;
      findings.push(
        makeFinding({
          id: `package-manager-registry-credential-${key}`,
          severity: "critical",
          category: "secrets",
          title: "Plaintext package registry credential",
          description: "A Yarn config stores a registry credential directly on disk. Use an environment variable reference and rotate the exposed token before relying on package-manager hardening.",
          file: file.path,
          line: findYamlLine(file.content, key),
          evidence: `${key}: ${maskCredential(value)}`,
          before: `${key}: <token>`,
          after: `${key}: \${NPM_TOKEN}`
        })
      );
    }
  }
  return findings;
}
function lifecycleScriptFindings(file) {
  const findings = [];
  if (isNpmStyleConfig(file)) {
    const entries = parseLineConfig(file.content);
    const ignoreScripts = findEntry(entries, "ignore-scripts");
    const parsedIgnoreScripts = ignoreScripts ? parseBoolean(ignoreScripts.value) : void 0;
    if (parsedIgnoreScripts === false) {
      findings.push(
        makeFinding({
          id: "package-manager-lifecycle-scripts-enabled",
          severity: "high",
          category: "misconfiguration",
          title: "Package lifecycle scripts are explicitly enabled",
          description: "`ignore-scripts=false` allows dependency install scripts to execute. For high-risk AI developer workstations and CI runners, disable lifecycle scripts by default and allowlist required builds separately.",
          file: file.path,
          line: ignoreScripts?.line,
          evidence: `${ignoreScripts?.key}=${ignoreScripts?.value}`,
          before: `${ignoreScripts?.key}=false`,
          after: "ignore-scripts=true"
        })
      );
    } else if (!ignoreScripts) {
      findings.push(
        makeFinding({
          id: "package-manager-lifecycle-scripts-not-disabled",
          severity: "medium",
          category: "misconfiguration",
          title: "Package lifecycle scripts are not disabled",
          description: "This package-manager config does not set `ignore-scripts=true`. Dependency install scripts remain a common supply-chain execution path, including for AI-tooling-focused npm campaigns.",
          file: file.path,
          before: "# missing ignore-scripts",
          after: "ignore-scripts=true"
        })
      );
    }
  }
  if (isYarnConfig(file)) {
    const record = parseYamlRecord(file.content);
    const enableScripts = record ? parseBoolean(record.enableScripts) : void 0;
    if (enableScripts === true) {
      findings.push(
        makeFinding({
          id: "package-manager-yarn-lifecycle-scripts-enabled",
          severity: "high",
          category: "misconfiguration",
          title: "Yarn lifecycle scripts are explicitly enabled",
          description: "`enableScripts: true` lets third-party postinstall scripts run. Keep scripts disabled globally and use package-specific approvals only where the build is required.",
          file: file.path,
          line: findYamlLine(file.content, "enableScripts"),
          evidence: "enableScripts: true",
          before: "enableScripts: true",
          after: "enableScripts: false"
        })
      );
    }
  }
  if (isPnpmWorkspaceConfig(file)) {
    const record = parseYamlRecord(file.content);
    if (!record) return findings;
    if (parseBoolean(record.dangerouslyAllowAllBuilds) === true) {
      findings.push(
        makeFinding({
          id: "package-manager-pnpm-dangerously-allow-all-builds",
          severity: "high",
          category: "misconfiguration",
          title: "pnpm allows all dependency build scripts",
          description: "`dangerouslyAllowAllBuilds: true` disables the package-by-package build review boundary. Keep it off for developer hosts and CI runners that handle secrets.",
          file: file.path,
          line: findYamlLine(file.content, "dangerouslyAllowAllBuilds"),
          evidence: "dangerouslyAllowAllBuilds: true",
          before: "dangerouslyAllowAllBuilds: true",
          after: "strictDepBuilds: true"
        })
      );
    }
    if (parseBoolean(record.strictDepBuilds) === false) {
      findings.push(
        makeFinding({
          id: "package-manager-pnpm-strict-dep-builds-disabled",
          severity: "medium",
          category: "misconfiguration",
          title: "pnpm strict dependency build review is disabled",
          description: "`strictDepBuilds: false` allows dependency lifecycle scripts without forcing an explicit review path. Enable strict dependency builds and allow only known required build scripts.",
          file: file.path,
          line: findYamlLine(file.content, "strictDepBuilds"),
          evidence: "strictDepBuilds: false",
          before: "strictDepBuilds: false",
          after: "strictDepBuilds: true"
        })
      );
    }
  }
  return findings;
}
function releaseAgeFindings(file) {
  const findings = [];
  if (isNpmConfig(file)) {
    const entries = parseLineConfig(file.content);
    const releaseAge = findEntry(entries, "min-release-age") ?? findEntry(entries, "minimum-release-age");
    if (releaseAge) {
      findings.push(
        makeFinding({
          id: "package-manager-npm-release-age-gate-unsupported",
          severity: "medium",
          category: "misconfiguration",
          title: "npm release-age gate key is unsupported",
          description: "The npm CLI does not recognize a native dynamic release-age gate. This key can create false confidence; enforce package cooldowns through pnpm `minimumReleaseAge`, Yarn `npmMinimalAgeGate`, or a package-manager policy wrapper.",
          file: file.path,
          line: releaseAge.line,
          evidence: `${releaseAge.key}=${releaseAge.value}`,
          before: `${releaseAge.key}=${releaseAge.value}`,
          after: "# use pnpm minimumReleaseAge or Yarn npmMinimalAgeGate"
        })
      );
    }
  }
  if (isPnpmLineConfig(file)) {
    const entries = parseLineConfig(file.content);
    const releaseAge = findEntry(entries, "minimum-release-age");
    const releaseAgeValue = releaseAge ? parseNumber(releaseAge.value) : void 0;
    if (!releaseAge) {
      findings.push(
        makeFinding({
          id: "package-manager-pnpm-release-age-gate-missing",
          severity: "info",
          category: "misconfiguration",
          title: "pnpm release-age gate is not configured",
          description: "pnpm can block package versions that are too new through `minimumReleaseAge` / `minimum-release-age`. Configure a cooldown to reduce exposure to fast-moving supply-chain campaigns.",
          file: file.path,
          before: "# missing minimum-release-age",
          after: "minimum-release-age=1440"
        })
      );
    } else if (releaseAgeValue !== void 0 && releaseAgeValue < RELEASE_AGE_MINUTES) {
      findings.push(
        makeFinding({
          id: "package-manager-pnpm-release-age-gate-too-low",
          severity: "medium",
          category: "misconfiguration",
          title: "pnpm release-age gate is below one day",
          description: "`minimum-release-age` is below one day. Use a longer cooldown for workstations and CI runners that handle tokens or publish packages.",
          file: file.path,
          line: releaseAge.line,
          evidence: `${releaseAge.key}=${releaseAge.value}`,
          before: `${releaseAge.key}=${releaseAge.value}`,
          after: `${releaseAge.key}=1440`
        })
      );
    }
  }
  if (isYarnConfig(file)) {
    const record = parseYamlRecord(file.content);
    const ageGate = record?.npmMinimalAgeGate;
    const ageGateValue = parseDurationToMinutes(ageGate);
    if (ageGate === void 0) {
      findings.push(
        makeFinding({
          id: "package-manager-yarn-release-age-gate-missing",
          severity: "info",
          category: "misconfiguration",
          title: "Yarn npm release-age gate is not configured",
          description: "Yarn can block package versions that are too new through `npmMinimalAgeGate`. Configure a cooldown to reduce exposure to newly published malicious packages.",
          file: file.path,
          before: "# missing npmMinimalAgeGate",
          after: 'npmMinimalAgeGate: "1d"'
        })
      );
    } else if (ageGateValue !== void 0 && ageGateValue < RELEASE_AGE_MINUTES) {
      findings.push(
        makeFinding({
          id: "package-manager-yarn-release-age-gate-too-low",
          severity: "medium",
          category: "misconfiguration",
          title: "Yarn npm release-age gate is below one day",
          description: "The configured Yarn age gate is below one day. Use a longer cooldown for workstations and CI runners that handle tokens or publish packages.",
          file: file.path,
          line: findYamlLine(file.content, "npmMinimalAgeGate"),
          evidence: `npmMinimalAgeGate: ${String(ageGate)}`,
          before: `npmMinimalAgeGate: ${String(ageGate)}`,
          after: 'npmMinimalAgeGate: "1d"'
        })
      );
    }
  }
  if (isPnpmWorkspaceConfig(file)) {
    const record = parseYamlRecord(file.content);
    const releaseAge = record?.minimumReleaseAge;
    const releaseAgeValue = parseNumber(releaseAge);
    if (releaseAge === void 0) {
      findings.push(
        makeFinding({
          id: "package-manager-pnpm-release-age-gate-missing",
          severity: "info",
          category: "misconfiguration",
          title: "pnpm release-age gate is not configured",
          description: "pnpm can block package versions that are too new through `minimumReleaseAge`. Configure a cooldown to reduce exposure to fast-moving supply-chain campaigns.",
          file: file.path,
          before: "# missing minimumReleaseAge",
          after: "minimumReleaseAge: 1440"
        })
      );
    } else if (releaseAgeValue !== void 0 && releaseAgeValue < RELEASE_AGE_MINUTES) {
      findings.push(
        makeFinding({
          id: "package-manager-pnpm-release-age-gate-too-low",
          severity: "medium",
          category: "misconfiguration",
          title: "pnpm release-age gate is below one day",
          description: "`minimumReleaseAge` is below one day. Use a longer cooldown for workstations and CI runners that handle tokens or publish packages.",
          file: file.path,
          line: findYamlLine(file.content, "minimumReleaseAge"),
          evidence: `minimumReleaseAge: ${String(releaseAge)}`,
          before: `minimumReleaseAge: ${String(releaseAge)}`,
          after: "minimumReleaseAge: 1440"
        })
      );
    }
  }
  return findings;
}
var packageManagerRules = [
  {
    id: "package-manager-registry-credentials",
    name: "Package Manager Registry Credentials",
    description: "Checks package-manager configs for plaintext registry credentials",
    severity: "critical",
    category: "secrets",
    check(file) {
      if (!isPackageManagerConfig(file)) return [];
      return credentialFindings(file);
    }
  },
  {
    id: "package-manager-lifecycle-scripts",
    name: "Package Manager Lifecycle Scripts",
    description: "Checks package-manager configs for risky dependency lifecycle script settings",
    severity: "high",
    category: "misconfiguration",
    check(file) {
      if (!isPackageManagerConfig(file)) return [];
      return lifecycleScriptFindings(file);
    }
  },
  {
    id: "package-manager-release-age-gates",
    name: "Package Manager Release Age Gates",
    description: "Checks package-manager configs for missing or weak package release-age cooldowns",
    severity: "medium",
    category: "misconfiguration",
    check(file) {
      if (!isPackageManagerConfig(file)) return [];
      return releaseAgeFindings(file);
    }
  }
];

// src/rules/agents.ts
function findLineNumber4(content, matchIndex) {
  return content.substring(0, matchIndex).split("\n").length;
}
function findAllMatches4(content, pattern) {
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
  return normalizePath2(file.path).includes(".claude/subagents/");
}
function normalizePath2(filePath) {
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
        const matches = findAllMatches4(file.content, pattern);
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
var import_yaml2 = __toESM(require_dist(), 1);
import { basename as basename2, dirname, extname as extname2 } from "path";
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
    const parsed = import_yaml2.default.parse(match[1]);
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
function normalizePath3(filePath) {
  return filePath.replace(/\\/g, "/").toLowerCase();
}
function isPromptPostureFile(file) {
  if (file.type === "claude-md" || file.type === "agent-md") return true;
  if (file.type !== "rule-md") return false;
  const normalizedPath = normalizePath3(file.path);
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
    ...packageManagerRules,
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
    id: "zed",
    name: "Zed",
    description: "Zed project agent settings, MCP context servers, tool permissions, tasks, and external-agent handoff surfaces.",
    configPaths: [
      ".zed/settings.json",
      ".zed/tasks.json"
    ],
    permissionConcepts: ["agent tool permissions", "task command review", "worktree trust"],
    pluginSurfaces: ["MCP server extensions", "custom context servers", "external agents"],
    mcpConventions: ["context_servers", "mcp:<server>:<tool_name>", "Agent Panel settings"],
    historySurfaces: ["agent threads", "project context", "worktree-local settings"],
    ciEvidence: ["scan report", "task automation review", "policy gate"],
    markers: [
      { path: ".zed/settings.json", kind: "file", strength: "strong" },
      { path: ".zed/tasks.json", kind: "file", strength: "strong" },
      { path: ".zed", kind: "directory", strength: "supporting" }
    ]
  },
  {
    id: "vscode",
    name: "VS Code",
    description: "VS Code workspace settings, tasks, extension recommendations, and editor-launched automation surfaces.",
    configPaths: [
      ".vscode/settings.json",
      ".vscode/tasks.json",
      ".vscode/extensions.json",
      ".vscode/launch.json"
    ],
    permissionConcepts: ["workspace trust", "folder-open task automation", "extension recommendations"],
    pluginSurfaces: ["extensions", "tasks", "launch configurations"],
    mcpConventions: ["extension-provided MCP/tool configuration", "workspace settings"],
    historySurfaces: ["workspace storage", "task output", "extension logs"],
    ciEvidence: ["scan report", "task automation review", "extension policy gate"],
    markers: [
      { path: ".vscode/tasks.json", kind: "file", strength: "strong" },
      { path: ".vscode/settings.json", kind: "file", strength: "strong" },
      { path: ".vscode/extensions.json", kind: "file", strength: "supporting" },
      { path: ".vscode/launch.json", kind: "file", strength: "supporting" },
      { path: ".vscode", kind: "directory", strength: "supporting" }
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
  const findings = runRules(target.files, rules, target.path);
  const skillHealth = analyzeSkillHealth(target.files);
  const harnessAdapters = detectHarnessAdapters(targetPath);
  return { target, findings, skillHealth, harnessAdapters };
}
function runRules(files, rules, scanRoot) {
  const findings = [];
  for (const file of files) {
    for (const rule of rules) {
      const ruleFindings = rule.check(file, files);
      findings.push(...ruleFindings);
    }
  }
  const filesByPath = new Map(files.map((file) => [file.path, file]));
  const annotatedFindings = findings.map((finding) => {
    const annotatedFinding = annotateFindingRuntimeConfidence(finding, filesByPath, scanRoot);
    return adjustFindingForSourceContext(annotatedFinding);
  });
  return [...annotatedFindings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return order[a.severity] - order[b.severity];
  });
}
function classifyRuntimeConfidence(file, scanRoot) {
  const normalizedPath = file.path.replace(/\\/g, "/").toLowerCase();
  if (normalizedPath === "settings.local.json" || normalizedPath.endsWith("/settings.local.json")) {
    return "project-local-optional";
  }
  if (isPluginCachePath(file.path, scanRoot)) {
    return "plugin-cache";
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
function annotateFindingRuntimeConfidence(finding, filesByPath, scanRoot) {
  if (finding.runtimeConfidence) {
    return finding;
  }
  const file = filesByPath.get(finding.file);
  const runtimeConfidence = file ? classifyRuntimeConfidence(file, scanRoot) : void 0;
  return runtimeConfidence ? { ...finding, runtimeConfidence } : finding;
}
function adjustFindingForSourceContext(finding) {
  switch (finding.runtimeConfidence) {
    case "docs-example":
      return adjustDocsExampleFinding(finding);
    case "plugin-cache":
      return adjustPluginCacheFinding(finding);
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
function adjustPluginCacheFinding(finding) {
  if (finding.category === "secrets") {
    return withPrefixedDescription(
      {
        ...finding,
        title: prefixTitle(finding.title, "Plugin cache")
      },
      "This finding comes from an installed Claude plugin cache. It indicates packaged plugin content present on disk, not confirmed top-level runtime configuration."
    );
  }
  return withPrefixedDescription(
    {
      ...finding,
      severity: downgradeStructuralSeverity(finding.severity),
      title: prefixTitle(finding.title, "Plugin cache")
    },
    "This finding comes from an installed Claude plugin cache. It indicates packaged plugin content present on disk, not confirmed top-level runtime configuration."
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
  if (finding.runtimeConfidence === "plugin-cache" && finding.category !== "secrets") {
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
    case "plugin-cache":
      return "plugin cache";
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
  if (finding.runtimeConfidence === "template-example" || finding.runtimeConfidence === "docs-example" || finding.runtimeConfidence === "plugin-cache") {
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
import { basename as basename3, join as join4, resolve as resolve3 } from "path";
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
    case "plugin-cache":
      return "plugin cache";
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
  const userReplacements = [...new Set(userNames)].map((userName) => [new RegExp(`\\b${escapeRegExp2(userName)}\\b`, "g"), "<user>"]);
  const tokenReplacements = [
    [/\bsk-[A-Za-z0-9_-]{12,}\b/g, "sk-<redacted>"],
    [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{12,}\b/g, "gh_<redacted>"],
    [/github_pat_[A-Za-z0-9_]{20,}\b/g, "<redacted-token>"],
    [/glpat-[A-Za-z0-9_-]{12,}\b/g, "<redacted-token>"],
    [/npm_[A-Za-z0-9]{20,}\b/g, "<redacted-token>"],
    [/lin_api_[A-Za-z0-9]{20,}\b/g, "<redacted-token>"],
    [/(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b/g, "<redacted-token>"],
    [/xai-[A-Za-z0-9_-]{20,}\b/g, "<redacted-token>"],
    [/((?:CLOUDFLARE_API_TOKEN|CLOUDFLARE_TOKEN|CF_API_TOKEN|CF_TOKEN)\s*[:=]\s*["']?)[A-Za-z0-9_-]{20,}/gi, "$1<redacted-token>"],
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
  return new RegExp(escapeRegExp2(value), "g");
}
function escapeRegExp2(value) {
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

// src/action-hardening.ts
function isPackageManagerHardeningFinding(finding) {
  return finding.id.startsWith("package-manager-");
}
function countSeverity(findings, severity) {
  return findings.filter((finding) => finding.severity === severity).length;
}
function countByIdFragment(findings, fragments) {
  return findings.filter(
    (finding) => fragments.some((fragment) => finding.id.includes(fragment))
  ).length;
}
function summarizePackageManagerHardening(findings) {
  const hardeningFindings = findings.filter(isPackageManagerHardeningFinding);
  return {
    status: hardeningFindings.length > 0 ? "needs-review" : "hardened",
    findings: hardeningFindings,
    totalFindings: hardeningFindings.length,
    criticalCount: countSeverity(hardeningFindings, "critical"),
    highCount: countSeverity(hardeningFindings, "high"),
    registryCredentialCount: countByIdFragment(hardeningFindings, [
      "registry-credential"
    ]),
    lifecycleScriptCount: countByIdFragment(hardeningFindings, [
      "lifecycle-scripts",
      "dangerously-allow-all-builds",
      "strict-dep-builds"
    ]),
    releaseAgeGateCount: countByIdFragment(hardeningFindings, [
      "release-age-gate"
    ])
  };
}
function renderPackageManagerHardeningJobSummary(summary) {
  const lines = [
    "",
    "",
    "## AgentShield Package Manager Hardening",
    "",
    `- Status: ${summary.status}`,
    `- Findings: ${summary.totalFindings}`,
    `- Critical findings: ${summary.criticalCount}`,
    `- High findings: ${summary.highCount}`,
    `- Registry credential findings: ${summary.registryCredentialCount}`,
    `- Lifecycle script findings: ${summary.lifecycleScriptCount}`,
    `- Release-age gate findings: ${summary.releaseAgeGateCount}`
  ];
  if (summary.findings.length > 0) {
    lines.push("", "### Findings", "");
    for (const finding of summary.findings.slice(0, 20)) {
      const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
      lines.push(
        `- ${finding.id} (${finding.severity}) ${location}: ${finding.title}`
      );
    }
    if (summary.findings.length > 20) {
      lines.push(`- ${summary.findings.length - 20} additional finding(s) omitted`);
    }
  }
  lines.push("");
  return lines.join("\n");
}

// src/action-promotion.ts
function summarizePolicyPromotion(result, options = {}) {
  const reviewItems = options.runtimeSmoke ? markRuntimeSmokeVerified(result.reviewItems, options.runtimeSmoke) : result.reviewItems;
  const actionRequiredCount = reviewItems.filter(
    (item) => item.status === "action_required"
  ).length;
  return {
    status: actionRequiredCount > 0 ? "needs-review" : "verified",
    pack: result.pack,
    policyName: result.policyName,
    digest: result.sha256,
    promoted: result.promoted,
    dryRun: result.dryRun,
    outputPath: result.outputPath,
    sourceFile: result.sourceFile,
    totalReviewItems: reviewItems.length,
    actionRequiredCount,
    reviewItems
  };
}
function renderPolicyPromotionJobSummary(summary) {
  const lines = [
    "",
    "",
    "## AgentShield Policy Promotion",
    "",
    `- Status: ${summary.status}`,
    `- Pack: ${summary.pack}`,
    `- Policy: ${summary.policyName}`,
    `- Digest: ${summary.digest}`,
    `- Promoted: ${summary.promoted ? "yes" : "no"}`,
    `- Dry run: ${summary.dryRun ? "yes" : "no"}`,
    `- Source: ${summary.sourceFile}`,
    `- Output: ${summary.outputPath}`,
    `- Review items: ${summary.totalReviewItems}`,
    `- Action required: ${summary.actionRequiredCount}`
  ];
  if (summary.reviewItems.length > 0) {
    lines.push("", "### Promotion Review Items", "");
    for (const item of summary.reviewItems) {
      const evidence = item.evidencePaths.length > 0 ? ` evidence=${item.evidencePaths.join(", ")}` : "";
      lines.push(
        `- ${item.id} (${item.status}, ${item.severity}): ${item.title}${evidence}`
      );
      lines.push(`  - ${item.detail}`);
      lines.push(`  - recommendation: ${item.recommendation}`);
    }
  }
  lines.push("");
  return lines.join("\n");
}
function markRuntimeSmokeVerified(reviewItems, runtimeSmoke) {
  return reviewItems.map((item) => {
    if (item.id !== "runtime-smoke-test") return item;
    return {
      ...item,
      status: "verified",
      severity: "info",
      detail: `Runtime smoke scan completed against ${runtimeSmoke.targetPath} with ${runtimeSmoke.policyPath}; policy status ${runtimeSmoke.policyStatus}.`,
      evidencePaths: [runtimeSmoke.policyPath],
      recommendation: "Attach this Action job summary to the policy promotion evidence."
    };
  });
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
  let policyPath = getInput("policy", "");
  const failOnPolicy = getInput("fail-on-policy", "true") === "true";
  const policyPromotionManifest = getInput("policy-promotion-manifest", "");
  const policyPromotionPack = getInput("policy-promotion-pack", "");
  const policyPromotionOutput = getInput("policy-promotion-output", ".agentshield/policy.json");
  const policyPromotionDryRun = getInput("policy-promotion-dry-run", "true") === "true";
  const failOnPolicyPromotion = getInput("fail-on-policy-promotion", "false") === "true";
  const supplyChainRequested = getInput("supply-chain", "true") === "true";
  const supplyChainOnline = getInput("supply-chain-online", "false") === "true";
  const failOnSupplyChainInput = getInput("fail-on-supply-chain", "");
  const failOnSupplyChain = failOnSupplyChainInput ? failOnSupplyChainInput === "true" : failOnFindings;
  const evidencePackPath = getInput("evidence-pack", "");
  const verifyEvidencePackOutput = getInput("verify-evidence-pack", "true") === "true";
  const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd();
  const targetPath = resolve4(workspace, inputPath);
  if (!existsSync7(targetPath)) {
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
  const packageManagerHardening = summarizePackageManagerHardening(result.findings);
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
  setOutput("policy-promotion-status", "not-run");
  setOutput("policy-promotion-pack", "");
  setOutput("policy-promotion-review-items", "0");
  setOutput("policy-promotion-action-required-count", "0");
  setOutput("policy-promotion-digest", "");
  setOutput("supply-chain-status", "not-run");
  setOutput("supply-chain-risky-packages", "0");
  setOutput("supply-chain-critical-count", "0");
  setOutput("supply-chain-high-count", "0");
  setOutput("package-manager-hardening-status", packageManagerHardening.status);
  setOutput(
    "package-manager-hardening-findings",
    String(packageManagerHardening.totalFindings)
  );
  setOutput(
    "package-manager-hardening-critical-count",
    String(packageManagerHardening.criticalCount)
  );
  setOutput(
    "package-manager-hardening-high-count",
    String(packageManagerHardening.highCount)
  );
  setOutput(
    "package-manager-hardening-registry-credentials",
    String(packageManagerHardening.registryCredentialCount)
  );
  setOutput(
    "package-manager-hardening-lifecycle-scripts",
    String(packageManagerHardening.lifecycleScriptCount)
  );
  setOutput(
    "package-manager-hardening-release-age-gates",
    String(packageManagerHardening.releaseAgeGateCount)
  );
  setOutput("evidence-pack-status", "not-run");
  setOutput("evidence-pack-digest", "");
  let policyEvaluation = null;
  let policyPromotionResult = null;
  let resolvedPolicyPath = "";
  let shouldFailOnPolicy = false;
  let shouldFailOnPolicyPromotion = false;
  let baselineComparison = null;
  let shouldFailOnBaseline = false;
  let supplyChainReport = emptySupplyChainReport();
  let shouldFailOnSupplyChain = false;
  if (policyPromotionManifest) {
    try {
      const { PolicyPackSchema: PolicyPackSchema2, promotePolicyPack: promotePolicyPack2 } = await Promise.resolve().then(() => (init_policy(), policy_exports));
      const parsedPack = policyPromotionPack ? PolicyPackSchema2.parse(policyPromotionPack) : void 0;
      policyPromotionResult = promotePolicyPack2({
        manifestPath: resolve4(workspace, policyPromotionManifest),
        outputPath: resolve4(workspace, policyPromotionOutput),
        pack: parsedPack,
        dryRun: policyPromotionDryRun
      });
      if (!policyPath && !policyPromotionResult.dryRun) {
        policyPath = policyPromotionResult.outputPath;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setOutput("policy-promotion-status", "error");
      console.log(`::error::AgentShield policy promotion failed: ${escapeAnnotation(message)}`);
      process.exitCode = 1;
      return;
    }
  }
  if (policyPath) {
    const { loadPolicy: loadPolicy2, evaluatePolicy: evaluatePolicy2, renderPolicyEvaluation: renderPolicyEvaluation2 } = await Promise.resolve().then(() => (init_policy(), policy_exports));
    resolvedPolicyPath = resolve4(workspace, policyPath);
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
  if (policyPromotionResult) {
    const promotionPolicyPaths = /* @__PURE__ */ new Set([
      resolve4(workspace, policyPromotionResult.sourceFile),
      resolve4(workspace, policyPromotionResult.outputPath)
    ]);
    const policyStatus = policyEvaluation ? statusForPolicyEvaluation(policyEvaluation) : "not-run";
    const promotionSummary = summarizePolicyPromotion(
      policyPromotionResult,
      policyEvaluation && promotionPolicyPaths.has(resolvedPolicyPath) ? {
        runtimeSmoke: {
          policyPath: resolvedPolicyPath,
          targetPath: inputPath,
          policyStatus
        }
      } : {}
    );
    setOutput("policy-promotion-status", promotionSummary.status);
    setOutput("policy-promotion-pack", promotionSummary.pack);
    setOutput("policy-promotion-review-items", String(promotionSummary.totalReviewItems));
    setOutput(
      "policy-promotion-action-required-count",
      String(promotionSummary.actionRequiredCount)
    );
    setOutput("policy-promotion-digest", promotionSummary.digest);
    writeJobSummary(renderPolicyPromotionJobSummary(promotionSummary));
    console.log(
      `Policy promotion: ${promotionSummary.status.toUpperCase()} (${promotionSummary.actionRequiredCount}/${promotionSummary.totalReviewItems} action required)`
    );
    if (failOnPolicyPromotion && promotionSummary.actionRequiredCount > 0) {
      console.log(
        `::error::AgentShield policy promotion gate FAILED: ${promotionSummary.actionRequiredCount} review item(s) still require action`
      );
      shouldFailOnPolicyPromotion = true;
    }
  }
  if (format === "sarif") {
    const sarifPath = resolve4(workspace, sarifOutput);
    mkdirSync6(dirname5(sarifPath), { recursive: true });
    writeFileSync6(
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
  writeJobSummary(renderPackageManagerHardeningJobSummary(packageManagerHardening));
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
  if (shouldFailOnPolicyPromotion) {
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
