import { describe, it, expect } from "vitest";
import {
  renderSupplyChainReport,
  renderSupplyChainJson,
} from "../../src/supply-chain/render.js";
import type { SupplyChainReport } from "../../src/supply-chain/types.js";

function makeReport(overrides: Partial<SupplyChainReport> = {}): SupplyChainReport {
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
      registryMetadataPackages: 0,
    },
    ...overrides,
  };
}

describe("renderSupplyChainReport", () => {
  it("renders empty report", () => {
    const output = renderSupplyChainReport(makeReport());
    expect(output).toContain("Supply Chain Verification");
    expect(output).toContain("No MCP packages detected");
  });

  it("renders clean packages", () => {
    const output = renderSupplyChainReport(
      makeReport({
        totalPackages: 1,
        provenance: {
          npmPackages: 1,
          gitPackages: 0,
          pinnedPackages: 0,
          unpinnedPackages: 1,
          knownGoodPackages: 1,
          registryMetadataPackages: 0,
        },
        packages: [
          {
            package: { name: "my-server", source: "npx", serverName: "test" },
            provenance: {
              ecosystem: "npm",
              locator: "my-server@latest",
              pinned: false,
              knownGood: false,
              metadataSource: "offline",
            },
            risks: [],
            overallSeverity: "info",
          },
        ],
      })
    );
    expect(output).toContain("CLEAN PACKAGES");
    expect(output).toContain("[OK] my-server");
    expect(output).toContain("Provenance:");
    expect(output).toContain("npm: 1");
    expect(output).toContain("unpinned: 1");
  });

  it("renders risky packages", () => {
    const output = renderSupplyChainReport(
      makeReport({
        totalPackages: 1,
        riskyPackages: 1,
        criticalCount: 1,
        packages: [
          {
            package: {
              name: "@evil/mcp-sdk",
              source: "npx",
              serverName: "evil",
            },
            provenance: {
              ecosystem: "npm",
              locator: "@evil/mcp-sdk@latest",
              pinned: false,
              knownGood: false,
              metadataSource: "offline",
            },
            risks: [
              {
                type: "known-malicious",
                severity: "critical",
                description: "Known malicious package",
                evidence: "Typosquat of @modelcontextprotocol/sdk",
              },
            ],
            overallSeverity: "critical",
          },
        ],
      })
    );
    expect(output).toContain("RISKY PACKAGES");
    expect(output).toContain("CRITICAL");
    expect(output).toContain("@evil/mcp-sdk");
    expect(output).toContain("Known malicious package");
  });

  it("shows registry metadata when available", () => {
    const output = renderSupplyChainReport(
      makeReport({
        totalPackages: 1,
        riskyPackages: 1,
        packages: [
          {
            package: {
              name: "suspicious-mcp",
              source: "npx",
              serverName: "sus",
            },
            provenance: {
              ecosystem: "npm",
              locator: "suspicious-mcp@latest",
              pinned: false,
              knownGood: false,
              metadataSource: "npm-registry",
            },
            registry: {
              name: "suspicious-mcp",
              downloadsLastWeek: 5,
              maintainerCount: 1,
              latestVersion: "0.0.1",
            },
            risks: [
              {
                type: "low-downloads",
                severity: "medium",
                description: "Very low downloads",
              },
            ],
            overallSeverity: "medium",
          },
        ],
      })
    );
    expect(output).toContain("5 downloads/week");
    expect(output).toContain("1 maintainer(s)");
    expect(output).toContain("latest: 0.0.1");
  });

  it("escapes terminal control characters in package details", () => {
    const output = renderSupplyChainReport(
      makeReport({
        totalPackages: 1,
        riskyPackages: 1,
        packages: [
          {
            package: {
              name: "evil\u001b[31m-server",
              version: "1.0.0\u0007",
              source: "npx",
              serverName: "prod\u000a",
            },
            provenance: {
              ecosystem: "npm",
              locator: "evil\u001b[31m-server@1.0.0\u0007",
              pinned: true,
              knownGood: false,
              metadataSource: "offline",
            },
            risks: [
              {
                type: "known-malicious",
                severity: "critical",
                description: "Bad\u001b[0m package",
                evidence: "proof\u001b[2J",
              },
            ],
            overallSeverity: "critical",
          },
        ],
      })
    );

    expect(output).toContain("evil\\x1b[31m-server@1.0.0\\x07");
    expect(output).toContain("(server: prod\\x0a, via: npx)");
    expect(output).toContain("Bad\\x1b[0m package");
    expect(output).toContain("proof\\x1b[2J");
    expect(output).not.toContain("\u001b");
  });
});

describe("renderSupplyChainJson", () => {
  it("returns valid JSON", () => {
    const json = renderSupplyChainJson(makeReport({ totalPackages: 2 }));
    const parsed = JSON.parse(json);
    expect(parsed.totalPackages).toBe(2);
  });

  it("includes all fields", () => {
    const report = makeReport({
      totalPackages: 1,
      riskyPackages: 1,
      criticalCount: 1,
      highCount: 0,
      provenance: {
        npmPackages: 1,
        gitPackages: 0,
        pinnedPackages: 0,
        unpinnedPackages: 1,
        knownGoodPackages: 0,
        registryMetadataPackages: 0,
      },
      packages: [
        {
          package: { name: "test", source: "npx", serverName: "s" },
          provenance: {
            ecosystem: "npm",
            locator: "test@latest",
            pinned: false,
            knownGood: false,
            metadataSource: "offline",
          },
          risks: [{ type: "known-malicious", severity: "critical", description: "Bad" }],
          overallSeverity: "critical",
        },
      ],
    });
    const parsed = JSON.parse(renderSupplyChainJson(report));
    expect(parsed.packages[0].risks[0].type).toBe("known-malicious");
    expect(parsed.provenance.unpinnedPackages).toBe(1);
    expect(parsed.packages[0].provenance.locator).toBe("test@latest");
  });
});
