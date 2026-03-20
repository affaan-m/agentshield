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
        packages: [
          {
            package: { name: "my-server", source: "npx", serverName: "test" },
            risks: [],
            overallSeverity: "info",
          },
        ],
      })
    );
    expect(output).toContain("CLEAN PACKAGES");
    expect(output).toContain("[OK] my-server");
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
      packages: [
        {
          package: { name: "test", source: "npx", serverName: "s" },
          risks: [{ type: "known-malicious", severity: "critical", description: "Bad" }],
          overallSeverity: "critical",
        },
      ],
    });
    const parsed = JSON.parse(renderSupplyChainJson(report));
    expect(parsed.packages[0].risks[0].type).toBe("known-malicious");
  });
});
