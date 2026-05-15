import { describe, expect, it } from "vitest";
import {
  renderSupplyChainJobSummary,
  shouldFailForSupplyChain,
  statusForSupplyChainReport,
} from "../src/action-supply-chain.js";
import type { SupplyChainReport } from "../src/supply-chain/index.js";

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

describe("action supply-chain helpers", () => {
  it("maps clean and risky reports to action statuses", () => {
    expect(statusForSupplyChainReport(makeReport())).toBe("clean");
    expect(statusForSupplyChainReport(makeReport({ riskyPackages: 1 }))).toBe("risky");
  });

  it("fails the action only for critical or high supply-chain risk when the gate is enabled", () => {
    expect(
      shouldFailForSupplyChain(
        makeReport({ riskyPackages: 1, criticalCount: 1 }),
        { failOnSupplyChain: true }
      )
    ).toBe(true);
    expect(
      shouldFailForSupplyChain(
        makeReport({ riskyPackages: 1, highCount: 1 }),
        { failOnSupplyChain: true }
      )
    ).toBe(true);
    expect(
      shouldFailForSupplyChain(
        makeReport({ riskyPackages: 1, highCount: 1 }),
        { failOnSupplyChain: false }
      )
    ).toBe(false);
    expect(
      shouldFailForSupplyChain(
        makeReport({ riskyPackages: 1, criticalCount: 0, highCount: 0 }),
        { failOnSupplyChain: true }
      )
    ).toBe(false);
  });

  it("renders branch-protection evidence for risky packages", () => {
    const report = makeReport({
      packages: [
        {
          package: {
            name: "@tanstack/react-router",
            version: "1.169.8",
            source: "npx",
            serverName: "router",
          },
          provenance: {
            ecosystem: "npm",
            locator: "@tanstack/react-router@1.169.8",
            pinned: true,
            knownGood: false,
            metadataSource: "offline",
          },
          risks: [
            {
              type: "known-malicious",
              severity: "critical",
              description: "Known compromised Mini Shai-Hulud campaign package.",
            },
          ],
          overallSeverity: "critical",
        },
      ],
      totalPackages: 1,
      riskyPackages: 1,
      criticalCount: 1,
      provenance: {
        npmPackages: 1,
        gitPackages: 0,
        pinnedPackages: 1,
        unpinnedPackages: 0,
        knownGoodPackages: 0,
        registryMetadataPackages: 0,
      },
    });

    const summary = renderSupplyChainJobSummary(report, {
      online: false,
      failOnSupplyChain: true,
    });

    expect(summary).toContain("## AgentShield Supply Chain");
    expect(summary).toContain("- Status: risky");
    expect(summary).toContain("- Gate: fail on critical/high risk");
    expect(summary).toContain("@tanstack/react-router@1.169.8");
    expect(summary).toContain("known-malicious/critical");
  });
});
