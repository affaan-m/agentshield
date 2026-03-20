import { describe, it, expect } from "vitest";
import {
  verifyPackages,
  checkTyposquatting,
  levenshteinDistance,
} from "../../src/supply-chain/verify.js";
import type { ExtractedPackage } from "../../src/supply-chain/types.js";

function makePackage(overrides: Partial<ExtractedPackage> = {}): ExtractedPackage {
  return {
    name: "@modelcontextprotocol/server-github",
    source: "npx",
    serverName: "github",
    ...overrides,
  };
}

describe("levenshteinDistance", () => {
  it("returns 0 for identical strings", () => {
    expect(levenshteinDistance("abc", "abc")).toBe(0);
  });

  it("returns correct distance for single edit", () => {
    expect(levenshteinDistance("cat", "bat")).toBe(1);
  });

  it("returns length for empty vs non-empty", () => {
    expect(levenshteinDistance("", "abc")).toBe(3);
    expect(levenshteinDistance("abc", "")).toBe(3);
  });

  it("handles both empty strings", () => {
    expect(levenshteinDistance("", "")).toBe(0);
  });

  it("calculates multi-edit distance", () => {
    expect(levenshteinDistance("kitten", "sitting")).toBe(3);
  });

  it("is symmetric", () => {
    expect(levenshteinDistance("abc", "xyz")).toBe(
      levenshteinDistance("xyz", "abc")
    );
  });
});

describe("checkTyposquatting", () => {
  it("returns null for known-good packages", () => {
    const result = checkTyposquatting("@modelcontextprotocol/server-github");
    expect(result).toBeNull();
  });

  it("detects typosquats of known-good packages", () => {
    const result = checkTyposquatting("@modelcontextprotocol/server-githup");
    expect(result).not.toBeNull();
    expect(result!.type).toBe("typosquat");
    expect(result!.severity).toBe("high");
    expect(result!.description).toContain("server-githup");
  });

  it("detects character swap typosquats", () => {
    const result = checkTyposquatting("@modelcontextprotocol/server-mamory");
    expect(result).not.toBeNull();
    expect(result!.type).toBe("typosquat");
  });

  it("returns null for completely different names", () => {
    const result = checkTyposquatting("completely-different-package-name");
    expect(result).toBeNull();
  });

  it("returns null for very short different names", () => {
    const result = checkTyposquatting("xyz");
    expect(result).toBeNull();
  });
});

describe("verifyPackages", () => {
  it("reports clean for known-good packages", async () => {
    const packages = [makePackage()];
    const report = await verifyPackages(packages);

    expect(report.totalPackages).toBe(1);
    expect(report.riskyPackages).toBe(0);
  });

  it("detects known malicious packages", async () => {
    const packages = [
      makePackage({
        name: "@anthropic-ai/model-context-protocol-sdk",
        serverName: "sdk",
      }),
    ];
    const report = await verifyPackages(packages);

    expect(report.riskyPackages).toBeGreaterThan(0);
    expect(report.criticalCount).toBeGreaterThan(0);

    const pkg = report.packages[0];
    expect(pkg.risks.some((r) => r.type === "known-malicious")).toBe(true);
  });

  it("detects known vulnerable servers", async () => {
    const packages = [
      makePackage({
        name: "mcp-remote",
        source: "command",
        serverName: "remote",
      }),
    ];
    const report = await verifyPackages(packages);

    expect(report.riskyPackages).toBeGreaterThan(0);
    const pkg = report.packages[0];
    expect(pkg.risks.some((r) => r.type === "known-vulnerable")).toBe(true);
  });

  it("flags unpinned git URLs", async () => {
    const packages = [
      makePackage({
        name: "org/custom-server",
        source: "git",
        serverName: "custom",
        gitUrl: "https://github.com/org/custom-server",
        gitRef: undefined,
      }),
    ];
    const report = await verifyPackages(packages);

    const pkg = report.packages[0];
    expect(pkg.risks.some((r) => r.type === "unpinned-git")).toBe(true);
  });

  it("allows pinned git URLs", async () => {
    const packages = [
      makePackage({
        name: "org/custom-server",
        source: "git",
        serverName: "custom",
        gitUrl: "https://github.com/org/custom-server#abc123",
        gitRef: "abc123",
      }),
    ];
    const report = await verifyPackages(packages);

    const pkg = report.packages[0];
    expect(pkg.risks.some((r) => r.type === "unpinned-git")).toBe(false);
  });

  it("handles empty package list", async () => {
    const report = await verifyPackages([]);
    expect(report.totalPackages).toBe(0);
    expect(report.riskyPackages).toBe(0);
  });

  it("assigns overall severity from worst risk", async () => {
    const packages = [
      makePackage({
        name: "@anthropic-ai/model-context-protocol-sdk",
        serverName: "sdk",
      }),
    ];
    const report = await verifyPackages(packages);

    expect(report.packages[0].overallSeverity).toBe("critical");
  });

  it("reports info severity for clean packages", async () => {
    const packages = [makePackage()];
    const report = await verifyPackages(packages);

    expect(report.packages[0].overallSeverity).toBe("info");
  });
});
