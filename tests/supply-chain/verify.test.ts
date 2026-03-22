import { describe, it, expect, vi, afterEach } from "vitest";
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

function mockJsonResponse(body: unknown, ok = true): Response {
  return {
    ok,
    json: async () => body,
  } as Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

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

  it("allows git URLs pinned to commit hashes", async () => {
    const packages = [
      makePackage({
        name: "org/custom-server",
        source: "git",
        serverName: "custom",
        gitUrl: "https://github.com/org/custom-server#0123456789abcdef0123456789abcdef01234567",
        gitRef: "0123456789abcdef0123456789abcdef01234567",
      }),
    ];
    const report = await verifyPackages(packages);

    const pkg = report.packages[0];
    expect(pkg.risks.some((r) => r.type === "unpinned-git")).toBe(false);
  });

  it("flags branch refs as unpinned git URLs", async () => {
    const packages = [
      makePackage({
        name: "org/custom-server",
        source: "git",
        serverName: "custom",
        gitUrl: "https://github.com/org/custom-server#main",
        gitRef: "main",
      }),
    ];
    const report = await verifyPackages(packages);

    const pkg = report.packages[0];
    expect(pkg.risks.some((r) => r.type === "unpinned-git")).toBe(true);
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

  it("assesses registry metadata risks when online mode is enabled", async () => {
    const recentPublish = new Date();
    recentPublish.setDate(recentPublish.getDate() - 10);

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(mockJsonResponse({
        time: { created: recentPublish.toISOString() },
        maintainers: [{ name: "solo" }],
        "dist-tags": { latest: "1.2.3" },
        versions: {
          "1.2.3": {
            scripts: {
              postinstall: "node install.js",
            },
          },
        },
        deprecated: true,
        description: "Suspicious test package",
      }))
      .mockResolvedValueOnce(mockJsonResponse({ downloads: 12 }));

    vi.stubGlobal("fetch", fetchMock);

    const report = await verifyPackages([
      makePackage({
        name: "very-rare-package",
        serverName: "rare",
      }),
    ], { online: true });

    const verifiedPackage = report.packages[0];
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(verifiedPackage.registry).toMatchObject({
      name: "very-rare-package",
      maintainerCount: 1,
      downloadsLastWeek: 12,
      hasPostinstall: true,
      latestVersion: "1.2.3",
      deprecated: true,
    });
    expect(verifiedPackage.risks.map((risk) => risk.type)).toEqual(
      expect.arrayContaining([
        "deprecated",
        "has-postinstall",
        "single-maintainer",
        "low-downloads",
        "new-package",
      ])
    );
    expect(verifiedPackage.overallSeverity).toBe("medium");
  });

  it("tolerates download API failures after fetching registry metadata", async () => {
    const olderPublish = new Date("2020-01-01T00:00:00.000Z");

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(mockJsonResponse({
        time: { created: olderPublish.toISOString() },
        maintainers: [{ name: "alice" }, { name: "bob" }],
        "dist-tags": { latest: "2.0.0" },
        versions: {
          "2.0.0": {
            scripts: {},
          },
        },
        deprecated: false,
        description: "Stable package",
      }))
      .mockRejectedValueOnce(new Error("downloads endpoint unavailable"));

    vi.stubGlobal("fetch", fetchMock);

    const report = await verifyPackages([
      makePackage({
        name: "stable-package",
        serverName: "stable",
      }),
    ], { online: true });

    const verifiedPackage = report.packages[0];
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(verifiedPackage.registry?.downloadsLastWeek).toBeUndefined();
    expect(verifiedPackage.risks).toEqual([]);
    expect(verifiedPackage.overallSeverity).toBe("info");
  });

  it("treats registry lookup failures as optional metadata", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(mockJsonResponse({}, false));
    vi.stubGlobal("fetch", fetchMock);

    const report = await verifyPackages([
      makePackage({
        name: "missing-registry-entry",
        serverName: "missing",
      }),
    ], { online: true });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(report.packages[0].registry).toBeUndefined();
    expect(report.packages[0].risks).toEqual([]);
    expect(report.packages[0].overallSeverity).toBe("info");
  });
});
