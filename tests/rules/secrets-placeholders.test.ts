import { describe, expect, it } from "vitest";
import { secretRules } from "../../src/rules/secrets.js";
import type { ConfigFile } from "../../src/types.js";

function makeBearerConfig(tokenParts: ReadonlyArray<string>): ConfigFile {
  return {
    path: "mcp-configs/mcp-servers.json",
    type: "mcp-json",
    content: JSON.stringify({
      mcpServers: {
        example: {
          headers: {
            Authorization: [["Bear", "er"].join(""), tokenParts.join("_")].join(" "),
          },
        },
      },
    }),
  };
}

function hasBearerFinding(file: ConfigFile): boolean {
  return secretRules
    .flatMap((rule) => rule.check(file))
    .some((finding) => finding.title.includes("bearer token"));
}

describe("explicit bearer-token placeholders", () => {
  it("does not classify the documented placeholder convention as a secret", () => {
    const file = makeBearerConfig(["YOUR", "MEMXUS", "API", "KEY", "HERE"]);

    expect(hasBearerFinding(file)).toBe(false);
  });

  it("still detects credential-shaped bearer-token literals", () => {
    const file = makeBearerConfig(["prod", "abcdefghijklmnopqrstuvwxyz123456"]);

    expect(hasBearerFinding(file)).toBe(true);
  });

  it("does not suppress uppercase near misses", () => {
    const file = makeBearerConfig(["YOUR", "PRODUCTION", "TOKEN", "ACTIVE1234567890"]);

    expect(hasBearerFinding(file)).toBe(true);
  });
});
