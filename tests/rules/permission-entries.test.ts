import { describe, expect, it } from "vitest";
import {
  entryCovers,
  findCoveringEntries,
  normalizePermissionEntry,
  parsePermissionEntry,
} from "../../src/rules/permission-entries.js";

describe("parsePermissionEntry", () => {
  it("parses the colon prefix form", () => {
    const parsed = parsePermissionEntry("Bash(npm run build:*)");
    expect(parsed).toMatchObject({ tool: "Bash", command: "npm", args: "run build", prefix: "npm run build", wildcard: true });
  });

  it("parses the space wildcard form and path-spelled commands", () => {
    const parsed = parsePermissionEntry("Bash(/opt/homebrew/bin/node -e *)");
    expect(parsed).toMatchObject({ command: "node", args: "-e", prefix: "node -e", wildcard: true });
  });

  it("parses exact entries without a wildcard", () => {
    const parsed = parsePermissionEntry("Bash(git status)");
    expect(parsed).toMatchObject({ prefix: "git status", wildcard: false });
  });

  it("parses the blanket entry", () => {
    expect(parsePermissionEntry("Bash(*)")).toMatchObject({ prefix: "", wildcard: true });
  });

  it("returns null for malformed entries", () => {
    expect(parsePermissionEntry("Bash")).toBeNull();
  });
});

describe("normalizePermissionEntry", () => {
  it.each([
    ["Bash(sudo:*)", "Bash(sudo *)"],
    ["Bash(/usr/bin/sudo mv *)", "Bash(sudo mv *)"],
    ["Bash(rm)", "Bash(rm)"],
    ["Bash(*)", "Bash(*)"],
    ["Write(src/*)", "Write(src/*)"],
    ["Read(*)", "Read(*)"],
  ])("normalizes %s to %s", (input, expected) => {
    expect(normalizePermissionEntry(input)).toBe(expected);
  });
});

describe("entryCovers", () => {
  const p = (entry: string) => parsePermissionEntry(entry)!;

  it("covers a longer prefix at a token boundary", () => {
    expect(entryCovers(p("Bash(vercel:*)"), p("Bash(vercel env:*)"))).toBe(true);
    expect(entryCovers(p("Bash(vercel:*)"), p("Bash(vercel env pull)"))).toBe(true);
  });

  it("does not cover a different command that shares a prefix string", () => {
    expect(entryCovers(p("Bash(git:*)"), p("Bash(github:*)"))).toBe(false);
  });

  it("requires a wildcard on the covering entry", () => {
    expect(entryCovers(p("Bash(vercel)"), p("Bash(vercel env:*)"))).toBe(false);
  });

  it("never reports an entry as covering itself", () => {
    expect(entryCovers(p("Bash(vercel:*)"), p("Bash(vercel:*)"))).toBe(false);
  });

  it("does not cross tools", () => {
    expect(entryCovers(p("Read(*)"), p("Bash(cat x)"))).toBe(false);
  });
});

describe("findCoveringEntries", () => {
  it("lists every covering entry", () => {
    const all = ["Bash(*)", "Bash(vercel:*)", "Bash(vercel env:*)", "Bash(git status)"];
    expect(findCoveringEntries("Bash(vercel env:*)", all)).toEqual(["Bash(*)", "Bash(vercel:*)"]);
    expect(findCoveringEntries("Bash(*)", all)).toEqual([]);
  });
});
