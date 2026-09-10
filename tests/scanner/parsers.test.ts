import { describe, expect, it } from "vitest";
import {
  parseFrontmatter,
  parseJsonLenient,
  parseTomlSafe,
  parseYamlSafe,
} from "../../src/scanner/parsers.js";

describe("parsers", () => {
  it("parses TOML tables and returns null on garbage", () => {
    const parsed = parseTomlSafe('approval_policy = "never"\n[mcp_servers.x]\ncommand = "npx"\n');
    expect(parsed?.approval_policy).toBe("never");
    expect((parsed?.mcp_servers as Record<string, unknown>)?.x).toMatchObject({ command: "npx" });
    expect(parseTomlSafe("= = =")).toBeNull();
  });

  it("parses YAML mappings and rejects scalars and sequences", () => {
    expect(parseYamlSafe("approvals:\n  mode: off\n")).toMatchObject({ approvals: { mode: "off" } });
    expect(parseYamlSafe("- a\n- b\n")).toBeNull();
    expect(parseYamlSafe("just text")).toBeNull();
  });

  it("parses strict JSON first and falls back to lenient JSONC", () => {
    expect(parseJsonLenient('{"a":1}')).toEqual({ a: 1 });
    const jsonc = '{\n  // comment\n  "a": 1, /* block */\n  "url": "https://x.y/z",\n}';
    expect(parseJsonLenient(jsonc)).toEqual({ a: 1, url: "https://x.y/z" });
    expect(parseJsonLenient('{"a": 1' + String.fromCharCode(1) + '}')).toEqual({ a: 1 });
    expect(parseJsonLenient("not json")).toBeNull();
  });

  it("reads YAML frontmatter only when it opens the file", () => {
    expect(parseFrontmatter("---\nname: x\nallowed-tools: Bash\n---\nbody")).toMatchObject({ name: "x" });
    expect(parseFrontmatter("body\n---\nname: x\n---")).toBeNull();
    expect(parseFrontmatter("---\nname: x\n")).toBeNull();
  });
});
