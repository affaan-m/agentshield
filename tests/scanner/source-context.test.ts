import { describe, expect, it } from "vitest";
import {
  isExampleLikePath,
  isStrongDocumentationExamplePath,
} from "../../src/source-context.js";

describe("source context", () => {
  it.each(["packages/demo/.mcp.json", "packages/demos/.mcp.json"])(
    "keeps broad example matching for %s without treating it as strong documentation evidence",
    (path) => {
      expect(isExampleLikePath(path)).toBe(true);
      expect(isStrongDocumentationExamplePath(path)).toBe(false);
    },
  );

  it.each([
    "examples/demo/.mcp.json",
    "docs/examples/.mcp.json",
    "docs\\examples\\.mcp.json",
  ])("recognizes strong documentation/example path %s", (path) => {
    expect(isStrongDocumentationExamplePath(path)).toBe(true);
  });
});
