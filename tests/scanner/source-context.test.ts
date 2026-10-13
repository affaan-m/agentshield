import { describe, expect, it } from "vitest";
import {
  isExampleLikePath,
  isNonClaudeSettingsPath,
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

  it.each([
    ".vscode/settings.json",
    ".vscode/tasks.json",
    "packages/web/.vscode/settings.json",
    ".zed\\settings.json",
    ".cursor/settings.json",
    ".gemini/settings.json",
  ])("treats %s as an editor or other-harness settings file", (path) => {
    expect(isNonClaudeSettingsPath(path)).toBe(true);
  });

  it.each(["settings.json", ".claude/settings.json", ".claude/settings.local.json", "vscode/settings.json"])(
    "keeps %s as a possible Claude Code settings file",
    (path) => {
      expect(isNonClaudeSettingsPath(path)).toBe(false);
    },
  );
});
