const EXAMPLE_LIKE_SEGMENTS = [
  "docs",
  "doc",
  "documentation",
  "commands",
  "examples",
  "example",
  "samples",
  "sample",
  "demo",
  "demos",
  "tutorial",
  "tutorials",
  "guide",
  "guides",
  "cookbook",
  "playground",
] as const;

const EXAMPLE_LIKE_PATH_PATTERN = new RegExp(
  `(^|/)(${EXAMPLE_LIKE_SEGMENTS.join("|")})(/|$)`,
  "i"
);

const STRONG_DOCUMENTATION_EXAMPLE_SEGMENTS: ReadonlyArray<
  (typeof EXAMPLE_LIKE_SEGMENTS)[number]
> = EXAMPLE_LIKE_SEGMENTS.filter((segment) => segment !== "demo" && segment !== "demos");

const STRONG_DOCUMENTATION_EXAMPLE_PATH_PATTERN = new RegExp(
  `(^|/)(${STRONG_DOCUMENTATION_EXAMPLE_SEGMENTS.join("|")})(/|$)`,
  "i"
);

/**
 * Editor and other-harness directories. A settings.json or tasks.json under one of them is
 * not a Claude Code settings file: Claude Code never reads its permissions or hooks (#162).
 */
const NON_CLAUDE_SETTINGS_DIRS = [".vscode", ".zed", ".cursor", ".gemini"] as const;

const CLAUDE_PLUGIN_CACHE_PATH_PATTERN = /(^|\/)\.claude\/plugins\/cache(\/|$)/i;
const CLAUDE_SCAN_ROOT_PLUGIN_CACHE_PATH_PATTERN = /^plugins\/cache(\/|$)/i;

function findAllMatches(content: string, pattern: RegExp): Array<RegExpMatchArray> {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return [...content.matchAll(new RegExp(pattern.source, flags))];
}

export function isExampleLikePath(path: string): boolean {
  return EXAMPLE_LIKE_PATH_PATTERN.test(path.replace(/\\/g, "/"));
}

export function isStrongDocumentationExamplePath(path: string): boolean {
  return (
    findAllMatches(path.replace(/\\/g, "/"), STRONG_DOCUMENTATION_EXAMPLE_PATH_PATTERN).length > 0
  );
}

/**
 * True when the file sits directly in an editor or other-harness directory. Only the owning
 * directory counts, so a Claude project nested under one (.vscode/app/.claude/settings.json)
 * keeps its settings checks. Case is ignored, as on case-insensitive file systems.
 */
export function isNonClaudeSettingsPath(path: string): boolean {
  const segments = path.replace(/\\/g, "/").toLowerCase().split("/");
  const owningDir = segments.length >= 2 ? segments[segments.length - 2] : "";
  return NON_CLAUDE_SETTINGS_DIRS.some((dir) => owningDir === dir);
}

export function isPluginCachePath(path: string, scanRoot?: string): boolean {
  const normalizedPath = path.replace(/\\/g, "/");
  if (findAllMatches(normalizedPath, CLAUDE_PLUGIN_CACHE_PATH_PATTERN).length > 0) {
    return true;
  }

  if (!scanRoot || !isClaudeScanRoot(scanRoot)) {
    return false;
  }

  return findAllMatches(normalizedPath, CLAUDE_SCAN_ROOT_PLUGIN_CACHE_PATH_PATTERN).length > 0;
}

function isClaudeScanRoot(scanRoot: string): boolean {
  const normalizedRoot = scanRoot.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  return normalizedRoot === ".claude" || normalizedRoot.endsWith("/.claude");
}

export { EXAMPLE_LIKE_SEGMENTS };
