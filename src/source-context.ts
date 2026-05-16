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

const CLAUDE_PLUGIN_CACHE_PATH_PATTERN = /(^|\/)\.claude\/plugins\/cache(\/|$)/i;
const CLAUDE_SCAN_ROOT_PLUGIN_CACHE_PATH_PATTERN = /^plugins\/cache(\/|$)/i;

function findAllMatches(content: string, pattern: RegExp): Array<RegExpMatchArray> {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return [...content.matchAll(new RegExp(pattern.source, flags))];
}

export function isExampleLikePath(path: string): boolean {
  return EXAMPLE_LIKE_PATH_PATTERN.test(path.replace(/\\/g, "/"));
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
