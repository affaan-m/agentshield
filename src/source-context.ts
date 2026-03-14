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

export function isExampleLikePath(path: string): boolean {
  return EXAMPLE_LIKE_PATH_PATTERN.test(path.replace(/\\/g, "/"));
}

export { EXAMPLE_LIKE_SEGMENTS };
