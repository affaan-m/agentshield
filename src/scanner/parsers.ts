import { parse as parseToml } from "smol-toml";
import { parse as parseYaml } from "yaml";

/**
 * Lenient parsers for harness configuration files. Every parser returns
 * null instead of throwing so rules can fail closed on malformed input.
 */

export function parseTomlSafe(content: string): Record<string, unknown> | null {
  try {
    const value = parseToml(content);
    return value && typeof value === "object" ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export function parseYamlSafe(content: string): Record<string, unknown> | null {
  try {
    const value = parseYaml(content);
    return value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function stripControlCharacters(text: string): string {
  let out = "";
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    const isControl = code < 32 && code !== 9 && code !== 10 && code !== 13;
    if (!isControl) out += ch;
  }
  return out;
}

/**
 * JSON with comments, trailing commas, and stray control characters, which
 * real harness configs contain. Strict JSON is tried first so valid files
 * never change meaning.
 */
export function parseJsonLenient(content: string): Record<string, unknown> | null {
  const attempt = (text: string): Record<string, unknown> | null => {
    try {
      const value = JSON.parse(text);
      return value && typeof value === "object" && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : null;
    } catch {
      return null;
    }
  };
  const strict = attempt(content);
  if (strict) return strict;

  const withoutComments = content
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:\\"'])\/\/[^\n]*/g, "$1");
  const withoutTrailingCommas = withoutComments.replace(/,\s*([}\]])/g, "$1");
  const withoutControl = stripControlCharacters(withoutTrailingCommas);
  return attempt(withoutControl);
}

/** Frontmatter block of a markdown file, parsed as YAML, or null. */
export function parseFrontmatter(content: string): Record<string, unknown> | null {
  if (!content.startsWith("---")) return null;
  const end = content.indexOf("\n---", 3);
  if (end === -1) return null;
  return parseYamlSafe(content.slice(3, end));
}
