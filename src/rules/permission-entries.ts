/**
 * Normalized view of a Claude Code permission rule such as `Bash(npm run build:*)`.
 *
 * Claude Code accepts several spellings for the same grant: `Bash(cmd:*)`
 * (the prefix form the approval prompt writes), `Bash(cmd *)`, `Bash(cmd)`,
 * and commands spelled with an absolute path. Rules that reason about what an
 * allow entry grants must compare the normalized shape, not the raw string.
 */
export interface ParsedPermissionEntry {
  /** Tool name, for example `Bash`, `Write`, `Read`. */
  readonly tool: string;
  /** The raw entry as written in settings. */
  readonly raw: string;
  /** The text inside the parentheses, trimmed. */
  readonly spec: string;
  /** First command token with any directory prefix removed, lowercased. */
  readonly command: string;
  /** Remaining tokens after the command, joined by single spaces. */
  readonly args: string;
  /** `command` plus `args`, the prefix this entry grants. Empty for `Bash(*)`. */
  readonly prefix: string;
  /** True when the entry ends in a wildcard (`:*`, ` *`, or is exactly `*`). */
  readonly wildcard: boolean;
}

export function parsePermissionEntry(entry: string): ParsedPermissionEntry | null {
  const match = entry.match(/^([A-Za-z]+)\((.*)\)$/s);
  if (!match) return null;

  const tool = match[1];
  const spec = match[2].trim();

  // Only Bash entries carry a command line. Other tools take a path or glob
  // pattern, which is kept verbatim; only the bare `*` counts as a wildcard.
  if (tool !== "Bash") {
    const blanket = spec === "*";
    return { tool, raw: entry, spec, command: "", args: "", prefix: blanket ? "" : spec, wildcard: blanket };
  }

  let body = spec;
  let wildcard = false;
  if (body === "*") {
    body = "";
    wildcard = true;
  } else if (body.endsWith(":*")) {
    body = body.slice(0, -2);
    wildcard = true;
  } else if (/\s\*$/.test(body)) {
    body = body.replace(/\s\*$/, "");
    wildcard = true;
  }

  const tokens = body.trim().split(/\s+/).filter(Boolean);
  const rawCommand = tokens[0] ?? "";
  const command = rawCommand.replace(/^.*[\\/]/, "").toLowerCase();
  const args = tokens.slice(1).join(" ");
  const prefix = [command, ...tokens.slice(1)].filter(Boolean).join(" ");

  return { tool, raw: entry, spec, command, args, prefix, wildcard };
}

/**
 * Canonical spelling used by pattern-based checks: the command is reduced to
 * its basename and the `:*` and ` *` wildcard forms collapse to ` *`.
 * `Bash(/opt/homebrew/bin/node -e:*)` becomes `Bash(node -e *)`.
 */
export function normalizePermissionEntry(entry: string): string {
  const parsed = parsePermissionEntry(entry);
  if (!parsed) return entry;
  if (parsed.prefix === "" && parsed.wildcard) return `${parsed.tool}(*)`;
  return `${parsed.tool}(${parsed.prefix}${parsed.wildcard ? " *" : ""})`;
}

/**
 * True when `covering` grants at least everything `covered` grants: same tool,
 * `covering` ends in a wildcard, and its prefix is a token-boundary prefix of
 * the covered entry's prefix. `Bash(*)` covers every Bash entry.
 */
export function entryCovers(covering: ParsedPermissionEntry, covered: ParsedPermissionEntry): boolean {
  if (covering.raw === covered.raw) return false;
  if (covering.tool !== covered.tool) return false;
  if (!covering.wildcard) return false;
  if (covering.prefix === "") return true;
  if (covered.prefix === covering.prefix) return true;
  return covered.prefix.startsWith(`${covering.prefix} `);
}

/**
 * Other allow entries that already grant everything `entry` grants.
 */
export function findCoveringEntries(
  entry: string,
  allEntries: ReadonlyArray<string>,
): ReadonlyArray<string> {
  const covered = parsePermissionEntry(entry);
  if (!covered) return [];
  const covering: string[] = [];
  for (const candidate of allEntries) {
    const parsed = parsePermissionEntry(candidate);
    if (parsed && entryCovers(parsed, covered)) covering.push(candidate);
  }
  return covering;
}
