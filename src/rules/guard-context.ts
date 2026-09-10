/**
 * Guard-pattern context detection for hook rules.
 *
 * A PreToolUse guard that greps for `mkfs` in order to deny it contains the
 * dangerous token as data, not as an executed command. These helpers decide
 * whether a regex match sits in such a context so the caller can report the
 * match as an informational "guard pattern" instead of flagging the defense.
 *
 * Everything here fails closed: when the context is ambiguous the helpers
 * return false and the caller keeps the original severity.
 */

export interface GuardContextOptions {
  /** True when the content comes from a hook configuration file (settings.json, hooks.json). */
  readonly isHookConfig?: boolean;
}

interface QuoteSpan {
  /** Index of the opening quote within the line. */
  readonly open: number;
  /** Index of the closing quote within the line. */
  readonly close: number;
  readonly quote: "'" | '"';
}

interface LineBounds {
  readonly start: number;
  readonly end: number;
}

const DENY_SIGNAL_PATTERNS: ReadonlyArray<RegExp> = [
  /"decision"\s*:\s*"deny"/,
  /"permissionDecision"\s*:\s*"deny"/,
  /\bexit\s+[12]\b/,
  /\breturn\s+1\b/,
  /\bprocess\.exit\s*\(\s*2\s*\)/,
  /\bsys\.exit\s*\(\s*2\s*\)/,
  /\becho\b.*\bblocked\b/i,
];

const BLOCK_TERMINATOR_PATTERN = /^\s*(?:fi|esac|done|\}|\)|;;|end)\s*;?\s*$/;

const DENY_LIST_KEY_PATTERN = /(?:deny|denied|block|blocked|blocklist|denylist|forbid|forbidden|disallow|disallowed|banned)/i;
const HOOK_CONFIG_LIST_KEY_PATTERN = /^patterns?$/i;
const NEUTRAL_LIST_KEY_PATTERN = /^(?:patterns?|commands?|list|items|values|entries|matchers?|regex(?:es)?|rules?)$/i;

/** Shell separators that start a new simple command. */
const COMMAND_SEPARATOR_PATTERN = /&&|\|\||\||;|\(|\{|`|\bif\b|\belif\b|\bwhile\b|\buntil\b|\bthen\b|\bdo\b|\belse\b|(?:^|\s)!(?=\s)/;

const GREP_COMMAND_PATTERN = /^(?:command\s+|\\)?(?:grep|egrep|fgrep|rg|ag|pcregrep|pcre2grep)(?:\s+(?:-{1,2}[^\s'"]+|'[^']*'|"[^"]*"))*\s*$/;
const AWK_COMMAND_PATTERN = /^(?:command\s+)?[gmn]?awk(?:\s+(?:-{1,2}[^\s'"]+(?:\s+[^\s'"-][^\s'"]*)?))*\s*$/;
const SED_COMMAND_PATTERN = /^(?:command\s+)?sed(?:\s+-{1,2}[^\s'"]+)*\s*$/;
const JQ_COMMAND_PATTERN = /^(?:command\s+)?jq(?:\s+(?:-{1,2}[^\s'"]+|'[^']*'|"[^"]*"))*\s*$/;
const PRINT_COMMAND_PATTERN = /^(?:command\s+)?(?:echo|printf)(?:\s+-[a-zA-Z]+)*\s*$/;
/** Wording that marks a printed string as a deny message rather than a command. */
const DENY_MESSAGE_PATTERN = /"(?:decision|permissionDecision)"\s*:\s*"deny"|\b(?:blocked|denied|not allowed|forbidden|refus(?:ed|ing))\b/i;

const AWK_REGEX_BEFORE_PATTERN = /(?:^|[\s(!~,;{])\/(?:[^/\\]|\\.)*$/;
const AWK_REGEX_AFTER_PATTERN = /^(?:[^/\\]|\\.)*\//;
const AWK_STRING_MATCH_BEFORE_PATTERN = /(?:~\s*"[^"]*|\bindex\s*\([^)]*"[^"]*)$/;

const SED_ADDRESS_BEFORE_PATTERN = /(?:^|[;\s])\/(?:[^/\\]|\\.)*$/;
const SED_MATCH_ONLY_AFTER_PATTERN = /^(?:[^/\\]|\\.)*\/(?:,\/(?:[^/\\]|\\.)*\/)?I?!?[dpq](?:\s*[;}]|\s*$)/;

const JQ_MATCH_CALL_PATTERN = /\b(?:test|match|contains|startswith|endswith|inside|select)\s*\(/g;

const PYTHON_RE_BEFORE_PATTERN = /\bre\.(?:search|match|fullmatch|compile|findall|finditer)\s*\(\s*$/;
const MEMBERSHIP_TUPLE_BEFORE_PATTERN = /\bin\s*[([{]\s*(?:[rbfuRBFU]*(?:"[^"]*"|'[^']*')\s*,\s*)*$/;
const MEMBERSHIP_AFTER_PATTERN = /^\s+(?:not\s+)?in\s+\S/;
const STRING_METHOD_BEFORE_PATTERN = /\.(?:startswith|endswith|test|match|includes|search|startsWith|endsWith|indexOf)\s*\(\s*$/;
const NEW_REGEXP_BEFORE_PATTERN = /\bnew\s+RegExp\s*\(\s*$/;
const DENY_LIST_LITERAL_BEFORE_PATTERN = /\b(?:deny|denied|block|blocked|blocklist|denylist|forbidden|disallowed|banned)\w*\s*[=:]\s*[([{]\s*(?:[rbfuRBFU]*(?:"[^"]*"|'[^']*')\s*,\s*)*$/i;

const JS_REGEX_LITERAL_BEFORE_PATTERN = /(?:^|[=(,:!&|?\s])\/(?:[^/\\\n]|\\.)*$/;
const JS_REGEX_LITERAL_TEST_AFTER_PATTERN = /^(?:[^/\\\n]|\\.)*\/[dgimsuvy]*\s*\.(?:test|exec)\s*\(/;
const JS_REGEX_LITERAL_MATCH_BEFORE_PATTERN = /\.(?:match|search|matchAll)\s*\(\s*\/(?:[^/\\\n]|\\.)*$/;

const SHELL_TEST_OPEN_PATTERN = /(?:^|[\s(!;&|])\[\[?\s/g;
const SHELL_TEST_CLOSE_PATTERN = /\s\]\]?(?:\s|$|;|&|\|)/;
const SHELL_TEST_OPERATOR_PATTERN = /(?:=~|==|!=|\s=\s)/;

const CASE_OPEN_PATTERN = /\bcase\s+(?:"[^"]*"|'[^']*'|\S+)\s+in\b/g;
const CASE_CLOSE_PATTERN = /\besac\b/g;
const CASE_PATTERN_LINE_PATTERN = /^\s*\(?\s*(?:(?:"[^"]*"|'[^']*'|[^\s()|;&"'])+\s*\|\s*)*(?:"[^"]*"|'[^']*'|[^\s()|;&"'])+\s*\)/;

/** Text that turns quoted data back into an executed command. */
const EXECUTION_SINK_PATTERN = /\|\s*(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b|\beval\b|\bsource\b|\bexec\b|\bxargs\b/;
const COMMAND_SUBSTITUTION_PATTERN = /\$\(|`/;

function findAllMatches(content: string, pattern: RegExp): Array<RegExpMatchArray> {
  return [...content.matchAll(new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g"))];
}

function getLineBounds(content: string, index: number): LineBounds {
  const start = content.lastIndexOf("\n", index - 1) + 1;
  const nextNewline = content.indexOf("\n", index);
  return { start, end: nextNewline === -1 ? content.length : nextNewline };
}

/**
 * Finds the single- or double-quoted span enclosing `relativeIndex` on a line.
 * Returns null when the index is unquoted or the quote never closes on the line.
 */
function getQuoteSpan(line: string, relativeIndex: number): QuoteSpan | null {
  let quote: "'" | '"' | null = null;
  let open = -1;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];

    if (quote === '"' && ch === "\\") {
      i += 1;
      continue;
    }

    if (quote === null && ch === "\\") {
      i += 1;
      continue;
    }

    if (quote === null && (ch === "'" || ch === '"')) {
      quote = ch;
      open = i;
      continue;
    }

    if (quote !== null && ch === quote) {
      if (open < relativeIndex && relativeIndex < i) {
        return { open, close: i, quote };
      }
      quote = null;
      open = -1;
      continue;
    }

    if (i === relativeIndex && quote === null) {
      return null;
    }
  }

  return null;
}

function getSimpleCommandPrefix(before: string): string {
  const segments = before.split(COMMAND_SEPARATOR_PATTERN);
  return (segments[segments.length - 1] ?? "").trimStart();
}

function lastCallIsOpen(text: string, callPattern: RegExp): boolean {
  const calls = findAllMatches(text, callPattern);
  const last = calls[calls.length - 1];
  if (!last || last.index === undefined) return false;
  return !text.slice(last.index + last[0].length).includes(")");
}

function isQuotedMatchingArgument(line: string, span: QuoteSpan, relativeIndex: number): boolean {
  const beforeQuote = line.slice(0, span.open);
  const afterQuote = line.slice(span.close + 1);
  const quotedBefore = line.slice(span.open + 1, relativeIndex);
  const quotedAfter = line.slice(relativeIndex, span.close);

  if (COMMAND_SUBSTITUTION_PATTERN.test(quotedBefore)) return false;
  if (EXECUTION_SINK_PATTERN.test(afterQuote)) return false;

  const commandPrefix = getSimpleCommandPrefix(beforeQuote);

  if (GREP_COMMAND_PATTERN.test(commandPrefix)) return true;

  if (AWK_COMMAND_PATTERN.test(commandPrefix)) {
    if (AWK_REGEX_BEFORE_PATTERN.test(quotedBefore) && AWK_REGEX_AFTER_PATTERN.test(quotedAfter)) return true;
    return AWK_STRING_MATCH_BEFORE_PATTERN.test(quotedBefore);
  }

  if (SED_COMMAND_PATTERN.test(commandPrefix)) {
    return SED_ADDRESS_BEFORE_PATTERN.test(quotedBefore) && SED_MATCH_ONLY_AFTER_PATTERN.test(quotedAfter);
  }

  if (JQ_COMMAND_PATTERN.test(commandPrefix)) {
    return lastCallIsOpen(quotedBefore, JQ_MATCH_CALL_PATTERN);
  }

  // echo '{"decision":"deny","reason":"Blocked: mkfs"}' prints a deny message
  // that names the token; the string is output, not executed.
  if (PRINT_COMMAND_PATTERN.test(commandPrefix)) {
    return DENY_MESSAGE_PATTERN.test(line.slice(span.open + 1, span.close));
  }

  // Python / JavaScript string checks. Strip a raw/bytes string prefix first.
  const beforeQuoteCore = beforeQuote.replace(/[rbfuRBFU]+$/, "");

  if (PYTHON_RE_BEFORE_PATTERN.test(beforeQuoteCore)) return true;
  if (MEMBERSHIP_TUPLE_BEFORE_PATTERN.test(beforeQuoteCore)) return true;
  if (STRING_METHOD_BEFORE_PATTERN.test(beforeQuoteCore)) return true;
  if (NEW_REGEXP_BEFORE_PATTERN.test(beforeQuoteCore)) return true;
  if (DENY_LIST_LITERAL_BEFORE_PATTERN.test(beforeQuoteCore)) return true;
  if (MEMBERSHIP_AFTER_PATTERN.test(afterQuote)) return true;

  return false;
}

function isInsideShellTest(line: string, contextStart: number, relativeIndex: number): boolean {
  const prefix = line.slice(0, contextStart);
  const opens = findAllMatches(prefix, SHELL_TEST_OPEN_PATTERN);
  const lastOpen = opens[opens.length - 1];
  if (!lastOpen || lastOpen.index === undefined) return false;

  const afterOpen = prefix.slice(lastOpen.index + lastOpen[0].length);
  if (SHELL_TEST_CLOSE_PATTERN.test(afterOpen)) return false;
  if (COMMAND_SUBSTITUTION_PATTERN.test(afterOpen)) return false;
  if (!SHELL_TEST_OPERATOR_PATTERN.test(afterOpen)) return false;

  const rest = line.slice(relativeIndex);
  return SHELL_TEST_CLOSE_PATTERN.test(rest);
}

function isCaseBlockActive(content: string, lineStart: number): boolean {
  const preceding = content.slice(0, lineStart);
  const opens = findAllMatches(preceding, CASE_OPEN_PATTERN);
  const closes = findAllMatches(preceding, CASE_CLOSE_PATTERN);
  const lastOpen = opens[opens.length - 1]?.index ?? -1;
  const lastClose = closes[closes.length - 1]?.index ?? -1;
  return lastOpen > lastClose;
}

function isCasePatternLine(content: string, bounds: LineBounds, matchIndex: number): boolean {
  const line = content.slice(bounds.start, bounds.end);
  const relativeIndex = matchIndex - bounds.start;

  // Inline form: case "$cmd" in *mkfs*) ...
  const inlineOpen = findAllMatches(line.slice(0, relativeIndex), CASE_OPEN_PATTERN);
  const lastInline = inlineOpen[inlineOpen.length - 1];
  const patternStart = lastInline && lastInline.index !== undefined ? lastInline.index + lastInline[0].length : 0;

  if (patternStart === 0 && !isCaseBlockActive(content, bounds.start)) return false;

  const patternLine = line.slice(patternStart);
  const patternMatch = CASE_PATTERN_LINE_PATTERN.exec(patternLine);
  if (!patternMatch) return false;

  const patternEnd = patternStart + patternMatch[0].length;
  return relativeIndex < patternEnd;
}

function isJsRegexLiteralCheck(line: string, relativeIndex: number): boolean {
  const before = line.slice(0, relativeIndex);
  const after = line.slice(relativeIndex);

  if (JS_REGEX_LITERAL_MATCH_BEFORE_PATTERN.test(before)) return true;
  return JS_REGEX_LITERAL_BEFORE_PATTERN.test(before) && JS_REGEX_LITERAL_TEST_AFTER_PATTERN.test(after);
}

interface DenyListWalkState {
  /** Nearest object key above the current node. */
  readonly nearestKey: string | null;
  /** True when some ancestor key names a deny or block list. */
  readonly ancestorDenyKey: boolean;
  /** True when the current node is an element of an array (a list entry, not a single value). */
  readonly inList: boolean;
}

function collectDenyListStrings(
  node: unknown,
  state: DenyListWalkState,
  isHookConfig: boolean,
  output: string[],
): void {
  if (typeof node === "string") {
    if (state.nearestKey === null) return;
    const keyIsDeny =
      DENY_LIST_KEY_PATTERN.test(state.nearestKey) ||
      (isHookConfig && HOOK_CONFIG_LIST_KEY_PATTERN.test(state.nearestKey));
    // A neutral list name (commands, patterns, ...) only counts when it holds a
    // list under a deny key. A single "command" string under a deny-named object
    // is more likely something the hook runs.
    const keyIsNeutralUnderDeny =
      state.ancestorDenyKey && state.inList && NEUTRAL_LIST_KEY_PATTERN.test(state.nearestKey);
    if (keyIsDeny || keyIsNeutralUnderDeny) output.push(node);
    return;
  }

  if (Array.isArray(node)) {
    for (const element of node) {
      collectDenyListStrings(element, { ...state, inList: true }, isHookConfig, output);
    }
    return;
  }

  if (node && typeof node === "object") {
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      collectDenyListStrings(
        value,
        {
          nearestKey: key,
          ancestorDenyKey: state.ancestorDenyKey || DENY_LIST_KEY_PATTERN.test(key),
          inList: false,
        },
        isHookConfig,
        output,
      );
    }
  }
}

function isInsideJsonDenyListValue(content: string, matchIndex: number, isHookConfig: boolean): boolean {
  const trimmed = content.trimStart();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return false;

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return false;
  }

  const values: string[] = [];
  collectDenyListStrings(parsed, { nearestKey: null, ancestorDenyKey: false, inList: false }, isHookConfig, values);

  const searchOffsets = new Map<string, number>();
  for (const value of values) {
    const encoded = JSON.stringify(value).slice(1, -1);
    if (encoded.length === 0) continue;
    const startIndex = searchOffsets.get(encoded) ?? 0;
    const index = content.indexOf(encoded, startIndex);
    if (index === -1) continue;
    searchOffsets.set(encoded, index + encoded.length);
    if (matchIndex >= index && matchIndex < index + encoded.length) return true;
  }

  return false;
}

/**
 * Returns true when the match at `matchIndex` sits in a guard-pattern
 * context: a quoted argument to a matching or filtering command (grep, awk,
 * sed match-only forms, jq select/test, python re.* and membership checks,
 * JS .test/.match/.includes/new RegExp), a `[[ ... =~ ... ]]` or `[[ ... == ... ]]`
 * test, a case pattern line, or a JSON string under a deny/block list key.
 *
 * A match that is later eval'd, piped to a shell, or produced by command
 * substitution is never treated as a guard.
 */
export function isGuardPatternContext(
  content: string,
  matchIndex: number,
  options: GuardContextOptions = {},
): boolean {
  if (matchIndex < 0 || matchIndex >= content.length) return false;

  if (isInsideJsonDenyListValue(content, matchIndex, options.isHookConfig === true)) return true;

  const bounds = getLineBounds(content, matchIndex);
  const line = content.slice(bounds.start, bounds.end);
  const relativeIndex = matchIndex - bounds.start;

  if (line.trimStart().startsWith("#")) return false;

  const span = getQuoteSpan(line, relativeIndex);

  if (span !== null) {
    if (isQuotedMatchingArgument(line, span, relativeIndex)) return true;
    if (EXECUTION_SINK_PATTERN.test(line.slice(span.close + 1))) return false;
    if (COMMAND_SUBSTITUTION_PATTERN.test(line.slice(span.open + 1, relativeIndex))) return false;
    if (isInsideShellTest(line, span.open, relativeIndex)) return true;
    return isCasePatternLine(content, bounds, matchIndex);
  }

  if (EXECUTION_SINK_PATTERN.test(line.slice(relativeIndex))) return false;

  if (isInsideShellTest(line, relativeIndex, relativeIndex)) return true;
  if (isCasePatternLine(content, bounds, matchIndex)) return true;
  return isJsRegexLiteralCheck(line, relativeIndex);
}

/**
 * Returns true when the block enclosing the match (the match line plus the
 * following lines up to a closing fi/esac/}/;; or a blank line, capped at
 * `maxLines`) contains a deny signal such as `"decision":"deny"`, `exit 2`,
 * `return 1`, `process.exit(2)`, or an echo mentioning "Blocked".
 */
export function hasDenySignalInBlock(content: string, matchIndex: number, maxLines = 12): boolean {
  if (matchIndex < 0 || matchIndex > content.length) return false;

  const { start } = getLineBounds(content, matchIndex);
  const lines = content.slice(start).split("\n");
  const limit = Math.min(lines.length, Math.max(1, maxLines));

  for (let i = 0; i < limit; i++) {
    const line = lines[i] ?? "";
    if (i > 0 && line.trim().length === 0) return false;
    if (DENY_SIGNAL_PATTERNS.some((pattern) => pattern.test(line))) return true;
    if (i > 0 && BLOCK_TERMINATOR_PATTERN.test(line)) return false;
  }

  return false;
}
