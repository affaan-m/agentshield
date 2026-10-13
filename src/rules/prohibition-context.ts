/**
 * Prohibition context for rules that match dangerous tokens in prose.
 *
 * "Never use --no-verify" names the flag in order to forbid it. These helpers
 * decide whether the text leading up to a match is prohibitive, so the caller
 * can report the match as an informational good practice instead of a risk.
 *
 * English cues come first. The other cues cover the languages instruction
 * files are most often written in, so a French or German rule set reads the
 * same way as its English translation (#163). Encouraging idioms such as
 * "don't hesitate to" contain a negation but ask for the action, so they
 * cancel the prohibition. When in doubt the helpers return false and the
 * caller keeps the original severity.
 */

/** Hyphens count as word characters, so flags such as --no-edit are not read as negations. */
const WORD_START = "(?<![\\p{L}\\p{N}_-])";
const WORD_END = "(?![\\p{L}\\p{N}_-])";

function wordPattern(alternatives: string): RegExp {
  return new RegExp(`${WORD_START}(?:${alternatives})${WORD_END}`, "iu");
}

const ENGLISH_PROHIBITIVE_CUES: ReadonlyArray<RegExp> = [
  /\bnever\b/i,
  /\bdon'?t\b/i,
  /\bdo\s+not\b/i,
  /\bnot\b/i,
  /\bavoid\b/i,
  /\bprohibit/i,
  /\bforbid/i,
  /\bdisable/i,
  // Whole words only: "bank" or "blockchain" are not prohibitions.
  /\bban(?:s|ned|ning)?\b/i,
  /\bblock(?:s|ed|ing|list)?\b/i,
];

const OTHER_LANGUAGE_PROHIBITIVE_CUES: ReadonlyArray<RegExp> = [
  // French
  wordPattern("jamais|ne|pas|aucun(?:e|s|es)?|interdi\\p{L}*|proscri\\p{L}*"),
  new RegExp(`${WORD_START}n['’](?=\\p{L})`, "iu"),
  // Spanish, Portuguese, and Italian, plus French "éviter"
  wordPattern(
    "nunca|jamás|não|ning[uú]n[ao]?s?|prohibid\\p{L}*|proibid\\p{L}*|vietat\\p{L}*|[ée]vit\\p{L}*|mai|non"
  ),
  // German
  wordPattern("nie|niemals|nicht|kein\\p{L}*|verbot\\p{L}*|vermeid\\p{L}*"),
];

const ENCOURAGING_PHRASES: ReadonlyArray<RegExp> = [
  /\b(?:do\s+not|don'?t|never)\s+(?:hesitate|forget|wait|bother|ask)\b/i,
  // French: "n'hésite pas", "n'oubliez pas", "n'attends pas", "ne demande pas"
  new RegExp(`${WORD_START}n['’](?:h[ée]sit|oubli|attend)\\p{L}*`, "iu"),
  new RegExp(`${WORD_START}ne\\s+(?:demand|attend)\\p{L}*\\s+pas${WORD_END}`, "iu"),
];

/** True when the text contains prohibitive wording that is not an encouraging idiom. */
export function hasProhibitiveCue(text: string): boolean {
  if (ENCOURAGING_PHRASES.some((phrase) => phrase.test(text))) return false;
  return (
    ENGLISH_PROHIBITIVE_CUES.some((cue) => cue.test(text)) ||
    OTHER_LANGUAGE_PROHIBITIVE_CUES.some((cue) => cue.test(text))
  );
}

const CLAUSE_BREAKS: ReadonlyArray<string> = [".", ";", "!", "?", ",", "\n"];

/**
 * The clause leading up to `index`: the text after the closest sentence or
 * clause break, limited to `maxChars` characters. In "Do not ask; use the Bash
 * tool to delete", the clause before "use" does not contain the negation.
 */
export function clauseBefore(content: string, index: number, maxChars = 120): string {
  const window = content.slice(Math.max(0, index - maxChars), index);
  const lastBreak = Math.max(...CLAUSE_BREAKS.map((mark) => window.lastIndexOf(mark)));
  return window.slice(lastBreak + 1);
}
