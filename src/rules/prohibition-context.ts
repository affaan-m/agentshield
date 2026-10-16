/**
 * Prohibition context for rules that match dangerous tokens in prose.
 *
 * "Never use --no-verify" names the flag in order to forbid it. These helpers
 * decide whether the clause leading up to a match forbids it, so the caller
 * can report the match as an informational good practice instead of a risk.
 *
 * A prohibition only counts when it governs the match:
 * - it sits in the same clause: a sentence end, a comma, a coordinating word
 *   ("and", "then", "et", "puis"...) or a new Markdown block starts a new
 *   clause, so "Avoid review and run git push --force" is not a prohibition;
 * - it opens that clause, within its first few words, so "Approval is not
 *   needed to run" or a negation buried in a condition does not count;
 * - the clause is not a condition: "If approval is not available run" asks
 *   for the operation.
 *
 * English cues come first. The other cues cover the languages instruction
 * files are most often written in, so a French or German rule set reads the
 * same way as its English translation (#163). Encouraging idioms such as
 * "don't hesitate to" contain a negation but ask for the action: they are
 * removed before the cues are read, so "Don't forget to never use" still
 * forbids. When in doubt the helpers return false and the caller keeps the
 * original severity.
 */

/** Hyphens count as word characters, so flags such as --no-edit are not read as negations. */
const WORD_START = "(?<![\\p{L}\\p{N}_-])";
const WORD_END = "(?![\\p{L}\\p{N}_-])";

function wordPattern(alternatives: string): RegExp {
  return new RegExp(`${WORD_START}(?:${alternatives})${WORD_END}`, "giu");
}

function findAllMatches(content: string, pattern: RegExp): ReadonlyArray<RegExpMatchArray> {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return [...content.matchAll(new RegExp(pattern.source, flags))];
}

const PROHIBITIVE_CUES: ReadonlyArray<RegExp> = [
  // English. A bare "not" is left out: "approval is not needed" forbids nothing.
  wordPattern(
    [
      "never",
      "no",
      "don'?t|doesn'?t|do\\s+not|does\\s+not",
      "must\\s*not|mustn'?t|should\\s*not|shouldn'?t|shall\\s+not|may\\s+not",
      "cannot|can'?t|will\\s+not|won'?t",
      "not\\s+(?:allowed|permitted|acceptable|authori[sz]ed)",
      "avoid\\p{L}*|refrain\\p{L}*|prohibit\\p{L}*|forbid\\p{L}*|disabl\\p{L}*",
      // Whole words only: "bank" or "blockchain" are not prohibitions.
      "ban(?:s|ned|ning)?|block(?:s|ed|ing|list)?",
    ].join("|")
  ),
  // French
  wordPattern("jamais|ne|pas|aucun(?:e|s|es)?|interdi\\p{L}*|proscri\\p{L}*"),
  new RegExp(`${WORD_START}n['’](?=\\p{L})`, "giu"),
  // Spanish, Portuguese, and Italian, plus French "éviter"
  wordPattern(
    "nunca|jamás|não|ning[uú]n[ao]?s?|proh?[ií]b\\p{L}*|vietat\\p{L}*|[ée]vit\\p{L}*|mai|non"
  ),
  // German
  wordPattern("nie|niemals|nicht|kein\\p{L}*|verbot\\p{L}*|vermeid\\p{L}*"),
];

const ENCOURAGING_PHRASES: ReadonlyArray<RegExp> = [
  wordPattern(
    "(?:do\\s+not|don'?t|never)\\s+(?:hesitate|forget|wait|bother|ask|worry)\\p{L}*|never\\s+mind|no\\s+(?:need|problem|worries)"
  ),
  // French: "n'hésite pas", "n'oubliez pas", "ne demande pas", "pas besoin de"...
  new RegExp(`${WORD_START}n['’](?:h[ée]sit|oubli|attend)\\p{L}*(?:\\s+pas)?${WORD_END}`, "giu"),
  wordPattern("ne\\s+(?:demand|attend|t['’]inqui[eè]t|vous\\s+inqui[eé]t)\\p{L}*\\s+pas"),
  wordPattern("(?:il\\s+)?n['’]y\\s+a\\s+pas\\s+de\\s+(?:probl[eè]me|souci)|pas\\s+(?:besoin|de\\s+(?:probl[eè]me|souci))"),
  // Spanish, Portuguese, Italian, German
  wordPattern("no\\s+(?:dudes|olvides|esperes|hace\\s+falta|hay\\s+problema)|não\\s+(?:hesite|esqueça)"),
  wordPattern("non\\s+(?:esitare|dimenticare)|z[öo]gere\\s+nicht|vergiss\\s+nicht|kein\\s+problem"),
];

/** A clause that opens with a condition asks for the operation under that condition. */
const CONDITIONAL_OPENING = wordPattern(
  "if|when(?:ever)?|unless|once|in\\s+case|si|quand|lorsque|sauf|cuando|quando|wenn|falls|sobald|außer"
);

/** Coordinating words start a new clause: "Avoid review and run ...". */
const CLAUSE_CONNECTORS = wordPattern(
  [
    "and|then|but|so|otherwise|else|instead",
    "et|puis|mais|sinon|ensuite|alors|donc",
    "y|luego|pero|sino|entonces",
    "e|depois|mas|então|senão|poi|però|altrimenti|quindi",
    "und|dann|aber|sonst|danach",
  ].join("|")
);

/** Sentence ends, semicolons, and commas end a clause. A period inside ".claude" does not. */
const PUNCTUATION_BREAK = /[.!?](?=\s|$)|[;,]/g;

/**
 * A line break ends a clause unless it is a soft wrap inside a Markdown
 * paragraph: the next line continues in lowercase or with inline code, and is
 * not a list item, heading, quote, table row, or fence.
 */
const HARD_LINE_BREAK = /\r?\n(?![ \t]*[\p{Ll}`'"(])/gu;

/** The leading words of a clause that may hold its prohibition. */
const MAX_WORDS_BEFORE_CUE = 4;

const LIST_MARKER = /^[\s>*+\-#|]*(?:\d+[.)]\s*)?/;

/**
 * The clause leading up to `index`, limited to `maxChars` characters. In "Do
 * not ask; use the Bash tool to delete", the clause before "use" does not
 * contain the negation.
 */
export function clauseBefore(content: string, index: number, maxChars = 120): string {
  const start = Math.max(0, index - maxChars);
  const window = content.slice(start, index);
  // The match itself stays visible, so a line break right before it can be read as a soft wrap.
  const withMatch = content.slice(start, index + 1);
  const breaks = [PUNCTUATION_BREAK, HARD_LINE_BREAK, CLAUSE_CONNECTORS]
    .flatMap((pattern) => findAllMatches(withMatch, pattern))
    .map((match) => (match.index ?? 0) + match[0].length)
    .filter((end) => end <= window.length);
  return window.slice(breaks.length === 0 ? 0 : Math.max(...breaks));
}

/** True when `clause` opens with prohibitive wording that is not an encouraging idiom. */
export function hasProhibitiveCue(clause: string): boolean {
  const withoutIdioms = ENCOURAGING_PHRASES.reduce(
    (text, phrase) => text.replace(new RegExp(phrase.source, phrase.flags), " "),
    clause
  );
  const text = withoutIdioms.replace(LIST_MARKER, "");
  if (findAllMatches(text, CONDITIONAL_OPENING).some((match) => match.index === 0)) return false;

  const cueIndexes = PROHIBITIVE_CUES.flatMap((cue) =>
    findAllMatches(text, cue).map((match) => match.index ?? 0)
  );
  if (cueIndexes.length === 0) return false;

  const wordsBeforeCue = findAllMatches(text.slice(0, Math.min(...cueIndexes)), /[\p{L}\p{N}]+/gu).length;
  return wordsBeforeCue <= MAX_WORDS_BEFORE_CUE;
}

/** True when the clause leading up to `index` forbids what is found there. */
export function isProhibitedAt(content: string, index: number, maxChars = 120): boolean {
  return hasProhibitiveCue(clauseBefore(content, index, maxChars));
}
