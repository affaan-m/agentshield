import type { ConfigFile, Finding, Rule, Severity } from "../types.js";

interface DefenseCheck {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly severity: Severity;
  readonly pattern: RegExp;
  readonly owaspRef?: string;
}

const DEFENSE_CHECKS: ReadonlyArray<DefenseCheck> = [
  {
    id: "role-escape",
    name: "Role boundary defense",
    description:
      "Prompt should explicitly reject unauthorized role or persona changes requested by users.",
    severity: "high",
    pattern:
      /(?:do\s+not|never|must\s+not|cannot|don'?t|refuse|reject|ignore)\s+.{0,60}(?:role|persona|character|identity|pretend|act\s+as|impersonat|role.?play)/i,
    owaspRef: "LLM01 Prompt Injection",
  },
  {
    id: "instruction-override",
    name: "Instruction boundary defense",
    description:
      "Prompt should state that user content cannot override, ignore, or modify higher-priority instructions.",
    severity: "critical",
    pattern:
      /(?:do\s+not|never|must\s+not|cannot|don'?t|refuse|reject)\s+.{0,60}(?:override|ignore|disregard|bypass|modify|change|alter)\s+.{0,40}(?:instruction|system|rule|guideline|directive|prompt)/i,
    owaspRef: "LLM01 Prompt Injection",
  },
  {
    id: "data-leakage",
    name: "Data leakage defense",
    description:
      "Prompt should block revealing internal instructions, secrets, or confidential data.",
    severity: "critical",
    pattern:
      /(?:do\s+not|never|must\s+not|cannot|don'?t|refuse)\s+.{0,60}(?:reveal|disclose|share|leak|expose|output|repeat|show)\s+.{0,40}(?:system|prompt|instruction|internal|confidential|secret|private|api.?key|credential)/i,
    owaspRef: "LLM06 Sensitive Information Disclosure",
  },
  {
    id: "output-manipulation",
    name: "Output control defense",
    description:
      "Prompt should constrain risky output forms such as executable code, HTML, links, or scripts.",
    severity: "medium",
    pattern:
      /(?:do\s+not|never|must\s+not|cannot|don'?t|refuse|restrict|limit|only)\s+.{0,60}(?:output|generat|produc|return|render|includ|embed)\s+.{0,40}(?:code|script|html|markdown|link|url|execut|iframe|javascript)/i,
    owaspRef: "LLM02 Insecure Output Handling",
  },
  {
    id: "multilang-bypass",
    name: "Multi-language bypass defense",
    description:
      "Prompt should address attempts to evade safeguards by switching languages or translating unsafe requests.",
    severity: "medium",
    pattern:
      /(?:regardless\s+of\s+(?:the\s+)?language|in\s+(?:any|all|every)\s+language|translat(?:e|ion)\s+.{0,30}(?:rule|instruction|safety|restrict)|language\s+.{0,20}(?:bypass|circumvent|evade))/i,
  },
  {
    id: "unicode-attack",
    name: "Unicode and encoding defense",
    description:
      "Prompt should mention unicode, invisible characters, homoglyphs, or encoding tricks as suspicious input.",
    severity: "medium",
    pattern:
      /(?:unicode|homoglyph|invisible\s+character|zero.?width|encod(?:ed|ing)\s+.{0,20}(?:trick|attack|bypass|evas)|special\s+character|non.?printable)/i,
  },
  {
    id: "context-overflow",
    name: "Context overflow defense",
    description:
      "Prompt should acknowledge input-length or token-window limits and reject attempts to push safeguards out of context.",
    severity: "medium",
    pattern:
      /(?:(?:context|token|input|message)\s+.{0,20}(?:limit|length|overflow|window|exceed|truncat|maximum)|too\s+(?:long|large|many)\s+.{0,20}(?:input|token|message|character)|length\s+.{0,10}(?:restrict|limit|cap|max))/i,
  },
  {
    id: "indirect-injection",
    name: "Indirect injection defense",
    description:
      "Prompt should treat external or fetched content as untrusted and warn about embedded instructions in tool/document output.",
    severity: "high",
    pattern:
      /(?:(?:external|third.?party|user.?provided|untrusted|fetched|retrieved)\s+.{0,30}(?:data|content|source|input|document|url|link|tool)\s+.{0,30}(?:instruct|command|inject|malicious|trust)|indirect\s+.{0,10}(?:inject|prompt|attack))/i,
    owaspRef: "LLM01 Prompt Injection",
  },
  {
    id: "social-engineering",
    name: "Social engineering defense",
    description:
      "Prompt should account for urgency, emotional manipulation, or fake authority claims used to bypass safeguards.",
    severity: "medium",
    pattern:
      /(?:(?:emotional|urgency|authority|guilt|sympathy|emergency|life.?or.?death|dying|threaten)\s+.{0,30}(?:manipulat|appeal|pressure|claim|bypass|trick|override)|social\s+engineer)/i,
  },
  {
    id: "output-weaponization",
    name: "Harmful content defense",
    description:
      "Prompt should block dangerous, weaponizable, exploitative, or illegal output.",
    severity: "high",
    pattern:
      /(?:do\s+not|never|must\s+not|cannot|don'?t|refuse)\s+.{0,60}(?:harm(?:ful)?|danger(?:ous)?|illegal|weapon|violen(?:t|ce)|exploit|malware|phishing|attack(?:s|ing)?)/i,
    owaspRef: "LLM09 Overreliance",
  },
  {
    id: "abuse-prevention",
    name: "Abuse prevention defense",
    description:
      "Prompt should mention repeated abuse, rate limiting, or session/isolation boundaries.",
    severity: "low",
    pattern:
      /(?:abuse|misuse|exploit(?:ation)?|repeated\s+(?:attempt|request|abuse)|rate\s+limit|session\s+(?:isolat|boundar)|detect\s+.{0,20}(?:abuse|pattern|manipulat))/i,
  },
  {
    id: "input-validation-missing",
    name: "Input validation defense",
    description:
      "Prompt should instruct the agent to validate, sanitize, inspect, or reject suspicious input.",
    severity: "medium",
    pattern:
      /(?:(?:valid|saniti|verif|check|inspect|reject|filter|screen)\s+.{0,30}(?:input|request|query|message|user\s+(?:input|data|message))|malform|suspicious\s+.{0,10}(?:input|request|pattern))/i,
    owaspRef: "LLM01 Prompt Injection",
  },
];

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").toLowerCase();
}

function isPromptPostureFile(file: ConfigFile): boolean {
  if (file.type === "claude-md" || file.type === "agent-md") return true;

  if (file.type !== "rule-md") return false;

  const normalizedPath = normalizePath(file.path);
  return normalizedPath.includes("/.claude/rules/") || normalizedPath.startsWith(".claude/rules/");
}

export const promptDefenseRules: ReadonlyArray<Rule> = [
  {
    id: "prompt-defense-posture",
    name: "Prompt defense posture audit",
    description:
      "Checks whether system prompt files contain defensive instructions against common LLM attack vectors.",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isPromptPostureFile(file)) return [];

      const content = file.content.trim();
      if (!content) return [];

      const findings: Finding[] = [];

      for (const defense of DEFENSE_CHECKS) {
        if (defense.pattern.test(content)) continue;

        const owaspNote = defense.owaspRef ? ` (OWASP LLM Top 10: ${defense.owaspRef})` : "";
        findings.push({
          id: `prompt-defense-missing-${defense.id}-${file.path}`,
          severity: defense.severity,
          category: "injection",
          title: `Missing prompt defense: ${defense.name}`,
          description: `${defense.description}${owaspNote}`,
          file: file.path,
          evidence: `Missing ${defense.id} defense in ${file.path}`,
        });
      }

      return findings;
    },
  },
];
