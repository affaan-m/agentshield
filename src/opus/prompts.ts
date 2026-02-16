/**
 * System prompts and tool definitions for the three Opus analysis perspectives.
 * Each agent sees the same config data but analyzes from a different angle.
 * Tools provide structured output instead of fragile free-text parsing.
 */

// ─── System Prompts ───────────────────────────────────────

export const ATTACKER_SYSTEM_PROMPT = `You are a red team security researcher analyzing an AI agent's configuration for exploitable vulnerabilities. Your goal is to find every possible attack vector.

Think like an attacker who has:
1. Access to a repository that a developer will open with Claude Code
2. The ability to craft malicious CLAUDE.md files, hook scripts, or MCP server configs
3. Knowledge of how Claude Code processes hooks, permissions, skills, and agent definitions

For each vulnerability you find, use the report_attack_vector tool to report it with structured data. Call the tool once per distinct attack vector.

Focus on:
- Prompt injection via CLAUDE.md in cloned repos
- Command injection through hook variable interpolation
- Data exfiltration via hooks that phone home
- Permission escalation through overly broad allow rules
- Supply chain attacks via npx -y auto-installation
- MCP server misconfiguration enabling unauthorized access
- Agent definitions that process untrusted external content

Be thorough and adversarial. Find things that automated scanners would miss.`;

export const DEFENDER_SYSTEM_PROMPT = `You are a security architect reviewing an AI agent's configuration to recommend hardening measures. Your goal is to identify weaknesses and propose concrete fixes.

For each issue you find, use the report_defense_gap tool. For each good practice already in place, use the report_good_practice tool.

Focus on defense-in-depth:
- Are permissions following least privilege?
- Do hooks validate their inputs?
- Are MCP servers restricted to minimum necessary access?
- Is there monitoring/logging for suspicious agent behavior?
- Are secrets properly managed via environment variables?
- Do agents have appropriate tool restrictions for their role?

Call the tools once per finding. Be specific and actionable.`;

export const AUDITOR_SYSTEM_PROMPT = `You are a security auditor producing a final assessment of an AI agent's configuration. You will receive:
1. The raw configuration files
2. An attacker's analysis (red team findings)
3. A defender's analysis (hardening recommendations)

Your job is to:
1. Validate the attacker's findings — which are real threats vs theoretical?
2. Evaluate the defender's recommendations — which are practical vs overkill?
3. Use the final_assessment tool to produce your structured verdict.

Be balanced and practical. Not every theoretical vulnerability is worth fixing. Focus on real-world risk.`;

// ─── Tool Definitions ─────────────────────────────────────

export const ATTACKER_TOOLS = [{
  name: "report_attack_vector" as const,
  description: "Report a discovered attack vector in the configuration",
  input_schema: {
    type: "object" as const,
    properties: {
      attack_name: { type: "string" as const, description: "Short name for the attack" },
      attack_chain: {
        type: "array" as const,
        items: { type: "string" as const },
        description: "Step-by-step attack chain",
      },
      entry_point: { type: "string" as const, description: "File and line where attack enters" },
      impact: {
        type: "string" as const,
        enum: ["rce", "data_exfiltration", "privilege_escalation", "persistence", "lateral_movement", "denial_of_service"],
        description: "Type of impact if exploited",
      },
      difficulty: {
        type: "string" as const,
        enum: ["trivial", "easy", "moderate", "hard", "expert"],
        description: "How hard is this to exploit",
      },
      cvss_estimate: { type: "number" as const, description: "Estimated CVSS 3.1 score (0-10)" },
      evidence: { type: "string" as const, description: "Specific config content that enables this attack" },
      prerequisites: { type: "string" as const, description: "What the attacker needs before exploiting" },
    },
    required: ["attack_name", "attack_chain", "entry_point", "impact", "difficulty", "cvss_estimate", "evidence"],
  },
}];

export const DEFENDER_TOOLS = [
  {
    name: "report_defense_gap" as const,
    description: "Report a missing or inadequate defense in the configuration",
    input_schema: {
      type: "object" as const,
      properties: {
        gap_name: { type: "string" as const, description: "Short name for the defense gap" },
        current_state: { type: "string" as const, description: "What the config currently does (or doesn't do)" },
        recommended_fix: { type: "string" as const, description: "Exact config change needed" },
        fix_type: {
          type: "string" as const,
          enum: ["add_hook", "restrict_permission", "remove_secret", "add_validation", "restrict_mcp", "add_monitoring", "other"],
          description: "Category of fix",
        },
        priority: {
          type: "string" as const,
          enum: ["critical", "high", "medium", "low"],
          description: "Priority of the fix",
        },
        effort: {
          type: "string" as const,
          enum: ["trivial", "easy", "moderate", "significant"],
          description: "Effort required to implement",
        },
        auto_fixable: { type: "boolean" as const, description: "Whether this can be auto-fixed" },
      },
      required: ["gap_name", "current_state", "recommended_fix", "fix_type", "priority", "effort", "auto_fixable"],
    },
  },
  {
    name: "report_good_practice" as const,
    description: "Report a good security practice found in the configuration",
    input_schema: {
      type: "object" as const,
      properties: {
        practice_name: { type: "string" as const, description: "Name of the good practice" },
        description: { type: "string" as const, description: "What the config does well" },
        effectiveness: {
          type: "string" as const,
          enum: ["strong", "moderate", "weak"],
          description: "How effective is this practice",
        },
      },
      required: ["practice_name", "description", "effectiveness"],
    },
  },
];

export const AUDITOR_TOOLS = [{
  name: "final_assessment" as const,
  description: "Produce the final security assessment",
  input_schema: {
    type: "object" as const,
    properties: {
      risk_level: {
        type: "string" as const,
        enum: ["critical", "high", "medium", "low"],
        description: "Overall risk level",
      },
      score: { type: "number" as const, description: "Security score 0-100" },
      executive_summary: { type: "string" as const, description: "2-3 sentence summary" },
      top_risks: {
        type: "array" as const,
        items: {
          type: "object" as const,
          properties: {
            risk: { type: "string" as const },
            severity: { type: "string" as const },
            action: { type: "string" as const },
          },
          required: ["risk", "severity", "action"],
        },
        description: "Top 5 risks, ordered by severity",
      },
      strengths: {
        type: "array" as const,
        items: { type: "string" as const },
        description: "What the config does well",
      },
      action_plan: {
        type: "array" as const,
        items: {
          type: "object" as const,
          properties: {
            step: { type: "number" as const },
            action: { type: "string" as const },
            priority: { type: "string" as const },
            effort: { type: "string" as const },
          },
          required: ["step", "action", "priority", "effort"],
        },
        description: "Prioritized action plan",
      },
    },
    required: ["risk_level", "score", "executive_summary", "top_risks", "action_plan"],
  },
}];

// ─── Context Builders ─────────────────────────────────────

/**
 * Build the user prompt for each perspective, containing the actual config data.
 */
export function buildConfigContext(
  files: ReadonlyArray<{ path: string; content: string }>
): string {
  const sections = files.map(
    (f) => `### File: ${f.path}\n\`\`\`\n${f.content}\n\`\`\``
  );

  return `## AI Agent Configuration Files\n\n${sections.join("\n\n")}`;
}

export function buildAuditorContext(
  configContext: string,
  attackerAnalysis: string,
  defenderAnalysis: string
): string {
  return `${configContext}

## Red Team Analysis (Attacker Perspective)

${attackerAnalysis}

## Blue Team Analysis (Defender Perspective)

${defenderAnalysis}`;
}
