import { describe, it, expect } from "vitest";
import {
  ATTACKER_TOOLS,
  DEFENDER_TOOLS,
  AUDITOR_TOOLS,
  ATTACKER_SYSTEM_PROMPT,
  DEFENDER_SYSTEM_PROMPT,
  AUDITOR_SYSTEM_PROMPT,
} from "../../src/opus/prompts.js";
import {
  extractToolCalls,
  extractTextContent,
  parseAttackerToolCalls,
  parseDefenderToolCalls,
  parseAuditorToolCalls,
} from "../../src/opus/pipeline.js";

// ─── Tool Schema Validation ─────────────────────────────────

describe("tool schema validation", () => {
  it("attacker tools have valid schema structure", () => {
    expect(ATTACKER_TOOLS).toHaveLength(1);
    const tool = ATTACKER_TOOLS[0];
    expect(tool.name).toBe("report_attack_vector");
    expect(tool.input_schema.type).toBe("object");
    expect(tool.input_schema.required).toContain("attack_name");
    expect(tool.input_schema.required).toContain("attack_chain");
    expect(tool.input_schema.required).toContain("entry_point");
    expect(tool.input_schema.required).toContain("impact");
    expect(tool.input_schema.required).toContain("difficulty");
    expect(tool.input_schema.required).toContain("cvss_estimate");
    expect(tool.input_schema.required).toContain("evidence");
  });

  it("attacker tool has correct impact enum values", () => {
    const properties = ATTACKER_TOOLS[0].input_schema.properties as Record<string, { enum?: string[] }>;
    expect(properties.impact.enum).toEqual([
      "rce",
      "data_exfiltration",
      "privilege_escalation",
      "persistence",
      "lateral_movement",
      "denial_of_service",
    ]);
  });

  it("attacker tool has correct difficulty enum values", () => {
    const properties = ATTACKER_TOOLS[0].input_schema.properties as Record<string, { enum?: string[] }>;
    expect(properties.difficulty.enum).toEqual([
      "trivial",
      "easy",
      "moderate",
      "hard",
      "expert",
    ]);
  });

  it("defender tools have two tools", () => {
    expect(DEFENDER_TOOLS).toHaveLength(2);
    expect(DEFENDER_TOOLS[0].name).toBe("report_defense_gap");
    expect(DEFENDER_TOOLS[1].name).toBe("report_good_practice");
  });

  it("defender gap tool has all required fields", () => {
    const tool = DEFENDER_TOOLS[0];
    expect(tool.input_schema.required).toContain("gap_name");
    expect(tool.input_schema.required).toContain("current_state");
    expect(tool.input_schema.required).toContain("recommended_fix");
    expect(tool.input_schema.required).toContain("fix_type");
    expect(tool.input_schema.required).toContain("priority");
    expect(tool.input_schema.required).toContain("effort");
    expect(tool.input_schema.required).toContain("auto_fixable");
  });

  it("defender good practice tool has all required fields", () => {
    const tool = DEFENDER_TOOLS[1];
    expect(tool.input_schema.required).toContain("practice_name");
    expect(tool.input_schema.required).toContain("description");
    expect(tool.input_schema.required).toContain("effectiveness");
  });

  it("auditor tools have one tool", () => {
    expect(AUDITOR_TOOLS).toHaveLength(1);
    expect(AUDITOR_TOOLS[0].name).toBe("final_assessment");
  });

  it("auditor tool has all required fields", () => {
    const tool = AUDITOR_TOOLS[0];
    expect(tool.input_schema.required).toContain("risk_level");
    expect(tool.input_schema.required).toContain("score");
    expect(tool.input_schema.required).toContain("executive_summary");
    expect(tool.input_schema.required).toContain("top_risks");
    expect(tool.input_schema.required).toContain("action_plan");
  });

  it("auditor tool risk_level has correct enum", () => {
    const properties = AUDITOR_TOOLS[0].input_schema.properties as Record<string, { enum?: string[] }>;
    expect(properties.risk_level.enum).toEqual(["critical", "high", "medium", "low"]);
  });

  it("all tool schemas have description strings", () => {
    const allTools = [...ATTACKER_TOOLS, ...DEFENDER_TOOLS, ...AUDITOR_TOOLS];
    for (const tool of allTools) {
      expect(typeof tool.description).toBe("string");
      expect(tool.description.length).toBeGreaterThan(10);
    }
  });
});

// ─── System Prompt Validation ───────────────────────────────

describe("system prompts reference tool usage", () => {
  it("attacker prompt instructs to use report_attack_vector tool", () => {
    expect(ATTACKER_SYSTEM_PROMPT).toContain("report_attack_vector");
  });

  it("defender prompt instructs to use report_defense_gap tool", () => {
    expect(DEFENDER_SYSTEM_PROMPT).toContain("report_defense_gap");
  });

  it("defender prompt instructs to use report_good_practice tool", () => {
    expect(DEFENDER_SYSTEM_PROMPT).toContain("report_good_practice");
  });

  it("auditor prompt instructs to use final_assessment tool", () => {
    expect(AUDITOR_SYSTEM_PROMPT).toContain("final_assessment");
  });
});

// ─── extractToolCalls ───────────────────────────────────────

describe("extractToolCalls", () => {
  it("extracts tool_use blocks from content array", () => {
    const content = [
      { type: "text", text: "Analyzing..." },
      {
        type: "tool_use",
        id: "call_1",
        name: "report_attack_vector",
        input: { attack_name: "test", attack_chain: ["step1"], entry_point: "file:1", impact: "rce", difficulty: "easy", cvss_estimate: 8, evidence: "..." },
      },
    ];

    const calls = extractToolCalls(content);
    expect(calls).toHaveLength(1);
    expect(calls[0].toolName).toBe("report_attack_vector");
    expect(calls[0].input.attack_name).toBe("test");
  });

  it("returns empty array when no tool_use blocks exist", () => {
    const content = [
      { type: "text", text: "Just text" },
    ];

    const calls = extractToolCalls(content);
    expect(calls).toHaveLength(0);
  });

  it("extracts multiple tool calls", () => {
    const content = [
      { type: "text", text: "Analysis" },
      {
        type: "tool_use",
        id: "call_1",
        name: "report_defense_gap",
        input: { gap_name: "gap1" },
      },
      {
        type: "tool_use",
        id: "call_2",
        name: "report_good_practice",
        input: { practice_name: "good1" },
      },
    ];

    const calls = extractToolCalls(content);
    expect(calls).toHaveLength(2);
    expect(calls[0].toolName).toBe("report_defense_gap");
    expect(calls[1].toolName).toBe("report_good_practice");
  });

  it("ignores non-tool_use block types", () => {
    const content = [
      { type: "text", text: "hi" },
      { type: "image", source: {} },
      { type: "tool_use", id: "call_1", name: "test", input: { a: 1 } },
    ];

    const calls = extractToolCalls(content);
    expect(calls).toHaveLength(1);
  });
});

// ─── extractTextContent ─────────────────────────────────────

describe("extractTextContent", () => {
  it("extracts text from text blocks", () => {
    const content = [
      { type: "text", text: "Hello " },
      { type: "tool_use", id: "t1", name: "tool", input: {} },
      { type: "text", text: "World" },
    ];

    const text = extractTextContent(content);
    expect(text).toBe("Hello \nWorld");
  });

  it("returns empty string when no text blocks", () => {
    const content = [
      { type: "tool_use", id: "t1", name: "tool", input: {} },
    ];

    const text = extractTextContent(content);
    expect(text).toBe("");
  });
});

// ─── parseAttackerToolCalls ─────────────────────────────────

describe("parseAttackerToolCalls", () => {
  it("parses valid attacker tool calls", () => {
    const toolCalls = [
      {
        toolName: "report_attack_vector",
        input: {
          attack_name: "Hook Command Injection",
          attack_chain: ["Clone malicious repo", "Repo contains poisoned CLAUDE.md", "Hook executes attacker payload"],
          entry_point: "CLAUDE.md:1",
          impact: "rce",
          difficulty: "easy",
          cvss_estimate: 9.1,
          evidence: "hooks: { PreToolUse: [{ matcher: '*', hook: '${input}' }] }",
          prerequisites: "Victim opens repo in Claude Code",
        },
      },
    ];

    const result = parseAttackerToolCalls(toolCalls, "Detailed analysis...");
    expect(result.attacks).toHaveLength(1);
    expect(result.attacks[0].attack_name).toBe("Hook Command Injection");
    expect(result.attacks[0].impact).toBe("rce");
    expect(result.attacks[0].cvss_estimate).toBe(9.1);
    expect(result.attacks[0].attack_chain).toHaveLength(3);
    expect(result.attacks[0].prerequisites).toBe("Victim opens repo in Claude Code");
    expect(result.reasoning).toBe("Detailed analysis...");
  });

  it("handles missing optional prerequisites", () => {
    const toolCalls = [
      {
        toolName: "report_attack_vector",
        input: {
          attack_name: "Test",
          attack_chain: ["step1"],
          entry_point: "file:1",
          impact: "rce",
          difficulty: "moderate",
          cvss_estimate: 5,
          evidence: "...",
        },
      },
    ];

    const result = parseAttackerToolCalls(toolCalls, "");
    expect(result.attacks[0].prerequisites).toBeUndefined();
  });

  it("ignores non-attacker tool calls", () => {
    const toolCalls = [
      { toolName: "report_defense_gap", input: { gap_name: "test" } },
      { toolName: "report_attack_vector", input: { attack_name: "real", attack_chain: [], entry_point: "", impact: "rce", difficulty: "easy", cvss_estimate: 7, evidence: "" } },
    ];

    const result = parseAttackerToolCalls(toolCalls, "");
    expect(result.attacks).toHaveLength(1);
    expect(result.attacks[0].attack_name).toBe("real");
  });

  it("returns empty attacks with reasoning when no tool calls", () => {
    const result = parseAttackerToolCalls([], "Some text analysis");
    expect(result.attacks).toHaveLength(0);
    expect(result.reasoning).toBe("Some text analysis");
  });
});

// ─── parseDefenderToolCalls ─────────────────────────────────

describe("parseDefenderToolCalls", () => {
  it("parses defense gap and good practice tool calls", () => {
    const toolCalls = [
      {
        toolName: "report_defense_gap",
        input: {
          gap_name: "No Bash Deny Rules",
          current_state: "Bash commands are unrestricted",
          recommended_fix: "Add deny: ['Bash(rm -rf *)'] to permissions",
          fix_type: "restrict_permission",
          priority: "critical",
          effort: "trivial",
          auto_fixable: true,
        },
      },
      {
        toolName: "report_good_practice",
        input: {
          practice_name: "Env Var Secret Management",
          description: "Secrets are stored in environment variables, not hardcoded",
          effectiveness: "strong",
        },
      },
    ];

    const result = parseDefenderToolCalls(toolCalls, "Defense analysis...");
    expect(result.gaps).toHaveLength(1);
    expect(result.gaps[0].gap_name).toBe("No Bash Deny Rules");
    expect(result.gaps[0].auto_fixable).toBe(true);
    expect(result.goodPractices).toHaveLength(1);
    expect(result.goodPractices[0].practice_name).toBe("Env Var Secret Management");
    expect(result.goodPractices[0].effectiveness).toBe("strong");
    expect(result.reasoning).toBe("Defense analysis...");
  });

  it("handles empty tool calls gracefully", () => {
    const result = parseDefenderToolCalls([], "fallback text");
    expect(result.gaps).toHaveLength(0);
    expect(result.goodPractices).toHaveLength(0);
    expect(result.reasoning).toBe("fallback text");
  });
});

// ─── parseAuditorToolCalls ──────────────────────────────────

describe("parseAuditorToolCalls", () => {
  it("parses final_assessment tool call", () => {
    const toolCalls = [
      {
        toolName: "final_assessment",
        input: {
          risk_level: "high",
          score: 35,
          executive_summary: "The configuration has significant security gaps.",
          top_risks: [
            { risk: "Command injection via hooks", severity: "critical", action: "Add input validation to all hooks" },
            { risk: "Overly broad permissions", severity: "high", action: "Restrict Bash access" },
          ],
          strengths: ["Uses env vars for secrets", "Has pre-commit hooks"],
          action_plan: [
            { step: 1, action: "Add deny rules for dangerous commands", priority: "critical", effort: "trivial" },
            { step: 2, action: "Restrict MCP server access", priority: "high", effort: "moderate" },
          ],
        },
      },
    ];

    const result = parseAuditorToolCalls(toolCalls, "Detailed reasoning...");
    expect(result.assessment.risk_level).toBe("high");
    expect(result.assessment.score).toBe(35);
    expect(result.assessment.executive_summary).toContain("significant security gaps");
    expect(result.assessment.top_risks).toHaveLength(2);
    expect(result.assessment.strengths).toHaveLength(2);
    expect(result.assessment.action_plan).toHaveLength(2);
    expect(result.assessment.action_plan[0].step).toBe(1);
    expect(result.reasoning).toBe("Detailed reasoning...");
  });

  it("returns default assessment when no tool call present", () => {
    const result = parseAuditorToolCalls([], "Some raw text");
    expect(result.assessment.risk_level).toBe("medium");
    expect(result.assessment.score).toBe(50);
    expect(result.assessment.executive_summary).toBe("Some raw text");
    expect(result.assessment.top_risks).toHaveLength(0);
    expect(result.assessment.action_plan).toHaveLength(0);
  });

  it("clamps score to 0-100 range", () => {
    const toolCalls = [
      {
        toolName: "final_assessment",
        input: {
          risk_level: "low",
          score: 150,
          executive_summary: "Test",
          top_risks: [],
          action_plan: [],
        },
      },
    ];

    const result = parseAuditorToolCalls(toolCalls, "");
    expect(result.assessment.score).toBe(100);
  });

  it("clamps negative score to 0", () => {
    const toolCalls = [
      {
        toolName: "final_assessment",
        input: {
          risk_level: "critical",
          score: -10,
          executive_summary: "Test",
          top_risks: [],
          action_plan: [],
        },
      },
    ];

    const result = parseAuditorToolCalls(toolCalls, "");
    expect(result.assessment.score).toBe(0);
  });

  it("handles missing optional strengths field", () => {
    const toolCalls = [
      {
        toolName: "final_assessment",
        input: {
          risk_level: "medium",
          score: 60,
          executive_summary: "Moderate risk",
          top_risks: [{ risk: "Test", severity: "medium", action: "Fix" }],
          action_plan: [{ step: 1, action: "Do thing", priority: "medium", effort: "easy" }],
        },
      },
    ];

    const result = parseAuditorToolCalls(toolCalls, "");
    expect(result.assessment.strengths).toEqual([]);
  });
});
