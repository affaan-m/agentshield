import Anthropic from "@anthropic-ai/sdk";
import chalk from "chalk";
import type {
  OpusAnalysis,
  OpusPerspective,
  OpusAudit,
  Severity,
  AttackVector,
  DefenseGap,
  GoodPractice,
  FinalAssessment,
  StructuredAttackerResult,
  StructuredDefenderResult,
  StructuredAuditorResult,
} from "../types.js";
import type { ScanResult } from "../scanner/index.js";
import {
  ATTACKER_SYSTEM_PROMPT,
  DEFENDER_SYSTEM_PROMPT,
  AUDITOR_SYSTEM_PROMPT,
  ATTACKER_TOOLS,
  DEFENDER_TOOLS,
  AUDITOR_TOOLS,
  buildConfigContext,
  buildAuditorContext,
} from "./prompts.js";

const MODEL = "claude-opus-4-6";

// ─── Phase Banner Rendering ─────────────────────────────────

function renderPhaseBanner(
  phaseNumber: string,
  title: string,
  subtitle: string,
  colorFn: typeof chalk.red
): void {
  const divider = "\u2501".repeat(56);
  process.stdout.write("\n");
  process.stdout.write(colorFn(`  \u250F${divider}\u2513\n`));
  process.stdout.write(colorFn(`  \u2503  ${phaseNumber}: ${title.padEnd(divider.length - phaseNumber.length - 4)}\u2503\n`));
  process.stdout.write(colorFn(`  \u2503  ${subtitle.padEnd(divider.length - 2)}\u2503\n`));
  process.stdout.write(colorFn(`  \u2517${divider}\u251B\n`));
  process.stdout.write("\n");
}

function renderPhaseComplete(
  label: string,
  tokenCount: number,
  colorFn: typeof chalk.red
): void {
  process.stdout.write("\n");
  process.stdout.write(
    colorFn(`  \u2713 ${label} complete`) +
    chalk.dim(` (${tokenCount} tokens)\n`)
  );
}

// ─── Streaming Progress ─────────────────────────────────────

const SPINNER_FRAMES: ReadonlyArray<string> = ["\u280B", "\u2819", "\u2839", "\u2838", "\u283C", "\u2834", "\u2826", "\u2827", "\u2807", "\u280F"];

function createSpinner(label: string, colorFn: typeof chalk.red): {
  readonly update: (tokenCount: number) => void;
  readonly stop: () => void;
} {
  let frame = 0;
  let lastTokenCount = 0;
  const intervalId = setInterval(() => {
    frame = (frame + 1) % SPINNER_FRAMES.length;
    const spinner = colorFn(SPINNER_FRAMES[frame]);
    process.stdout.write(`\r  ${spinner} ${label} \u2014 ${chalk.dim(`${lastTokenCount} tokens`)}`);
  }, 80);

  return {
    update(tokenCount: number) {
      lastTokenCount = tokenCount;
    },
    stop() {
      clearInterval(intervalId);
      process.stdout.write("\r" + " ".repeat(60) + "\r");
    },
  };
}

// ─── Tool Call Extraction ───────────────────────────────────

interface ToolCallResult {
  readonly toolName: string;
  readonly input: Record<string, unknown>;
}

/**
 * Extract tool_use blocks from an Anthropic API response.
 * Works with both streaming (accumulated) and non-streaming responses.
 * Accepts Anthropic SDK ContentBlock[] or any typed-block array.
 */
export function extractToolCalls(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  contentBlocks: ReadonlyArray<any>
): ReadonlyArray<ToolCallResult> {
  return contentBlocks
    .filter((block) => block.type === "tool_use")
    .map((block) => ({
      toolName: String(block.name),
      input: (block.input ?? {}) as Record<string, unknown>,
    }));
}

/**
 * Extract text blocks from an Anthropic API response for display/reasoning.
 * Accepts Anthropic SDK ContentBlock[] or any typed-block array.
 */
export function extractTextContent(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  contentBlocks: ReadonlyArray<any>
): string {
  return contentBlocks
    .filter((block) => block.type === "text")
    .map((block) => String(block.text ?? ""))
    .join("\n");
}

// ─── Structured Result Parsers ──────────────────────────────

/**
 * Parse attacker tool calls into structured AttackVector results.
 */
export function parseAttackerToolCalls(
  toolCalls: ReadonlyArray<ToolCallResult>,
  reasoning: string
): StructuredAttackerResult {
  const attacks: AttackVector[] = toolCalls
    .filter((tc) => tc.toolName === "report_attack_vector")
    .map((tc) => ({
      attack_name: String(tc.input.attack_name ?? ""),
      attack_chain: Array.isArray(tc.input.attack_chain)
        ? (tc.input.attack_chain as string[]).map(String)
        : [],
      entry_point: String(tc.input.entry_point ?? ""),
      impact: String(tc.input.impact ?? "rce") as AttackVector["impact"],
      difficulty: String(tc.input.difficulty ?? "moderate") as AttackVector["difficulty"],
      cvss_estimate: Number(tc.input.cvss_estimate ?? 5),
      evidence: String(tc.input.evidence ?? ""),
      prerequisites: tc.input.prerequisites ? String(tc.input.prerequisites) : undefined,
    }));

  return { attacks, reasoning };
}

/**
 * Parse defender tool calls into structured DefenseGap and GoodPractice results.
 */
export function parseDefenderToolCalls(
  toolCalls: ReadonlyArray<ToolCallResult>,
  reasoning: string
): StructuredDefenderResult {
  const gaps: DefenseGap[] = toolCalls
    .filter((tc) => tc.toolName === "report_defense_gap")
    .map((tc) => ({
      gap_name: String(tc.input.gap_name ?? ""),
      current_state: String(tc.input.current_state ?? ""),
      recommended_fix: String(tc.input.recommended_fix ?? ""),
      fix_type: String(tc.input.fix_type ?? "other") as DefenseGap["fix_type"],
      priority: String(tc.input.priority ?? "medium") as DefenseGap["priority"],
      effort: String(tc.input.effort ?? "moderate") as DefenseGap["effort"],
      auto_fixable: Boolean(tc.input.auto_fixable),
    }));

  const goodPractices: GoodPractice[] = toolCalls
    .filter((tc) => tc.toolName === "report_good_practice")
    .map((tc) => ({
      practice_name: String(tc.input.practice_name ?? ""),
      description: String(tc.input.description ?? ""),
      effectiveness: String(tc.input.effectiveness ?? "moderate") as GoodPractice["effectiveness"],
    }));

  return { gaps, goodPractices, reasoning };
}

/**
 * Parse auditor tool calls into structured FinalAssessment.
 */
export function parseAuditorToolCalls(
  toolCalls: ReadonlyArray<ToolCallResult>,
  reasoning: string
): StructuredAuditorResult {
  const assessmentCall = toolCalls.find((tc) => tc.toolName === "final_assessment");

  if (!assessmentCall) {
    return {
      assessment: {
        risk_level: "medium",
        score: 50,
        executive_summary: reasoning.substring(0, 300),
        top_risks: [],
        strengths: [],
        action_plan: [],
      },
      reasoning,
    };
  }

  const input = assessmentCall.input;
  const topRisks = Array.isArray(input.top_risks)
    ? (input.top_risks as Array<Record<string, unknown>>).map((r) => ({
        risk: String(r.risk ?? ""),
        severity: String(r.severity ?? ""),
        action: String(r.action ?? ""),
      }))
    : [];

  const strengths = Array.isArray(input.strengths)
    ? (input.strengths as string[]).map(String)
    : [];

  const actionPlan = Array.isArray(input.action_plan)
    ? (input.action_plan as Array<Record<string, unknown>>).map((a) => ({
        step: Number(a.step ?? 0),
        action: String(a.action ?? ""),
        priority: String(a.priority ?? ""),
        effort: String(a.effort ?? ""),
      }))
    : [];

  return {
    assessment: {
      risk_level: String(input.risk_level ?? "medium") as FinalAssessment["risk_level"],
      score: Math.min(100, Math.max(0, Number(input.score ?? 50))),
      executive_summary: String(input.executive_summary ?? ""),
      top_risks: topRisks,
      strengths,
      action_plan: actionPlan,
    },
    reasoning,
  };
}

// ─── Backward-Compatible Converters ─────────────────────────

/**
 * Convert structured attacker result to the legacy OpusPerspective format.
 * Preserves backward compatibility with render.ts and existing consumers.
 */
function toAttackerPerspective(result: StructuredAttackerResult): OpusPerspective {
  const findings: string[] = result.attacks.map((a) =>
    `[${a.impact.toUpperCase()}] ${a.attack_name} (CVSS ${a.cvss_estimate}) — ${a.attack_chain[0] ?? ""}${a.attack_chain.length > 1 ? ` (+${a.attack_chain.length - 1} steps)` : ""}`
  );

  return {
    role: "attacker",
    findings: findings.length > 0 ? findings : [result.reasoning.substring(0, 500)],
    reasoning: result.reasoning,
  };
}

/**
 * Convert structured defender result to the legacy OpusPerspective format.
 */
function toDefenderPerspective(result: StructuredDefenderResult): OpusPerspective {
  const gapFindings = result.gaps.map((g) =>
    `[${g.priority.toUpperCase()}] ${g.gap_name} — ${g.recommended_fix.substring(0, 100)}`
  );
  const practiceFindings = result.goodPractices.map((p) =>
    `[GOOD] ${p.practice_name} (${p.effectiveness})`
  );

  const findings = [...gapFindings, ...practiceFindings];

  return {
    role: "defender",
    findings: findings.length > 0 ? findings : [result.reasoning.substring(0, 500)],
    reasoning: result.reasoning,
  };
}

/**
 * Convert structured auditor result to the legacy OpusAudit format.
 */
function toAudit(result: StructuredAuditorResult): OpusAudit {
  const { assessment } = result;

  const recommendations = assessment.action_plan.map((a) =>
    `[${a.priority.toUpperCase()}] ${a.action}`
  );

  // Append top risks if there is space
  const riskRecs = assessment.top_risks.map((r) =>
    `[${r.severity.toUpperCase()}] ${r.risk}: ${r.action}`
  );

  const allRecs = [...recommendations, ...riskRecs];

  return {
    overallAssessment: assessment.executive_summary || result.reasoning,
    riskLevel: assessment.risk_level as Severity,
    recommendations: allRecs.length > 0 ? allRecs : ["Review the full audit output above"],
    score: assessment.score,
  };
}

// ─── Summarize Structured Results for Auditor Context ───────

function summarizeAttacker(result: StructuredAttackerResult): string {
  if (result.attacks.length === 0) {
    return result.reasoning;
  }

  const lines: string[] = [];
  for (const attack of result.attacks) {
    lines.push(`### ${attack.attack_name}`);
    lines.push(`- **Impact**: ${attack.impact} | **Difficulty**: ${attack.difficulty} | **CVSS**: ${attack.cvss_estimate}`);
    lines.push(`- **Entry point**: ${attack.entry_point}`);
    lines.push(`- **Attack chain**: ${attack.attack_chain.join(" -> ")}`);
    lines.push(`- **Evidence**: ${attack.evidence}`);
    if (attack.prerequisites) {
      lines.push(`- **Prerequisites**: ${attack.prerequisites}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

function summarizeDefender(result: StructuredDefenderResult): string {
  const lines: string[] = [];

  if (result.gaps.length > 0) {
    lines.push("### Defense Gaps");
    for (const gap of result.gaps) {
      lines.push(`- **${gap.gap_name}** [${gap.priority}/${gap.effort}] — ${gap.recommended_fix}`);
    }
    lines.push("");
  }

  if (result.goodPractices.length > 0) {
    lines.push("### Good Practices");
    for (const p of result.goodPractices) {
      lines.push(`- **${p.practice_name}** (${p.effectiveness}) — ${p.description}`);
    }
    lines.push("");
  }

  return lines.length > 0 ? lines.join("\n") : result.reasoning;
}

// ─── Main Pipeline ──────────────────────────────────────────

/**
 * Run the three-agent Opus analysis pipeline:
 * 1a. Attacker (Red Team) -- streamed first
 * 1b. Defender (Blue Team) -- streamed second
 * 2.  Auditor (Final Verdict) -- synthesizes both
 *
 * Uses structured tool_use for reliable output parsing.
 * In streaming mode, phases run sequentially so output does not interleave.
 * In non-streaming mode, Attacker + Defender run in parallel for speed.
 */
export async function runOpusPipeline(
  scanResult: ScanResult,
  options: { readonly verbose: boolean; readonly stream: boolean }
): Promise<OpusAnalysis> {
  const client = new Anthropic();

  const configContext = buildConfigContext(
    scanResult.target.files.map((f) => ({ path: f.path, content: f.content }))
  );

  let attackerResult: StructuredAttackerResult;
  let defenderResult: StructuredDefenderResult;

  if (options.stream) {
    // Phase 1a: Attacker (sequential in stream mode to avoid interleaving)
    renderPhaseBanner(
      "Phase 1a",
      "ATTACKER (Red Team)",
      "Adversarial analysis \u2014 finding attack vectors",
      chalk.red
    );

    attackerResult = await runAttackerStreaming(
      client,
      configContext,
      options.verbose,
      chalk.red
    );

    renderPhaseComplete("Attacker analysis", attackerResult.attacks.length, chalk.red);

    // Phase 1b: Defender
    renderPhaseBanner(
      "Phase 1b",
      "DEFENDER (Blue Team)",
      "Defensive analysis \u2014 hardening recommendations",
      chalk.blue
    );

    defenderResult = await runDefenderStreaming(
      client,
      configContext,
      options.verbose,
      chalk.blue
    );

    renderPhaseComplete("Defender analysis", defenderResult.gaps.length, chalk.blue);
  } else {
    // Non-streaming: run attacker + defender in parallel for speed
    const [aResult, dResult] = await Promise.all([
      runAttackerNonStreaming(client, configContext),
      runDefenderNonStreaming(client, configContext),
    ]);
    attackerResult = aResult;
    defenderResult = dResult;
  }

  // Phase 2: Auditor
  const auditorContext = buildAuditorContext(
    configContext,
    summarizeAttacker(attackerResult),
    summarizeDefender(defenderResult)
  );

  let auditorResult: StructuredAuditorResult;

  if (options.stream) {
    renderPhaseBanner(
      "Phase 2",
      "AUDITOR (Final Verdict)",
      "Synthesizing attacker + defender into final assessment",
      chalk.cyan
    );

    auditorResult = await runAuditorStreaming(
      client,
      auditorContext,
      options.verbose
    );

    renderPhaseComplete("Auditor synthesis", auditorResult.assessment.top_risks.length, chalk.cyan);
    process.stdout.write("\n");
  } else {
    auditorResult = await runAuditorNonStreaming(client, auditorContext);
  }

  // Convert to backward-compatible format
  const attacker = toAttackerPerspective(attackerResult);
  const defender = toDefenderPerspective(defenderResult);
  const auditor = toAudit(auditorResult);

  return { attacker, defender, auditor };
}

// ─── Streaming Attacker ─────────────────────────────────────

async function runAttackerStreaming(
  client: Anthropic,
  configContext: string,
  verbose: boolean,
  colorFn: typeof chalk.red
): Promise<StructuredAttackerResult> {
  const response = await runAgentStreaming(
    client,
    ATTACKER_SYSTEM_PROMPT,
    `Analyze the following AI agent configuration from your attacker perspective. Use the report_attack_vector tool for each vulnerability you find.\n\n${configContext}`,
    ATTACKER_TOOLS,
    "Attacker",
    verbose,
    colorFn
  );

  return parseAttackerToolCalls(response.toolCalls, response.text);
}

// ─── Streaming Defender ─────────────────────────────────────

async function runDefenderStreaming(
  client: Anthropic,
  configContext: string,
  verbose: boolean,
  colorFn: typeof chalk.red
): Promise<StructuredDefenderResult> {
  const response = await runAgentStreaming(
    client,
    DEFENDER_SYSTEM_PROMPT,
    `Analyze the following AI agent configuration from your defender perspective. Use the report_defense_gap and report_good_practice tools.\n\n${configContext}`,
    DEFENDER_TOOLS,
    "Defender",
    verbose,
    colorFn
  );

  return parseDefenderToolCalls(response.toolCalls, response.text);
}

// ─── Non-Streaming Attacker ─────────────────────────────────

async function runAttackerNonStreaming(
  client: Anthropic,
  configContext: string
): Promise<StructuredAttackerResult> {
  const response = await runAgentNonStreaming(
    client,
    ATTACKER_SYSTEM_PROMPT,
    `Analyze the following AI agent configuration from your attacker perspective. Use the report_attack_vector tool for each vulnerability you find.\n\n${configContext}`,
    ATTACKER_TOOLS
  );

  return parseAttackerToolCalls(response.toolCalls, response.text);
}

// ─── Non-Streaming Defender ─────────────────────────────────

async function runDefenderNonStreaming(
  client: Anthropic,
  configContext: string
): Promise<StructuredDefenderResult> {
  const response = await runAgentNonStreaming(
    client,
    DEFENDER_SYSTEM_PROMPT,
    `Analyze the following AI agent configuration from your defender perspective. Use the report_defense_gap and report_good_practice tools.\n\n${configContext}`,
    DEFENDER_TOOLS
  );

  return parseDefenderToolCalls(response.toolCalls, response.text);
}

// ─── Streaming Auditor ──────────────────────────────────────

async function runAuditorStreaming(
  client: Anthropic,
  auditorContext: string,
  verbose: boolean
): Promise<StructuredAuditorResult> {
  const response = await runAgentStreaming(
    client,
    AUDITOR_SYSTEM_PROMPT,
    `Produce your final security audit based on the following. Use the final_assessment tool for your verdict.\n\n${auditorContext}`,
    AUDITOR_TOOLS,
    "Auditor",
    verbose,
    chalk.cyan
  );

  return parseAuditorToolCalls(response.toolCalls, response.text);
}

// ─── Non-Streaming Auditor ──────────────────────────────────

async function runAuditorNonStreaming(
  client: Anthropic,
  auditorContext: string
): Promise<StructuredAuditorResult> {
  const response = await runAgentNonStreaming(
    client,
    AUDITOR_SYSTEM_PROMPT,
    `Produce your final security audit based on the following. Use the final_assessment tool for your verdict.\n\n${auditorContext}`,
    AUDITOR_TOOLS
  );

  return parseAuditorToolCalls(response.toolCalls, response.text);
}

// ─── Generic Agent Runner (Streaming) ───────────────────────

interface AgentResponse {
  readonly text: string;
  readonly toolCalls: ReadonlyArray<ToolCallResult>;
}

type ToolDef = ReadonlyArray<{
  readonly name: string;
  readonly description: string;
  readonly input_schema: Record<string, unknown>;
}>;

async function runAgentStreaming(
  client: Anthropic,
  systemPrompt: string,
  userMessage: string,
  tools: ToolDef,
  roleLabel: string,
  verbose: boolean,
  colorFn: typeof chalk.red
): Promise<AgentResponse> {
  let fullText = "";
  const collectedToolCalls: ToolCallResult[] = [];

  // Track tool_use blocks being built during streaming
  const pendingToolInputs: Map<number, { name: string; jsonStr: string }> = new Map();

  const stream = client.messages.stream({
    model: MODEL,
    max_tokens: 8192,
    system: systemPrompt,
    tools: tools as Anthropic.Messages.Tool[],
    tool_choice: { type: "any" },
    messages: [{ role: "user", content: userMessage }],
  });

  if (verbose) {
    for await (const event of stream) {
      if (event.type === "content_block_start") {
        const block = event.content_block;
        if (block.type === "text") {
          // text block starting
        } else if (block.type === "tool_use") {
          pendingToolInputs.set(event.index, { name: block.name, jsonStr: "" });
        }
      } else if (event.type === "content_block_delta") {
        if (event.delta.type === "text_delta") {
          fullText += event.delta.text;
          process.stdout.write(chalk.dim(event.delta.text));
        } else if (event.delta.type === "input_json_delta") {
          const pending = pendingToolInputs.get(event.index);
          if (pending) {
            pending.jsonStr += event.delta.partial_json;
          }
        }
      } else if (event.type === "content_block_stop") {
        const pending = pendingToolInputs.get(event.index);
        if (pending) {
          try {
            const input = JSON.parse(pending.jsonStr) as Record<string, unknown>;
            collectedToolCalls.push({ toolName: pending.name, input });
            process.stdout.write(chalk.dim(`\n  [tool: ${pending.name}]\n`));
          } catch {
            // malformed JSON from tool call - skip
          }
          pendingToolInputs.delete(event.index);
        }
      }
    }
  } else {
    const spinner = createSpinner(roleLabel, colorFn);
    let tokenCount = 0;

    for await (const event of stream) {
      if (event.type === "content_block_start") {
        const block = event.content_block;
        if (block.type === "tool_use") {
          pendingToolInputs.set(event.index, { name: block.name, jsonStr: "" });
        }
      } else if (event.type === "content_block_delta") {
        if (event.delta.type === "text_delta") {
          fullText += event.delta.text;
          tokenCount += event.delta.text.length;
          spinner.update(tokenCount);
        } else if (event.delta.type === "input_json_delta") {
          const pending = pendingToolInputs.get(event.index);
          if (pending) {
            pending.jsonStr += event.delta.partial_json;
            tokenCount += event.delta.partial_json.length;
            spinner.update(tokenCount);
          }
        }
      } else if (event.type === "content_block_stop") {
        const pending = pendingToolInputs.get(event.index);
        if (pending) {
          try {
            const input = JSON.parse(pending.jsonStr) as Record<string, unknown>;
            collectedToolCalls.push({ toolName: pending.name, input });
          } catch {
            // malformed JSON from tool call - skip
          }
          pendingToolInputs.delete(event.index);
        }
      }
    }

    spinner.stop();
  }

  return { text: fullText, toolCalls: collectedToolCalls };
}

// ─── Generic Agent Runner (Non-Streaming) ───────────────────

async function runAgentNonStreaming(
  client: Anthropic,
  systemPrompt: string,
  userMessage: string,
  tools: ToolDef
): Promise<AgentResponse> {
  const response = await client.messages.create({
    model: MODEL,
    max_tokens: 8192,
    system: systemPrompt,
    tools: tools as Anthropic.Messages.Tool[],
    tool_choice: { type: "any" },
    messages: [{ role: "user", content: userMessage }],
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const content = response.content as ReadonlyArray<any>;
  const text = extractTextContent(content);
  const toolCalls = extractToolCalls(content);

  return { text, toolCalls };
}
