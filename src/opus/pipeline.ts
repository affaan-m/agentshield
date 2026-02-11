import Anthropic from "@anthropic-ai/sdk";
import chalk from "chalk";
import type { OpusAnalysis, OpusPerspective, OpusAudit, Severity } from "../types.js";
import type { ScanResult } from "../scanner/index.js";
import {
  ATTACKER_SYSTEM_PROMPT,
  DEFENDER_SYSTEM_PROMPT,
  AUDITOR_SYSTEM_PROMPT,
  buildConfigContext,
  buildAuditorContext,
} from "./prompts.js";

const MODEL = "claude-opus-4-6";

/**
 * Run the three-agent Opus analysis pipeline:
 * 1. Attacker + Defender run in parallel (independent perspectives)
 * 2. Auditor runs after both complete (synthesizes their findings)
 */
export async function runOpusPipeline(
  scanResult: ScanResult,
  options: { verbose: boolean; stream: boolean }
): Promise<OpusAnalysis> {
  const client = new Anthropic();

  const configContext = buildConfigContext(
    scanResult.target.files.map((f) => ({ path: f.path, content: f.content }))
  );

  // Phase 1: Attacker + Defender in parallel
  if (options.stream) {
    console.log(chalk.bold.red("\n  Phase 1: Red Team (Attacker) + Blue Team (Defender)\n"));
  }

  const [attackerRaw, defenderRaw] = await Promise.all([
    runPerspective(client, "attacker", configContext, options),
    runPerspective(client, "defender", configContext, options),
  ]);

  // Phase 2: Auditor synthesizes
  if (options.stream) {
    console.log(chalk.bold.cyan("\n  Phase 2: Auditor (Final Assessment)\n"));
  }

  const auditorContext = buildAuditorContext(configContext, attackerRaw, defenderRaw);
  const auditorRaw = await runAuditor(client, auditorContext, options);

  // Parse structured results
  const attacker = parseAttackerResponse(attackerRaw);
  const defender = parseDefenderResponse(defenderRaw);
  const auditor = parseAuditorResponse(auditorRaw);

  return { attacker, defender, auditor };
}

async function runPerspective(
  client: Anthropic,
  role: "attacker" | "defender",
  configContext: string,
  options: { verbose: boolean; stream: boolean }
): Promise<string> {
  const systemPrompt =
    role === "attacker" ? ATTACKER_SYSTEM_PROMPT : DEFENDER_SYSTEM_PROMPT;

  const roleLabel = role === "attacker" ? "Red Team" : "Blue Team";
  const roleColor = role === "attacker" ? chalk.red : chalk.blue;

  if (options.stream) {
    process.stdout.write(roleColor(`  ${roleLabel}: `));
  }

  if (options.stream) {
    // Streaming mode — show tokens as they arrive
    let fullText = "";
    const stream = client.messages.stream({
      model: MODEL,
      max_tokens: 4096,
      system: systemPrompt,
      messages: [
        {
          role: "user",
          content: `Analyze the following AI agent configuration from your ${role} perspective.\n\n${configContext}`,
        },
      ],
    });

    for await (const event of stream) {
      if (
        event.type === "content_block_delta" &&
        event.delta.type === "text_delta"
      ) {
        const text = event.delta.text;
        fullText += text;
        if (options.verbose) {
          process.stdout.write(chalk.dim(text));
        }
      }
    }

    if (options.verbose) {
      console.log("");
    } else {
      console.log(roleColor("done"));
    }

    return fullText;
  } else {
    // Non-streaming mode
    const response = await client.messages.create({
      model: MODEL,
      max_tokens: 4096,
      system: systemPrompt,
      messages: [
        {
          role: "user",
          content: `Analyze the following AI agent configuration from your ${role} perspective.\n\n${configContext}`,
        },
      ],
    });

    const textBlock = response.content.find((b) => b.type === "text");
    return textBlock?.type === "text" ? textBlock.text : "";
  }
}

async function runAuditor(
  client: Anthropic,
  auditorContext: string,
  options: { verbose: boolean; stream: boolean }
): Promise<string> {
  if (options.stream) {
    process.stdout.write(chalk.cyan("  Auditor: "));
  }

  if (options.stream) {
    let fullText = "";
    const stream = client.messages.stream({
      model: MODEL,
      max_tokens: 4096,
      system: AUDITOR_SYSTEM_PROMPT,
      messages: [
        {
          role: "user",
          content: `Produce your final security audit based on the following:\n\n${auditorContext}`,
        },
      ],
    });

    for await (const event of stream) {
      if (
        event.type === "content_block_delta" &&
        event.delta.type === "text_delta"
      ) {
        const text = event.delta.text;
        fullText += text;
        if (options.verbose) {
          process.stdout.write(chalk.dim(text));
        }
      }
    }

    if (options.verbose) {
      console.log("");
    } else {
      console.log(chalk.cyan("done"));
    }

    return fullText;
  } else {
    const response = await client.messages.create({
      model: MODEL,
      max_tokens: 4096,
      system: AUDITOR_SYSTEM_PROMPT,
      messages: [
        {
          role: "user",
          content: `Produce your final security audit based on the following:\n\n${auditorContext}`,
        },
      ],
    });

    const textBlock = response.content.find((b) => b.type === "text");
    return textBlock?.type === "text" ? textBlock.text : "";
  }
}

// ─── Response Parsers ────────────────────────────────────────

function parseAttackerResponse(raw: string): OpusPerspective {
  // Extract bullet points as findings
  const findingLines = raw
    .split("\n")
    .filter((line) => line.match(/^[-*]\s+/) || line.match(/^\d+\.\s+/))
    .map((line) => line.replace(/^[-*\d.]+\s+/, "").trim())
    .filter((line) => line.length > 10);

  return {
    role: "attacker",
    findings: findingLines.length > 0 ? findingLines : [raw.substring(0, 500)],
    reasoning: raw,
  };
}

function parseDefenderResponse(raw: string): OpusPerspective {
  const findingLines = raw
    .split("\n")
    .filter((line) => line.match(/^[-*]\s+/) || line.match(/^\d+\.\s+/))
    .map((line) => line.replace(/^[-*\d.]+\s+/, "").trim())
    .filter((line) => line.length > 10);

  return {
    role: "defender",
    findings: findingLines.length > 0 ? findingLines : [raw.substring(0, 500)],
    reasoning: raw,
  };
}

function parseAuditorResponse(raw: string): OpusAudit {
  // Try to extract a score
  const scoreMatch = raw.match(/(?:score|rating)[:\s]*(\d{1,3})\s*(?:\/\s*100)?/i);
  const score = scoreMatch ? Math.min(100, parseInt(scoreMatch[1], 10)) : 50;

  // Try to extract risk level
  const riskMatch = raw.match(
    /(?:risk\s+level|overall\s+risk|severity)[:\s]*(critical|high|medium|low)/i
  );
  const riskLevel: Severity = (riskMatch?.[1]?.toLowerCase() as Severity) ?? "medium";

  // Extract recommendations (bullet points after "recommend" or "action")
  const recommendations = raw
    .split("\n")
    .filter(
      (line) =>
        (line.match(/^[-*]\s+/) || line.match(/^\d+\.\s+/)) &&
        line.length > 20
    )
    .map((line) => line.replace(/^[-*\d.]+\s+/, "").trim())
    .slice(0, 10);

  return {
    overallAssessment: raw,
    riskLevel,
    recommendations:
      recommendations.length > 0 ? recommendations : ["Review the full audit output above"],
    score,
  };
}
