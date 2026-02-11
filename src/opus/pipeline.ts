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

// ─── Phase Banner Rendering ─────────────────────────────────

function renderPhaseBanner(
  phaseNumber: string,
  title: string,
  subtitle: string,
  colorFn: typeof chalk.red
): void {
  const divider = "━".repeat(56);
  process.stdout.write("\n");
  process.stdout.write(colorFn(`  ┏${divider}┓\n`));
  process.stdout.write(colorFn(`  ┃  ${phaseNumber}: ${title.padEnd(divider.length - phaseNumber.length - 4)}┃\n`));
  process.stdout.write(colorFn(`  ┃  ${subtitle.padEnd(divider.length - 2)}┃\n`));
  process.stdout.write(colorFn(`  ┗${divider}┛\n`));
  process.stdout.write("\n");
}

function renderPhaseComplete(
  label: string,
  tokenCount: number,
  colorFn: typeof chalk.red
): void {
  process.stdout.write("\n");
  process.stdout.write(
    colorFn(`  ✓ ${label} complete`) +
    chalk.dim(` (${tokenCount} tokens)\n`)
  );
}

// ─── Streaming Progress ─────────────────────────────────────

const SPINNER_FRAMES: ReadonlyArray<string> = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

function createSpinner(label: string, colorFn: typeof chalk.red): {
  readonly update: (tokenCount: number) => void;
  readonly stop: () => void;
} {
  let frame = 0;
  let lastTokenCount = 0;
  const intervalId = setInterval(() => {
    frame = (frame + 1) % SPINNER_FRAMES.length;
    const spinner = colorFn(SPINNER_FRAMES[frame]);
    process.stdout.write(`\r  ${spinner} ${label} — ${chalk.dim(`${lastTokenCount} tokens`)}`);
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

/**
 * Run the three-agent Opus analysis pipeline:
 * 1a. Attacker (Red Team) — streamed first
 * 1b. Defender (Blue Team) — streamed second
 * 2.  Auditor (Final Verdict) — synthesizes both
 *
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

  let attackerRaw: string;
  let defenderRaw: string;

  if (options.stream) {
    // ── Phase 1a: Attacker (sequential in stream mode to avoid interleaving) ──
    renderPhaseBanner(
      "Phase 1a",
      "ATTACKER (Red Team)",
      "Adversarial analysis — finding attack vectors",
      chalk.red
    );

    attackerRaw = await runPerspectiveStreaming(
      client,
      "attacker",
      configContext,
      options.verbose,
      chalk.red
    );

    renderPhaseComplete("Attacker analysis", attackerRaw.length, chalk.red);

    // ── Phase 1b: Defender ──
    renderPhaseBanner(
      "Phase 1b",
      "DEFENDER (Blue Team)",
      "Defensive analysis — hardening recommendations",
      chalk.blue
    );

    defenderRaw = await runPerspectiveStreaming(
      client,
      "defender",
      configContext,
      options.verbose,
      chalk.blue
    );

    renderPhaseComplete("Defender analysis", defenderRaw.length, chalk.blue);
  } else {
    // Non-streaming: run attacker + defender in parallel for speed
    const [aRaw, dRaw] = await Promise.all([
      runPerspectiveNonStreaming(client, "attacker", configContext),
      runPerspectiveNonStreaming(client, "defender", configContext),
    ]);
    attackerRaw = aRaw;
    defenderRaw = dRaw;
  }

  // ── Phase 2: Auditor ──
  const auditorContext = buildAuditorContext(configContext, attackerRaw, defenderRaw);

  let auditorRaw: string;

  if (options.stream) {
    renderPhaseBanner(
      "Phase 2",
      "AUDITOR (Final Verdict)",
      "Synthesizing attacker + defender into final assessment",
      chalk.cyan
    );

    auditorRaw = await runAuditorStreaming(
      client,
      auditorContext,
      options.verbose
    );

    renderPhaseComplete("Auditor synthesis", auditorRaw.length, chalk.cyan);
    process.stdout.write("\n");
  } else {
    auditorRaw = await runAuditorNonStreaming(client, auditorContext);
  }

  // Parse structured results
  const attacker = parseAttackerResponse(attackerRaw);
  const defender = parseDefenderResponse(defenderRaw);
  const auditor = parseAuditorResponse(auditorRaw);

  return { attacker, defender, auditor };
}

// ─── Streaming Perspective ──────────────────────────────────

async function runPerspectiveStreaming(
  client: Anthropic,
  role: "attacker" | "defender",
  configContext: string,
  verbose: boolean,
  colorFn: typeof chalk.red
): Promise<string> {
  const systemPrompt =
    role === "attacker" ? ATTACKER_SYSTEM_PROMPT : DEFENDER_SYSTEM_PROMPT;

  const roleLabel = role === "attacker" ? "Attacker" : "Defender";

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

  if (verbose) {
    // Verbose: stream every token to stdout with dim coloring
    for await (const event of stream) {
      if (
        event.type === "content_block_delta" &&
        event.delta.type === "text_delta"
      ) {
        const text = event.delta.text;
        fullText += text;
        process.stdout.write(chalk.dim(text));
      }
    }
  } else {
    // Non-verbose: show spinner with token count
    const spinner = createSpinner(roleLabel, colorFn);
    for await (const event of stream) {
      if (
        event.type === "content_block_delta" &&
        event.delta.type === "text_delta"
      ) {
        fullText += event.delta.text;
        spinner.update(fullText.length);
      }
    }
    spinner.stop();
  }

  return fullText;
}

// ─── Non-Streaming Perspective ──────────────────────────────

async function runPerspectiveNonStreaming(
  client: Anthropic,
  role: "attacker" | "defender",
  configContext: string
): Promise<string> {
  const systemPrompt =
    role === "attacker" ? ATTACKER_SYSTEM_PROMPT : DEFENDER_SYSTEM_PROMPT;

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

// ─── Streaming Auditor ──────────────────────────────────────

async function runAuditorStreaming(
  client: Anthropic,
  auditorContext: string,
  verbose: boolean
): Promise<string> {
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

  if (verbose) {
    for await (const event of stream) {
      if (
        event.type === "content_block_delta" &&
        event.delta.type === "text_delta"
      ) {
        const text = event.delta.text;
        fullText += text;
        process.stdout.write(chalk.dim(text));
      }
    }
  } else {
    const spinner = createSpinner("Auditor", chalk.cyan);
    for await (const event of stream) {
      if (
        event.type === "content_block_delta" &&
        event.delta.type === "text_delta"
      ) {
        fullText += event.delta.text;
        spinner.update(fullText.length);
      }
    }
    spinner.stop();
  }

  return fullText;
}

// ─── Non-Streaming Auditor ──────────────────────────────────

async function runAuditorNonStreaming(
  client: Anthropic,
  auditorContext: string
): Promise<string> {
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

// ─── Response Parsers ────────────────────────────────────────

function parseBulletFindings(raw: string): ReadonlyArray<string> {
  return raw
    .split("\n")
    .filter((line) => {
      const bulletMatches = [...line.matchAll(/^[-*]\s+/g)];
      const numberedMatches = [...line.matchAll(/^\d+\.\s+/g)];
      return bulletMatches.length > 0 || numberedMatches.length > 0;
    })
    .map((line) => line.replace(/^[-*\d.]+\s+/, "").trim())
    .filter((line) => line.length > 10);
}

function parseAttackerResponse(raw: string): OpusPerspective {
  const findingLines = parseBulletFindings(raw);

  return {
    role: "attacker",
    findings: findingLines.length > 0 ? findingLines : [raw.substring(0, 500)],
    reasoning: raw,
  };
}

function parseDefenderResponse(raw: string): OpusPerspective {
  const findingLines = parseBulletFindings(raw);

  return {
    role: "defender",
    findings: findingLines.length > 0 ? findingLines : [raw.substring(0, 500)],
    reasoning: raw,
  };
}

function parseAuditorResponse(raw: string): OpusAudit {
  // Try to extract a score
  const scoreMatches = [...raw.matchAll(/(?:score|rating)[:\s]*(\d{1,3})\s*(?:\/\s*100)?/gi)];
  const scoreMatch = scoreMatches.length > 0 ? scoreMatches[0] : undefined;
  const score = scoreMatch ? Math.min(100, parseInt(scoreMatch[1], 10)) : 50;

  // Try to extract risk level
  const riskMatches = [
    ...raw.matchAll(/(?:risk\s+level|overall\s+risk|severity)[:\s]*(critical|high|medium|low)/gi),
  ];
  const riskMatch = riskMatches.length > 0 ? riskMatches[0] : undefined;
  const riskLevel: Severity = (riskMatch?.[1]?.toLowerCase() as Severity) ?? "medium";

  // Extract recommendations (bullet points after "recommend" or "action")
  const recommendations = raw
    .split("\n")
    .filter((line) => {
      const bulletMatches = [...line.matchAll(/^[-*]\s+/g)];
      const numberedMatches = [...line.matchAll(/^\d+\.\s+/g)];
      return (bulletMatches.length > 0 || numberedMatches.length > 0) && line.length > 20;
    })
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
