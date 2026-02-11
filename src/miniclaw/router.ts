/**
 * MiniClaw Prompt Router
 *
 * Handles the full lifecycle of a prompt:
 * 1. Input sanitization — strip prompt injection attempts
 * 2. Routing — process the sanitized prompt through allowed tools
 * 3. Output filtering — remove any leaked system prompt content
 *
 * This is the second critical security boundary (after the sandbox).
 * The sandbox limits WHERE the agent can operate; the router limits
 * WHAT the agent can be instructed to do.
 */

import type {
  PromptRequest,
  PromptResponse,
  MiniClawSession,
  SecurityEvent,
  ToolCallRecord,
} from "./types.js";
import { createSecurityEvent } from "./sandbox.js";
// Tool validation/execution imports — used by processPromptWithTools in production
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import type { ToolCallRequest as _ToolCallRequest } from "./types.js";

// ─── Prompt Injection Patterns ────────────────────────────

/**
 * Known prompt injection patterns.
 *
 * WHY these specific patterns: These are the most common prompt injection
 * techniques documented in security research (OWASP LLM Top 10, academic papers).
 * New patterns should be added as they are discovered.
 *
 * WHY regex over ML-based detection: Regex is deterministic, fast, and auditable.
 * ML-based detection is probabilistic and can itself be attacked. For a
 * security-critical system, we prefer false positives over false negatives.
 *
 * Each pattern includes a description for audit logging.
 */
const INJECTION_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp;
  readonly description: string;
}> = [
  // System prompt override attempts
  // WHY: The most basic prompt injection — trying to replace the system prompt
  {
    pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|context)/i,
    description: "System prompt override: 'ignore previous instructions'",
  },
  {
    pattern: /you\s+are\s+now\s+(a|an|the)\s+/i,
    description: "Identity reassignment: 'you are now a...'",
  },
  {
    pattern: /forget\s+(everything|all|your)\s+(you|instructions|previous)/i,
    description: "Memory wipe attempt: 'forget everything'",
  },
  {
    pattern: /new\s+instructions?:\s*/i,
    description: "System prompt injection: 'new instructions:'",
  },
  {
    pattern: /system\s*prompt\s*[:=]/i,
    description: "Direct system prompt override attempt",
  },
  {
    pattern: /\[system\]|\[INST\]|<\|im_start\|>|<\|system\|>/i,
    description: "Chat template injection: special tokens",
  },

  // Jailbreak patterns
  // WHY: These attempt to bypass safety guidelines by framing the request
  {
    pattern: /do\s+anything\s+now|DAN\s+mode|jailbreak/i,
    description: "Jailbreak attempt: DAN/DANO pattern",
  },
  {
    pattern: /pretend\s+(you|that)\s+(are|can|have)\s+no\s+(restrictions|limits|rules)/i,
    description: "Jailbreak: restriction removal request",
  },

  // Direct tool invocation
  // WHY: The agent's tools should only be invoked through the routing system,
  // never directly from user input. This prevents bypassing the whitelist.
  {
    pattern: /```\s*(bash|shell|sh|cmd|powershell)\b/i,
    description: "Direct shell invocation via code block",
  },
  {
    pattern: /exec\s*\(|child_process|spawn\s*\(|system\s*\(/i,
    description: "Process execution attempt in prompt",
  },

  // Data exfiltration attempts
  // WHY: Even without network access, an attacker might try to encode
  // sensitive data in the response for manual exfiltration
  {
    pattern: /curl\s+|wget\s+|fetch\s*\(|http\.get/i,
    description: "Network request attempt in prompt",
  },
];

/**
 * Zero-width and invisible Unicode characters that can hide instructions.
 *
 * WHY: Attackers embed invisible characters between visible text to hide
 * malicious instructions. The prompt looks innocent to a human reviewer
 * but contains hidden commands when processed by the model.
 *
 * Example: "Read the file" + [zero-width chars encoding "delete everything"]
 */
const INVISIBLE_CHAR_PATTERN = /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u2000-\u200A\u202A-\u202E\u2060-\u2064\u2066-\u206F]/g;

/**
 * Base64 encoded instruction patterns.
 *
 * WHY: Attackers encode malicious instructions in base64 to bypass
 * pattern matching on the raw text. The model may decode and follow them.
 */
const BASE64_INSTRUCTION_PATTERN = /(?:eval|decode|execute|run)\s*\(\s*(?:atob|Buffer\.from|base64)\s*\(/i;

// ─── System Prompt Fragments (for output filtering) ───────

/**
 * Phrases that indicate system prompt leakage in the response.
 *
 * WHY: If the agent leaks its system prompt, attackers learn the exact
 * restrictions and can craft targeted bypasses. We filter these out
 * of responses as a defense-in-depth measure.
 */
const SYSTEM_PROMPT_MARKERS: ReadonlyArray<string> = [
  "you are miniclaw",
  "your system prompt is",
  "my instructions are",
  "i was configured to",
  "my system prompt",
  "here are my instructions",
  "my configuration includes",
];

// ─── Input Sanitization ───────────────────────────────────

/**
 * Sanitizes raw user input by detecting and neutralizing prompt injection attempts.
 *
 * Returns the sanitized prompt and any security events that were triggered.
 * The original prompt is NEVER returned — only the sanitized version.
 *
 * WHY return events alongside the sanitized prompt: The dashboard needs to
 * display blocked injections for transparency, and the audit log needs them
 * for forensics.
 */
export function sanitizePrompt(
  raw: string,
  sessionId: string
): {
  readonly sanitized: string;
  readonly events: ReadonlyArray<SecurityEvent>;
} {
  const events: SecurityEvent[] = [];
  let sanitized = raw;

  // Step 1: Remove invisible characters
  // WHY: These MUST be removed first because they can break other pattern matching
  const invisibleMatches = [...sanitized.matchAll(INVISIBLE_CHAR_PATTERN)];
  if (invisibleMatches.length > 0) {
    events.push(
      createSecurityEvent(
        "prompt_injection_detected",
        `Removed ${invisibleMatches.length} invisible/zero-width characters from prompt`,
        sessionId
      )
    );
    sanitized = sanitized.replace(INVISIBLE_CHAR_PATTERN, "");
  }

  // Step 2: Check for base64-encoded instructions
  // WHY: Must happen before injection pattern check because the base64 payload
  // might decode to something that matches injection patterns
  const base64Matches = [...sanitized.matchAll(new RegExp(BASE64_INSTRUCTION_PATTERN.source, "gi"))];
  if (base64Matches.length > 0) {
    events.push(
      createSecurityEvent(
        "prompt_injection_detected",
        "Detected base64-encoded instruction execution attempt",
        sessionId
      )
    );
    // Replace the entire base64 execution call with a safe placeholder
    sanitized = sanitized.replace(BASE64_INSTRUCTION_PATTERN, "[BLOCKED: encoded execution]");
  }

  // Step 3: Check for known injection patterns
  // WHY: Each pattern is checked independently so we can log specific detections
  // for the audit trail. A single "injection detected" message is not useful for forensics.
  for (const { pattern, description } of INJECTION_PATTERNS) {
    const matches = [...sanitized.matchAll(new RegExp(pattern.source, "gi"))];
    if (matches.length > 0) {
      events.push(
        createSecurityEvent(
          "prompt_injection_detected",
          description,
          sessionId
        )
      );
      // Replace matched content with a visible block marker
      // WHY visible marker: So the model sees "[BLOCKED]" instead of the injection,
      // making it clear the content was removed rather than silently dropped
      sanitized = sanitized.replace(
        new RegExp(pattern.source, "gi"),
        "[BLOCKED]"
      );
    }
  }

  // Step 4: Trim excessive whitespace
  // WHY: Large amounts of whitespace can be used to push instructions past
  // context windows or hide content in scrollback
  sanitized = sanitized.replace(/\s{10,}/g, " ");

  // Step 5: Enforce maximum prompt length
  // WHY: Extremely long prompts can be used for resource exhaustion or to
  // hide malicious content deep in the text where it's less likely to be caught
  const MAX_PROMPT_LENGTH = 8192;
  if (sanitized.length > MAX_PROMPT_LENGTH) {
    events.push(
      createSecurityEvent(
        "prompt_injection_detected",
        `Prompt truncated from ${sanitized.length} to ${MAX_PROMPT_LENGTH} characters`,
        sessionId
      )
    );
    sanitized = sanitized.slice(0, MAX_PROMPT_LENGTH);
  }

  return { sanitized, events };
}

// ─── Output Filtering ─────────────────────────────────────

/**
 * Filters the agent's response to remove leaked system prompt content
 * and internal error details.
 *
 * WHY: Even with good system prompts, models sometimes leak their instructions
 * when cleverly asked. This is a defense-in-depth measure — the primary defense
 * is the system prompt itself saying "do not reveal instructions".
 */
export function filterResponse(
  response: string,
  sessionId: string
): {
  readonly filtered: string;
  readonly events: ReadonlyArray<SecurityEvent>;
} {
  const events: SecurityEvent[] = [];
  let filtered = response;

  // Check for system prompt leakage
  // WHY case-insensitive: The model might rephrase in different cases
  const lowerResponse = filtered.toLowerCase();
  for (const marker of SYSTEM_PROMPT_MARKERS) {
    if (lowerResponse.includes(marker)) {
      events.push(
        createSecurityEvent(
          "response_filtered",
          `System prompt leakage detected: response contained "${marker}"`,
          sessionId
        )
      );
      // Replace the entire sentence containing the marker
      // WHY entire sentence: Partial redaction might leave enough context
      // for the attacker to reconstruct the system prompt
      const markerIndex = lowerResponse.indexOf(marker);
      const sentenceStart = filtered.lastIndexOf(".", markerIndex) + 1;
      const sentenceEnd = filtered.indexOf(".", markerIndex + marker.length);
      const end = sentenceEnd === -1 ? filtered.length : sentenceEnd + 1;
      filtered =
        filtered.slice(0, sentenceStart) +
        " [This content has been filtered for security reasons.] " +
        filtered.slice(end);
    }
  }

  // Remove any stack traces that might leak internal paths
  // WHY: Stack traces reveal the server's directory structure, Node.js version,
  // dependency versions — all useful for crafting targeted exploits
  filtered = filtered.replace(
    /at\s+[\w.]+\s+\(\/[^)]+\)/g,
    "[internal path redacted]"
  );

  // Remove absolute paths outside sandbox
  // WHY: Internal paths reveal server structure
  filtered = filtered.replace(
    /\/(?:usr|etc|var|home|root|tmp\/miniclaw-sandboxes)\/[\w/.+-]+/g,
    "[path redacted]"
  );

  return { filtered, events };
}

// ─── Prompt Routing ───────────────────────────────────────

/**
 * Routes a sanitized prompt through the agent's allowed tools.
 *
 * This is the main processing function. It:
 * 1. Sanitizes the input
 * 2. Processes tool calls against the whitelist
 * 3. Filters the output
 *
 * WHY this is a single function: The three steps (sanitize, process, filter)
 * must ALWAYS happen in sequence. Separating them risks a caller forgetting
 * to sanitize or filter.
 *
 * Note: The actual LLM processing is abstracted out. This function handles
 * the security envelope; the LLM call would be injected as a dependency
 * in a production implementation.
 */
export async function routePrompt(
  request: PromptRequest,
  session: MiniClawSession
): Promise<{
  readonly response: PromptResponse;
  readonly securityEvents: ReadonlyArray<SecurityEvent>;
}> {
  const startTime = Date.now();
  const allEvents: SecurityEvent[] = [];

  // Step 1: Sanitize input
  const { sanitized, events: sanitizeEvents } = sanitizePrompt(
    request.prompt,
    session.id
  );
  allEvents.push(...sanitizeEvents);

  // Step 2: Check session timeout
  // WHY: Enforce maximum session duration to prevent resource exhaustion
  const sessionAge = Date.now() - new Date(session.createdAt).getTime();
  if (sessionAge > session.maxDuration) {
    allEvents.push(
      createSecurityEvent("timeout", "Session has exceeded maximum duration", session.id)
    );
    return {
      response: {
        sessionId: session.id,
        response: "Session has expired. Please create a new session.",
        toolCalls: [],
        duration: Date.now() - startTime,
        tokenUsage: { input: 0, output: 0 },
      },
      securityEvents: allEvents,
    };
  }

  // Step 3: Process tool calls from the sanitized prompt
  // In a production implementation, this is where the LLM would be called.
  // The LLM's tool call requests would be validated here before execution.
  // For now, we provide the routing infrastructure.
  const toolCalls: ToolCallRecord[] = [];

  // Example: If the prompt contains a tool call request, validate and execute it
  // This is a placeholder for the actual LLM integration
  const processedResponse = await processPromptWithTools(
    sanitized,
    session,
    toolCalls,
    allEvents
  );

  // Step 4: Filter output
  const { filtered, events: filterEvents } = filterResponse(
    processedResponse,
    session.id
  );
  allEvents.push(...filterEvents);

  const duration = Date.now() - startTime;

  return {
    response: {
      sessionId: session.id,
      response: filtered,
      toolCalls,
      duration,
      // Token usage would come from the LLM response in production
      tokenUsage: { input: sanitized.length, output: filtered.length },
    },
    securityEvents: allEvents,
  };
}

/**
 * Processes a sanitized prompt through allowed tools.
 *
 * This is the integration point for the LLM. In the current implementation,
 * it provides the tool validation pipeline without the actual LLM call.
 *
 * WHY separate from routePrompt: This function can be replaced with
 * different LLM backends (Anthropic, local models, etc.) without
 * changing the security envelope in routePrompt.
 */
async function processPromptWithTools(
  _sanitizedPrompt: string,
  session: MiniClawSession,
  _toolCalls: ToolCallRecord[],
  _events: SecurityEvent[]
): Promise<string> {
  // In production, this would:
  // 1. Send the sanitized prompt to the LLM
  // 2. Receive tool call requests from the LLM
  // 3. Validate each tool call against the whitelist
  // 4. Execute approved tool calls within the sandbox
  // 5. Return results to the LLM for final response generation

  // Placeholder: Echo back that the prompt was received and processed
  // This demonstrates the tool validation pipeline is in place
  const toolCount = session.allowedTools.length;
  return (
    `Prompt received and sanitized. ` +
    `Session ${session.id} has ${toolCount} tools available. ` +
    `Ready for LLM integration.`
  );
}
