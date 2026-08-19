import Anthropic from "@anthropic-ai/sdk";

// ─── Provider Configuration ────────────────────────────────
//
// AgentShield's LLM-powered analysis modes (--opus and --injection) talk to an
// Anthropic-compatible Messages API.  Besides the default Anthropic endpoint
// they can run through OrcaRouter, an OpenAI/Anthropic-compatible gateway that
// routes each request to the most cost-effective upstream model.
//
//   - baseURL: https://api.orcarouter.ai  (SDK appends /v1/messages)
//   - auth:    ORCAROUTER_API_KEY, sent as both `x-api-key` and
//              `Authorization: Bearer` (both are accepted by the gateway)
//   - model:   namespaced gateway ids (`anthropic/claude-sonnet-5`, …) — the
//              gateway rejects bare `claude-*` ids
//
// See https://www.orcarouter.ai

export type LLMProvider = "anthropic" | "orcarouter";

export const ORCAROUTER_BASE_URL = "https://api.orcarouter.ai";
export const ORCAROUTER_ENV_KEY = "ORCAROUTER_API_KEY";

/** Model ids the OrcaRouter gateway exposes for the same Anthropic models
 * AgentShield uses by default. The gateway requires the `anthropic/` prefix. */
const ORCAROUTER_MODELS: Readonly<Record<string, string>> = {
  "claude-opus-4-6": "anthropic/claude-opus-4.6",
  "claude-sonnet-4-5-20250929": "anthropic/claude-sonnet-4.5",
};

/** Resolve the model id to send for a given provider. */
export function resolveModel(
  provider: LLMProvider,
  defaultModel: string
): string {
  if (provider === "orcarouter") {
    return ORCAROUTER_MODELS[defaultModel] ?? defaultModel;
  }
  return defaultModel;
}

/**
 * Build the Anthropic SDK client for a provider.
 *
 * The default Anthropic provider uses the SDK's standard behavior
 * (ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL). The OrcaRouter provider points the
 * client at the OrcaRouter Messages endpoint and authenticates with
 * ORCAROUTER_API_KEY.
 */
export function createLLMClient(provider: LLMProvider): Anthropic {
  if (provider === "orcarouter") {
    return new Anthropic({
      baseURL: ORCAROUTER_BASE_URL,
      apiKey: process.env[ORCAROUTER_ENV_KEY] ?? "",
    });
  }
  return new Anthropic();
}
