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
//
// Cheaper Inference, an OpenAI-compatible LLM gateway, also serves the
// Anthropic Messages API:
//
//   - baseURL: https://api.cheaperinference.com  (SDK appends /v1/messages)
//   - auth:    CHEAPER_INFERENCE_API_KEY, sent as `x-api-key`
//   - model:   bare ids (`claude-opus-5`, `claude-sonnet-5`), so the default
//              models are sent unchanged
//
// See https://cheaperinference.com/docs

export type LLMProvider = "anthropic" | "orcarouter" | "cheaperinference";

export const ORCAROUTER_BASE_URL = "https://api.orcarouter.ai";
export const ORCAROUTER_ENV_KEY = "ORCAROUTER_API_KEY";

export const CHEAPERINFERENCE_BASE_URL = "https://api.cheaperinference.com";
export const CHEAPERINFERENCE_ENV_KEY = "CHEAPER_INFERENCE_API_KEY";

/** Model ids the OrcaRouter gateway exposes for the same Anthropic models
 * AgentShield uses by default. The gateway requires the `anthropic/` prefix. */
const ORCAROUTER_MODELS: Readonly<Record<string, string>> = {
  "claude-opus-5": "anthropic/claude-opus-5",
  "claude-sonnet-5": "anthropic/claude-sonnet-5",
  "claude-opus-4-6": "anthropic/claude-opus-4.6",
  "claude-sonnet-4-5-20250929": "anthropic/claude-sonnet-4.5",
};

/** Resolve the model id to send for a given provider. */
export function resolveModel(
  provider: LLMProvider,
  defaultModel: string
): string {
  if (provider === "orcarouter") {
    const mapped = ORCAROUTER_MODELS[defaultModel];
    if (mapped) return mapped;
    // The gateway requires a namespaced id. Assume an unmapped model is an
    // Anthropic model unless the caller already supplied a namespace.
    return defaultModel.includes("/") ? defaultModel : `anthropic/${defaultModel}`;
  }
  return defaultModel;
}

/**
 * Build the Anthropic SDK client for a provider.
 *
 * The default Anthropic provider uses the SDK's standard behavior
 * (ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL). The OrcaRouter provider points the
 * client at the OrcaRouter Messages endpoint and authenticates with
 * ORCAROUTER_API_KEY. The Cheaper Inference provider does the same with
 * CHEAPER_INFERENCE_API_KEY.
 */
export function createLLMClient(provider: LLMProvider): Anthropic {
  if (provider === "orcarouter") {
    return new Anthropic({
      baseURL: ORCAROUTER_BASE_URL,
      apiKey: process.env[ORCAROUTER_ENV_KEY] ?? "",
    });
  }
  if (provider === "cheaperinference") {
    return new Anthropic({
      baseURL: CHEAPERINFERENCE_BASE_URL,
      apiKey: process.env[CHEAPERINFERENCE_ENV_KEY] ?? "",
    });
  }
  return new Anthropic();
}
