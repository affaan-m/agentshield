import { describe, it, expect, vi, afterEach } from "vitest";
import {
  resolveModel,
  createLLMClient,
  ORCAROUTER_BASE_URL,
  ORCAROUTER_ENV_KEY,
  CHEAPERINFERENCE_BASE_URL,
  CHEAPERINFERENCE_ENV_KEY,
} from "../../src/llm/client.js";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("resolveModel", () => {
  it("maps the current default models to their gateway ids", () => {
    expect(resolveModel("orcarouter", "claude-opus-5")).toBe("anthropic/claude-opus-5");
    expect(resolveModel("orcarouter", "claude-sonnet-5")).toBe("anthropic/claude-sonnet-5");
  });

  it("returns the default model for the anthropic provider", () => {
    expect(resolveModel("anthropic", "claude-opus-4-6")).toBe("claude-opus-4-6");
    expect(resolveModel("anthropic", "claude-sonnet-4-5-20250929")).toBe(
      "claude-sonnet-4-5-20250929"
    );
  });

  it("maps known models to namespaced OrcaRouter ids", () => {
    expect(resolveModel("orcarouter", "claude-opus-4-6")).toBe(
      "anthropic/claude-opus-4.6"
    );
    expect(resolveModel("orcarouter", "claude-sonnet-4-5-20250929")).toBe(
      "anthropic/claude-sonnet-4.5"
    );
  });

  it("falls back to the anthropic/ prefix for unmapped models on orcarouter", () => {
    expect(resolveModel("orcarouter", "claude-custom-model")).toBe(
      "anthropic/claude-custom-model"
    );
  });

  it("sends the default models unchanged on cheaperinference", () => {
    expect(resolveModel("cheaperinference", "claude-opus-5")).toBe("claude-opus-5");
    expect(resolveModel("cheaperinference", "claude-sonnet-5")).toBe("claude-sonnet-5");
  });

  it("keeps an already namespaced model id on orcarouter", () => {
    expect(resolveModel("orcarouter", "openai/gpt-5")).toBe("openai/gpt-5");
  });
});

describe("createLLMClient", () => {
  it("points the client at the OrcaRouter base URL for the orcarouter provider", () => {
    vi.stubEnv(ORCAROUTER_ENV_KEY, "sk-orca-test-123");
    const client = createLLMClient("orcarouter") as any;
    expect(client.baseURL).toBe(ORCAROUTER_BASE_URL);
  });

  it("uses the ORCAROUTER_API_KEY for the orcarouter provider", () => {
    vi.stubEnv(ORCAROUTER_ENV_KEY, "sk-orca-test-123");
    const client = createLLMClient("orcarouter") as any;
    expect(client.apiKey).toBe("sk-orca-test-123");
  });

  it("points the client at the Cheaper Inference base URL for the cheaperinference provider", () => {
    vi.stubEnv(CHEAPERINFERENCE_ENV_KEY, "ci_live_test_123");
    const client = createLLMClient("cheaperinference") as any;
    expect(client.baseURL).toBe(CHEAPERINFERENCE_BASE_URL);
  });

  it("uses the CHEAPER_INFERENCE_API_KEY for the cheaperinference provider", () => {
    vi.stubEnv(CHEAPERINFERENCE_ENV_KEY, "ci_live_test_123");
    const client = createLLMClient("cheaperinference") as any;
    expect(client.apiKey).toBe("ci_live_test_123");
  });
});
