import { describe, it, expect, vi, afterEach } from "vitest";
import {
  resolveModel,
  createLLMClient,
  ORCAROUTER_BASE_URL,
  ORCAROUTER_ENV_KEY,
} from "../../src/llm/client.js";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("resolveModel", () => {
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

  it("passes through unknown models untouched", () => {
    expect(resolveModel("orcarouter", "claude-custom-model")).toBe(
      "claude-custom-model"
    );
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
});
