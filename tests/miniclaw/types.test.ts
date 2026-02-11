import { describe, it, expect } from "vitest";
import {
  DEFAULT_SANDBOX_CONFIG,
  DEFAULT_SERVER_CONFIG,
} from "../../src/miniclaw/types.js";

describe("DEFAULT_SANDBOX_CONFIG", () => {
  it("has rootPath set to /tmp/miniclaw-sandboxes", () => {
    expect(DEFAULT_SANDBOX_CONFIG.rootPath).toBe("/tmp/miniclaw-sandboxes");
  });

  it("has maxFileSize set to 10MB (10_485_760 bytes)", () => {
    expect(DEFAULT_SANDBOX_CONFIG.maxFileSize).toBe(10_485_760);
  });

  it("includes core allowed extensions (.ts, .js, .json, .md, .txt)", () => {
    const extensions = DEFAULT_SANDBOX_CONFIG.allowedExtensions;
    expect(extensions).toContain(".ts");
    expect(extensions).toContain(".js");
    expect(extensions).toContain(".json");
    expect(extensions).toContain(".md");
    expect(extensions).toContain(".txt");
  });

  it("has networkPolicy set to none", () => {
    expect(DEFAULT_SANDBOX_CONFIG.networkPolicy).toBe("none");
  });

  it("has maxDuration set to 300_000ms (5 minutes)", () => {
    expect(DEFAULT_SANDBOX_CONFIG.maxDuration).toBe(300_000);
  });
});

describe("DEFAULT_SERVER_CONFIG", () => {
  it("has port set to 3847", () => {
    expect(DEFAULT_SERVER_CONFIG.port).toBe(3847);
  });

  it("has hostname set to localhost", () => {
    expect(DEFAULT_SERVER_CONFIG.hostname).toBe("localhost");
  });

  it("has corsOrigins including localhost URLs", () => {
    expect(DEFAULT_SERVER_CONFIG.corsOrigins).toContain(
      "http://localhost:3847"
    );
    expect(DEFAULT_SERVER_CONFIG.corsOrigins).toContain(
      "http://localhost:3000"
    );
  });

  it("has rateLimit set to 10", () => {
    expect(DEFAULT_SERVER_CONFIG.rateLimit).toBe(10);
  });

  it("has maxRequestSize set to 10_240 bytes", () => {
    expect(DEFAULT_SERVER_CONFIG.maxRequestSize).toBe(10_240);
  });
});
