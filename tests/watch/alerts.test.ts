import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  renderTerminalAlert,
  formatWebhookPayload,
  dispatchAlert,
} from "../../src/watch/alerts.js";
import type { DriftResult } from "../../src/watch/types.js";
import type { Finding } from "../../src/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "test-rule",
    severity: "medium",
    category: "permissions",
    title: "Test finding",
    description: "A test finding",
    file: "settings.json",
    evidence: "some evidence",
    ...overrides,
  };
}

function makeDrift(overrides: Partial<DriftResult> = {}): DriftResult {
  return {
    timestamp: "2026-03-20T12:00:00.000Z",
    newFindings: [],
    resolvedFindings: [],
    scoreDelta: 0,
    previousScore: 80,
    currentScore: 80,
    isRegression: false,
    hasCritical: false,
    ...overrides,
  };
}

describe("renderTerminalAlert", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("renders new findings", () => {
    const drift = makeDrift({
      newFindings: [
        makeFinding({ severity: "high", title: "Dangerous permission" }),
      ],
      isRegression: true,
      scoreDelta: -10,
      previousScore: 90,
      currentScore: 80,
    });

    renderTerminalAlert(drift);

    const output = (console.error as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");

    expect(output).toContain("Drift Detected");
    expect(output).toContain("90 → 80");
    expect(output).toContain("REGRESSED");
    expect(output).toContain("NEW findings (1)");
    expect(output).toContain("Dangerous permission");
  });

  it("renders resolved findings", () => {
    const drift = makeDrift({
      resolvedFindings: [
        makeFinding({ title: "Fixed issue" }),
      ],
      scoreDelta: 5,
      previousScore: 75,
      currentScore: 80,
    });

    renderTerminalAlert(drift);

    const output = (console.error as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");

    expect(output).toContain("RESOLVED findings (1)");
    expect(output).toContain("Fixed issue");
    expect(output).toContain("IMPROVED");
  });

  it("renders critical warning", () => {
    const drift = makeDrift({
      hasCritical: true,
      newFindings: [makeFinding({ severity: "critical", title: "API key exposed" })],
    });

    renderTerminalAlert(drift);

    const output = (console.error as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");

    expect(output).toContain("CRITICAL findings detected");
  });

  it("omits score line when delta is 0", () => {
    const drift = makeDrift({
      scoreDelta: 0,
      newFindings: [makeFinding()],
    });

    renderTerminalAlert(drift);

    const output = (console.error as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");

    expect(output).not.toContain("Score:");
  });
});

describe("formatWebhookPayload", () => {
  it("formats a valid JSON payload", () => {
    const drift = makeDrift({
      newFindings: [
        makeFinding({ id: "SEC-001", severity: "high", title: "Bad perm", file: "s.json" }),
      ],
      resolvedFindings: [
        makeFinding({ id: "SEC-002", severity: "low", title: "Good fix", file: "m.json" }),
      ],
      scoreDelta: -5,
      previousScore: 85,
      currentScore: 80,
      isRegression: true,
    });

    const payload = JSON.parse(formatWebhookPayload(drift));

    expect(payload.event).toBe("agentshield.drift");
    expect(payload.timestamp).toBe("2026-03-20T12:00:00.000Z");
    expect(payload.isRegression).toBe(true);
    expect(payload.score.previous).toBe(85);
    expect(payload.score.current).toBe(80);
    expect(payload.score.delta).toBe(-5);
    expect(payload.newFindings).toHaveLength(1);
    expect(payload.newFindings[0].id).toBe("SEC-001");
    expect(payload.resolvedFindings).toHaveLength(1);
    expect(payload.resolvedFindings[0].id).toBe("SEC-002");
  });

  it("includes hasCritical flag", () => {
    const drift = makeDrift({ hasCritical: true });
    const payload = JSON.parse(formatWebhookPayload(drift));
    expect(payload.hasCritical).toBe(true);
  });

  it("handles empty findings arrays", () => {
    const drift = makeDrift();
    const payload = JSON.parse(formatWebhookPayload(drift));
    expect(payload.newFindings).toEqual([]);
    expect(payload.resolvedFindings).toEqual([]);
  });
});

describe("dispatchAlert", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("dispatches terminal alert in terminal mode", async () => {
    const drift = makeDrift({
      newFindings: [makeFinding()],
      isRegression: true,
    });

    await dispatchAlert(drift, "terminal");

    const output = (console.error as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");

    expect(output).toContain("Drift Detected");
  });

  it("does not send webhook in terminal-only mode", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("ok", { status: 200 })
    );

    const drift = makeDrift({ newFindings: [makeFinding()] });
    await dispatchAlert(drift, "terminal", "https://example.com/hook");

    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("sends webhook in webhook mode", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("ok", { status: 200 })
    );

    const drift = makeDrift({ newFindings: [makeFinding()] });
    await dispatchAlert(drift, "webhook", "https://example.com/hook");

    expect(fetchSpy).toHaveBeenCalledOnce();
    const [url, options] = fetchSpy.mock.calls[0];
    expect(url).toBe("https://example.com/hook");
    expect(options?.method).toBe("POST");
    expect(options?.headers).toEqual({ "Content-Type": "application/json" });
    fetchSpy.mockRestore();
  });

  it("dispatches both in both mode", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("ok", { status: 200 })
    );

    const drift = makeDrift({ newFindings: [makeFinding()] });
    await dispatchAlert(drift, "both", "https://example.com/hook");

    const output = (console.error as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(output).toContain("Drift Detected");
    expect(fetchSpy).toHaveBeenCalledOnce();
    fetchSpy.mockRestore();
  });

  it("handles webhook failure gracefully", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(
      new Error("Connection refused")
    );

    const drift = makeDrift({ newFindings: [makeFinding()] });
    // Should not throw
    await dispatchAlert(drift, "webhook", "https://example.com/hook");

    const output = (console.error as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(output).toContain("Webhook alert failed");
    fetchSpy.mockRestore();
  });
});
