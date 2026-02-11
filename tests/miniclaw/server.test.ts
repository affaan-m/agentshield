import { describe, it, expect, afterAll, beforeAll } from "vitest";
import type { AddressInfo } from "node:net";
import { rm, mkdir } from "node:fs/promises";
import { createMiniClawServer } from "../../src/miniclaw/server.js";
import { DEFAULT_SANDBOX_CONFIG, DEFAULT_SERVER_CONFIG } from "../../src/miniclaw/types.js";
import { createSafeWhitelist } from "../../src/miniclaw/tools.js";

// ─── Test Helpers ──────────────────────────────────────────

const TEST_ROOT = `/tmp/miniclaw-test-${Date.now()}`;

function createTestConfig() {
  return {
    sandbox: { ...DEFAULT_SANDBOX_CONFIG, rootPath: TEST_ROOT },
    server: { ...DEFAULT_SERVER_CONFIG, port: 0, rateLimit: 100 }, // high rate limit for tests
    tools: createSafeWhitelist(),
  };
}

/**
 * Starts a MiniClaw server on a random port and returns the base URL and stop function.
 * Wraps server.listen(0) in a promise that resolves on the 'listening' event.
 */
async function startTestServer() {
  const config = createTestConfig();
  const { server, stop } = createMiniClawServer(config);

  const baseUrl = await new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${addr.port}`);
    });
  });

  return { server, stop, baseUrl };
}

// ─── Test Suite ────────────────────────────────────────────

describe("MiniClaw HTTP Server", () => {
  let baseUrl: string;
  let stop: () => void;

  beforeAll(async () => {
    await mkdir(TEST_ROOT, { recursive: true });
    const instance = await startTestServer();
    baseUrl = instance.baseUrl;
    stop = instance.stop;
  });

  afterAll(async () => {
    stop();
    await rm(TEST_ROOT, { recursive: true, force: true }).catch(() => {});
  });

  // ── Health Endpoint ──────────────────────────────────────

  describe("GET /api/health", () => {
    it("returns 200 with status ok", async () => {
      const res = await fetch(`${baseUrl}/api/health`);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body).toHaveProperty("status", "ok");
      expect(body).toHaveProperty("sessions");
      expect(typeof body.sessions).toBe("number");
    });
  });

  // ── Session Lifecycle ────────────────────────────────────

  describe("Session lifecycle", () => {
    it("POST /api/session creates a new session and returns 201", async () => {
      const res = await fetch(`${baseUrl}/api/session`, { method: "POST" });
      expect(res.status).toBe(201);

      const body = await res.json();
      expect(body).toHaveProperty("sessionId");
      expect(typeof body.sessionId).toBe("string");
      expect(body.sessionId.length).toBeGreaterThan(0);
      expect(body).toHaveProperty("createdAt");
      expect(body).toHaveProperty("allowedTools");
      expect(Array.isArray(body.allowedTools)).toBe(true);
      expect(body).toHaveProperty("maxDuration");
    });

    it("GET /api/session returns sessions array", async () => {
      // Create a session first
      await fetch(`${baseUrl}/api/session`, { method: "POST" });

      const res = await fetch(`${baseUrl}/api/session`);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body).toHaveProperty("sessions");
      expect(Array.isArray(body.sessions)).toBe(true);
      expect(body.sessions.length).toBeGreaterThanOrEqual(1);

      const session = body.sessions[0];
      expect(session).toHaveProperty("id");
      expect(session).toHaveProperty("createdAt");
      expect(session).toHaveProperty("allowedTools");
      expect(session).toHaveProperty("maxDuration");
    });

    it("DELETE /api/session/:id destroys an existing session", async () => {
      // Create a session to delete
      const createRes = await fetch(`${baseUrl}/api/session`, { method: "POST" });
      const { sessionId } = await createRes.json();

      const deleteRes = await fetch(`${baseUrl}/api/session/${sessionId}`, {
        method: "DELETE",
      });
      expect(deleteRes.status).toBe(200);

      const body = await deleteRes.json();
      expect(body).toHaveProperty("message", "Session destroyed");
      expect(body).toHaveProperty("sessionId", sessionId);
    });

    it("DELETE /api/session/:nonexistent returns 404", async () => {
      const res = await fetch(
        `${baseUrl}/api/session/nonexistent-session-id`,
        { method: "DELETE" }
      );
      expect(res.status).toBe(404);

      const body = await res.json();
      expect(body).toHaveProperty("error");
      expect(body.error).toContain("not found");
    });
  });

  // ── Prompt Endpoint ──────────────────────────────────────

  describe("POST /api/prompt", () => {
    it("returns 200 with response for valid session and prompt", async () => {
      // Create a session first
      const createRes = await fetch(`${baseUrl}/api/session`, { method: "POST" });
      const { sessionId } = await createRes.json();

      const res = await fetch(`${baseUrl}/api/prompt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId, prompt: "Hello, world!" }),
      });
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body).toHaveProperty("sessionId", sessionId);
      expect(body).toHaveProperty("response");
      expect(typeof body.response).toBe("string");
      expect(body).toHaveProperty("toolCalls");
      expect(Array.isArray(body.toolCalls)).toBe(true);
      expect(body).toHaveProperty("duration");
      expect(body).toHaveProperty("tokenUsage");
    });

    it("returns 404 when session does not exist", async () => {
      const res = await fetch(`${baseUrl}/api/prompt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId: "no-such-session", prompt: "test" }),
      });
      expect(res.status).toBe(404);

      const body = await res.json();
      expect(body).toHaveProperty("error");
      expect(body.error).toContain("not found");
    });

    it("returns 400 when required fields are missing", async () => {
      const res = await fetch(`${baseUrl}/api/prompt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId: "abc" }),
      });
      expect(res.status).toBe(400);

      const body = await res.json();
      expect(body).toHaveProperty("error");
      expect(body.error).toContain("Missing required fields");
    });

    it("returns 400 for invalid JSON body", async () => {
      const res = await fetch(`${baseUrl}/api/prompt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "this is not json{{{",
      });
      expect(res.status).toBe(400);

      const body = await res.json();
      expect(body).toHaveProperty("error");
      expect(body.error).toContain("Invalid JSON");
    });
  });

  // ── Security Events Endpoint ─────────────────────────────

  describe("GET /api/events/:sessionId", () => {
    it("returns events array for an existing session", async () => {
      // Create session and send a prompt to generate events
      const createRes = await fetch(`${baseUrl}/api/session`, { method: "POST" });
      const { sessionId } = await createRes.json();

      // Send a prompt so the events endpoint has something to return
      await fetch(`${baseUrl}/api/prompt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId, prompt: "list files" }),
      });

      const res = await fetch(`${baseUrl}/api/events/${sessionId}`);
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body).toHaveProperty("sessionId", sessionId);
      expect(body).toHaveProperty("events");
      expect(Array.isArray(body.events)).toBe(true);
    });

    it("returns 404 for nonexistent session", async () => {
      const res = await fetch(`${baseUrl}/api/events/nonexistent-id`);
      expect(res.status).toBe(404);

      const body = await res.json();
      expect(body).toHaveProperty("error");
      expect(body.error).toContain("not found");
    });
  });

  // ── 404 Handling ─────────────────────────────────────────

  describe("404 handling", () => {
    it("returns 404 for unknown routes", async () => {
      const res = await fetch(`${baseUrl}/api/unknown`);
      expect(res.status).toBe(404);

      const body = await res.json();
      expect(body).toHaveProperty("error", "Not found");
    });

    it("returns 404 for root path", async () => {
      const res = await fetch(`${baseUrl}/`);
      expect(res.status).toBe(404);

      const body = await res.json();
      expect(body).toHaveProperty("error", "Not found");
    });
  });

  // ── Security Headers ─────────────────────────────────────

  describe("Security headers", () => {
    it("includes security headers on JSON responses", async () => {
      const res = await fetch(`${baseUrl}/api/health`);

      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      expect(res.headers.get("x-frame-options")).toBe("DENY");
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(res.headers.get("content-type")).toBe("application/json");
    });
  });

  // ── CORS ─────────────────────────────────────────────────

  describe("CORS handling", () => {
    it("OPTIONS preflight returns 204 with CORS headers for allowed origin", async () => {
      const res = await fetch(`${baseUrl}/api/prompt`, {
        method: "OPTIONS",
        headers: {
          Origin: "http://localhost:3000",
          "Access-Control-Request-Method": "POST",
        },
      });
      expect(res.status).toBe(204);
      expect(res.headers.get("access-control-allow-origin")).toBe("http://localhost:3000");
      expect(res.headers.get("access-control-allow-methods")).toContain("POST");
      expect(res.headers.get("access-control-allow-headers")).toContain("Content-Type");
    });

    it("does not set CORS headers for disallowed origin", async () => {
      const res = await fetch(`${baseUrl}/api/health`, {
        headers: { Origin: "http://evil.example.com" },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("access-control-allow-origin")).toBeNull();
    });
  });

  // ── Server Stop ──────────────────────────────────────────

  describe("Server stop", () => {
    it("stop() cleans up sessions and closes the server", async () => {
      // Start a separate server instance for this test
      const instance = await startTestServer();

      // Create a session
      const createRes = await fetch(`${instance.baseUrl}/api/session`, {
        method: "POST",
      });
      expect(createRes.status).toBe(201);

      // Stop the server
      instance.stop();

      // After stop, making a request should fail
      await expect(
        fetch(`${instance.baseUrl}/api/health`).then((r) => r.json())
      ).rejects.toThrow();
    });
  });
});
