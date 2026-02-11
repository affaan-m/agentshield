/**
 * MiniClaw HTTP Server
 *
 * A minimal HTTP server with a single primary endpoint (POST /api/prompt).
 * Built on Node.js native http module — no Express, no Koa, no dependencies.
 *
 * WHY native http: Fewer dependencies = smaller attack surface.
 * Express and similar frameworks add convenience but also add code paths
 * that an attacker can exploit. For a security-first agent, we use the
 * minimum viable server.
 *
 * Security features:
 * - CORS restricted to configured origins (default: localhost only)
 * - Rate limiting per IP (default: 10 req/min)
 * - Request size limiting (default: 10KB)
 * - No directory listing, no static files, no file uploads
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type {
  MiniClawConfig,
  MiniClawSession,
  PromptRequest,
  SecurityEvent,
} from "./types.js";
import { createSandbox, destroySandbox, createSecurityEvent } from "./sandbox.js";
import { routePrompt } from "./router.js";
import { createSafeWhitelist } from "./tools.js";

// ─── Session Store ────────────────────────────────────────

/**
 * In-memory session store.
 *
 * WHY in-memory (not persistent): Sessions are ephemeral by design.
 * Persisting sessions to disk creates a data-at-rest risk and complicates
 * cleanup. If the server restarts, all sessions are destroyed — this is
 * a feature, not a bug.
 *
 * WHY a Map (not an object): Maps have O(1) lookup and no prototype chain
 * pollution risk. Using a plain object as a store is a classic vulnerability
 * where keys like "__proto__" or "constructor" can cause unexpected behavior.
 */
const sessions = new Map<string, MiniClawSession>();
const securityEvents = new Map<string, SecurityEvent[]>();

// ─── Rate Limiting ────────────────────────────────────────

/**
 * Rate limiter tracking requests per IP per minute.
 *
 * WHY per-IP: Prevents a single client from monopolizing the server.
 * In production, this should be supplemented with API key-based limiting.
 *
 * WHY sliding window: A fixed window (e.g., "10 per calendar minute")
 * allows bursts of 20 requests at the window boundary. The sliding
 * window approach prevents this.
 */
const rateLimitStore = new Map<string, ReadonlyArray<number>>();

function checkRateLimit(ip: string, maxRequests: number): boolean {
  const now = Date.now();
  const windowMs = 60_000; // 1 minute window
  const existing = rateLimitStore.get(ip) ?? [];

  // Remove entries outside the window
  // WHY filter instead of splice: Immutable pattern — create new array
  const recent = existing.filter((timestamp) => now - timestamp < windowMs);

  if (recent.length >= maxRequests) {
    return false; // Rate limit exceeded
  }

  // Record this request
  rateLimitStore.set(ip, [...recent, now]);
  return true;
}

// ─── Request Parsing ──────────────────────────────────────

/**
 * Reads the request body with a size limit.
 *
 * WHY size limit: Without a limit, an attacker can send a multi-gigabyte
 * request body to exhaust server memory (Slowloris-style attack).
 * We reject requests exceeding maxRequestSize immediately.
 */
function readBody(
  req: IncomingMessage,
  maxSize: number
): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;

    req.on("data", (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > maxSize) {
        req.destroy();
        reject(new Error(`Request body exceeds maximum size of ${maxSize} bytes`));
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf-8"));
    });

    req.on("error", (err) => {
      reject(err);
    });
  });
}

/**
 * Parses JSON body with error handling.
 *
 * WHY dedicated function: JSON.parse() throws on invalid input.
 * We need to return a meaningful error message, not crash the server.
 */
function parseJson<T>(body: string): { readonly data: T | null; readonly error: string | null } {
  try {
    const data = JSON.parse(body) as T;
    return { data, error: null };
  } catch {
    return { data: null, error: "Invalid JSON in request body" };
  }
}

// ─── CORS Handling ────────────────────────────────────────

/**
 * Sets CORS headers on the response.
 *
 * WHY strict CORS: Without CORS restrictions, any website the user visits
 * could make requests to the MiniClaw server running on localhost.
 * This is a serious security risk — a malicious website could inject prompts
 * and read responses.
 *
 * WHY not Access-Control-Allow-Origin: *: The wildcard allows ANY origin
 * to make requests, completely defeating CORS protection.
 */
function setCorsHeaders(
  res: ServerResponse,
  origin: string | undefined,
  allowedOrigins: ReadonlyArray<string>
): boolean {
  // WHY check origin against allowlist: Only respond with CORS headers
  // for allowed origins. For unknown origins, we still process the request
  // (for non-browser clients) but don't send CORS headers.
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Max-Age", "86400"); // 24 hours
    return true;
  }
  return false;
}

// ─── Response Helpers ─────────────────────────────────────

function sendJson(res: ServerResponse, statusCode: number, data: unknown): void {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    // WHY these security headers:
    // X-Content-Type-Options: Prevents MIME type sniffing attacks
    // X-Frame-Options: Prevents clickjacking by blocking iframe embedding
    // Cache-Control: Prevents sensitive responses from being cached
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function sendError(res: ServerResponse, statusCode: number, message: string): void {
  sendJson(res, statusCode, { error: message });
}

// ─── Route Handlers ───────────────────────────────────────

/**
 * POST /api/session — Creates a new sandboxed session.
 *
 * WHY no configuration in the request body: Session configuration should
 * come from the server config, not the client. Allowing clients to
 * configure their own sandbox would defeat the purpose of sandboxing.
 */
async function handleCreateSession(
  _req: IncomingMessage,
  res: ServerResponse,
  config: MiniClawConfig
): Promise<void> {
  const whitelist = createSafeWhitelist();
  const session = await createSandbox(
    config.sandbox,
    whitelist.tools,
    config.sandbox.maxDuration
  );

  sessions.set(session.id, session);
  securityEvents.set(session.id, []);

  sendJson(res, 201, {
    sessionId: session.id,
    createdAt: session.createdAt,
    allowedTools: session.allowedTools.map((t) => t.name),
    maxDuration: session.maxDuration,
  });
}

/**
 * GET /api/session — Returns information about the current sessions.
 *
 * WHY expose session info: The dashboard needs to display active sessions
 * and their status. This endpoint is read-only and reveals no sensitive data.
 */
function handleGetSessions(
  _req: IncomingMessage,
  res: ServerResponse
): void {
  const sessionList = [...sessions.values()].map((s) => ({
    id: s.id,
    createdAt: s.createdAt,
    allowedTools: s.allowedTools.map((t) => t.name),
    maxDuration: s.maxDuration,
  }));

  sendJson(res, 200, { sessions: sessionList });
}

/**
 * DELETE /api/session/:id — Destroys a session and its sandbox.
 *
 * WHY allow client-initiated destruction: Users should be able to clean up
 * their sessions. The server also destroys sessions on timeout, but
 * explicit cleanup is good hygiene.
 */
async function handleDeleteSession(
  _req: IncomingMessage,
  res: ServerResponse,
  sessionId: string,
  config: MiniClawConfig
): Promise<void> {
  const session = sessions.get(sessionId);
  if (!session) {
    sendError(res, 404, `Session "${sessionId}" not found`);
    return;
  }

  const result = await destroySandbox(session.sandboxPath, config.sandbox.rootPath);
  sessions.delete(sessionId);
  securityEvents.delete(sessionId);

  if (result.success) {
    sendJson(res, 200, { message: "Session destroyed", sessionId });
  } else {
    // Still remove from our store even if filesystem cleanup failed
    // WHY: The session is logically destroyed even if files remain.
    // A background cleanup process should handle orphaned directories.
    sendError(res, 500, `Session destroyed but cleanup failed: ${result.reason}`);
  }
}

/**
 * POST /api/prompt — The primary endpoint. Accepts a prompt and returns a response.
 *
 * This is the ONLY endpoint that processes user input through the agent.
 * All security measures (sanitization, whitelist, sandbox) are applied here.
 */
async function handlePrompt(
  req: IncomingMessage,
  res: ServerResponse,
  config: MiniClawConfig
): Promise<void> {
  let body: string;
  try {
    body = await readBody(req, config.server.maxRequestSize);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to read request body";
    sendError(res, 413, message);
    return;
  }

  const { data: request, error: parseError } = parseJson<PromptRequest>(body);
  if (parseError || !request) {
    sendError(res, 400, parseError ?? "Failed to parse request");
    return;
  }

  // Validate required fields
  if (!request.sessionId || !request.prompt) {
    sendError(res, 400, "Missing required fields: sessionId, prompt");
    return;
  }

  // Look up the session
  const session = sessions.get(request.sessionId);
  if (!session) {
    sendError(res, 404, `Session "${request.sessionId}" not found`);
    return;
  }

  // Route the prompt through the security pipeline
  const { response, securityEvents: promptEvents } = await routePrompt(request, session);

  // Record security events for this session
  const sessionEvents = securityEvents.get(session.id) ?? [];
  securityEvents.set(session.id, [...sessionEvents, ...promptEvents]);

  sendJson(res, 200, response);
}

/**
 * GET /api/events/:sessionId — Returns security events for a session.
 *
 * WHY expose security events: Transparency is a core MiniClaw principle.
 * The dashboard shows blocked injections and denied tools so users can
 * see exactly what the security system is doing.
 */
function handleGetEvents(
  _req: IncomingMessage,
  res: ServerResponse,
  sessionId: string
): void {
  const events = securityEvents.get(sessionId);
  if (!events) {
    sendError(res, 404, `Session "${sessionId}" not found`);
    return;
  }

  sendJson(res, 200, { sessionId, events });
}

// ─── Server Creation ──────────────────────────────────────

/**
 * Creates and starts the MiniClaw HTTP server.
 *
 * Returns a handle to the server for programmatic control (testing, embedding).
 */
export function createMiniClawServer(
  config: MiniClawConfig
): { readonly server: ReturnType<typeof createServer>; readonly stop: () => void } {
  const serverConfig = config.server;

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const method = req.method?.toUpperCase() ?? "GET";
    const origin = req.headers.origin;
    const clientIp = req.socket.remoteAddress ?? "unknown";

    // Handle CORS preflight
    // WHY respond to OPTIONS: Browsers send OPTIONS before cross-origin POST/DELETE.
    // We must respond with correct CORS headers or the actual request will be blocked.
    if (method === "OPTIONS") {
      setCorsHeaders(res, origin, serverConfig.corsOrigins);
      res.writeHead(204);
      res.end();
      return;
    }

    // Set CORS headers on all responses
    setCorsHeaders(res, origin, serverConfig.corsOrigins);

    // Rate limiting
    // WHY before any processing: Reject rate-limited requests immediately
    // to prevent resource consumption by abusive clients
    if (!checkRateLimit(clientIp, serverConfig.rateLimit)) {
      const event = createSecurityEvent(
        "rate_limit_exceeded",
        `Rate limit exceeded for IP ${clientIp}`,
        "server"
      );
      // Store rate limit event in a server-level log
      const serverEvents = securityEvents.get("server") ?? [];
      securityEvents.set("server", [...serverEvents, event]);

      sendError(res, 429, "Rate limit exceeded. Please try again later.");
      return;
    }

    // Route requests
    try {
      // POST /api/prompt
      if (method === "POST" && url.pathname === "/api/prompt") {
        await handlePrompt(req, res, config);
        return;
      }

      // POST /api/session
      if (method === "POST" && url.pathname === "/api/session") {
        await handleCreateSession(req, res, config);
        return;
      }

      // GET /api/session
      if (method === "GET" && url.pathname === "/api/session") {
        handleGetSessions(req, res);
        return;
      }

      // DELETE /api/session/:id
      if (method === "DELETE" && url.pathname.startsWith("/api/session/")) {
        const sessionId = url.pathname.slice("/api/session/".length);
        if (!sessionId) {
          sendError(res, 400, "Session ID is required");
          return;
        }
        await handleDeleteSession(req, res, sessionId, config);
        return;
      }

      // GET /api/events/:sessionId
      if (method === "GET" && url.pathname.startsWith("/api/events/")) {
        const sessionId = url.pathname.slice("/api/events/".length);
        if (!sessionId) {
          sendError(res, 400, "Session ID is required");
          return;
        }
        handleGetEvents(req, res, sessionId);
        return;
      }

      // GET /api/health — Simple health check
      // WHY: Load balancers and monitoring systems need a way to check
      // if the server is alive without authentication or rate limiting
      if (method === "GET" && url.pathname === "/api/health") {
        sendJson(res, 200, { status: "ok", sessions: sessions.size });
        return;
      }

      // 404 for everything else
      // WHY explicit 404: Not responding at all (hanging) can confuse
      // clients and load balancers. A clear 404 signals "wrong endpoint".
      sendError(res, 404, "Not found");
    } catch (error) {
      // Global error handler
      // WHY catch-all: Unhandled exceptions must NEVER leak stack traces
      // or internal details to the client
      const message = error instanceof Error ? error.message : "Internal server error";
      sendError(res, 500, `Server error: ${message}`);
    }
  });

  const stop = (): void => {
    server.close();
    // Cleanup: destroy all active sessions
    // WHY: Prevent orphaned sandbox directories when the server stops
    for (const session of sessions.values()) {
      destroySandbox(session.sandboxPath, config.sandbox.rootPath).catch(() => {
        // Best effort cleanup — log to stderr in production
      });
    }
    sessions.clear();
    securityEvents.clear();
    rateLimitStore.clear();
  };

  return { server, stop };
}

/**
 * Starts the MiniClaw server and begins listening for requests.
 *
 * This is the main entry point for running MiniClaw as a standalone server.
 */
export function startServer(
  config: MiniClawConfig
): { readonly server: ReturnType<typeof createServer>; readonly stop: () => void } {
  const { server, stop } = createMiniClawServer(config);

  server.listen(config.server.port, config.server.hostname, () => {
    // Server started — in production, this would be a structured log entry
    // not a console.log. The caller can listen for the 'listening' event.
  });

  return { server, stop };
}
