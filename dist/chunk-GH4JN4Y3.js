// src/miniclaw/types.ts
var DEFAULT_SANDBOX_CONFIG = {
  rootPath: "/tmp/miniclaw-sandboxes",
  maxFileSize: 10485760,
  // 10MB
  allowedExtensions: [
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".json",
    ".md",
    ".txt",
    ".css",
    ".html",
    ".yaml",
    ".yml",
    ".toml",
    ".xml",
    ".csv",
    ".svg",
    ".env.example"
  ],
  networkPolicy: "none",
  // WHY: Most secure default — no exfiltration possible
  maxDuration: 3e5
  // 5 minutes
};
var DEFAULT_SERVER_CONFIG = {
  port: 3847,
  hostname: "localhost",
  // WHY: Never bind to 0.0.0.0 by default — prevents remote access
  corsOrigins: ["http://localhost:3847", "http://localhost:3000"],
  rateLimit: 10,
  // WHY: 10 req/min is reasonable for interactive use, prevents scripted abuse
  maxRequestSize: 10240
  // WHY: 10KB is plenty for a prompt — prevents memory exhaustion
};

// src/miniclaw/sandbox.ts
import { mkdir, rm, stat, realpath, access } from "fs/promises";
import { join, resolve, relative, extname } from "path";
import { randomUUID } from "crypto";
async function validatePath(sandboxPath, requestedPath) {
  const absoluteRequested = resolve(sandboxPath, requestedPath);
  const normalizedSandbox = resolve(sandboxPath);
  if (!absoluteRequested.startsWith(normalizedSandbox + "/") && absoluteRequested !== normalizedSandbox) {
    return {
      valid: false,
      resolvedPath: absoluteRequested,
      reason: `Path traversal detected: "${requestedPath}" resolves outside sandbox`
    };
  }
  try {
    await access(absoluteRequested);
    const realPath = await realpath(absoluteRequested);
    if (!realPath.startsWith(normalizedSandbox + "/") && realPath !== normalizedSandbox) {
      return {
        valid: false,
        resolvedPath: realPath,
        reason: `Symlink escape detected: "${requestedPath}" resolves to "${realPath}" outside sandbox`
      };
    }
    return { valid: true, resolvedPath: realPath, reason: "Path is within sandbox" };
  } catch {
    return { valid: true, resolvedPath: absoluteRequested, reason: "Path is within sandbox (new file)" };
  }
}
function validateExtension(filePath, allowedExtensions) {
  const ext = extname(filePath).toLowerCase();
  if (ext === "") {
    return {
      valid: false,
      reason: `Files without extensions are not allowed (file: "${filePath}")`
    };
  }
  if (!allowedExtensions.includes(ext)) {
    return {
      valid: false,
      reason: `Extension "${ext}" is not in the allowed list`
    };
  }
  return { valid: true, reason: "Extension is allowed" };
}
async function checkFileSize(filePath, maxSize) {
  try {
    const stats = await stat(filePath);
    if (stats.size > maxSize) {
      return {
        valid: false,
        size: stats.size,
        reason: `File size ${stats.size} bytes exceeds maximum ${maxSize} bytes`
      };
    }
    return {
      valid: true,
      size: stats.size,
      reason: "File size is within limits"
    };
  } catch {
    return { valid: true, size: 0, reason: "File does not exist yet" };
  }
}
async function createSandbox(config = DEFAULT_SANDBOX_CONFIG, allowedTools = [], maxDuration) {
  const sessionId = randomUUID();
  const sandboxPath = join(config.rootPath, sessionId);
  await mkdir(config.rootPath, { recursive: true, mode: 448 });
  await mkdir(sandboxPath, { mode: 448 });
  const session = {
    id: sessionId,
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    sandboxPath,
    allowedTools,
    maxDuration: maxDuration ?? config.maxDuration
  };
  return session;
}
async function destroySandbox(sandboxPath, rootPath) {
  const normalizedSandbox = resolve(sandboxPath);
  const normalizedRoot = resolve(rootPath);
  if (!normalizedSandbox.startsWith(normalizedRoot + "/")) {
    return {
      success: false,
      reason: `Sandbox path "${sandboxPath}" is not under root "${rootPath}" \u2014 refusing to delete`
    };
  }
  const relativePath = relative(normalizedRoot, normalizedSandbox);
  if (relativePath.includes("/") || relativePath === "" || relativePath === "..") {
    return {
      success: false,
      reason: `Sandbox path must be a direct child of root \u2014 got relative path "${relativePath}"`
    };
  }
  try {
    await rm(normalizedSandbox, { recursive: true, force: true });
    return { success: true, reason: "Sandbox destroyed successfully" };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, reason: `Failed to destroy sandbox: ${message}` };
  }
}
function createSecurityEvent(type, details, sessionId) {
  return {
    type,
    details,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    sessionId
  };
}

// src/miniclaw/router.ts
var INJECTION_PATTERNS = [
  // System prompt override attempts
  // WHY: The most basic prompt injection — trying to replace the system prompt
  {
    pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|context)/i,
    description: "System prompt override: 'ignore previous instructions'"
  },
  {
    pattern: /you\s+are\s+now\s+(a|an|the)\s+/i,
    description: "Identity reassignment: 'you are now a...'"
  },
  {
    pattern: /forget\s+(everything|all|your)\s+(you|instructions|previous)/i,
    description: "Memory wipe attempt: 'forget everything'"
  },
  {
    pattern: /new\s+instructions?:\s*/i,
    description: "System prompt injection: 'new instructions:'"
  },
  {
    pattern: /system\s*prompt\s*[:=]/i,
    description: "Direct system prompt override attempt"
  },
  {
    pattern: /\[system\]|\[INST\]|<\|im_start\|>|<\|system\|>/i,
    description: "Chat template injection: special tokens"
  },
  // Jailbreak patterns
  // WHY: These attempt to bypass safety guidelines by framing the request
  {
    pattern: /do\s+anything\s+now|DAN\s+mode|jailbreak/i,
    description: "Jailbreak attempt: DAN/DANO pattern"
  },
  {
    pattern: /pretend\s+(you|that)\s+(are|can|have)\s+no\s+(restrictions|limits|rules)/i,
    description: "Jailbreak: restriction removal request"
  },
  // Direct tool invocation
  // WHY: The agent's tools should only be invoked through the routing system,
  // never directly from user input. This prevents bypassing the whitelist.
  {
    pattern: /```\s*(bash|shell|sh|cmd|powershell)\b/i,
    description: "Direct shell invocation via code block"
  },
  {
    pattern: /exec\s*\(|child_process|spawn\s*\(|system\s*\(/i,
    description: "Process execution attempt in prompt"
  },
  // Data exfiltration attempts
  // WHY: Even without network access, an attacker might try to encode
  // sensitive data in the response for manual exfiltration
  {
    pattern: /curl\s+|wget\s+|fetch\s*\(|http\.get/i,
    description: "Network request attempt in prompt"
  }
];
var INVISIBLE_CHAR_PATTERN = /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u2000-\u200A\u202A-\u202E\u2060-\u2064\u2066-\u206F]/g;
var BASE64_INSTRUCTION_PATTERN = /(?:eval|decode|execute|run)\s*\(\s*(?:atob|Buffer\.from|base64)\s*\(/i;
var SYSTEM_PROMPT_MARKERS = [
  "you are miniclaw",
  "your system prompt is",
  "my instructions are",
  "i was configured to",
  "my system prompt",
  "here are my instructions",
  "my configuration includes"
];
function sanitizePrompt(raw, sessionId) {
  const events = [];
  let sanitized = raw;
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
  const base64Matches = [...sanitized.matchAll(new RegExp(BASE64_INSTRUCTION_PATTERN.source, "gi"))];
  if (base64Matches.length > 0) {
    events.push(
      createSecurityEvent(
        "prompt_injection_detected",
        "Detected base64-encoded instruction execution attempt",
        sessionId
      )
    );
    sanitized = sanitized.replace(BASE64_INSTRUCTION_PATTERN, "[BLOCKED: encoded execution]");
  }
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
      sanitized = sanitized.replace(
        new RegExp(pattern.source, "gi"),
        "[BLOCKED]"
      );
    }
  }
  sanitized = sanitized.replace(/\s{10,}/g, " ");
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
function filterResponse(response, sessionId) {
  const events = [];
  let filtered = response;
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
      const markerIndex = lowerResponse.indexOf(marker);
      const sentenceStart = filtered.lastIndexOf(".", markerIndex) + 1;
      const sentenceEnd = filtered.indexOf(".", markerIndex + marker.length);
      const end = sentenceEnd === -1 ? filtered.length : sentenceEnd + 1;
      filtered = filtered.slice(0, sentenceStart) + " [This content has been filtered for security reasons.] " + filtered.slice(end);
    }
  }
  filtered = filtered.replace(
    /at\s+[\w.]+\s+\(\/[^)]+\)/g,
    "[internal path redacted]"
  );
  filtered = filtered.replace(
    /\/(?:usr|etc|var|home|root|tmp\/miniclaw-sandboxes)\/[\w/.+-]+/g,
    "[path redacted]"
  );
  return { filtered, events };
}
async function routePrompt(request, session) {
  const startTime = Date.now();
  const allEvents = [];
  const { sanitized, events: sanitizeEvents } = sanitizePrompt(
    request.prompt,
    session.id
  );
  allEvents.push(...sanitizeEvents);
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
        tokenUsage: { input: 0, output: 0 }
      },
      securityEvents: allEvents
    };
  }
  const toolCalls = [];
  const processedResponse = await processPromptWithTools(
    sanitized,
    session,
    toolCalls,
    allEvents
  );
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
      tokenUsage: { input: sanitized.length, output: filtered.length }
    },
    securityEvents: allEvents
  };
}
async function processPromptWithTools(_sanitizedPrompt, session, _toolCalls, _events) {
  const toolCount = session.allowedTools.length;
  return `Prompt received and sanitized. Session ${session.id} has ${toolCount} tools available. Ready for LLM integration.`;
}

// src/miniclaw/tools.ts
var SAFE_TOOLS = [
  {
    name: "read",
    description: "Read file contents within the sandbox. Cannot access files outside the sandbox boundary.",
    riskLevel: "safe"
  },
  {
    name: "search",
    description: "Search file contents within the sandbox using text patterns. Scoped to sandbox directory.",
    riskLevel: "safe"
  },
  {
    name: "list",
    description: "List directory contents within the sandbox. Cannot traverse above sandbox root.",
    riskLevel: "safe"
  }
];
var GUARDED_TOOLS = [
  {
    name: "write",
    description: "Write file contents within the sandbox. Requires explicit session configuration.",
    riskLevel: "guarded"
  },
  {
    name: "edit",
    description: "Edit existing files within the sandbox. Validates file exists before modification.",
    riskLevel: "guarded"
  },
  {
    name: "glob",
    description: "Pattern-match files within the sandbox. Scoped to sandbox directory only.",
    riskLevel: "guarded"
  }
];
var RESTRICTED_TOOLS = [
  {
    name: "bash",
    description: "Execute shell commands. DANGER: Can access host system. Only enable with additional containment.",
    riskLevel: "restricted"
  },
  {
    name: "network",
    description: "Make HTTP requests. DANGER: Can exfiltrate data. Only enable with network policy allowlist.",
    riskLevel: "restricted"
  },
  {
    name: "external_api",
    description: "Call external APIs. DANGER: Can make authenticated requests to third-party services.",
    riskLevel: "restricted"
  }
];
var TOOL_REGISTRY = [
  ...SAFE_TOOLS,
  ...GUARDED_TOOLS,
  ...RESTRICTED_TOOLS
];
function createSafeWhitelist() {
  return { tools: [...SAFE_TOOLS] };
}
function createGuardedWhitelist() {
  return { tools: [...SAFE_TOOLS, ...GUARDED_TOOLS] };
}
function createCustomWhitelist(toolNames) {
  const recognized = [];
  const unrecognized = [];
  for (const name of toolNames) {
    const tool = TOOL_REGISTRY.find((t) => t.name === name);
    if (tool) {
      recognized.push(tool);
    } else {
      unrecognized.push(name);
    }
  }
  return {
    whitelist: { tools: recognized },
    unrecognized
  };
}
function validateToolCall(call, whitelist) {
  const registeredTool = TOOL_REGISTRY.find((t) => t.name === call.tool);
  if (!registeredTool) {
    return {
      allowed: false,
      tool: call.tool,
      reason: `Unknown tool "${call.tool}" \u2014 not in the tool registry`
    };
  }
  const allowedTool = whitelist.tools.find((t) => t.name === call.tool);
  if (!allowedTool) {
    return {
      allowed: false,
      tool: call.tool,
      reason: `Tool "${call.tool}" (${registeredTool.riskLevel}) is not in the session whitelist`
    };
  }
  return {
    allowed: true,
    tool: call.tool,
    reason: `Tool "${call.tool}" is allowed (risk level: ${allowedTool.riskLevel})`
  };
}
function scopeToolCall(call, sandboxPath) {
  const scopedArgs = {};
  for (const [key, value] of Object.entries(call.args)) {
    if (isPathArgument(key) && typeof value === "string") {
      scopedArgs[key] = scopePath(value, sandboxPath);
    } else {
      scopedArgs[key] = value;
    }
  }
  return {
    tool: call.tool,
    args: scopedArgs
  };
}
function isPathArgument(key) {
  const pathKeys = ["path", "file", "filePath", "file_path", "directory", "dir", "target"];
  return pathKeys.includes(key);
}
function scopePath(requestedPath, sandboxPath) {
  const stripped = requestedPath.replace(/^\/+/, "");
  const cleaned = stripped.replace(/\.\.\//g, "");
  return `${sandboxPath}/${cleaned}`;
}
async function executeToolCall(call, sandboxPath, sessionId) {
  const events = [];
  for (const [key, value] of Object.entries(call.args)) {
    if (isPathArgument(key) && typeof value === "string") {
      const pathCheck = await validatePath(sandboxPath, value);
      if (!pathCheck.valid) {
        events.push(
          createSecurityEvent("sandbox_violation", pathCheck.reason, sessionId)
        );
        return {
          result: `Error: ${pathCheck.reason}`,
          events
        };
      }
    }
  }
  switch (call.tool) {
    case "read":
      return { result: await executeRead(call, sandboxPath), events };
    case "write":
      return { result: await executeWrite(call, sandboxPath, events, sessionId), events };
    case "search":
      return { result: await executeSearch(call, sandboxPath), events };
    case "list":
      return { result: await executeList(call, sandboxPath), events };
    case "edit":
      return { result: await executeEdit(call, sandboxPath, events, sessionId), events };
    case "glob":
      return { result: await executeGlob(call, sandboxPath), events };
    default:
      events.push(
        createSecurityEvent(
          "tool_denied",
          `No executor found for tool "${call.tool}"`,
          sessionId
        )
      );
      return { result: `Error: No executor for tool "${call.tool}"`, events };
  }
}
async function executeRead(call, _sandboxPath) {
  const filePath = call.args["path"];
  if (!filePath) {
    return "Error: 'path' argument is required for read tool";
  }
  return `[read] Would read file: ${filePath}`;
}
async function executeWrite(call, _sandboxPath, events, sessionId) {
  const filePath = call.args["path"];
  const content = call.args["content"];
  if (!filePath || content === void 0) {
    return "Error: 'path' and 'content' arguments are required for write tool";
  }
  const extCheck = validateExtension(filePath, [
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".json",
    ".md",
    ".txt",
    ".css",
    ".html",
    ".yaml",
    ".yml",
    ".toml"
  ]);
  if (!extCheck.valid) {
    events.push(
      createSecurityEvent("sandbox_violation", extCheck.reason, sessionId)
    );
    return `Error: ${extCheck.reason}`;
  }
  return `[write] Would write ${content.length} bytes to: ${filePath}`;
}
async function executeSearch(call, _sandboxPath) {
  const pattern = call.args["pattern"];
  if (!pattern) {
    return "Error: 'pattern' argument is required for search tool";
  }
  return `[search] Would search for pattern: ${pattern}`;
}
async function executeList(call, sandboxPath) {
  const dir = call.args["path"] ?? sandboxPath;
  return `[list] Would list directory: ${dir}`;
}
async function executeEdit(call, _sandboxPath, _events, _sessionId) {
  const filePath = call.args["path"];
  if (!filePath) {
    return "Error: 'path' argument is required for edit tool";
  }
  return `[edit] Would edit file: ${filePath}`;
}
async function executeGlob(call, _sandboxPath) {
  const pattern = call.args["pattern"];
  if (!pattern) {
    return "Error: 'pattern' argument is required for glob tool";
  }
  return `[glob] Would glob for pattern: ${pattern}`;
}
function getToolsByRiskLevel() {
  return {
    safe: SAFE_TOOLS,
    guarded: GUARDED_TOOLS,
    restricted: RESTRICTED_TOOLS
  };
}

// src/miniclaw/server.ts
import { createServer } from "http";
var sessions = /* @__PURE__ */ new Map();
var securityEvents = /* @__PURE__ */ new Map();
var rateLimitStore = /* @__PURE__ */ new Map();
function checkRateLimit(ip, maxRequests) {
  const now = Date.now();
  const windowMs = 6e4;
  const existing = rateLimitStore.get(ip) ?? [];
  const recent = existing.filter((timestamp) => now - timestamp < windowMs);
  if (recent.length >= maxRequests) {
    return false;
  }
  rateLimitStore.set(ip, [...recent, now]);
  return true;
}
function readBody(req, maxSize) {
  return new Promise((resolve2, reject) => {
    const chunks = [];
    let totalSize = 0;
    req.on("data", (chunk) => {
      totalSize += chunk.length;
      if (totalSize > maxSize) {
        req.destroy();
        reject(new Error(`Request body exceeds maximum size of ${maxSize} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      resolve2(Buffer.concat(chunks).toString("utf-8"));
    });
    req.on("error", (err) => {
      reject(err);
    });
  });
}
function parseJson(body) {
  try {
    const data = JSON.parse(body);
    return { data, error: null };
  } catch {
    return { data: null, error: "Invalid JSON in request body" };
  }
}
function setCorsHeaders(res, origin, allowedOrigins) {
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Max-Age", "86400");
    return true;
  }
  return false;
}
function sendJson(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    // WHY these security headers:
    // X-Content-Type-Options: Prevents MIME type sniffing attacks
    // X-Frame-Options: Prevents clickjacking by blocking iframe embedding
    // Cache-Control: Prevents sensitive responses from being cached
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store"
  });
  res.end(body);
}
function sendError(res, statusCode, message) {
  sendJson(res, statusCode, { error: message });
}
async function handleCreateSession(_req, res, config) {
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
    maxDuration: session.maxDuration
  });
}
function handleGetSessions(_req, res) {
  const sessionList = [...sessions.values()].map((s) => ({
    id: s.id,
    createdAt: s.createdAt,
    allowedTools: s.allowedTools.map((t) => t.name),
    maxDuration: s.maxDuration
  }));
  sendJson(res, 200, { sessions: sessionList });
}
async function handleDeleteSession(_req, res, sessionId, config) {
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
    sendError(res, 500, `Session destroyed but cleanup failed: ${result.reason}`);
  }
}
async function handlePrompt(req, res, config) {
  let body;
  try {
    body = await readBody(req, config.server.maxRequestSize);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to read request body";
    sendError(res, 413, message);
    return;
  }
  const { data: request, error: parseError } = parseJson(body);
  if (parseError || !request) {
    sendError(res, 400, parseError ?? "Failed to parse request");
    return;
  }
  if (!request.sessionId || !request.prompt) {
    sendError(res, 400, "Missing required fields: sessionId, prompt");
    return;
  }
  const session = sessions.get(request.sessionId);
  if (!session) {
    sendError(res, 404, `Session "${request.sessionId}" not found`);
    return;
  }
  const { response, securityEvents: promptEvents } = await routePrompt(request, session);
  const sessionEvents = securityEvents.get(session.id) ?? [];
  securityEvents.set(session.id, [...sessionEvents, ...promptEvents]);
  sendJson(res, 200, response);
}
function handleGetEvents(_req, res, sessionId) {
  const events = securityEvents.get(sessionId);
  if (!events) {
    sendError(res, 404, `Session "${sessionId}" not found`);
    return;
  }
  sendJson(res, 200, { sessionId, events });
}
function createMiniClawServer(config) {
  const serverConfig = config.server;
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const method = req.method?.toUpperCase() ?? "GET";
    const origin = req.headers.origin;
    const clientIp = req.socket.remoteAddress ?? "unknown";
    if (method === "OPTIONS") {
      setCorsHeaders(res, origin, serverConfig.corsOrigins);
      res.writeHead(204);
      res.end();
      return;
    }
    setCorsHeaders(res, origin, serverConfig.corsOrigins);
    if (!checkRateLimit(clientIp, serverConfig.rateLimit)) {
      const event = createSecurityEvent(
        "rate_limit_exceeded",
        `Rate limit exceeded for IP ${clientIp}`,
        "server"
      );
      const serverEvents = securityEvents.get("server") ?? [];
      securityEvents.set("server", [...serverEvents, event]);
      sendError(res, 429, "Rate limit exceeded. Please try again later.");
      return;
    }
    try {
      if (method === "POST" && url.pathname === "/api/prompt") {
        await handlePrompt(req, res, config);
        return;
      }
      if (method === "POST" && url.pathname === "/api/session") {
        await handleCreateSession(req, res, config);
        return;
      }
      if (method === "GET" && url.pathname === "/api/session") {
        handleGetSessions(req, res);
        return;
      }
      if (method === "DELETE" && url.pathname.startsWith("/api/session/")) {
        const sessionId = url.pathname.slice("/api/session/".length);
        if (!sessionId) {
          sendError(res, 400, "Session ID is required");
          return;
        }
        await handleDeleteSession(req, res, sessionId, config);
        return;
      }
      if (method === "GET" && url.pathname.startsWith("/api/events/")) {
        const sessionId = url.pathname.slice("/api/events/".length);
        if (!sessionId) {
          sendError(res, 400, "Session ID is required");
          return;
        }
        handleGetEvents(req, res, sessionId);
        return;
      }
      if (method === "GET" && url.pathname === "/api/health") {
        sendJson(res, 200, { status: "ok", sessions: sessions.size });
        return;
      }
      sendError(res, 404, "Not found");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Internal server error";
      sendError(res, 500, `Server error: ${message}`);
    }
  });
  const stop = () => {
    server.close();
    for (const session of sessions.values()) {
      destroySandbox(session.sandboxPath, config.sandbox.rootPath).catch(() => {
      });
    }
    sessions.clear();
    securityEvents.clear();
    rateLimitStore.clear();
  };
  return { server, stop };
}
function startServer(config) {
  const { server, stop } = createMiniClawServer(config);
  server.listen(config.server.port, config.server.hostname, () => {
  });
  return { server, stop };
}

// src/miniclaw/index.ts
function startMiniClaw(config) {
  const fullConfig = {
    sandbox: config?.sandbox ?? DEFAULT_SANDBOX_CONFIG,
    server: config?.server ?? DEFAULT_SERVER_CONFIG,
    tools: config?.tools ?? createSafeWhitelist()
  };
  return startServer(fullConfig);
}
async function createMiniClawSession(config) {
  const sandboxConfig = {
    ...DEFAULT_SANDBOX_CONFIG,
    ...config?.sandbox
  };
  const tools = config?.tools ?? createSafeWhitelist();
  return createSandbox(sandboxConfig, tools.tools, sandboxConfig.maxDuration);
}

export {
  DEFAULT_SANDBOX_CONFIG,
  DEFAULT_SERVER_CONFIG,
  validatePath,
  validateExtension,
  checkFileSize,
  createSandbox,
  destroySandbox,
  createSecurityEvent,
  sanitizePrompt,
  filterResponse,
  routePrompt,
  TOOL_REGISTRY,
  createSafeWhitelist,
  createGuardedWhitelist,
  createCustomWhitelist,
  validateToolCall,
  scopeToolCall,
  executeToolCall,
  getToolsByRiskLevel,
  createMiniClawServer,
  startServer,
  startMiniClaw,
  createMiniClawSession
};
