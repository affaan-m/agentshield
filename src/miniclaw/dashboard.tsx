/**
 * MiniClaw Dashboard Component
 *
 * A self-contained React component for interacting with a MiniClaw server.
 * This file can be dropped into any React 18+ project.
 *
 * PEER DEPENDENCY: React 18+ must be provided by the consuming application.
 * The agentshield package itself does NOT include React — this component
 * is for consumers who want to embed the MiniClaw dashboard in their UI.
 *
 * Features:
 * - Dark theme, minimal aesthetic
 * - Prompt input with submit
 * - Streaming response display placeholder
 * - Session status indicator
 * - Security events panel
 * - Tool whitelist display
 *
 * Usage:
 *   import { MiniClawDashboard } from '@agentshield/miniclaw/dashboard';
 *   <MiniClawDashboard endpoint="http://localhost:3847" />
 */

import React, { useState, useEffect, useCallback, useRef } from "react";

// ─── Types (local to component — no import from types.ts needed) ──

type SessionStatus = "idle" | "active" | "error";

interface SessionInfo {
  readonly sessionId: string;
  readonly createdAt: string;
  readonly allowedTools: ReadonlyArray<string>;
  readonly maxDuration: number;
}

interface SecurityEventDisplay {
  readonly type: string;
  readonly details: string;
  readonly timestamp: string;
}

interface PromptResponseDisplay {
  readonly response: string;
  readonly toolCalls: ReadonlyArray<{
    readonly tool: string;
    readonly result: string;
  }>;
  readonly duration: number;
}

interface MiniClawDashboardProps {
  /** Base URL of the MiniClaw server (e.g., "http://localhost:3847") */
  readonly endpoint: string;
  /** Optional custom title for the dashboard */
  readonly title?: string;
}

// ─── Styles ───────────────────────────────────────────────

/**
 * Inline styles for the dashboard.
 *
 * WHY inline styles (not CSS modules/Tailwind): This component must work
 * when dropped into any React project without requiring a CSS build pipeline.
 * Inline styles are self-contained and have no external dependencies.
 */
const styles = {
  container: {
    fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace",
    backgroundColor: "#0d1117",
    color: "#c9d1d9",
    borderRadius: "12px",
    border: "1px solid #30363d",
    padding: "24px",
    maxWidth: "800px",
    margin: "0 auto",
  } as const,

  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "20px",
    paddingBottom: "16px",
    borderBottom: "1px solid #21262d",
  } as const,

  title: {
    fontSize: "18px",
    fontWeight: 600,
    color: "#f0f6fc",
    margin: 0,
  } as const,

  statusBadge: {
    padding: "4px 12px",
    borderRadius: "12px",
    fontSize: "12px",
    fontWeight: 500,
  } as const,

  statusIdle: {
    backgroundColor: "#1f2937",
    color: "#9ca3af",
  } as const,

  statusActive: {
    backgroundColor: "#064e3b",
    color: "#6ee7b7",
  } as const,

  statusError: {
    backgroundColor: "#7f1d1d",
    color: "#fca5a5",
  } as const,

  promptArea: {
    marginBottom: "20px",
  } as const,

  promptInput: {
    width: "100%",
    padding: "12px 16px",
    backgroundColor: "#161b22",
    color: "#c9d1d9",
    border: "1px solid #30363d",
    borderRadius: "8px",
    fontSize: "14px",
    fontFamily: "inherit",
    outline: "none",
    resize: "none" as const,
    minHeight: "80px",
    boxSizing: "border-box" as const,
  } as const,

  submitButton: {
    marginTop: "8px",
    padding: "8px 20px",
    backgroundColor: "#238636",
    color: "#ffffff",
    border: "none",
    borderRadius: "6px",
    fontSize: "14px",
    fontWeight: 500,
    cursor: "pointer",
  } as const,

  submitButtonDisabled: {
    backgroundColor: "#21262d",
    color: "#484f58",
    cursor: "not-allowed",
  } as const,

  responseArea: {
    backgroundColor: "#161b22",
    border: "1px solid #21262d",
    borderRadius: "8px",
    padding: "16px",
    marginBottom: "20px",
    minHeight: "100px",
    maxHeight: "400px",
    overflowY: "auto" as const,
    whiteSpace: "pre-wrap" as const,
    fontSize: "13px",
    lineHeight: "1.6",
  } as const,

  sectionTitle: {
    fontSize: "14px",
    fontWeight: 600,
    color: "#f0f6fc",
    marginBottom: "8px",
    marginTop: "16px",
  } as const,

  eventList: {
    listStyle: "none",
    padding: 0,
    margin: 0,
  } as const,

  eventItem: {
    padding: "8px 12px",
    backgroundColor: "#161b22",
    border: "1px solid #21262d",
    borderRadius: "6px",
    marginBottom: "4px",
    fontSize: "12px",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
  } as const,

  eventType: {
    color: "#f85149",
    fontWeight: 500,
    fontSize: "11px",
    textTransform: "uppercase" as const,
  } as const,

  eventTime: {
    color: "#484f58",
    fontSize: "11px",
  } as const,

  toolList: {
    display: "flex",
    flexWrap: "wrap" as const,
    gap: "6px",
    marginTop: "8px",
  } as const,

  toolBadge: {
    padding: "2px 8px",
    borderRadius: "4px",
    fontSize: "12px",
    fontWeight: 500,
  } as const,

  toolSafe: {
    backgroundColor: "#064e3b",
    color: "#6ee7b7",
  } as const,

  toolGuarded: {
    backgroundColor: "#78350f",
    color: "#fcd34d",
  } as const,

  toolRestricted: {
    backgroundColor: "#7f1d1d",
    color: "#fca5a5",
  } as const,

  emptyState: {
    color: "#484f58",
    fontStyle: "italic" as const,
    textAlign: "center" as const,
    padding: "24px",
  } as const,

  duration: {
    color: "#484f58",
    fontSize: "12px",
    marginTop: "8px",
  } as const,

  sessionButton: {
    padding: "6px 14px",
    backgroundColor: "#21262d",
    color: "#c9d1d9",
    border: "1px solid #30363d",
    borderRadius: "6px",
    fontSize: "12px",
    cursor: "pointer",
    marginRight: "8px",
  } as const,

  footer: {
    marginTop: "20px",
    paddingTop: "12px",
    borderTop: "1px solid #21262d",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    fontSize: "11px",
    color: "#484f58",
  } as const,
} as const;

// ─── Subcomponents ────────────────────────────────────────

function StatusBadge({ status }: { readonly status: SessionStatus }): React.ReactElement {
  const statusStyles = {
    idle: styles.statusIdle,
    active: styles.statusActive,
    error: styles.statusError,
  };

  return (
    <span style={{ ...styles.statusBadge, ...statusStyles[status] }}>
      {status.toUpperCase()}
    </span>
  );
}

function SecurityEventsPanel({
  events,
}: {
  readonly events: ReadonlyArray<SecurityEventDisplay>;
}): React.ReactElement {
  return (
    <div>
      <h3 style={styles.sectionTitle}>Security Events</h3>
      {events.length === 0 ? (
        <p style={styles.emptyState}>No security events recorded</p>
      ) : (
        <ul style={styles.eventList}>
          {events.map((event, index) => (
            <li key={`${event.timestamp}-${index}`} style={styles.eventItem}>
              <div>
                <span style={styles.eventType}>{event.type}</span>
                <span style={{ marginLeft: "8px" }}>{event.details}</span>
              </div>
              <span style={styles.eventTime}>
                {new Date(event.timestamp).toLocaleTimeString()}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ToolWhitelistPanel({
  tools,
}: {
  readonly tools: ReadonlyArray<string>;
}): React.ReactElement {
  // Categorize tools by known risk levels for display
  // WHY hardcoded mapping: The dashboard doesn't need to query the server
  // for risk levels — they are part of the tool definition and don't change.
  const riskMap: Readonly<Record<string, string>> = {
    read: "safe",
    search: "safe",
    list: "safe",
    write: "guarded",
    edit: "guarded",
    glob: "guarded",
    bash: "restricted",
    network: "restricted",
    external_api: "restricted",
  };

  const badgeStyle = (tool: string): Record<string, string> => {
    const risk = riskMap[tool] ?? "safe";
    switch (risk) {
      case "guarded":
        return styles.toolGuarded;
      case "restricted":
        return styles.toolRestricted;
      default:
        return styles.toolSafe;
    }
  };

  return (
    <div>
      <h3 style={styles.sectionTitle}>Allowed Tools</h3>
      {tools.length === 0 ? (
        <p style={styles.emptyState}>No active session</p>
      ) : (
        <div style={styles.toolList}>
          {tools.map((tool) => (
            <span
              key={tool}
              style={{ ...styles.toolBadge, ...badgeStyle(tool) }}
            >
              {tool}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main Dashboard Component ─────────────────────────────

/**
 * MiniClaw Dashboard — the primary UI component.
 *
 * Manages session lifecycle, prompt submission, and security event display.
 * All communication with the MiniClaw server goes through the configured endpoint.
 */
export function MiniClawDashboard({
  endpoint,
  title = "MiniClaw",
}: MiniClawDashboardProps): React.ReactElement {
  const [status, setStatus] = useState<SessionStatus>("idle");
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [prompt, setPrompt] = useState("");
  const [response, setResponse] = useState<PromptResponseDisplay | null>(null);
  const [events, setEvents] = useState<ReadonlyArray<SecurityEventDisplay>>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const responseRef = useRef<HTMLDivElement>(null);

  // Create a new session
  const createSession = useCallback(async (): Promise<void> => {
    try {
      setStatus("active");
      setErrorMessage(null);
      const res = await fetch(`${endpoint}/api/session`, { method: "POST" });
      if (!res.ok) {
        throw new Error(`Failed to create session: ${res.statusText}`);
      }
      const data = (await res.json()) as SessionInfo;
      setSession(data);
    } catch (error) {
      setStatus("error");
      const message = error instanceof Error ? error.message : "Failed to create session";
      setErrorMessage(message);
    }
  }, [endpoint]);

  // Destroy the current session
  const destroySession = useCallback(async (): Promise<void> => {
    if (!session) return;

    try {
      await fetch(`${endpoint}/api/session/${session.sessionId}`, {
        method: "DELETE",
      });
    } catch {
      // Best effort cleanup
    }

    setSession(null);
    setStatus("idle");
    setResponse(null);
    setEvents([]);
    setErrorMessage(null);
  }, [endpoint, session]);

  // Submit a prompt
  const submitPrompt = useCallback(async (): Promise<void> => {
    if (!session || !prompt.trim() || isSubmitting) return;

    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      const res = await fetch(`${endpoint}/api/prompt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId: session.sessionId,
          prompt: prompt.trim(),
        }),
      });

      if (!res.ok) {
        throw new Error(`Prompt failed: ${res.statusText}`);
      }

      const data = (await res.json()) as PromptResponseDisplay;
      setResponse(data);
      setPrompt("");

      // Fetch updated security events
      const eventsRes = await fetch(
        `${endpoint}/api/events/${session.sessionId}`
      );
      if (eventsRes.ok) {
        const eventsData = (await eventsRes.json()) as {
          events: ReadonlyArray<SecurityEventDisplay>;
        };
        setEvents(eventsData.events);
      }
    } catch (error) {
      setStatus("error");
      const message = error instanceof Error ? error.message : "Failed to submit prompt";
      setErrorMessage(message);
    } finally {
      setIsSubmitting(false);
    }
  }, [endpoint, session, prompt, isSubmitting]);

  // Handle keyboard shortcut (Cmd/Ctrl + Enter to submit)
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>): void => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        submitPrompt();
      }
    },
    [submitPrompt]
  );

  // Auto-scroll response area when new content arrives
  useEffect(() => {
    if (responseRef.current) {
      responseRef.current.scrollTop = responseRef.current.scrollHeight;
    }
  }, [response]);

  return (
    <div style={styles.container}>
      {/* Header with status */}
      <div style={styles.header}>
        <h2 style={styles.title}>{title}</h2>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          {!session ? (
            <button style={styles.sessionButton} onClick={createSession}>
              New Session
            </button>
          ) : (
            <button style={styles.sessionButton} onClick={destroySession}>
              End Session
            </button>
          )}
          <StatusBadge status={status} />
        </div>
      </div>

      {/* Error display */}
      {errorMessage && (
        <div
          style={{
            backgroundColor: "#7f1d1d",
            color: "#fca5a5",
            padding: "8px 12px",
            borderRadius: "6px",
            marginBottom: "12px",
            fontSize: "13px",
          }}
        >
          {errorMessage}
        </div>
      )}

      {/* Prompt input */}
      <div style={styles.promptArea}>
        <textarea
          style={{
            ...styles.promptInput,
            borderColor: isSubmitting ? "#30363d" : "#30363d",
          }}
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={
            session
              ? "Enter your prompt... (Cmd+Enter to submit)"
              : "Create a session to start"
          }
          disabled={!session || isSubmitting}
        />
        <button
          style={{
            ...styles.submitButton,
            ...((!session || isSubmitting || !prompt.trim())
              ? styles.submitButtonDisabled
              : {}),
          }}
          onClick={submitPrompt}
          disabled={!session || isSubmitting || !prompt.trim()}
        >
          {isSubmitting ? "Processing..." : "Submit"}
        </button>
      </div>

      {/* Response display */}
      <h3 style={styles.sectionTitle}>Response</h3>
      <div ref={responseRef} style={styles.responseArea}>
        {response ? (
          <>
            <div>{response.response}</div>
            {response.toolCalls.length > 0 && (
              <div style={{ marginTop: "12px", opacity: 0.7 }}>
                <div style={{ fontWeight: 600, marginBottom: "4px" }}>
                  Tool Calls:
                </div>
                {response.toolCalls.map((tc, i) => (
                  <div key={`tc-${i}`} style={{ marginLeft: "8px" }}>
                    [{tc.tool}] {tc.result}
                  </div>
                ))}
              </div>
            )}
            <div style={styles.duration}>{response.duration}ms</div>
          </>
        ) : (
          <p style={styles.emptyState}>
            {session
              ? "Submit a prompt to see the response"
              : "Create a session to get started"}
          </p>
        )}
      </div>

      {/* Tool whitelist */}
      <ToolWhitelistPanel tools={session?.allowedTools ?? []} />

      {/* Security events */}
      <SecurityEventsPanel events={events} />

      {/* Footer */}
      <div style={styles.footer}>
        <span>
          {session ? `Session: ${session.sessionId.slice(0, 8)}...` : "No active session"}
        </span>
        <span>MiniClaw by AgentShield</span>
      </div>
    </div>
  );
}

export default MiniClawDashboard;
