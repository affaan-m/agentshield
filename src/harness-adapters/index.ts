import { existsSync, statSync } from "node:fs";
import { join } from "node:path";
import type {
  HarnessAdapterDetection,
  HarnessAdapterId,
  HarnessAdapterMetadata,
  HarnessAdapterSummary,
} from "../types.js";

type MarkerKind = "file" | "directory" | "any";
type MarkerStrength = "strong" | "supporting";

interface AdapterMarker {
  readonly path: string;
  readonly kind: MarkerKind;
  readonly strength: MarkerStrength;
}

interface HarnessAdapterDefinition extends HarnessAdapterMetadata {
  readonly markers: ReadonlyArray<AdapterMarker>;
}

const ADAPTERS: ReadonlyArray<HarnessAdapterDefinition> = [
  {
    id: "claude-code",
    name: "Claude Code",
    description: "Claude Code project rules, permissions, MCP, hooks, agents, skills, and command surfaces.",
    configPaths: [
      "CLAUDE.md",
      ".claude/CLAUDE.md",
      "settings.json",
      ".claude/settings.json",
      "mcp.json",
      ".claude/mcp.json",
      ".claude/agents",
      ".claude/skills",
      ".claude/hooks",
    ],
    permissionConcepts: ["allow/deny permissions", "dangerous shell commands", "project-local overrides"],
    pluginSurfaces: ["Claude plugins", "hooks manifests", "skills", "slash commands"],
    mcpConventions: ["mcpServers", ".claude.json", "mcp.json"],
    historySurfaces: ["Claude transcripts", "session hooks", "tool usage logs"],
    ciEvidence: ["AgentShield scan", "policy evaluation", "SARIF upload", "evidence pack"],
    markers: [
      { path: "CLAUDE.md", kind: "file", strength: "strong" },
      { path: ".claude/CLAUDE.md", kind: "file", strength: "strong" },
      { path: "settings.json", kind: "file", strength: "strong" },
      { path: ".claude/settings.json", kind: "file", strength: "strong" },
      { path: "mcp.json", kind: "file", strength: "supporting" },
      { path: ".claude/mcp.json", kind: "file", strength: "supporting" },
      { path: ".claude/agents", kind: "directory", strength: "supporting" },
      { path: ".claude/skills", kind: "directory", strength: "supporting" },
      { path: ".claude/hooks", kind: "directory", strength: "supporting" },
    ],
  },
  {
    id: "opencode",
    name: "OpenCode",
    description: "OpenCode agent, command, provider, plugin, and project configuration surfaces.",
    configPaths: [
      "opencode.json",
      "opencode.jsonc",
      ".opencode.json",
      ".opencode/config.json",
      ".opencode/agents",
      ".opencode/commands",
      ".opencode/plugins",
    ],
    permissionConcepts: ["provider permissions", "agent modes", "tool scopes"],
    pluginSurfaces: ["OpenCode plugins", "agents", "commands"],
    mcpConventions: ["provider/tool configuration", "project-local tool adapters"],
    historySurfaces: ["sessions", "client/server state", "tool traces"],
    ciEvidence: ["scan report", "package-surface checks", "policy gate"],
    markers: [
      { path: "opencode.json", kind: "file", strength: "strong" },
      { path: "opencode.jsonc", kind: "file", strength: "strong" },
      { path: ".opencode.json", kind: "file", strength: "strong" },
      { path: ".opencode/config.json", kind: "file", strength: "strong" },
      { path: ".opencode/agents", kind: "directory", strength: "supporting" },
      { path: ".opencode/commands", kind: "directory", strength: "supporting" },
      { path: ".opencode/plugins", kind: "directory", strength: "supporting" },
    ],
  },
  {
    id: "codex",
    name: "Codex",
    description: "Codex AGENTS instructions, project config, prompts, and local memory/tooling surfaces.",
    configPaths: [
      "AGENTS.md",
      ".codex/config.toml",
      ".codex/agents",
      ".codex/prompts",
      ".codex/skills",
    ],
    permissionConcepts: ["sandbox policy", "approval policy", "agent instructions"],
    pluginSurfaces: ["skills", "MCP servers", "project AGENTS.md"],
    mcpConventions: [".codex/config.toml", "MCP server entries"],
    historySurfaces: ["Codex session logs", "rollout summaries", "local memories"],
    ciEvidence: ["scan report", "rules conformance", "policy gate"],
    markers: [
      { path: "AGENTS.md", kind: "file", strength: "strong" },
      { path: ".codex/config.toml", kind: "file", strength: "strong" },
      { path: ".codex/agents", kind: "directory", strength: "supporting" },
      { path: ".codex/prompts", kind: "directory", strength: "supporting" },
      { path: ".codex/skills", kind: "directory", strength: "supporting" },
    ],
  },
  {
    id: "gemini",
    name: "Gemini CLI",
    description: "Gemini project instructions, commands, extensions, and MCP configuration surfaces.",
    configPaths: [
      "GEMINI.md",
      ".gemini/settings.json",
      ".gemini/commands",
      ".gemini/extensions",
      ".gemini/mcp.json",
    ],
    permissionConcepts: ["tool permissions", "extension scopes", "project rules"],
    pluginSurfaces: ["commands", "extensions", "MCP adapters"],
    mcpConventions: [".gemini/mcp.json", "settings tool entries"],
    historySurfaces: ["terminal transcripts", "command history", "tool traces"],
    ciEvidence: ["scan report", "policy gate", "extension review"],
    markers: [
      { path: "GEMINI.md", kind: "file", strength: "strong" },
      { path: ".gemini/settings.json", kind: "file", strength: "strong" },
      { path: ".gemini/mcp.json", kind: "file", strength: "supporting" },
      { path: ".gemini/commands", kind: "directory", strength: "supporting" },
      { path: ".gemini/extensions", kind: "directory", strength: "supporting" },
    ],
  },
  {
    id: "dmux",
    name: "dmux",
    description: "dmux multi-agent pane, worktree, launch, and lifecycle hook surfaces.",
    configPaths: [
      "dmux.yaml",
      "dmux.yml",
      "dmux.json",
      ".dmux/config.yaml",
      ".dmux/config.json",
      ".dmux",
    ],
    permissionConcepts: ["pane launch commands", "worktree lifecycle hooks", "merge workflows"],
    pluginSurfaces: ["launch recipes", "hooks", "agent templates"],
    mcpConventions: ["per-agent MCP environment", "launch-time tool config"],
    historySurfaces: ["tmux pane logs", "worktree state", "handoff files"],
    ciEvidence: ["scan report", "worktree safety review", "merge gate"],
    markers: [
      { path: "dmux.yaml", kind: "file", strength: "strong" },
      { path: "dmux.yml", kind: "file", strength: "strong" },
      { path: "dmux.json", kind: "file", strength: "strong" },
      { path: ".dmux/config.yaml", kind: "file", strength: "strong" },
      { path: ".dmux/config.json", kind: "file", strength: "strong" },
      { path: ".dmux", kind: "directory", strength: "supporting" },
    ],
  },
  {
    id: "generic-terminal",
    name: "Generic Terminal Agent",
    description: "Terminal-agent launch scripts, command wrappers, and shell-based orchestration surfaces.",
    configPaths: [
      "agent.yaml",
      "agent.yml",
      ".agents",
      "agents.yaml",
      "scripts/agents",
      "terminal-agents",
    ],
    permissionConcepts: ["shell command allowlists", "environment exposure", "working-directory scope"],
    pluginSurfaces: ["shell wrappers", "agent launch manifests", "local command packs"],
    mcpConventions: ["environment-provided MCP endpoints", "wrapper-managed tools"],
    historySurfaces: ["terminal logs", "agent run directories", "handoff files"],
    ciEvidence: ["scan report", "script review", "policy gate"],
    markers: [
      { path: "agent.yaml", kind: "file", strength: "strong" },
      { path: "agent.yml", kind: "file", strength: "strong" },
      { path: "agents.yaml", kind: "file", strength: "strong" },
      { path: ".agents", kind: "directory", strength: "strong" },
      { path: "scripts/agents", kind: "directory", strength: "supporting" },
      { path: "terminal-agents", kind: "directory", strength: "supporting" },
    ],
  },
  {
    id: "project-local-template",
    name: "Project-local Templates",
    description: "Repository-local skills, commands, rules, prompts, and reusable agent templates.",
    configPaths: [
      "skills",
      "commands",
      "rules",
      "contexts",
      "prompts",
      ".claude/commands",
      ".claude/skills",
    ],
    permissionConcepts: ["template guidance", "default tool scopes", "copy-forward examples"],
    pluginSurfaces: ["skills", "commands", "rules", "contexts", "prompts"],
    mcpConventions: ["template MCP examples", "copy-forward config snippets"],
    historySurfaces: ["template changelogs", "skill health history", "example traces"],
    ciEvidence: ["template scan", "docs-example downgrade evidence", "corpus fixture coverage"],
    markers: [
      { path: "skills", kind: "directory", strength: "strong" },
      { path: "commands", kind: "directory", strength: "strong" },
      { path: "rules", kind: "directory", strength: "supporting" },
      { path: "contexts", kind: "directory", strength: "supporting" },
      { path: "prompts", kind: "directory", strength: "supporting" },
      { path: ".claude/commands", kind: "directory", strength: "supporting" },
      { path: ".claude/skills", kind: "directory", strength: "supporting" },
    ],
  },
];

export function getHarnessAdapterRegistry(): ReadonlyArray<HarnessAdapterMetadata> {
  return ADAPTERS.map(({ markers: _markers, ...metadata }) => metadata);
}

export function detectHarnessAdapters(rootPath: string): HarnessAdapterSummary {
  const detections = ADAPTERS.map((adapter) => detectAdapter(rootPath, adapter));
  const matched = detections
    .filter((adapter) => adapter.matched)
    .sort((a, b) => a.id.localeCompare(b.id));

  return {
    totalRegistered: ADAPTERS.length,
    totalMatched: matched.length,
    matched,
    registered: getHarnessAdapterRegistry(),
  };
}

export function adapterById(id: HarnessAdapterId): HarnessAdapterMetadata | undefined {
  return getHarnessAdapterRegistry().find((adapter) => adapter.id === id);
}

function detectAdapter(
  rootPath: string,
  adapter: HarnessAdapterDefinition
): HarnessAdapterDetection {
  const evidence = adapter.markers
    .filter((marker) => markerExists(rootPath, marker))
    .map((marker) => marker.path)
    .sort();
  const strongMatches = adapter.markers.filter(
    (marker) => marker.strength === "strong" && evidence.includes(marker.path)
  ).length;

  const { markers: _markers, ...metadata } = adapter;
  return {
    ...metadata,
    matched: evidence.length > 0,
    confidence: strongMatches > 0 ? "strong" : "partial",
    evidence,
  };
}

function markerExists(rootPath: string, marker: AdapterMarker): boolean {
  try {
    const fullPath = join(rootPath, marker.path);
    if (!existsSync(fullPath)) return false;

    const stats = statSync(fullPath);
    switch (marker.kind) {
      case "file":
        return stats.isFile();
      case "directory":
        return stats.isDirectory();
      default:
        return stats.isFile() || stats.isDirectory();
    }
  } catch {
    return false;
  }
}
