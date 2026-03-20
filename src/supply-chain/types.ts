import type { Severity } from "../types.js";

// ─── Package Extraction ─────────────────────────────────────

export interface ExtractedPackage {
  readonly name: string;
  readonly version?: string;
  readonly source: "npx" | "command" | "args" | "git";
  readonly serverName: string;
  readonly gitUrl?: string;
  readonly gitRef?: string;
}

// ─── Registry Metadata ──────────────────────────────────────

export interface NpmRegistryMeta {
  readonly name: string;
  readonly publishedAt?: string;
  readonly downloadsLastWeek?: number;
  readonly maintainerCount?: number;
  readonly hasPostinstall?: boolean;
  readonly latestVersion?: string;
  readonly description?: string;
  readonly deprecated?: boolean;
}

// ─── Verification Result ────────────────────────────────────

export interface PackageVerification {
  readonly package: ExtractedPackage;
  readonly registry?: NpmRegistryMeta;
  readonly risks: ReadonlyArray<PackageRisk>;
  readonly overallSeverity: Severity;
}

export interface PackageRisk {
  readonly type: RiskType;
  readonly severity: Severity;
  readonly description: string;
  readonly evidence?: string;
}

export type RiskType =
  | "known-malicious"
  | "known-vulnerable"
  | "typosquat"
  | "low-downloads"
  | "new-package"
  | "single-maintainer"
  | "has-postinstall"
  | "unpinned-git"
  | "deprecated";

// ─── Supply Chain Report ────────────────────────────────────

export interface SupplyChainReport {
  readonly packages: ReadonlyArray<PackageVerification>;
  readonly totalPackages: number;
  readonly riskyPackages: number;
  readonly criticalCount: number;
  readonly highCount: number;
}

// ─── Known Good Packages ────────────────────────────────────

export const KNOWN_GOOD_PACKAGES: ReadonlyArray<string> = [
  "@modelcontextprotocol/sdk",
  "@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/server-github",
  "@modelcontextprotocol/server-postgres",
  "@modelcontextprotocol/server-brave-search",
  "@modelcontextprotocol/server-memory",
  "@modelcontextprotocol/server-puppeteer",
  "@modelcontextprotocol/server-sequential-thinking",
  "@modelcontextprotocol/server-everything",
  "@modelcontextprotocol/server-slack",
  "@anthropics/mcp-server-git",
  "firecrawl-mcp",
  "tavily-mcp",
  "exa-mcp-server",
  "@supabase/mcp-server-supabase",
  "@cloudflare/mcp-server-cloudflare",
  "@playwright/mcp",
  "context7-mcp",
];
