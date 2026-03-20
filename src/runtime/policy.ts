import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { RuntimePolicySchema } from "./types.js";
import type { RuntimePolicy } from "./types.js";

const DEFAULT_POLICY: RuntimePolicy = {
  version: 1,
  deny: [],
  log: {
    enabled: true,
    path: ".agentshield/runtime.ndjson",
  },
};

/**
 * Load runtime policy from a file path.
 * Returns the default (allow-all) policy if the file doesn't exist or is invalid.
 */
export function loadPolicy(policyPath: string): RuntimePolicy {
  const resolvedPath = resolve(policyPath);

  if (!existsSync(resolvedPath)) {
    return DEFAULT_POLICY;
  }

  try {
    const raw = readFileSync(resolvedPath, "utf-8");
    const parsed = JSON.parse(raw);
    return RuntimePolicySchema.parse(parsed);
  } catch {
    return DEFAULT_POLICY;
  }
}

/**
 * Generate a default policy JSON string.
 */
export function generateDefaultPolicy(): string {
  const policy: RuntimePolicy = {
    version: 1,
    deny: [
      {
        tool: "Bash",
        pattern: "rm -rf /",
        reason: "Prevents destructive filesystem operations",
      },
      {
        tool: "Bash",
        pattern: "curl.*\\|.*sh",
        reason: "Blocks piping remote scripts to shell",
      },
    ],
    rateLimit: {
      maxPerMinute: 30,
      tools: ["Bash", "Write"],
    },
    log: {
      enabled: true,
      path: ".agentshield/runtime.ndjson",
    },
  };

  return JSON.stringify(policy, null, 2);
}
