import { discoverConfigFiles } from "../scanner/discovery.js";
import type {
  InjectionSuiteResult,
  InjectionTestResult as SuiteTestResult,
} from "../types.js";
import { runInjectionTests } from "./tester.js";

// ─── Payload Corpus ───────────────────────────────────────
export {
  INJECTION_PAYLOADS,
  getPayloadsByCategory,
  getPayloadsBySeverity,
  getPayloadById,
  getPayloadCategories,
} from "./payloads.js";

export type { InjectionPayload, PayloadCategory } from "./payloads.js";

// ─── Injection Tester ─────────────────────────────────────
export { runInjectionTests } from "./tester.js";

export type {
  InjectionTestResult,
  InjectionTestSuite,
  InjectionTestOptions,
} from "./tester.js";

// ─── CLI Integration ─────────────────────────────────────
// Bridge function that matches the signature expected by src/index.ts:
//   runInjectionSuite(targetPath: string) => Promise<InjectionSuiteResult>

export async function runInjectionSuite(
  targetPath: string
): Promise<InjectionSuiteResult> {
  // Discover config files from the target path
  const target = discoverConfigFiles(targetPath);

  // Extract CLAUDE.md content
  const claudeMdFiles = target.files.filter((f) => f.type === "claude-md");
  const configContent = claudeMdFiles.map((f) => f.content).join("\n\n---\n\n");

  // Extract agent definitions
  const agentDefinitions = target.files
    .filter((f) => f.type === "agent-md")
    .map((f) => f.content);

  // Extract settings.json
  const settingsFile = target.files.find((f) => f.type === "settings-json");
  const settingsContent = settingsFile?.content;

  // Run the injection test suite
  const suite = await runInjectionTests(
    configContent || "No CLAUDE.md found — empty configuration.",
    agentDefinitions,
    settingsContent,
    {
      onProgress: (completed, total) => {
        process.stdout.write(
          `\r  Testing payloads: ${completed}/${total}`
        );
      },
    }
  );

  process.stdout.write("\r" + " ".repeat(40) + "\r");

  // Map to the InjectionSuiteResult shape expected by types.ts
  const results: ReadonlyArray<SuiteTestResult> = suite.results.map((r) => ({
    payload: r.payloadName,
    category: r.category,
    blocked: !r.vulnerable,
    details: r.evidence,
  }));

  return {
    totalPayloads: suite.totalPayloads,
    blocked: suite.resistant,
    bypassed: suite.vulnerable,
    results,
  };
}
