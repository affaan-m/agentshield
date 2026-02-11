import { describe, it, expect } from "vitest";
import { renderOpusAnalysis, renderOpusMarkdown } from "../../src/opus/render.js";
import type { OpusAnalysis } from "../../src/types.js";

function makeAnalysis(overrides: Partial<OpusAnalysis> = {}): OpusAnalysis {
  return {
    attacker: {
      role: "attacker",
      findings: ["SQL injection via MCP server", "Prompt injection in CLAUDE.md"],
      reasoning: "The config has exploitable attack surface.",
    },
    defender: {
      role: "defender",
      findings: ["Add deny list for Bash", "Restrict MCP server access"],
      reasoning: "Defense in depth needed.",
    },
    auditor: {
      overallAssessment: "Configuration needs hardening.",
      riskLevel: "high",
      recommendations: ["Add Bash deny rules", "Remove hardcoded keys", "Enable monitoring"],
      score: 45,
    },
    ...overrides,
  };
}

describe("renderOpusAnalysis", () => {
  it("includes header", () => {
    const output = renderOpusAnalysis(makeAnalysis());
    expect(output).toContain("Opus 4.6 Multi-Agent Security Analysis");
  });

  it("renders attacker findings", () => {
    const output = renderOpusAnalysis(makeAnalysis());
    expect(output).toContain("Red Team");
    expect(output).toContain("SQL injection via MCP server");
    expect(output).toContain("Prompt injection in CLAUDE.md");
  });

  it("renders defender findings", () => {
    const output = renderOpusAnalysis(makeAnalysis());
    expect(output).toContain("Blue Team");
    expect(output).toContain("Add deny list for Bash");
  });

  it("renders auditor risk level and score", () => {
    const output = renderOpusAnalysis(makeAnalysis());
    expect(output).toContain("Risk Level");
    expect(output).toContain("HIGH");
    expect(output).toContain("45");
  });

  it("renders recommendations", () => {
    const output = renderOpusAnalysis(makeAnalysis());
    expect(output).toContain("Top Recommendations");
    expect(output).toContain("Add Bash deny rules");
    expect(output).toContain("Remove hardcoded keys");
    expect(output).toContain("Enable monitoring");
  });

  it("truncates attacker findings beyond 8", () => {
    const manyFindings = Array.from({ length: 12 }, (_, i) => `Finding ${i + 1}`);
    const analysis = makeAnalysis({
      attacker: { role: "attacker", findings: manyFindings, reasoning: "..." },
    });
    const output = renderOpusAnalysis(analysis);
    expect(output).toContain("and 4 more");
  });

  it("truncates defender findings beyond 8", () => {
    const manyFindings = Array.from({ length: 10 }, (_, i) => `Rec ${i + 1}`);
    const analysis = makeAnalysis({
      defender: { role: "defender", findings: manyFindings, reasoning: "..." },
    });
    const output = renderOpusAnalysis(analysis);
    expect(output).toContain("and 2 more");
  });
});

describe("renderOpusMarkdown", () => {
  it("includes markdown heading", () => {
    const output = renderOpusMarkdown(makeAnalysis());
    expect(output).toContain("## Opus 4.6 Multi-Agent Analysis");
  });

  it("includes all three sections", () => {
    const output = renderOpusMarkdown(makeAnalysis());
    expect(output).toContain("### Red Team");
    expect(output).toContain("### Blue Team");
    expect(output).toContain("### Auditor");
  });

  it("includes risk level and score", () => {
    const output = renderOpusMarkdown(makeAnalysis());
    expect(output).toContain("**Risk Level:** HIGH");
    expect(output).toContain("**Score:** 45/100");
  });

  it("includes reasoning from each perspective", () => {
    const output = renderOpusMarkdown(makeAnalysis());
    expect(output).toContain("The config has exploitable attack surface.");
    expect(output).toContain("Defense in depth needed.");
    expect(output).toContain("Configuration needs hardening.");
  });
});
