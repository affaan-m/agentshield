import { describe, it, expect } from "vitest";
import {
  mapFindingsToControls,
  renderComplianceReport,
  parseFrameworks,
  COMPLIANCE_FRAMEWORKS,
} from "../../src/compliance/index.js";
import type { Finding } from "../../src/types.js";

function f(overrides: Partial<Finding>): Finding {
  return {
    id: "x",
    severity: "high",
    category: "secrets",
    title: "A finding",
    description: "d",
    file: "CLAUDE.md",
    ...overrides,
  };
}

describe("mapFindingsToControls", () => {
  it("maps a hardcoded-secret finding to the expected controls per framework", () => {
    const findings = [f({ category: "secrets", severity: "critical", title: "Hardcoded key" })];

    const soc2 = mapFindingsToControls(findings, "soc2");
    expect(soc2.controls.map((c) => c.controlId)).toContain("CC6.1");

    const pci = mapFindingsToControls(findings, "pci");
    expect(pci.controls.map((c) => c.controlId)).toContain("Req 3");

    const iso = mapFindingsToControls(findings, "iso");
    expect(iso.controls.map((c) => c.controlId)).toContain("A.5.17");
  });

  it("aggregates multiple findings under a shared control and tracks the highest severity", () => {
    const report = mapFindingsToControls(
      [
        f({ category: "permissions", severity: "high", title: "Bash(*)" }),
        f({ category: "permissions", severity: "critical", title: "sudo allowed" }),
      ],
      "soc2"
    );
    const cc61 = report.controls.find((c) => c.controlId === "CC6.1");
    expect(cc61).toBeDefined();
    expect(cc61!.findingCount).toBe(2);
    expect(cc61!.highestSeverity).toBe("critical");
    expect(cc61!.severities.critical).toBe(1);
    expect(cc61!.severities.high).toBe(1);
  });

  it("counts mapped vs unmapped findings (every category maps in v1)", () => {
    const report = mapFindingsToControls(
      [f({ category: "secrets" }), f({ category: "mcp" }), f({ category: "exfiltration" })],
      "iso"
    );
    expect(report.totalFindings).toBe(3);
    expect(report.mappedFindingCount).toBe(3);
    expect(report.unmappedFindingCount).toBe(0);
  });

  it("orders controls by highest severity first", () => {
    const report = mapFindingsToControls(
      [
        f({ category: "agents", severity: "low", title: "low agent issue" }),
        f({ category: "secrets", severity: "critical", title: "critical secret" }),
      ],
      "soc2"
    );
    expect(report.controls[0].highestSeverity).toBe("critical");
  });

  it("limits example findings to three", () => {
    const report = mapFindingsToControls(
      [
        f({ category: "secrets", title: "s1" }),
        f({ category: "secrets", title: "s2" }),
        f({ category: "secrets", title: "s3" }),
        f({ category: "secrets", title: "s4" }),
      ],
      "pci"
    );
    const req3 = report.controls.find((c) => c.controlId === "Req 3");
    expect(req3!.exampleFindings.length).toBeLessThanOrEqual(3);
    expect(req3!.findingCount).toBe(4);
  });
});

describe("parseFrameworks", () => {
  it("expands 'all' to every framework", () => {
    expect(parseFrameworks("all")).toEqual(COMPLIANCE_FRAMEWORKS);
  });

  it("parses a comma-separated subset and ignores unknown tokens", () => {
    expect(parseFrameworks("soc2, iso, bogus")).toEqual(["soc2", "iso"]);
  });

  it("returns empty for an unrecognized value", () => {
    expect(parseFrameworks("hipaa")).toEqual([]);
  });
});

describe("renderComplianceReport", () => {
  it("renders a control-coverage table with a guidance disclaimer", () => {
    const report = mapFindingsToControls([f({ category: "secrets", severity: "critical", title: "Hardcoded key" })], "soc2");
    const md = renderComplianceReport(report);
    expect(md).toContain("## Compliance Mapping: SOC 2");
    expect(md).toContain("| Control | Title | Highest | Findings | Examples |");
    expect(md).toContain("CC6.1");
    expect(md).toMatch(/not a certified crosswalk/i);
  });

  it("handles an empty finding set gracefully", () => {
    const report = mapFindingsToControls([], "pci");
    const md = renderComplianceReport(report);
    expect(md).toContain("No findings mapped to controls");
  });
});
