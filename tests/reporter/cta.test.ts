import { describe, it, expect } from "vitest";
import {
  ctaSuppressed,
  proCtaPlainLines,
  proCtaMarkdownLines,
  PRO_CTA_PLAIN,
  PRO_CTA_MARKDOWN,
} from "../../src/reporter/cta.js";

describe("pro CTA", () => {
  it("leads with the privacy wedge and points at the real ECC Tools app", () => {
    expect(PRO_CTA_PLAIN).toMatch(/locally/i);
    expect(PRO_CTA_PLAIN).toContain("https://github.com/apps/ecc-tools");
    expect(PRO_CTA_MARKDOWN).toContain("[ECC Tools Pro](https://github.com/apps/ecc-tools)");
  });

  it("is shown by default", () => {
    expect(ctaSuppressed({})).toBe(false);
    expect(proCtaPlainLines({})).toEqual([PRO_CTA_PLAIN]);
    expect(proCtaMarkdownLines({})).toContain(PRO_CTA_MARKDOWN);
  });

  it("is suppressed by ECC_NO_CTA / AGENTSHIELD_NO_CTA", () => {
    expect(ctaSuppressed({ ECC_NO_CTA: "1" })).toBe(true);
    expect(ctaSuppressed({ AGENTSHIELD_NO_CTA: "true" })).toBe(true);
    expect(proCtaPlainLines({ ECC_NO_CTA: "1" })).toEqual([]);
    expect(proCtaMarkdownLines({ AGENTSHIELD_NO_CTA: "yes" })).toEqual([]);
  });

  it("treats empty / 0 / false as not-suppressed", () => {
    expect(ctaSuppressed({ ECC_NO_CTA: "" })).toBe(false);
    expect(ctaSuppressed({ ECC_NO_CTA: "0" })).toBe(false);
    expect(ctaSuppressed({ AGENTSHIELD_NO_CTA: "false" })).toBe(false);
  });
});
