import { describe, it, expect } from "vitest";
import {
  ctaOptedIn,
  ctaSuppressed,
  ctaEnabled,
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

  it("is off by default", () => {
    expect(ctaOptedIn({})).toBe(false);
    expect(ctaEnabled({})).toBe(false);
    expect(proCtaPlainLines({})).toEqual([]);
    expect(proCtaMarkdownLines({})).toEqual([]);
  });

  it("is enabled by ECC_CTA / AGENTSHIELD_CTA opt-in", () => {
    expect(ctaOptedIn({ ECC_CTA: "1" })).toBe(true);
    expect(ctaOptedIn({ AGENTSHIELD_CTA: "true" })).toBe(true);
    expect(ctaEnabled({ AGENTSHIELD_CTA: "yes" })).toBe(true);
    expect(proCtaPlainLines({ ECC_CTA: "1" })).toEqual([PRO_CTA_PLAIN]);
    expect(proCtaMarkdownLines({ AGENTSHIELD_CTA: "1" })).toContain(PRO_CTA_MARKDOWN);
  });

  it("treats empty / 0 / false opt-in values as not opted in", () => {
    expect(ctaOptedIn({ ECC_CTA: "" })).toBe(false);
    expect(ctaOptedIn({ ECC_CTA: "0" })).toBe(false);
    expect(ctaOptedIn({ AGENTSHIELD_CTA: "false" })).toBe(false);
    expect(ctaOptedIn({ AGENTSHIELD_CTA: "FALSE" })).toBe(false);
    expect(proCtaPlainLines({ ECC_CTA: "0" })).toEqual([]);
  });

  it("opt-out beats opt-in", () => {
    expect(ctaSuppressed({ ECC_NO_CTA: "1" })).toBe(true);
    expect(ctaSuppressed({ AGENTSHIELD_NO_CTA: "true" })).toBe(true);
    expect(ctaEnabled({ ECC_CTA: "1", ECC_NO_CTA: "1" })).toBe(false);
    expect(ctaEnabled({ AGENTSHIELD_CTA: "1", AGENTSHIELD_NO_CTA: "1" })).toBe(false);
    expect(ctaEnabled({ ECC_CTA: "1", AGENTSHIELD_NO_CTA: "yes" })).toBe(false);
    expect(proCtaPlainLines({ ECC_CTA: "1", ECC_NO_CTA: "1" })).toEqual([]);
    expect(proCtaMarkdownLines({ AGENTSHIELD_CTA: "1", AGENTSHIELD_NO_CTA: "1" })).toEqual([]);
  });

  it("treats empty / 0 / false opt-out values as not suppressed", () => {
    expect(ctaSuppressed({ ECC_NO_CTA: "" })).toBe(false);
    expect(ctaSuppressed({ ECC_NO_CTA: "0" })).toBe(false);
    expect(ctaSuppressed({ AGENTSHIELD_NO_CTA: "false" })).toBe(false);
    expect(ctaEnabled({ ECC_CTA: "1", ECC_NO_CTA: "0" })).toBe(true);
  });
});
