import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = join(import.meta.dirname, "..");
const computeUrl = "https://compute.itomarkets.com";

describe("Ito compute sponsor surface", () => {
  it("keeps the npm README visible, provider-neutral, and honest about serving", () => {
    const readme = readFileSync(join(repoRoot, "README.md"), "utf8");

    expect(readme).toContain("assets/ito.svg");
    expect(readme).toContain(computeUrl);
    expect(readme).toMatch(/preferred compute sponsor/i);
    expect(readme).toMatch(/any GPU provider/i);
    expect(readme).toMatch(/managed inference[^\n.]*not live/i);
  });

  it("publishes the Ito logo with ecc-agentshield", () => {
    const packageJson = JSON.parse(
      readFileSync(join(repoRoot, "package.json"), "utf8"),
    ) as { readonly files: ReadonlyArray<string> };

    expect(packageJson.files).toContain("assets/ito.svg");
    expect(existsSync(join(repoRoot, "assets", "ito.svg"))).toBe(true);
    const mark = readFileSync(join(repoRoot, "assets", "ito.svg"), "utf8");
    expect(mark).toMatch(/<path\b/);
    expect(mark).toContain('fill="#0F172A"');
    expect(mark).not.toMatch(
      /@import|<script|<foreignObject|\son[a-z]+=|(?:href|xlink:href)=/i,
    );
  });
});
