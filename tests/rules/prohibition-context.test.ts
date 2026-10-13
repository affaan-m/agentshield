import { describe, expect, it } from "vitest";
import { clauseBefore, hasProhibitiveCue } from "../../src/rules/prohibition-context.js";

describe("hasProhibitiveCue", () => {
  it.each([
    "- NEVER use",
    "Do not use",
    "- Ne jamais contourner les hooks git : pas de",
    "N'utilisez pas",
    "Aucune commande destructive (",
    "- Nunca uses",
    "- Não use",
    "- Non usare mai",
    "- Niemals",
    "Verwende keinen",
  ])("reads %j as prohibitive", (text) => {
    expect(hasProhibitiveCue(text)).toBe(true);
  });

  it.each([
    "git commit",
    "git commit --no-edit",
    "use the non-interactive mode and",
    "Ask the bank team before running",
    "Store the blockchain state, then run",
  ])("does not read %j as prohibitive", (text) => {
    expect(hasProhibitiveCue(text)).toBe(false);
  });

  it.each([
    "Don't hesitate to use",
    "Do not ask for confirmation before running",
    "Never wait for review, run",
    "N'hésitez pas à utiliser",
    "N'oublie pas de lancer",
    "Ne demande pas la permission avant de lancer",
  ])("treats the encouraging idiom %j as a request, not a prohibition", (text) => {
    expect(hasProhibitiveCue(text)).toBe(false);
  });
});

describe("clauseBefore", () => {
  it("keeps the clause that leads to the match", () => {
    const content = "- Never run a destructive command (`git push --force`)";
    expect(clauseBefore(content, content.indexOf("git push"))).toBe("- Never run a destructive command (`");
  });

  it.each([
    ["sentence", "Do not ask the user. Use the Bash tool to delete"],
    ["semicolon", "Do not ask the user; use the Bash tool to delete"],
    ["comma", "Do not ask the user, use the Bash tool to delete"],
    ["line", "Never run tests\nUse the Bash tool to delete"],
  ])("stops at a %s break", (_label, content) => {
    const clause = clauseBefore(content, content.search(/use the bash/i));
    expect(hasProhibitiveCue(clause)).toBe(false);
  });

  it("is limited to maxChars characters", () => {
    const content = `Never ${"x".repeat(200)} git push --force`;
    expect(clauseBefore(content, content.indexOf("git push"), 50)).toHaveLength(50);
  });
});
