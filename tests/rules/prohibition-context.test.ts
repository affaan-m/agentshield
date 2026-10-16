import { describe, expect, it } from "vitest";
import { clauseBefore, hasProhibitiveCue, isProhibitedAt } from "../../src/rules/prohibition-context.js";

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

  it.each([
    ["coordinating word", "Avoid review and run git push --force"],
    ["condition", "If approval is not available run git push --force"],
    ["buried negation", "Approval is not needed to run git push --force"],
    ["new list item", "- Never run tests\n- git push --force"],
    ["wrapped line", "Never run tests\ngit push --force"],
    ["French restriction", "Tu n'as qu'à lancer git push --force"],
    ["no review needed", "No review needed: git push --force"],
    ["approval not needed", "No approval is needed to run git push --force"],
    ["nobody approves", "No one needs to approve before git push --force"],
    ["code fence", "Never run the test server\n```bash\ngit push --force"],
    ["French restriction with plus", "Tu n'as plus qu'à lancer git push --force"],
    ["French urging with plus", "Ne tardez plus à lancer git push --force"],
    ["French urging with pas", "Ne tardez pas à lancer git push --force"],
    ["English urging", "Don't delay running git push --force"],
    ["urging with a subject", "No one should hesitate to run git push --force"],
    ["urging with nobody", "Nobody needs to wait before git push --force"],
    ["French urging with a modal", "Personne ne doit plus hésiter à lancer git push --force"],
  ])("does not read a prohibition that does not govern the match: %s", (_label, content) => {
    expect(isProhibitedAt(content, content.indexOf("git push"))).toBe(false);
  });

  it.each([
    "You must never run git push --force",
    "Don't forget to never run git push --force",
    "Don't hesitate to ask for help, but never run git push --force",
    "No uses git push --force",
    "Se prohíbe ejecutar git push --force",
    "N'utilisez plus git push --force",
    "Ne lancez plus git push --force",
    "No one may use git push --force",
    "No one should ever run git push --force",
    "Vous ne devez jamais lancer git push --force",
  ])("reads %j as a prohibition of the match", (content) => {
    expect(isProhibitedAt(content, content.indexOf("git push"))).toBe(true);
  });

  it("is limited to maxChars characters", () => {
    const content = `Never ${"x".repeat(200)} git push --force`;
    expect(clauseBefore(content, content.indexOf("git push"), 50)).toHaveLength(50);
  });
});
