import { describe, it, expect } from "vitest";
import {
  replaceHardcodedSecret,
  tightenWildcardPermission,
  applyGenericTransform,
  applyTransform,
} from "../../src/fixer/transforms.js";
import type { Finding } from "../../src/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "TEST-001",
    severity: "critical",
    category: "secrets",
    title: "Hardcoded secret",
    description: "Found secret",
    file: "CLAUDE.md",
    ...overrides,
  };
}

describe("replaceHardcodedSecret", () => {
  it("replaces a hardcoded secret with env var reference", () => {
    const finding = makeFinding({
      fix: {
        description: "Use env var",
        before: "sk-ant-api03-abc123",
        after: "${ANTHROPIC_API_KEY}",
        auto: true,
      },
    });
    const result = replaceHardcodedSecret(
      "api_key: sk-ant-api03-abc123",
      finding
    );
    expect(result.applied).toBe(true);
    expect(result.content).toBe("api_key: ${ANTHROPIC_API_KEY}");
  });

  it("returns unapplied when no fix defined", () => {
    const finding = makeFinding();
    const result = replaceHardcodedSecret("some content", finding);
    expect(result.applied).toBe(false);
    expect(result.content).toBe("some content");
  });

  it("returns unapplied when before text not found", () => {
    const finding = makeFinding({
      fix: {
        description: "Fix",
        before: "not-in-content",
        after: "replacement",
        auto: true,
      },
    });
    const result = replaceHardcodedSecret("different content", finding);
    expect(result.applied).toBe(false);
  });
});

describe("tightenWildcardPermission", () => {
  it("replaces Bash(*) with scoped permissions", () => {
    const finding = makeFinding({
      category: "permissions",
      fix: {
        description: "Scope Bash permission",
        before: "Bash(*)",
        after: "Bash(git *), Bash(npm *)",
        auto: true,
      },
    });
    const content = '["Read", "Write", "Bash(*)"]';
    const result = tightenWildcardPermission(content, finding);
    expect(result.applied).toBe(true);
    expect(result.content).toContain("Bash(git *)");
    expect(result.content).not.toContain("Bash(*)");
  });

  it("returns unapplied when no fix", () => {
    const finding = makeFinding({ category: "permissions" });
    const result = tightenWildcardPermission("content", finding);
    expect(result.applied).toBe(false);
  });
});

describe("applyGenericTransform", () => {
  it("replaces before with after", () => {
    const finding = makeFinding({
      category: "hooks",
      fix: {
        description: "Fix hook",
        before: "echo $SECRET",
        after: "# removed",
        auto: true,
      },
    });
    const result = applyGenericTransform("cmd: echo $SECRET", finding);
    expect(result.applied).toBe(true);
    expect(result.content).toBe("cmd: # removed");
  });

  it("returns unapplied when before not found", () => {
    const finding = makeFinding({
      fix: {
        description: "Fix",
        before: "missing",
        after: "new",
        auto: true,
      },
    });
    const result = applyGenericTransform("other content", finding);
    expect(result.applied).toBe(false);
  });
});

describe("applyTransform", () => {
  it("routes secrets to replaceHardcodedSecret", () => {
    const finding = makeFinding({
      category: "secrets",
      fix: {
        description: "Use env var",
        before: "sk-proj-abc",
        after: "${OPENAI_API_KEY}",
        auto: true,
      },
    });
    const result = applyTransform("key: sk-proj-abc", finding);
    expect(result.applied).toBe(true);
    expect(result.content).toContain("${OPENAI_API_KEY}");
  });

  it("routes permissions to tightenWildcardPermission", () => {
    const finding = makeFinding({
      category: "permissions",
      fix: {
        description: "Tighten",
        before: "Bash(*)",
        after: "Bash(git *)",
        auto: true,
      },
    });
    const result = applyTransform('["Bash(*)"]', finding);
    expect(result.applied).toBe(true);
  });

  it("routes other categories to generic transform", () => {
    const finding = makeFinding({
      category: "hooks",
      fix: {
        description: "Fix",
        before: "bad",
        after: "good",
        auto: true,
      },
    });
    const result = applyTransform("this is bad", finding);
    expect(result.applied).toBe(true);
    expect(result.content).toBe("this is good");
  });
});
