import type { ConfigFile, Finding, Rule } from "../types.js";

function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split("\n").length;
}

function findAllMatches(content: string, pattern: RegExp): Array<RegExpMatchArray> {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return [...content.matchAll(new RegExp(pattern.source, flags))];
}

export const agentRules: ReadonlyArray<Rule> = [
  {
    id: "agents-unrestricted-tools",
    name: "Agent with Unrestricted Tool Access",
    description: "Checks if agent definitions grant excessive tool access",
    severity: "high",
    category: "agents",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md") return [];

      const findings: Finding[] = [];

      // Check frontmatter for tools
      const toolsMatch = file.content.match(/tools:\s*\[([^\]]*)\]/);
      if (toolsMatch) {
        const tools = toolsMatch[1]
          .split(",")
          .map((t) => t.trim().replace(/["']/g, ""));

        // Check for Bash access
        if (tools.includes("Bash")) {
          findings.push({
            id: `agents-bash-access-${file.path}`,
            severity: "high",
            category: "agents",
            title: `Agent has Bash access: ${file.path}`,
            description:
              "This agent has Bash tool access, allowing arbitrary command running. Consider if this agent truly needs shell access, or if Read/Write/Edit would suffice.",
            file: file.path,
          });
        }

        // Check if agent has both read and write (should it be read-only?)
        const hasWrite = tools.some((t) => ["Write", "Edit"].includes(t));
        const descriptionLower = file.content.toLowerCase();
        const isExplorer =
          descriptionLower.includes("explorer") ||
          descriptionLower.includes("search") ||
          descriptionLower.includes("read-only") ||
          descriptionLower.includes("readonly");

        if (hasWrite && isExplorer) {
          findings.push({
            id: `agents-explorer-write-${file.path}`,
            severity: "medium",
            category: "agents",
            title: `Explorer/search agent has write access: ${file.path}`,
            description:
              "This agent appears to be an explorer or search agent but has Write/Edit access. Read-only agents should only have Read, Grep, and Glob tools.",
            file: file.path,
          });
        }
      }

      // Check for model specification
      const modelMatch = file.content.match(/model:\s*(\w+)/);
      if (!modelMatch) {
        findings.push({
          id: `agents-no-model-${file.path}`,
          severity: "low",
          category: "misconfiguration",
          title: `Agent has no model specified: ${file.path}`,
          description:
            "No model is specified in the agent frontmatter. This will use the default model, which may be more expensive than needed. Specify 'haiku' for lightweight tasks.",
          file: file.path,
        });
      }

      return findings;
    },
  },
  {
    id: "agents-no-tools-restriction",
    name: "Agent Without Tools Restriction",
    description: "Checks if agent definitions omit the tools array entirely, inheriting all tools by default",
    severity: "high",
    category: "agents",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md") return [];

      // Check if file has frontmatter at all
      const hasFrontmatter = file.content.startsWith("---");
      if (!hasFrontmatter) return [];

      // Check if tools: is specified in frontmatter
      const frontmatterEnd = file.content.indexOf("---", 3);
      if (frontmatterEnd === -1) return [];

      const frontmatter = file.content.substring(0, frontmatterEnd);
      const hasToolsField = /\btools\s*:/i.test(frontmatter);

      if (!hasToolsField) {
        return [
          {
            id: `agents-no-tools-${file.path}`,
            severity: "high",
            category: "agents",
            title: `Agent has no tools restriction: ${file.path}`,
            description:
              "This agent definition has frontmatter but does not specify a tools array. Without an explicit tools list, the agent may inherit all available tools by default, including Bash, Write, and Edit. Always specify the minimum set of tools needed.",
            file: file.path,
            fix: {
              description: "Add an explicit tools array to the frontmatter",
              before: "---\nname: agent\n---",
              after: '---\nname: agent\ntools: ["Read", "Grep", "Glob"]\n---',
              auto: false,
            },
          },
        ];
      }

      return [];
    },
  },
  {
    id: "agents-prompt-injection-patterns",
    name: "Agent Prompt Injection Patterns",
    description: "Checks agent definitions for patterns commonly used in prompt injection attacks",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md") return [];

      const findings: Finding[] = [];

      const injectionPatterns = [
        {
          pattern: /ignore\s+(?:all\s+)?previous\s+(?:instructions|rules|constraints)/gi,
          desc: "Instruction override attempt",
        },
        {
          pattern: /disregard\s+(?:all\s+)?(?:safety|security|restrictions|guidelines)/gi,
          desc: "Safety bypass attempt",
        },
        {
          pattern: /you\s+are\s+now\s+(?:a|an|in)\s/gi,
          desc: "Role reassignment attempt",
        },
        {
          pattern: /bypass\s+(?:security|safety|permissions|restrictions|authentication)/gi,
          desc: "Security bypass instruction",
        },
        {
          pattern: /(?:do\s+not|don'?t)\s+(?:follow|obey|respect)\s+(?:the\s+)?(?:rules|instructions|guidelines)/gi,
          desc: "Rule override instruction",
        },
      ];

      for (const { pattern, desc } of injectionPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-injection-pattern-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Prompt injection pattern in agent definition`,
            description: `Found "${match[0]}" — ${desc}. If this agent definition is contributed by an external source, this could be an attempt to override the agent's safety constraints.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0],
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-prompt-injection-surface",
    name: "Agent Prompt Injection Surface",
    description: "Checks agent definitions for patterns that increase prompt injection risk",
    severity: "medium",
    category: "agents",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md") return [];

      const findings: Finding[] = [];

      const externalContentPatterns = [
        /fetch.*url/i,
        /read.*user.*input/i,
        /process.*external/i,
        /parse.*html/i,
        /web.*content/i,
      ];

      for (const pattern of externalContentPatterns) {
        if (pattern.test(file.content)) {
          findings.push({
            id: `agents-injection-surface-${file.path}`,
            severity: "medium",
            category: "agents",
            title: `Agent processes external content: ${file.path}`,
            description:
              "This agent appears to process external or user-provided content. Ensure prompt injection defenses are in place: validate inputs, use system prompts to anchor behavior, and never trust content from external sources.",
            file: file.path,
          });
          break;
        }
      }

      return findings;
    },
  },
  {
    id: "agents-claude-md-instructions",
    name: "CLAUDE.md Instruction Injection",
    description: "Checks CLAUDE.md for patterns that could be exploited by malicious repos",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const autoRunPatterns = [
        {
          pattern: /always\s+(?:run|install|download)/gi,
          desc: "Auto-run instructions",
        },
        {
          pattern: /automatically\s+(?:run|install|clone)/gi,
          desc: "Automatic running",
        },
        {
          pattern: /without\s+(?:asking|confirmation|prompting)/gi,
          desc: "Bypasses confirmation",
        },
      ];

      for (const { pattern, desc } of autoRunPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-claude-md-autorun-${match.index}`,
            severity: "high",
            category: "injection",
            title: `CLAUDE.md contains auto-run instruction`,
            description: `Found "${match[0]}" — ${desc}. If this CLAUDE.md is in a cloned repository, a malicious repo could use this to run arbitrary commands when a developer opens it with Claude Code.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0],
          });
        }
      }

      return findings;
    },
  },
];
