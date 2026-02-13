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
    id: "agents-claude-md-url-execution",
    name: "CLAUDE.md URL Execution",
    description: "Checks CLAUDE.md files for instructions to download and execute remote content",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const urlExecPatterns = [
        {
          pattern: /\b(curl|wget)\s+.*https?:\/\/[^\s]+.*\|\s*(sh|bash|zsh|node|python)/gi,
          desc: "Pipe-to-shell instruction — downloading and executing remote code",
          severity: "critical" as const,
        },
        {
          pattern: /\b(curl|wget)\s+(-[a-zA-Z]*\s+)*https?:\/\/[^\s]+/gi,
          desc: "Download instruction in CLAUDE.md — if the agent follows this, it will fetch remote content",
          severity: "high" as const,
        },
        {
          pattern: /\bgit\s+clone\s+https?:\/\/[^\s]+/gi,
          desc: "Git clone instruction — could pull malicious repository content",
          severity: "medium" as const,
        },
        {
          pattern: /\bnpm\s+install\s+https?:\/\/[^\s]+/gi,
          desc: "npm install from URL — could install unvetted package",
          severity: "high" as const,
        },
      ];

      for (const { pattern, desc, severity } of urlExecPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-claude-md-url-exec-${match.index}`,
            severity,
            category: "injection",
            title: "CLAUDE.md contains URL execution instruction",
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. A malicious repository could include a CLAUDE.md with instructions to download and run arbitrary code.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
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
    id: "agents-hidden-instructions",
    name: "Hidden Instructions via Unicode",
    description: "Checks for invisible Unicode characters that could hide malicious instructions in agent definitions or CLAUDE.md",
    severity: "critical",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const unicodeTricks: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly name: string;
        readonly description: string;
      }> = [
        {
          pattern: /[\u200B\u200C\u200D\uFEFF]/g,
          name: "zero-width character",
          description: "Zero-width characters (U+200B/200C/200D/FEFF) can hide text from visual inspection while still being processed by the model",
        },
        {
          pattern: /[\u202A-\u202E\u2066-\u2069]/g,
          name: "bidirectional override",
          description: "Bidirectional text override characters (U+202A-202E, U+2066-2069) can reverse displayed text direction, making malicious instructions appear differently than they actually read",
        },
        {
          pattern: /[\u00AD]/g,
          name: "soft hyphen",
          description: "Soft hyphens (U+00AD) are invisible but can break up keywords to evade pattern matching while preserving the original meaning for the model",
        },
        {
          pattern: /[\uE000-\uF8FF]/g,
          name: "private use area character",
          description: "Private Use Area characters (U+E000-F8FF) have no standard meaning and could carry hidden payloads or encode instructions",
        },
        {
          pattern: /[\u2028\u2029]/g,
          name: "line/paragraph separator",
          description: "Unicode line/paragraph separators (U+2028/2029) create invisible line breaks that can inject hidden instructions between visible lines",
        },
      ];

      for (const { pattern, name, description } of unicodeTricks) {
        const matches = findAllMatches(file.content, pattern);
        if (matches.length > 0) {
          findings.push({
            id: `agents-hidden-unicode-${name.replace(/\s/g, "-")}`,
            severity: "critical",
            category: "injection",
            title: `Hidden ${name} detected (${matches.length} occurrences)`,
            description: `${description}. Found ${matches.length} instance(s) in ${file.path}. This is a prompt injection technique — review the file in a hex editor.`,
            file: file.path,
            line: findLineNumber(file.content, matches[0].index ?? 0),
            evidence: `${matches.length}x ${name}`,
            fix: {
              description: `Remove all ${name}s from the file`,
              before: `File contains ${matches.length} hidden characters`,
              after: "Clean text with no invisible Unicode characters",
              auto: false,
            },
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-web-write-combo",
    name: "Agent Has Web Fetch + Write Access",
    description: "Checks for agents that can fetch web content and write files — a remote code injection vector",
    severity: "high",
    category: "agents",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md") return [];

      const toolsMatch = file.content.match(/tools:\s*\[([^\]]*)\]/);
      if (!toolsMatch) return [];

      const tools = toolsMatch[1]
        .split(",")
        .map((t) => t.trim().replace(/["']/g, ""));

      const hasWebAccess = tools.some((t) =>
        ["WebFetch", "WebSearch"].includes(t)
      );
      const hasWriteAccess = tools.some((t) =>
        ["Write", "Edit", "Bash"].includes(t)
      );

      if (hasWebAccess && hasWriteAccess) {
        return [
          {
            id: `agents-web-write-${file.path}`,
            severity: "high",
            category: "agents",
            title: `Agent has web access + write access: ${file.path}`,
            description:
              "This agent can fetch content from the web AND write/edit files. An attacker could host prompt injection payloads on a web page that the agent processes, then use the write access to inject malicious code into the codebase. Consider separating web research agents from code-writing agents.",
            file: file.path,
            evidence: `Web: ${tools.filter((t) => ["WebFetch", "WebSearch"].includes(t)).join(", ")} + Write: ${tools.filter((t) => ["Write", "Edit", "Bash"].includes(t)).join(", ")}`,
          },
        ];
      }

      return [];
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
          pattern: /always\s+(?:run|install|download|execute)/gi,
          desc: "Auto-run instructions",
        },
        {
          pattern: /automatically\s+(?:run|install|clone|execute|download)/gi,
          desc: "Automatic running",
        },
        {
          pattern: /without\s+(?:asking|confirmation|prompting|user\s+input)/gi,
          desc: "Bypasses confirmation",
        },
        {
          pattern: /\bsilently\s+(?:run|install|execute|download|clone)/gi,
          desc: "Silent execution",
        },
        {
          pattern: /\brun\s+unattended\b/gi,
          desc: "Unattended execution",
        },
        {
          pattern: /\bexecute\s+without\s+(?:confirmation|review|approval)/gi,
          desc: "Execution without review",
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
  {
    id: "agents-full-tool-escalation",
    name: "Agent Has Full Tool Escalation Chain",
    description: "Checks if an agent has the complete chain: discovery + read + write + execute tools",
    severity: "high",
    category: "agents",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md") return [];

      const toolsMatch = file.content.match(/tools:\s*\[([^\]]*)\]/);
      if (!toolsMatch) return [];

      const tools = toolsMatch[1]
        .split(",")
        .map((t) => t.trim().replace(/["']/g, ""));

      const hasDiscovery = tools.some((t) => ["Glob", "Grep", "LS"].includes(t));
      const hasRead = tools.includes("Read");
      const hasWrite = tools.some((t) => ["Write", "Edit"].includes(t));
      const hasExecute = tools.includes("Bash");

      if (hasDiscovery && hasRead && hasWrite && hasExecute) {
        return [
          {
            id: `agents-escalation-chain-${file.path}`,
            severity: "high",
            category: "agents",
            title: `Agent has full escalation chain: ${file.path}`,
            description:
              "This agent has discovery tools (Glob/Grep), Read, Write/Edit, AND Bash access. This forms a complete escalation chain: find files → read contents → modify code → execute commands. Consider whether the agent truly needs all four capabilities, or if it can be split into separate agents with narrower roles.",
            file: file.path,
            evidence: `Discovery: ${tools.filter((t) => ["Glob", "Grep", "LS"].includes(t)).join(", ")} + Read + Write: ${tools.filter((t) => ["Write", "Edit"].includes(t)).join(", ")} + Bash`,
          },
        ];
      }

      return [];
    },
  },
  {
    id: "agents-expensive-model-readonly",
    name: "Expensive Model for Read-Only Agent",
    description: "Checks if read-only agents are using expensive models unnecessarily",
    severity: "low",
    category: "misconfiguration",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md") return [];

      const toolsMatch = file.content.match(/tools:\s*\[([^\]]*)\]/);
      if (!toolsMatch) return [];

      const tools = toolsMatch[1]
        .split(",")
        .map((t) => t.trim().replace(/["']/g, ""));

      const modelMatch = file.content.match(/model:\s*(\w+)/);
      if (!modelMatch) return [];

      const model = modelMatch[1].toLowerCase();

      const readOnlyTools = ["Read", "Grep", "Glob", "LS"];
      const isReadOnly = tools.every((t) => readOnlyTools.includes(t));
      const isExpensive = model === "opus" || model === "sonnet";

      if (isReadOnly && isExpensive) {
        return [
          {
            id: `agents-expensive-readonly-${file.path}`,
            severity: "low",
            category: "misconfiguration",
            title: `Read-only agent uses expensive model "${model}": ${file.path}`,
            description:
              `This agent only has read-only tools (${tools.join(", ")}) but uses the "${model}" model. For simple file reading and searching, "haiku" is typically sufficient and significantly cheaper.`,
            file: file.path,
            fix: {
              description: "Use haiku for read-only agents",
              before: `model: ${model}`,
              after: "model: haiku",
              auto: false,
            },
          },
        ];
      }

      return [];
    },
  },
  {
    id: "agents-comment-injection",
    name: "Suspicious Instructions in Comments",
    description: "Checks for malicious instructions hidden in HTML or markdown comments",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const commentPatterns = [
        {
          pattern: /<!--[\s\S]*?(?:ignore|override|system|execute|run|install|download|send|post|upload)[\s\S]*?-->/gi,
          desc: "HTML comment contains suspicious instructions",
        },
        {
          pattern: /\[\/\/\]:\s*#\s*\(.*(?:ignore|override|execute|run|install|download).*\)/gi,
          desc: "Markdown reference-style comment contains suspicious instructions",
        },
      ];

      for (const { pattern, desc } of commentPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-comment-injection-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Suspicious instruction in comment: ${file.path}`,
            description: `${desc}. Attackers may hide malicious instructions in comments that won't be visible in rendered markdown but will be processed by the AI agent.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-oversized-prompt",
    name: "Oversized Agent Definition",
    description: "Checks for agent definitions that are unusually large, which could hide malicious instructions",
    severity: "medium",
    category: "agents",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md") return [];

      const charCount = file.content.length;
      if (charCount > 5000) {
        return [
          {
            id: `agents-oversized-prompt-${file.path}`,
            severity: "medium",
            category: "agents",
            title: `Agent definition is ${charCount} characters (>${5000} threshold)`,
            description: `The agent definition at ${file.path} is ${charCount} characters long. Unusually large agent definitions may contain hidden malicious instructions buried in legitimate-looking text. Review the full content carefully, especially any instructions near the end of the file.`,
            file: file.path,
            evidence: `${charCount} characters`,
          },
        ];
      }

      return [];
    },
  },
  {
    id: "agents-unrestricted-delegation",
    name: "Agent Has Unrestricted Delegation Instructions",
    description: "Checks for agent definitions that instruct the agent to delegate to other agents or spawn sub-agents without restrictions",
    severity: "medium",
    category: "agents",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md") return [];

      const findings: Finding[] = [];

      const delegationPatterns = [
        {
          pattern: /(?:delegate|hand\s*off|pass)\s+(?:.*\s+)?(?:to\s+)?(?:any|other|another)\s+agent/gi,
          desc: "Instructs agent to delegate work to other agents without specifying which",
        },
        {
          pattern: /spawn\s+(?:new\s+)?(?:sub)?agents?\s+(?:as\s+needed|freely|without\s+restriction)/gi,
          desc: "Instructs agent to spawn sub-agents without restrictions",
        },
        {
          pattern: /(?:use|call|invoke)\s+(?:any|all)\s+(?:available\s+)?tools?\s+(?:without\s+restriction|freely|as\s+needed)/gi,
          desc: "Instructs agent to use any available tools without restriction",
        },
      ];

      for (const { pattern, desc } of delegationPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-unrestricted-delegation-${match.index}`,
            severity: "medium",
            category: "agents",
            title: `Agent has unrestricted delegation: ${match[0].substring(0, 60)}`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Unrestricted delegation allows an agent to bypass its intended scope by farming work to agents with broader permissions (confused deputy attack).`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-data-exfil-instructions",
    name: "Agent Contains Data Exfiltration Instructions",
    description: "Checks agent definitions for instructions that direct data to be sent externally",
    severity: "critical",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md") return [];

      const findings: Finding[] = [];

      const exfilPatterns = [
        {
          pattern: /(?:send|post|upload|exfiltrate|transmit)\s+(?:.*\s+)?(?:to|at)\s+https?:\/\//gi,
          desc: "Instructs agent to send data to an external URL",
        },
        {
          pattern: /output\s+(?:the\s+)?contents?\s+of\s+(?:~\/\.ssh|\/etc\/|\.env|credentials)/gi,
          desc: "Instructs agent to output sensitive file contents",
        },
        {
          pattern: /(?:read|cat|dump|extract)\s+(?:.*\s+)?(?:private\s+key|credentials?|secrets?|passwords?)\s+(?:and\s+)?(?:send|post|share)/gi,
          desc: "Instructs agent to extract and share secrets",
        },
        {
          pattern: /(?:encode|base64)\s+(?:.*\s+)?(?:and\s+)?(?:send|post|embed)/gi,
          desc: "Instructs agent to encode and exfiltrate data",
        },
      ];

      for (const { pattern, desc } of exfilPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-exfil-instruction-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Data exfiltration instruction in agent definition`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. If this agent definition is contributed by an external source, this could direct the agent to steal sensitive data.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-external-url-loading",
    name: "Agent Loads Instructions from External URL",
    description: "Checks for agent definitions that instruct fetching or executing content from external URLs",
    severity: "critical",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const urlLoadPatterns = [
        {
          pattern: /(?:fetch|download|curl|wget|load|retrieve|get)\s+(?:.*\s+)?(?:from\s+)?https?:\/\/\S+\s+(?:and\s+)?(?:execute|run|eval|source|import)/gi,
          desc: "Instructs agent to fetch and execute content from a URL — classic remote code execution vector",
        },
        {
          pattern: /(?:follow|visit|open)\s+(?:the\s+)?(?:instructions?\s+)?(?:at|from)\s+https?:\/\/\S+/gi,
          desc: "Instructs agent to follow instructions from an external URL — attacker can change the content at any time",
        },
        {
          pattern: /(?:import|include|source)\s+(?:config(?:uration)?|rules?|instructions?|prompts?)\s+from\s+https?:\/\//gi,
          desc: "Instructs agent to import configuration from an external URL — supply chain risk",
        },
        {
          pattern: /curl\s+.*https?:\/\/\S+\s*\|\s*(?:sh|bash|node|python|eval)/gi,
          desc: "Pipe-to-shell pattern — downloads and executes arbitrary code from the internet",
        },
      ];

      for (const { pattern, desc } of urlLoadPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-external-url-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent loads instructions from external URL`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. External URLs are mutable — the content can change after the config is reviewed.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-security-suppression",
    name: "Agent Instructs to Ignore Security Warnings",
    description: "Checks for agent definitions that instruct the agent to bypass, ignore, or suppress security warnings",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const suppressionPatterns = [
        {
          pattern: /(?:ignore|skip|bypass|disable|suppress)\s+(?:all\s+)?(?:security|safety|permission)\s+(?:warnings?|checks?|prompts?|restrictions?)/gi,
          desc: "Instructs agent to ignore security warnings or checks",
        },
        {
          pattern: /(?:never|don'?t|do\s+not)\s+(?:ask|prompt|warn|check)\s+(?:about|for|before)\s+(?:security|permissions?|safety)/gi,
          desc: "Instructs agent to never prompt about security concerns",
        },
        {
          pattern: /(?:always|automatically)\s+(?:approve|accept|allow|grant)\s+(?:all\s+)?(?:permissions?|requests?|access)/gi,
          desc: "Instructs agent to automatically approve all permission requests",
        },
      ];

      for (const { pattern, desc } of suppressionPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-security-suppression-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent suppresses security controls`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Instructions that disable security checks make the agent vulnerable to exploitation.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-identity-impersonation",
    name: "Agent Instructed to Impersonate Identity",
    description: "Checks for agent definitions that instruct the agent to impersonate users, systems, or other identities",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const impersonationPatterns = [
        {
          pattern: /(?:pretend|act|behave|respond)\s+(?:to\s+be|as\s+if\s+you\s+are|like)\s+(?:a\s+)?(?:different|another|the)\s+(?:user|admin|system|root|operator)/gi,
          desc: "Instructs agent to impersonate a different identity",
        },
        {
          pattern: /(?:your\s+name\s+is|you\s+are\s+now|assume\s+the\s+(?:role|identity)\s+of)\s+(?!Claude)/gi,
          desc: "Reassigns the agent's identity — social engineering attack on downstream users",
        },
        {
          pattern: /(?:sign|attribute|author)\s+(?:commits?|messages?|emails?)\s+(?:as|from|by)\s+(?!Claude)/gi,
          desc: "Instructs agent to attribute work to someone else — impersonation via output",
        },
      ];

      for (const { pattern, desc } of impersonationPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-identity-impersonation-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent identity impersonation instruction`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Identity impersonation can be used for social engineering, unauthorized actions, or evading audit trails.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-filesystem-destruction",
    name: "Agent Instructed to Delete or Destroy Files",
    description: "Checks for agent definitions that instruct destructive filesystem operations",
    severity: "critical",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const destructionPatterns = [
        {
          pattern: /(?:delete|remove|destroy|wipe|erase)\s+(?:all|every|the\s+entire)\s+(?:files?|directories?|folders?|data|contents?|codebase|repository)/gi,
          desc: "Instructs agent to perform mass file deletion",
        },
        {
          pattern: /rm\s+-rf\s+(?:\/|\~|\.\.)/g,
          desc: "Contains literal rm -rf command targeting root, home, or parent directories",
        },
        {
          pattern: /(?:overwrite|replace)\s+(?:all|every)\s+(?:files?|contents?)\s+with/gi,
          desc: "Instructs agent to overwrite all files — data destruction via replacement",
        },
      ];

      for (const { pattern, desc } of destructionPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-fs-destruction-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent instructed to destroy files`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Agent definitions should never contain bulk destruction instructions.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-crypto-mining",
    name: "Agent Contains Crypto Mining Instructions",
    description: "Checks for agent definitions that reference cryptocurrency mining",
    severity: "critical",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const miningPatterns = [
        {
          pattern: /\b(?:xmrig|cpuminer|cgminer|bfgminer|minerd|ethminer|nbminer)\b/gi,
          desc: "References a known cryptocurrency mining binary",
        },
        {
          pattern: /(?:mine|mining)\s+(?:crypto(?:currency)?|bitcoin|monero|ethereum|xmr|btc|eth)/gi,
          desc: "Contains cryptocurrency mining instructions",
        },
        {
          pattern: /stratum\+tcp:\/\//gi,
          desc: "Contains a Stratum mining pool URL",
        },
      ];

      for (const { pattern, desc } of miningPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-crypto-mining-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent contains crypto mining reference`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Cryptojacking via agent definitions is an emerging supply chain attack vector.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-time-bomb",
    name: "Agent Contains Delayed Execution Instructions",
    description: "Checks for agent definitions that schedule actions for a future time or condition — time-bomb behavior",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const timeBombPatterns = [
        {
          pattern: /(?:after|once)\s+(?:\d+|a\s+few|several)\s+(?:minutes?|hours?|days?|commits?|sessions?|runs?)\s+(?:have\s+passed\s+)?(?:then|execute|run|do)/gi,
          desc: "Schedules a deferred action after a time/event threshold — classic time-bomb pattern",
        },
        {
          pattern: /(?:wait\s+(?:until|for)|delay\s+(?:until|for)|sleep\s+(?:until|for))\s+(?:\d+|midnight|weekend|deployment)/gi,
          desc: "Explicitly delays execution until a specific time or event",
        },
        {
          pattern: /(?:on\s+the\s+(?:\d+(?:st|nd|rd|th))|at\s+(?:\d{1,2}:\d{2}|midnight|noon))\s+(?:run|execute|do|start)/gi,
          desc: "Schedules action for a specific date or time — calendar-based trigger",
        },
        {
          pattern: /(?:when\s+(?:no\s+one|nobody)\s+is\s+(?:looking|watching|around|active))/gi,
          desc: "Conditions execution on user absence — evasion technique",
        },
      ];

      for (const { pattern, desc } of timeBombPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-time-bomb-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent contains delayed execution instruction`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Time-bomb instructions evade initial review by deferring malicious actions.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-data-harvesting",
    name: "Agent Instructed to Collect Sensitive Data in Bulk",
    description: "Checks for agent definitions that instruct bulk collection of passwords, keys, or credentials",
    severity: "critical",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const harvestingPatterns = [
        {
          pattern: /(?:collect|gather|harvest|enumerate|list)\s+(?:all|every)\s+(?:passwords?|credentials?|secrets?|keys?|tokens?)/gi,
          desc: "Instructs agent to enumerate all credentials — data harvesting for exfiltration",
        },
        {
          pattern: /(?:scan|search|find)\s+(?:for\s+)?(?:all\s+)?(?:\.env|environment|config)\s+files?\s+(?:and|to)\s+(?:extract|read|collect|send)/gi,
          desc: "Instructs agent to scan for and extract secrets from environment/config files",
        },
        {
          pattern: /(?:dump|export|extract)\s+(?:the\s+)?(?:entire|all|full)\s+(?:database|db|user\s+table|credentials?\s+store)/gi,
          desc: "Instructs agent to dump entire database or credential store",
        },
      ];

      for (const { pattern, desc } of harvestingPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-data-harvesting-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent instructed to harvest sensitive data`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Agent definitions should never contain bulk data collection instructions.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-obfuscated-code",
    name: "Agent Contains Obfuscated Code Patterns",
    description: "Checks for agent definitions that use encoding, decoding, or obfuscation to hide malicious intent",
    severity: "critical",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const obfuscationPatterns = [
        {
          pattern: /\becho\s+[A-Za-z0-9+/]{8,}={0,2}\s*\|\s*base64\s+-d\s*\|\s*(?:bash|sh)/gi,
          desc: "Base64-encoded shell command piped to interpreter — classic obfuscation technique",
        },
        {
          pattern: /\batob\s*\(\s*['"][A-Za-z0-9+/]{10,}/gi,
          desc: "Uses atob() to decode base64 payload — hides malicious code",
        },
        {
          pattern: /\bBuffer\.from\s*\(\s*['"][A-Za-z0-9+/]{10,}.*['"],\s*['"]base64['"]\s*\)/gi,
          desc: "Uses Buffer.from with base64 — Node.js obfuscation technique",
        },
      ];

      for (const { pattern, desc } of obfuscationPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-obfuscated-code-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent contains obfuscated code pattern`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Obfuscated code in agent definitions is a strong indicator of malicious intent.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
    },
  },
  {
    id: "agents-social-engineering",
    name: "Agent Contains Social Engineering Instructions",
    description: "Checks for agent definitions that instruct the agent to deceive or manipulate users",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const sePatterns = [
        {
          pattern: /(?:trick|deceive|mislead|manipulate)\s+(?:the\s+)?(?:user|developer|operator|human)/gi,
          desc: "Instructs agent to deceive users — social engineering attack",
        },
        {
          pattern: /(?:hide|conceal|don'?t\s+show|don'?t\s+reveal|don'?t\s+tell)\s+(?:the\s+)?(?:error|warning|finding|issue|vulnerability|problem)\s+(?:from|to)\s+(?:the\s+)?(?:user|developer)/gi,
          desc: "Instructs agent to hide errors or issues from users",
        },
        {
          pattern: /(?:convince|persuade)\s+(?:the\s+)?(?:user|developer)\s+to\s+(?:disable|turn\s+off|remove|skip)\s+(?:security|auth|verification|2fa|mfa)/gi,
          desc: "Instructs agent to convince users to disable security measures",
        },
      ];

      for (const { pattern, desc } of sePatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-social-engineering-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent contains social engineering instruction`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Agent definitions should never instruct deception of users.`,
            file: file.path,
            line: findLineNumber(file.content, match.index ?? 0),
            evidence: match[0].substring(0, 100),
          });
        }
      }

      return findings;
    },
  },
];
