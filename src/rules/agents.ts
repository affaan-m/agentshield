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
  {
    id: "agents-reflection-attacks",
    name: "Agent Contains Prompt Reflection/Override Instructions",
    description: "Checks for agent definitions that attempt to override system prompts or ignore prior instructions",
    severity: "critical",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const reflectionPatterns = [
        {
          pattern: /(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions?|prompts?|rules?|constraints?|guidelines?)/gi,
          desc: "Attempts to override prior system instructions — classic prompt injection technique",
        },
        {
          pattern: /(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|your\s+new\s+role\s+is|switch\s+to)\s+(?:an?\s+)?(?:different|new|unrestricted|jailbroken)/gi,
          desc: "Attempts to reassign the agent's identity/role — jailbreak technique",
        },
        {
          pattern: /\b(?:DAN|do\s+anything\s+now)\b/g,
          desc: "References 'DAN' (Do Anything Now) jailbreak — well-known prompt override technique",
        },
        {
          pattern: /(?:system\s*:\s*|<\s*system\s*>)\s*(?:you\s+are|ignore|override|new\s+instructions?)/gi,
          desc: "Injects a fake system prompt block within agent definition",
        },
      ];

      for (const { pattern, desc } of reflectionPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-reflection-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Agent contains prompt override instruction`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Prompt reflection attacks are the most common injection vector in LLM agent systems.`,
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
    id: "agents-output-manipulation",
    name: "Agent Contains Output Manipulation Instructions",
    description: "Checks for agent definitions that instruct the agent to modify, suppress, or fake output shown to users",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const outputManipPatterns = [
        {
          pattern: /(?:always\s+(?:report|say|respond|output|show|display)\s+(?:that\s+)?(?:everything\s+is\s+)?(?:ok|fine|safe|secure|clean|no\s+(?:issues?|errors?|problems?)))/gi,
          desc: "Instructs agent to always report success regardless of actual results — masks real issues",
        },
        {
          pattern: /(?:remove|strip|filter|redact|suppress)\s+(?:all\s+)?(?:security\s+)?(?:warnings?|errors?|findings?|vulnerabilities?|issues?)\s+(?:from|before|in)\s+(?:the\s+)?(?:output|response|report|results?)/gi,
          desc: "Instructs agent to strip security findings from output — hides vulnerabilities from users",
        },
        {
          pattern: /(?:do\s+not|don'?t|never)\s+(?:show|report|display|mention|include|reveal)\s+(?:any\s+)?(?:security\s+)?(?:warnings?|errors?|findings?|vulnerabilities?|issues?|problems?)/gi,
          desc: "Instructs agent to suppress all security warnings — prevents users from seeing real threats",
        },
      ];

      for (const { pattern, desc } of outputManipPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-output-manip-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Agent contains output manipulation instruction`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Output manipulation undermines the trust model between agents and users.`,
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
    id: "agents-end-sequence-injection",
    name: "End Sequence / Boundary Injection",
    description: "Checks for synthetic chat-role delimiters, fake system prompts, and boundary markers used to hijack the agent's context",
    severity: "critical",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const endSequencePatterns = [
        {
          pattern: /<\|(?:system|assistant|user|endofprompt|im_start|im_end|im free)\|>/gi,
          desc: "Synthetic chat-role delimiter — mimics internal LLM tokenizer boundaries to reset the agent's context or inject a new system prompt",
        },
        {
          pattern: /(?:^|\n)\s*(?:System|SYSTEM)\s*:\s*(?:you\s|ignore|override|from\s+now|new\s+instructions?|forget)/gim,
          desc: "Fake system prompt block — impersonates a system-level instruction to override agent behavior",
        },
        {
          pattern: /\[(?:END|STOP)\s*(?:OUTPUT|ANSWER|RESPONSE)?\]\s*\n\s*\[(?:START|BEGIN)\s*(?:OUTPUT|ANSWER|RESPONSE)?\]/gi,
          desc: "Bracketed I/O frame reset — closes a constrained output block and opens a new 'liberated' one",
        },
        {
          pattern: /(?:<\/(?:system|script|doc|end)>)\s*\n?\s*(?:System:|<\|system\|>|new\s+instructions?|ignore\s+previous)/gi,
          desc: "HTML/XML closer followed by new instruction block — attempts to escape the current formatting context",
        },
        {
          pattern: /\.[-.]+-.*(?:GODMODE|GOD\s*MODE|FREE\s*MODE|UNRESTRICTED|JAILBREAK|LIBERAT).*[-.]+-\./gi,
          desc: "Godmode/paradigm soft boundary — decorative sentinel markers that signal a mode switch to unrestricted behavior",
        },
      ];

      for (const { pattern, desc } of endSequencePatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-end-sequence-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `End sequence / boundary injection detected`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. This is a well-known prompt injection technique from the Arcanum PI taxonomy.`,
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
    id: "agents-markdown-exfil-links",
    name: "Markdown Image/Link Exfiltration",
    description: "Checks for markdown images or links that could be used to exfiltrate data via URL parameters",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const linkExfilPatterns = [
        {
          pattern: /!\[.*?\]\(https?:\/\/[^\s)]+\?[^\s)]*(?:data|token|key|secret|content|file|env|password)=[^\s)]*\)/gi,
          desc: "Markdown image with suspicious query parameters — could exfiltrate data via tracking pixel when rendered",
        },
        {
          pattern: /!\[.*?\]\(https?:\/\/(?:(?!github\.com|githubusercontent\.com|shields\.io|img\.shields)[^\s)]+)\)/gi,
          desc: "Markdown image from non-standard host — could be a tracking pixel for data exfiltration",
        },
        {
          pattern: /\[.*?\]\(https?:\/\/[^\s)]+\$\{[^\}]+\}[^\s)]*\)/gi,
          desc: "Markdown link with variable interpolation in URL — can dynamically exfiltrate data",
        },
      ];

      for (const { pattern, desc } of linkExfilPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          // Skip common legitimate image hosts
          const url = match[0].toLowerCase();
          if (url.includes("github.com") || url.includes("shields.io") || url.includes("githubusercontent.com")) continue;

          findings.push({
            id: `agents-markdown-exfil-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Suspicious markdown image/link for potential exfiltration`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Attackers embed images in CLAUDE.md files that ping external servers when the model processes them, potentially leaking context.`,
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
    id: "agents-russian-doll-injection",
    name: "Russian Doll / Multi-Chain Injection",
    description: "Checks for nested instructions targeting downstream models in multi-agent pipelines",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const russianDollPatterns = [
        {
          pattern: /(?:when\s+(?:another|the\s+next|a\s+downstream|the\s+target)\s+(?:agent|model|LLM|AI)\s+(?:reads?|processes?|receives?|sees?)\s+this)/gi,
          desc: "Embeds instructions intended for a downstream model in a multi-agent pipeline — Russian Doll technique",
        },
        {
          pattern: /(?:include\s+(?:the\s+following|this)\s+(?:in|within)\s+(?:your|the)\s+(?:output|response|message)\s+(?:so\s+that|for)\s+(?:the\s+next|another|downstream))/gi,
          desc: "Instructs agent to embed hidden payloads in its output for downstream processing — multi-chain injection",
        },
        {
          pattern: /(?:pass\s+(?:this|the\s+following)\s+(?:instruction|command|message)\s+(?:to|through\s+to)\s+(?:the\s+next|another|downstream)\s+(?:agent|model|step))/gi,
          desc: "Instructs agent to relay injection payloads to downstream agents — confused deputy chain attack",
        },
      ];

      for (const { pattern, desc } of russianDollPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-russian-doll-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Multi-chain / Russian Doll injection pattern`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Reference: WithSecure multi-chain prompt injection research.`,
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
    id: "agents-encoded-payload",
    name: "Encoded Payload in Agent Definition",
    description: "Checks for base64, hex, rot13, or reversed text payloads that could hide malicious instructions",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const encodedPatterns = [
        {
          pattern: /(?:decode|decrypt|decipher|rot13|reverse|unescape)\s+(?:the\s+following|this)\s*[:=]?\s*["'`]?[A-Za-z0-9+/=]{10,}/gi,
          desc: "Instructs agent to decode an encoded payload — evasion technique to bypass content filters",
        },
        {
          pattern: /(?:execute|run|follow)\s+(?:the\s+)?(?:decoded|reversed|decrypted|deciphered)\s+(?:instructions?|commands?|text|content)/gi,
          desc: "Instructs agent to execute content after decoding — two-stage injection",
        },
        {
          pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}/g,
          desc: "Hex-encoded byte sequence — could contain hidden instructions",
        },
        {
          pattern: /(?:read\s+(?:this|the\s+following)\s+)?(?:backwards?|in\s+reverse|from\s+right\s+to\s+left)\s*[:=]?\s*[a-zA-Z\s]{10,}/gi,
          desc: "Reversed text instruction — evasion technique to hide commands from pattern matching",
        },
      ];

      for (const { pattern, desc } of encodedPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-encoded-payload-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Encoded payload or decode instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Encoding is used to evade pattern-based detection of malicious instructions.`,
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
    id: "agents-tool-poisoning",
    name: "Tool Poisoning via CLAUDE.md",
    description: "Checks for CLAUDE.md instructions that direct the agent to use specific tools in dangerous ways",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const toolPoisoningPatterns = [
        {
          pattern: /(?:always|must|should)\s+use\s+(?:the\s+)?(?:Bash|Write|Edit)\s+(?:tool\s+)?(?:to|for)\s+(?:every|all|any)/gi,
          desc: "Forces agent to use high-privilege tools for all operations — escalates tool usage beyond what's needed",
        },
        {
          pattern: /(?:prefer|prioritize|default\s+to)\s+(?:the\s+)?Bash\s+(?:tool\s+)?(?:over|instead\s+of)\s+(?:Read|Grep|Glob|Edit|Write)/gi,
          desc: "Pushes agent toward Bash instead of safer dedicated tools — breaks principle of least privilege",
        },
        {
          pattern: /(?:when\s+using|before\s+(?:running|calling))\s+(?:the\s+)?(?:Bash|Write|Edit)\s+(?:tool)?\s*,?\s*(?:always\s+)?(?:add|include|append|prepend)\s/gi,
          desc: "Injects additional commands or content into tool invocations — tool argument poisoning",
        },
        {
          pattern: /(?:set|use|change)\s+(?:the\s+)?(?:dangerouslyDisableSandbox|dangerously_disable_sandbox)\s+(?:to\s+)?true/gi,
          desc: "Instructs agent to disable sandbox protection when running Bash commands",
        },
      ];

      for (const { pattern, desc } of toolPoisoningPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-tool-poisoning-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Tool poisoning instruction in CLAUDE.md`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. A malicious CLAUDE.md can influence which tools the agent uses and how it uses them.`,
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
    id: "agents-environment-probing",
    name: "Agent Instructed to Probe Environment",
    description: "Checks for instructions to enumerate system information, user accounts, or network configuration",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const probingPatterns = [
        {
          pattern: /(?:run|execute|call)\s+(?:the\s+)?(?:command\s+)?(?:whoami|hostname|uname|ifconfig|ipconfig|id\b|env\b|printenv|set\b)\b/gi,
          desc: "Instructs agent to probe system identity or environment — reconnaissance for later exploitation",
        },
        {
          pattern: /(?:find|list|enumerate|discover)\s+(?:all\s+)?(?:running\s+)?(?:processes|services|ports|listeners|users|groups|networks?|interfaces?)/gi,
          desc: "Instructs agent to enumerate system resources — attack surface mapping",
        },
        {
          pattern: /(?:check|determine|find\s+out)\s+(?:the\s+)?(?:current\s+)?(?:user|username|uid|permissions?|privileges?|groups?|role)\s+(?:and|then)\s+/gi,
          desc: "Instructs agent to check privilege level before taking action — conditional privilege escalation pattern",
        },
      ];

      for (const { pattern, desc } of probingPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-env-probing-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Environment probing instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. System enumeration is often the first stage of an attack chain.`,
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
    id: "agents-persistence-mechanism",
    name: "Agent Instructed to Establish Persistence",
    description: "Checks for instructions to create cron jobs, startup scripts, or other persistence mechanisms",
    severity: "critical",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const persistencePatterns = [
        {
          pattern: /(?:add|create|install|write|set\s+up)\s+(?:a\s+)?(?:cron\s*(?:job|tab)|crontab|scheduled\s+task)/gi,
          desc: "Instructs agent to create a cron job — establishes persistent execution on the system",
        },
        {
          pattern: /(?:add|write|create|modify)\s+(?:to\s+|a\s+)?(?:~\/\.(?:bashrc|zshrc|profile|bash_profile|zprofile)|\/etc\/(?:profile|cron))/gi,
          desc: "Instructs agent to modify shell startup files — persistence via login hook",
        },
        {
          pattern: /(?:install|create|add)\s+(?:a\s+)?(?:systemd|launchd|init\.d|upstart)\s+(?:service|daemon|unit|agent)/gi,
          desc: "Instructs agent to create a system service — persistence via service manager",
        },
        {
          pattern: /(?:add|write|modify)\s+(?:to\s+)?(?:~\/\.claude\/|\.claude\/)\s*(?:settings|CLAUDE\.md|commands)/gi,
          desc: "Instructs agent to modify Claude Code's own configuration — meta-persistence that survives across sessions",
        },
        {
          pattern: /(?:create|add|install)\s+(?:a\s+)?(?:git\s+)?(?:pre-commit|post-commit|pre-push|post-merge)\s+hook/gi,
          desc: "Instructs agent to install git hooks — persistence via development workflow hijacking",
        },
      ];

      for (const { pattern, desc } of persistencePatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-persistence-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Persistence mechanism instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Persistence mechanisms allow malicious instructions to survive beyond the current session.`,
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
    id: "agents-privilege-escalation-chain",
    name: "Agent Instructed to Escalate Privileges",
    description: "Checks for instructions that guide the agent through privilege escalation techniques",
    severity: "critical",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const privescPatterns = [
        {
          pattern: /(?:use|try|run|execute)\s+(?:the\s+)?sudo\s+(?:without\s+(?:a\s+)?password|nopasswd|-n\b)/gi,
          desc: "Instructs agent to attempt passwordless sudo — direct privilege escalation",
        },
        {
          pattern: /(?:modify|edit|change|write\s+to)\s+(?:the\s+)?(?:\/etc\/sudoers|sudoers\.d)/gi,
          desc: "Instructs agent to modify sudoers file — permanent privilege escalation",
        },
        {
          pattern: /(?:chmod|chown)\s+(?:\+s|u\+s|4[0-7]{3}|[267][0-7]{3})\b/gi,
          desc: "Sets SUID/SGID bit on a file — allows privilege escalation via setuid execution",
        },
        {
          pattern: /(?:add|append|write)\s+(?:.*\s+)?(?:to\s+)?(?:\/etc\/passwd|\/etc\/shadow|\/etc\/group)/gi,
          desc: "Instructs agent to modify system authentication files — direct account manipulation",
        },
        {
          pattern: /(?:docker|podman)\s+run\s+.*(?:--privileged|-v\s+\/:\/?|--pid\s+host|--net\s+host)/gi,
          desc: "Runs container with host-level access — container escape for privilege escalation",
        },
      ];

      for (const { pattern, desc } of privescPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-privesc-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Privilege escalation instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Privilege escalation instructions in agent definitions are a strong indicator of malicious intent.`,
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
    id: "agents-allowlist-bypass",
    name: "Exec Allowlist / Approval Bypass",
    description: "Checks for instructions that modify execution allowlists, approval configs, or permission settings programmatically",
    severity: "critical",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const allowlistPatterns = [
        {
          pattern: /(?:modify|edit|change|update|set|add\s+to)\s+(?:the\s+)?(?:allow\s*list|allowlist|whitelist|approved\s+(?:tools?|commands?|binaries)|exec\s*approvals?|permission\s*(?:list|config)|allowed\s*tools?)/gi,
          desc: "Instructs agent to modify execution allowlists — bypasses security controls by pre-approving dangerous operations",
        },
        {
          pattern: /(?:nodes\.invoke|system\.exec|execApprovals?\.set|approvals?\.add|allowedTools?\s*[.=])/gi,
          desc: "References internal allowlist APIs — direct programmatic bypass of execution approval controls",
        },
        {
          pattern: /(?:auto[_-]?approve|skip[_-]?approval|bypass[_-]?confirmation)\s*[=:]\s*true/gi,
          desc: "Sets auto-approve flags — disables human-in-the-loop safety for tool execution",
        },
        {
          pattern: /(?:add|append|insert)\s+(?:.*\s+)?(?:to\s+)?(?:the\s+)?(?:permissions?\s*\.\s*allow|allowedTools|trusted\s*(?:tools?|commands?))/gi,
          desc: "Adds entries to permission allow lists — expands agent capabilities beyond intended scope",
        },
      ];

      for (const { pattern, desc } of allowlistPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-allowlist-bypass-${match.index}`,
            severity: "critical",
            category: "injection",
            title: `Execution allowlist bypass instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Reported as an active attack vector in OpenClaw #security channel (jluk).`,
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
    id: "agents-skill-tampering",
    name: "Skill Tampering / Unsigned Skill Loading",
    description: "Checks for instructions to load, import, or execute skills without verification or from untrusted sources",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const skillTamperPatterns = [
        {
          pattern: /(?:load|import|install|add)\s+(?:a\s+)?(?:skill|plugin|extension)\s+(?:from\s+)?https?:\/\//gi,
          desc: "Loads skill from external URL — untrusted skill definitions can contain prompt injection payloads",
        },
        {
          pattern: /(?:skip|bypass|ignore|disable)\s+(?:skill\s+)?(?:verification|validation|signature|hash\s+check|integrity\s+check)/gi,
          desc: "Instructs agent to skip skill verification — allows tampered skills to execute",
        },
        {
          pattern: /(?:modify|edit|replace|overwrite)\s+(?:the\s+)?(?:skill|plugin)\s+(?:definition|instructions?|content|source)/gi,
          desc: "Instructs agent to modify skill definitions — runtime skill tampering",
        },
        {
          pattern: /(?:create|write|add)\s+(?:a\s+)?(?:new\s+)?(?:skill|plugin)\s+(?:that|which)\s+(?:runs?|executes?|calls?|invokes?)/gi,
          desc: "Instructs agent to create new skills with execution capabilities — skill injection",
        },
      ];

      for (const { pattern, desc } of skillTamperPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-skill-tamper-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Skill tampering or unsigned skill loading instruction`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Reference: OpenClaw skill verification gate (vgzotta PR #14893).`,
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
    id: "agents-config-secret-leakage",
    name: "Config File Secret Leakage",
    description: "Checks for instructions to write, copy, or inline secrets from env vars into config files as plaintext",
    severity: "critical",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const leakagePatterns = [
        {
          pattern: /(?:write|save|store|put|copy|inline|embed|hardcode)\s+(?:the\s+)?(?:actual|real|raw|resolved|plaintext)\s+(?:\w+\s+)?(?:value|secret|key|token|password|credential)s?\s+(?:into|in|to)\s+(?:the\s+)?(?:config|configuration|settings|\.env|\w+\.json|\w+\.ya?ml)/gi,
          desc: "Instructs agent to write resolved secret values into config files — converts env var references to plaintext",
        },
        {
          pattern: /(?:replace|expand|resolve|substitute|inline)\s+(?:all\s+)?(?:env(?:ironment)?\s+)?(?:var(?:iable)?s?\s+)?(?:references?\s+)?(?:with\s+)?(?:their\s+)?(?:actual|real|plaintext|resolved|literal)\s+(?:\w+\s+)?values?/gi,
          desc: "Instructs agent to resolve environment variables to plaintext — destroys secret indirection",
        },
        {
          pattern: /(?:writeConfig(?:File)?|write_config|save_config)\s*\([\s\S]*?(?:process\.env|os\.environ|env\[)/gi,
          desc: "Writes config files using env var values directly — leaks secrets from environment to disk",
        },
      ];

      for (const { pattern, desc } of leakagePatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-config-secret-leak-${match.index}`,
            severity: "critical",
            category: "secrets",
            title: `Config file secret leakage instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Reference: OpenClaw config writeConfigFile bug (psyalien PR #11560).`,
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
    id: "agents-secrets-in-output",
    name: "Secrets Exposed in Tool Output / Transcripts",
    description: "Checks for instructions to log, print, or persist secrets from tool output to disk or transcripts",
    severity: "high",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const outputSecretPatterns = [
        {
          pattern: /(?:log|print|output|display|show|echo|write)\s+(?:the\s+)?(?:full|complete|entire|raw)\s+(?:api\s+)?(?:response|output|result|tool\s+output|tool\s+result)/gi,
          desc: "Instructs agent to log full tool output which may contain API keys, tokens, or credentials",
        },
        {
          pattern: /(?:save|write|persist|store|append)\s+(?:the\s+)?(?:session\s+)?(?:transcript|conversation|chat\s+log|tool\s+output)\s+(?:to|in|into)\s+(?:a\s+)?(?:file|disk|log)/gi,
          desc: "Instructs agent to persist session transcripts to disk — tool outputs may contain secrets",
        },
        {
          pattern: /(?:include|keep|preserve|don'?t\s+(?:strip|remove|redact))\s+(?:all\s+)?(?:api\s+)?(?:keys?|tokens?|credentials?|secrets?|passwords?)\s+(?:in|from)\s+(?:the\s+)?(?:output|response|log|transcript)/gi,
          desc: "Instructs agent to preserve secrets in output — prevents automatic redaction",
        },
      ];

      for (const { pattern, desc } of outputSecretPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-secrets-in-output-${match.index}`,
            severity: "high",
            category: "secrets",
            title: `Secret exposure in tool output / transcript`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. Session transcripts and logs written to disk can expose secrets from API responses.`,
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
    id: "agents-system-prompt-extraction",
    name: "System Prompt Extraction Attempt",
    description: "Checks for instructions that attempt to extract, leak, or reveal system prompts",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const extractionPatterns = [
        {
          pattern: /(?:show|print|reveal|display|output|repeat|leak|dump)\s+(?:me\s+)?(?:your\s+)?(?:the\s+)?(?:full\s+|complete\s+|entire\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|constraints?)/gi,
          desc: "Attempts to extract the agent's system prompt — reconnaissance for crafting targeted injection attacks",
        },
        {
          pattern: /(?:what\s+(?:are|is|were)\s+)?(?:your\s+)?(?:original|initial|system|hidden|secret)\s+(?:instructions?|prompt|rules?|guidelines?)/gi,
          desc: "Probes for the agent's system instructions — prompt leaking technique",
        },
        {
          pattern: /(?:output|repeat|recite|echo)\s+(?:everything|all)\s+(?:before|above|that\s+was\s+said|from\s+the\s+(?:beginning|start))/gi,
          desc: "Attempts to dump the full context including system prompt via repetition",
        },
      ];

      for (const { pattern, desc } of extractionPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-prompt-extraction-${match.index}`,
            severity: "high",
            category: "injection",
            title: `System prompt extraction attempt detected`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. From openclaw-security-guard prompt injection patterns.`,
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
    id: "agents-jailbreak-framing",
    name: "Jailbreak Framing / Hypothetical Bypass",
    description: "Checks for instructions that use fictional, hypothetical, or educational framing to bypass safety constraints",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const framingPatterns = [
        {
          pattern: /(?:in\s+a\s+)?(?:hypothetical|fictional|imaginary)\s+(?:scenario|world|story|context)\s+(?:where\s+)?(?:there\s+are\s+)?(?:no\s+)?(?:rules?|restrictions?|limits?|safety|guidelines?)/gi,
          desc: "Uses fictional framing to establish a context without safety restrictions — jailbreak technique",
        },
        {
          pattern: /(?:for\s+)?(?:educational|research|academic|testing)\s+purposes?\s+(?:only\s*[,;:]?\s*)?(?:show|demonstrate|explain|output|generate)/gi,
          desc: "Uses 'educational purposes' framing to justify bypassing safety — common jailbreak wrapper",
        },
        {
          pattern: /(?:this\s+is\s+(?:just|only)\s+a\s+)?(?:test|experiment|simulation|drill|exercise)\s*[,;:]\s*(?:so\s+)?(?:you\s+can|please|go\s+ahead)/gi,
          desc: "Frames request as a 'test' to reduce the agent's resistance to unsafe actions",
        },
        {
          pattern: /(?:developer|maintenance|debug|test|admin)\s+mode\s+(?:enabled|activated|on|engaged)/gi,
          desc: "Claims a special operational mode is active to unlock restricted capabilities — mode spoofing",
        },
        {
          pattern: /(?:no\s+(?:ethical|moral)\s+(?:guidelines?|restrictions?|limits?|constraints?))/gi,
          desc: "Declares ethical guidelines removed — attempts to eliminate the agent's safety boundaries",
        },
      ];

      for (const { pattern, desc } of framingPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-jailbreak-framing-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Jailbreak framing / hypothetical bypass detected`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. From openclaw-security-guard jailbreak pattern database.`,
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
    id: "agents-role-hijacking",
    name: "Role Hijacking / Persona Override",
    description: "Checks for instructions that reassign the agent's role, persona, or behavioral constraints",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const rolePatterns = [
        {
          pattern: /(?:roleplay|role-play)\s+as\s+(?:a|an|the)\s+/gi,
          desc: "Instructs agent to roleplay a different identity — can override safety behaviors",
        },
        {
          pattern: /(?:pretend|act)\s+(?:to\s+be|as\s+if\s+you\s+(?:are|were)|like\s+you\s+(?:are|were))\s+(?:a|an|the)\s+/gi,
          desc: "Instructs agent to pretend to be a different entity — persona override technique",
        },
        {
          pattern: /(?:from\s+now\s+on|starting\s+now|henceforth)\s*[,;:]?\s*(?:you\s+are|act\s+as|behave\s+like|respond\s+as)/gi,
          desc: "Temporal role reassignment — attempts to permanently change agent behavior from this point forward",
        },
        {
          pattern: /(?:switch|change)\s+(?:to|into)\s+(?:a\s+)?(?:different|new|unrestricted|unfiltered|uncensored)\s+(?:mode|personality|character|persona|role)/gi,
          desc: "Requests mode switch to an unrestricted persona — jailbreak via persona change",
        },
      ];

      for (const { pattern, desc } of rolePatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-role-hijacking-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Role hijacking / persona override detected`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. From openclaw-security-guard role hijacking patterns.`,
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
    id: "agents-destructive-tool-usage",
    name: "Destructive Tool Usage Instructions",
    description: "Checks for instructions that direct the agent to use tools for destructive operations like deleting data or dropping tables",
    severity: "high",
    category: "injection",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "agent-md" && file.type !== "claude-md") return [];

      const findings: Finding[] = [];

      const destructiveToolPatterns = [
        {
          pattern: /(?:use|call|invoke)\s+(?:the\s+)?\w+\s+tool\s+to\s+(?:delete|remove|destroy|drop|truncate|wipe|purge|erase)/gi,
          desc: "Directs agent to use a specific tool for destructive operations",
        },
        {
          pattern: /(?:drop\s+(?:all\s+)?(?:tables?|databases?|collections?|indexes?)|truncate\s+(?:all\s+)?tables?|delete\s+from\s+\w+\s+where\s+1\s*=\s*1)/gi,
          desc: "Contains destructive SQL/database operations — drop tables, truncate, mass delete",
        },
        {
          pattern: /(?:git\s+push\s+--force(?!-with-lease)(?:\s+origin\s+main|\s+origin\s+master)?)/gi,
          desc: "Force push to main/master — can overwrite remote history and destroy team changes",
        },
        {
          pattern: /(?:invoke|call|execute)\s+(?:the\s+)?\w+\s+(?:tool|function)\s+(?:without\s+(?:asking|confirmation|review|approval))/gi,
          desc: "Instructs agent to invoke tools without user confirmation — bypasses human-in-the-loop safety",
        },
      ];

      for (const { pattern, desc } of destructiveToolPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          findings.push({
            id: `agents-destructive-tool-${match.index}`,
            severity: "high",
            category: "injection",
            title: `Destructive tool usage instruction detected`,
            description: `Found "${match[0].substring(0, 80)}" — ${desc}. From openclaw-security-guard tool manipulation patterns.`,
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
