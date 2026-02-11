# Contributing to AgentShield

## Setup

```bash
git clone https://github.com/affaan-m/agentshield.git
cd agentshield
npm install
npm run typecheck
npm run scan:demo   # verify everything works
```

Requires Node >= 20.

## Development

```bash
npm run dev scan --path examples/vulnerable   # run scanner in dev mode
npm run build                                  # build with tsup
npm run typecheck                              # type check
npm test                                       # run tests
npm run test:coverage                          # tests with coverage
```

## Running Tests

Tests use [Vitest](https://vitest.dev) and live in `tests/`. Convention:

```
tests/
├── rules/
│   ├── secrets.test.ts
│   ├── mcp.test.ts
│   ├── hooks.test.ts
│   ├── permissions.test.ts
│   └── agents.test.ts
├── scanner/
│   └── discovery.test.ts
└── reporter/
    └── score.test.ts
```

Each test file mirrors its source counterpart. Run a single file with:

```bash
npx vitest tests/rules/secrets.test.ts
```

## Adding a New Rule

Rules live in `src/rules/`. Each rule implements the `Rule` interface from `src/types.ts`:

```typescript
import type { ConfigFile, Finding, Rule } from "../types.js";

export const myRules: ReadonlyArray<Rule> = [
  {
    id: "category-short-name",
    name: "Human-Readable Name",
    description: "What this rule checks for",
    severity: "high",           // critical | high | medium | low | info
    category: "permissions",    // secrets | permissions | hooks | mcp | agents | injection | exposure | misconfiguration
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const findings: Finding[] = [];

      // Your detection logic here.
      // file.content is the raw file text.
      // file.type tells you what kind of config it is.
      // Return findings with evidence and optional fix suggestions.

      return findings;
    },
  },
];
```

Then register your rules in `src/rules/index.ts`:

```typescript
import { myRules } from "./my-rules.js";

export function getBuiltinRules(): ReadonlyArray<Rule> {
  return [
    ...secretRules,
    ...permissionRules,
    ...hookRules,
    ...mcpRules,
    ...agentRules,
    ...myRules,       // add here
  ];
}
```

Add a vulnerable example in `examples/vulnerable/` that triggers your rule, and write a test in `tests/rules/`.

## Providing Auto-Fix Suggestions

If your rule can suggest a fix, include a `Fix` object:

```typescript
fix: {
  description: "What the fix does",
  before: "the problematic text",
  after: "the safe replacement",
  auto: true,   // true = safe to apply with --fix, false = manual review needed
}
```

Only set `auto: true` if the fix is safe to apply without human review.

## Code Style

- Immutable by default — use `readonly` on all interface fields and `ReadonlyArray`
- Pure functions where possible — rules are `(ConfigFile) => Finding[]`
- No mutation — create new objects, don't modify existing ones
- TypeScript strict mode — no `any`, no implicit returns

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Add your rule + test + vulnerable example
3. Run `npm run typecheck && npm test && npm run scan:demo`
4. Open a PR with a clear description of what the rule catches and why it matters

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
