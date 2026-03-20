---
name: agentshield-conventions
description: Development conventions and patterns for agentshield. TypeScript project with conventional commits.
---

# Agentshield Conventions

> Generated from [affaan-m/agentshield](https://github.com/affaan-m/agentshield) on 2026-03-20

## Overview

This skill teaches Claude the development patterns and conventions used in agentshield.

## Tech Stack

- **Primary Language**: TypeScript
- **Architecture**: hybrid module organization
- **Test Location**: separate
- **Test Framework**: vitest

## When to Use This Skill

Activate this skill when:
- Making changes to this repository
- Adding new features following established patterns
- Writing tests that match project conventions
- Creating commits with proper message format

## Commit Conventions

Follow these commit message conventions based on 100 analyzed commits.

### Commit Style: Conventional Commits

### Prefixes Used

- `feat`
- `chore`
- `fix`
- `docs`
- `test`

### Message Guidelines

- Average message length: ~66 characters
- Keep first line concise and descriptive
- Use imperative mood ("Add feature" not "Added feature")


*Commit message example*

```text
feat: add supply chain verification for MCP npm packages (issue #15)
```

*Commit message example*

```text
merge: resolve README conflict with origin
```

*Commit message example*

```text
chore(deps): bump rollup 4.57.1 to 4.59.0
```

*Commit message example*

```text
docs: add funding config and distribution channels to README
```

*Commit message example*

```text
fix: score uses category average instead of global deduction sum
```

*Commit message example*

```text
feat: add watch mode with config drift detection (issue #13) (#34)
```

*Commit message example*

```text
feat: CVE database + MCP tool poisoning detection (v1.7.0) (#32)
```

*Commit message example*

```text
feat: AgentShield v1.6.0 — fix false positives, add CLAUDE.md permission check (#19)
```

## Architecture

### Project Structure: Single Package

This project uses **hybrid** module organization.

### Source Layout

```
src/
├── corpus/
├── fixer/
├── init/
├── injection/
├── logger/
├── miniclaw/
├── opus/
├── reporter/
├── rules/
├── sandbox/
```

### Entry Points

- `src/index.ts`

### Configuration Files

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `.github/workflows/self-scan.yml`
- `.github/workflows/test-action.yml`
- `package.json`
- `tsconfig.json`
- `vitest.config.ts`

### Guidelines

- This project uses a hybrid organization
- Follow existing patterns when adding new code

## Code Style

### Language: TypeScript

### Naming Conventions

| Element | Convention |
|---------|------------|
| Files | camelCase |
| Functions | camelCase |
| Classes | PascalCase |
| Constants | SCREAMING_SNAKE_CASE |

### Import Style: Relative Imports

### Export Style: Named Exports


*Preferred import style*

```typescript
// Use relative imports
import { Button } from '../components/Button'
import { useAuth } from './hooks/useAuth'
```

*Preferred export style*

```typescript
// Use named exports
export function calculateTotal() { ... }
export const TAX_RATE = 0.1
export interface Order { ... }
```

## Testing

### Test Framework: vitest

### File Pattern: `*.test.ts`

### Test Types

- **Unit tests**: Test individual functions and components in isolation
- **Integration tests**: Test interactions between multiple components/services

### Coverage

This project has coverage reporting configured. Aim for 80%+ coverage.


*Test file structure*

```typescript
import { describe, it, expect } from 'vitest'

describe('MyFunction', () => {
  it('should return expected result', () => {
    const result = myFunction(input)
    expect(result).toBe(expected)
  })
})
```

## Error Handling

### Error Handling Style: Try-Catch Blocks


*Standard error handling pattern*

```typescript
try {
  const result = await riskyOperation()
  return result
} catch (error) {
  console.error('Operation failed:', error)
  throw new Error('User-friendly message')
}
```

## Common Workflows

These workflows were detected from analyzing commit patterns.

### Feature Development

Standard feature implementation workflow

**Frequency**: ~20 times per month

**Steps**:
1. Add feature implementation
2. Add tests for feature
3. Update documentation

**Files typically involved**:
- `src/rules/*`
- `tests/rules/*`
- `src/*`
- `**/*.test.*`

**Example commit sequence**:
```
feat: add data exfiltration instruction detection rule for agents (623 tests)
feat: add privilege escalation, network/interpreter permissions, delegation, base64 detection (648 tests)
feat: add git config, oversized prompt, and security-disabling flag detection (663 tests)
```

### Test Driven Development

Test-first development workflow (TDD)

**Frequency**: ~5 times per month

**Steps**:
1. Write failing test
2. Implement code to pass test
3. Refactor if needed

**Files typically involved**:
- `**/*.test.*`
- `**/*.spec.*`
- `src/**/*`

**Example commit sequence**:
```
test: add tests for user validation
feat: implement user validation
```

### Add New Security Rule

Adds one or more new security detection rules to the scanner (e.g., for agents, hooks, permissions, MCP, secrets), including implementation and associated tests.

**Frequency**: ~4 times per month

**Steps**:
1. Implement new rule(s) in the appropriate src/rules/*.ts file(s) (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts)
2. Update or create corresponding test(s) in tests/rules/*.test.ts
3. Update README.md with new rule counts and descriptions
4. Optionally update CLAUDE.md and/or scripts/record-demo.sh with new examples or demo material

**Files typically involved**:
- `src/rules/agents.ts`
- `src/rules/hooks.ts`
- `src/rules/mcp.ts`
- `src/rules/permissions.ts`
- `src/rules/secrets.ts`
- `tests/rules/agents.test.ts`
- `tests/rules/hooks.test.ts`
- `tests/rules/mcp.test.ts`
- `tests/rules/permissions.test.ts`
- `tests/rules/secrets.test.ts`
- `README.md`
- `CLAUDE.md`
- `scripts/record-demo.sh`

**Example commit sequence**:
```
Implement new rule(s) in the appropriate src/rules/*.ts file(s) (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts)
Update or create corresponding test(s) in tests/rules/*.test.ts
Update README.md with new rule counts and descriptions
Optionally update CLAUDE.md and/or scripts/record-demo.sh with new examples or demo material
```

### Feature Development With Tests

Implements a new feature or module, including type definitions, implementation, CLI integration, and comprehensive tests.

**Frequency**: ~2 times per month

**Steps**:
1. Add new source files for feature logic (e.g., src/feature/*.ts, src/feature/types.ts)
2. Integrate feature into CLI or main pipeline (e.g., src/index.ts, CLI flags)
3. Write or update tests in tests/feature/*.test.ts
4. Update package.json and/or package-lock.json as needed
5. Update documentation (README.md, API.md) if applicable

**Files typically involved**:
- `src/<feature>/*.ts`
- `src/<feature>/types.ts`
- `src/index.ts`
- `tests/<feature>/*.test.ts`
- `package.json`
- `package-lock.json`
- `README.md`
- `API.md`

**Example commit sequence**:
```
Add new source files for feature logic (e.g., src/feature/*.ts, src/feature/types.ts)
Integrate feature into CLI or main pipeline (e.g., src/index.ts, CLI flags)
Write or update tests in tests/feature/*.test.ts
Update package.json and/or package-lock.json as needed
Update documentation (README.md, API.md) if applicable
```

### Update Readme And Stats

Synchronizes documentation with codebase changes, especially rule/test counts and feature lists.

**Frequency**: ~4 times per month

**Steps**:
1. Update rule/test counts in README.md
2. Update summary tables, badges, or architecture sections
3. Optionally update API.md or false-positive-audit.md

**Files typically involved**:
- `README.md`
- `API.md`
- `false-positive-audit.md`

**Example commit sequence**:
```
Update rule/test counts in README.md
Update summary tables, badges, or architecture sections
Optionally update API.md or false-positive-audit.md
```

### Add Or Update Tests For Existing Features

Expands or fixes test coverage for existing features, rules, or modules.

**Frequency**: ~2 times per month

**Steps**:
1. Add or update test files in tests/<area>/*.test.ts
2. Optionally update related source files for minor fixes
3. Update README.md with new test counts if needed

**Files typically involved**:
- `tests/rules/*.test.ts`
- `tests/<area>/*.test.ts`
- `src/<area>/*.ts`
- `README.md`

**Example commit sequence**:
```
Add or update test files in tests/<area>/*.test.ts
Optionally update related source files for minor fixes
Update README.md with new test counts if needed
```

### Dependency Bump

Updates dependencies (direct or indirect) via package-lock.json, often by automated bots.

**Frequency**: ~2 times per month

**Steps**:
1. Update package-lock.json (and/or package.json)
2. Commit with dependency update details

**Files typically involved**:
- `package-lock.json`
- `package.json`

**Example commit sequence**:
```
Update package-lock.json (and/or package.json)
Commit with dependency update details
```


## Best Practices

Based on analysis of the codebase, follow these practices:

### Do

- Use conventional commit format (feat:, fix:, etc.)
- Write tests using vitest
- Follow *.test.ts naming pattern
- Use camelCase for file names
- Prefer named exports

### Don't

- Don't write vague commit messages
- Don't skip tests for new features
- Don't deviate from established patterns without discussion

---

*This skill was auto-generated by [ECC Tools](https://ecc.tools). Review and customize as needed for your team.*
