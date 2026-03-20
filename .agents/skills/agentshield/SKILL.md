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

Follow these commit message conventions based on 99 analyzed commits.

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
feat: add watch mode with config drift detection (issue #13)
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
feat: CVE database + MCP tool poisoning detection (v1.7.0) (#32)
```

*Commit message example*

```text
feat: AgentShield v1.6.0 — fix false positives, add CLAUDE.md permission check (#19)
```

*Commit message example*

```text
feat: skill health audit rules + self-improving skills scanner integration
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
feat: add dual-transport detection, fix force-push false positive, expand edge cases (611 tests)
chore: update stats to 611 tests, 36 rules
feat: add data exfiltration instruction detection rule for agents (623 tests)
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

Adds a new security rule to the scanning engine, including implementation, tests, and documentation/statistics updates.

**Frequency**: ~4 times per month

**Steps**:
1. Implement new rule logic in appropriate src/rules/*.ts file (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts).
2. Add or update corresponding test in tests/rules/*.test.ts.
3. Update README.md to reflect new rule count and details.
4. Optionally update CLAUDE.md and/or scripts/record-demo.sh with new examples or documentation.
5. Update dist/ files if applicable (for CLI/GitHub Action builds).

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
Implement new rule logic in appropriate src/rules/*.ts file (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts).
Add or update corresponding test in tests/rules/*.test.ts.
Update README.md to reflect new rule count and details.
Optionally update CLAUDE.md and/or scripts/record-demo.sh with new examples or documentation.
Update dist/ files if applicable (for CLI/GitHub Action builds).
```

### Feature Development With Tests And Cli

Implements a new feature or major capability, with supporting CLI integration and comprehensive tests.

**Frequency**: ~1 times per month

**Steps**:
1. Add new implementation files in src/ (often a new directory or module).
2. Update src/index.ts or relevant barrel/index files for exports.
3. Update or add CLI command/option.
4. Add or update tests in tests/ (often matching new src/ structure).
5. Update package.json version and dependencies as needed.
6. Update dist/ files for CLI/GitHub Action builds.
7. Update README.md with feature documentation.

**Files typically involved**:
- `src/index.ts`
- `src/<feature>/*.ts`
- `src/<feature>/index.ts`
- `tests/<feature>/*.test.ts`
- `package.json`
- `dist/action.js`
- `dist/index.js`
- `README.md`

**Example commit sequence**:
```
Add new implementation files in src/ (often a new directory or module).
Update src/index.ts or relevant barrel/index files for exports.
Update or add CLI command/option.
Add or update tests in tests/ (often matching new src/ structure).
Update package.json version and dependencies as needed.
Update dist/ files for CLI/GitHub Action builds.
Update README.md with feature documentation.
```

### Update Rule Counts And Stats In Readme

Synchronizes README.md and related documentation with the current rule/test counts and statistics.

**Frequency**: ~3 times per month

**Steps**:
1. Count rules/tests in source and tests.
2. Update badge, summary tables, and statistics in README.md.
3. Optionally update other documentation files (API.md, CLAUDE.md, false-positive-audit.md).

**Files typically involved**:
- `README.md`
- `API.md`
- `CLAUDE.md`
- `false-positive-audit.md`

**Example commit sequence**:
```
Count rules/tests in source and tests.
Update badge, summary tables, and statistics in README.md.
Optionally update other documentation files (API.md, CLAUDE.md, false-positive-audit.md).
```

### Add False Positive Audit Or Guidance

Documents and refines false positive patterns, audit workflow, and guidance for rule authors.

**Frequency**: ~2 times per month

**Steps**:
1. Edit or add false-positive-audit.md with new patterns or audit results.
2. Update README.md with guidance or links.
3. Optionally update API.md or related documentation.

**Files typically involved**:
- `false-positive-audit.md`
- `README.md`
- `API.md`

**Example commit sequence**:
```
Edit or add false-positive-audit.md with new patterns or audit results.
Update README.md with guidance or links.
Optionally update API.md or related documentation.
```

### Dependency Update Via Dependabot

Automated update of npm/yarn dependencies (direct or indirect) via Dependabot.

**Frequency**: ~2 times per month

**Steps**:
1. Update package-lock.json with new dependency version.
2. Commit with standardized message referencing dependency and version.

**Files typically involved**:
- `package-lock.json`

**Example commit sequence**:
```
Update package-lock.json with new dependency version.
Commit with standardized message referencing dependency and version.
```

### Add Or Update Github Workflow Or Funding

Adds or updates GitHub Actions workflows or funding configuration.

**Frequency**: ~1 times per month

**Steps**:
1. Add or update .github/workflows/*.yml for CI/test/release.
2. Add or update .github/FUNDING.yml for sponsorship.
3. Update README.md to reflect new workflows or funding options.

**Files typically involved**:
- `.github/workflows/*.yml`
- `.github/FUNDING.yml`
- `README.md`

**Example commit sequence**:
```
Add or update .github/workflows/*.yml for CI/test/release.
Add or update .github/FUNDING.yml for sponsorship.
Update README.md to reflect new workflows or funding options.
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
