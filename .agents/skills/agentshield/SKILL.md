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
feat: add PR security gate with baseline comparison (issue #16)
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
├── baseline/
├── corpus/
├── fixer/
├── init/
├── injection/
├── logger/
├── miniclaw/
├── opus/
├── reporter/
├── rules/
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

### Add New Scan Rule

Adds a new security scan rule to the codebase, including implementation and corresponding tests.

**Frequency**: ~6 times per month

**Steps**:
1. Implement new rule logic in src/rules/{category}.ts (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts)
2. Add or update corresponding test cases in tests/rules/{category}.test.ts
3. Update README.md with new rule counts or descriptions
4. Optionally update CLAUDE.md or scripts/record-demo.sh with new examples or documentation

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
Implement new rule logic in src/rules/{category}.ts (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts)
Add or update corresponding test cases in tests/rules/{category}.test.ts
Update README.md with new rule counts or descriptions
Optionally update CLAUDE.md or scripts/record-demo.sh with new examples or documentation
```

### Feature Development With Tests And Docs

Implements a new feature or major capability, including code, tests, and documentation updates.

**Frequency**: ~2 times per month

**Steps**:
1. Implement new feature across src/ (may include new modules, types, or CLI flags)
2. Add or update tests in tests/ (unit, integration, or feature-specific)
3. Update documentation files such as README.md, API.md, or add new docs
4. Update package.json version if releasing
5. Optionally update dist/ files if distributing as an action or CLI

**Files typically involved**:
- `src/**`
- `tests/**`
- `README.md`
- `API.md`
- `package.json`
- `dist/action.js`
- `dist/index.js`

**Example commit sequence**:
```
Implement new feature across src/ (may include new modules, types, or CLI flags)
Add or update tests in tests/ (unit, integration, or feature-specific)
Update documentation files such as README.md, API.md, or add new docs
Update package.json version if releasing
Optionally update dist/ files if distributing as an action or CLI
```

### Rule Or Test Count Documentation Update

Synchronizes rule/test counts and statistics in documentation to match the current codebase.

**Frequency**: ~3 times per month

**Steps**:
1. Count rules and tests in source and test files
2. Update README.md with new counts in badges, tables, and sections
3. Update other documentation files (API.md, CLAUDE.md) as needed

**Files typically involved**:
- `README.md`
- `API.md`
- `CLAUDE.md`

**Example commit sequence**:
```
Count rules and tests in source and test files
Update README.md with new counts in badges, tables, and sections
Update other documentation files (API.md, CLAUDE.md) as needed
```

### Add Or Update Test Cases

Adds or expands test coverage for existing or new features/rules.

**Frequency**: ~3 times per month

**Steps**:
1. Add or update test cases in tests/ directory (unit, integration, or regression tests)
2. Optionally update README.md test badge or documentation if test count changes

**Files typically involved**:
- `tests/**`
- `README.md`

**Example commit sequence**:
```
Add or update test cases in tests/ directory (unit, integration, or regression tests)
Optionally update README.md test badge or documentation if test count changes
```

### Dependency Or Version Bump

Updates dependencies or bumps the version for a new release.

**Frequency**: ~2 times per month

**Steps**:
1. Update package.json and/or package-lock.json with new dependency or version
2. Optionally update src/index.ts or other entry points for version export
3. Optionally update dist/ files if building for distribution

**Files typically involved**:
- `package.json`
- `package-lock.json`
- `src/index.ts`
- `dist/action.js`
- `dist/index.js`

**Example commit sequence**:
```
Update package.json and/or package-lock.json with new dependency or version
Optionally update src/index.ts or other entry points for version export
Optionally update dist/ files if building for distribution
```

### Add Or Update Github Action Or Workflow

Adds or updates GitHub Actions workflows or related configuration for CI/CD or Marketplace.

**Frequency**: ~1 times per month

**Steps**:
1. Add or update workflow YAML files in .github/workflows/
2. Update dist/ files if needed for action distribution
3. Update .gitignore to include/exclude dist/ as required
4. Update package.json or package-lock.json if dependencies change

**Files typically involved**:
- `.github/workflows/*.yml`
- `.gitignore`
- `dist/action.js`
- `dist/index.js`
- `package.json`
- `package-lock.json`

**Example commit sequence**:
```
Add or update workflow YAML files in .github/workflows/
Update dist/ files if needed for action distribution
Update .gitignore to include/exclude dist/ as required
Update package.json or package-lock.json if dependencies change
```

### Add Or Update False Positive Audit Documentation

Documents, refines, or updates the false positive audit process and related findings.

**Frequency**: ~2 times per month

**Steps**:
1. Update or create false-positive-audit.md with new findings or guidance
2. Update README.md with references or summaries
3. Optionally update API.md or other docs

**Files typically involved**:
- `false-positive-audit.md`
- `README.md`
- `API.md`

**Example commit sequence**:
```
Update or create false-positive-audit.md with new findings or guidance
Update README.md with references or summaries
Optionally update API.md or other docs
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
