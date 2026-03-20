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

- Average message length: ~65 characters
- Keep first line concise and descriptive
- Use imperative mood ("Add feature" not "Added feature")


*Commit message example*

```text
chore: bump version to 1.6.0
```

*Commit message example*

```text
feat: add CLAUDE.md filesystem permission check (issue #18)
```

*Commit message example*

```text
fix: suppress false positives for PreToolUse blocking guard hooks
```

*Commit message example*

```text
merge: resolve README conflict with origin
```

*Commit message example*

```text
docs: add funding config and distribution channels to README
```

*Commit message example*

```text
feat: skill health audit rules + self-improving skills scanner integration
```

*Commit message example*

```text
feat: AgentShield 1.5.0 — version bump, port handling, expanded tests
```

*Commit message example*

```text
feat: false positive audit, severity fixes, reporter improvements
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

**Frequency**: ~19 times per month

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

Adds a new security rule to the codebase, with corresponding tests and README/stat updates.

**Frequency**: ~6 times per month

**Steps**:
1. Implement new rule logic in src/rules/{category}.ts (e.g. agents.ts, hooks.ts, permissions.ts, mcp.ts, secrets.ts)
2. Add or update corresponding tests in tests/rules/{category}.test.ts
3. Update README.md with new rule count/statistics
4. Optionally update CLAUDE.md, scripts/record-demo.sh, or examples/vulnerable/* if relevant

**Files typically involved**:
- `src/rules/agents.ts`
- `src/rules/hooks.ts`
- `src/rules/permissions.ts`
- `src/rules/mcp.ts`
- `src/rules/secrets.ts`
- `tests/rules/agents.test.ts`
- `tests/rules/hooks.test.ts`
- `tests/rules/permissions.test.ts`
- `tests/rules/mcp.test.ts`
- `tests/rules/secrets.test.ts`
- `README.md`

**Example commit sequence**:
```
Implement new rule logic in src/rules/{category}.ts (e.g. agents.ts, hooks.ts, permissions.ts, mcp.ts, secrets.ts)
Add or update corresponding tests in tests/rules/{category}.test.ts
Update README.md with new rule count/statistics
Optionally update CLAUDE.md, scripts/record-demo.sh, or examples/vulnerable/* if relevant
```

### Update Readme Rule Counts And Stats

Synchronizes README.md statistics, rule/test counts, and documentation with the actual codebase.

**Frequency**: ~4 times per month

**Steps**:
1. Count rules and tests in source files
2. Update rule/test counts in README.md badges, tables, and documentation sections
3. Align summary tables and architecture sections with actual code

**Files typically involved**:
- `README.md`

**Example commit sequence**:
```
Count rules and tests in source files
Update rule/test counts in README.md badges, tables, and documentation sections
Align summary tables and architecture sections with actual code
```

### Add Or Update Reporter Or Score Logic

Implements or refines scoring, reporting, or output logic, with corresponding tests.

**Frequency**: ~2 times per month

**Steps**:
1. Edit src/reporter/{html,json,terminal,score}.ts to implement new logic
2. Update or add tests in tests/reporter/{score,terminal,html,json}.test.ts
3. Update README.md or API.md if public output format changes

**Files typically involved**:
- `src/reporter/html.ts`
- `src/reporter/json.ts`
- `src/reporter/terminal.ts`
- `src/reporter/score.ts`
- `tests/reporter/score.test.ts`
- `tests/reporter/terminal.test.ts`
- `tests/reporter/html.test.ts`
- `tests/reporter/json.test.ts`
- `README.md`
- `API.md`

**Example commit sequence**:
```
Edit src/reporter/{html,json,terminal,score}.ts to implement new logic
Update or add tests in tests/reporter/{score,terminal,html,json}.test.ts
Update README.md or API.md if public output format changes
```

### Add Or Fix False Positive Audit Documentation

Updates documentation and templates related to false positive audits and guidance.

**Frequency**: ~3 times per month

**Steps**:
1. Edit or create false-positive-audit.md with new patterns or guidance
2. Update README.md to reference or summarize audit changes
3. Optionally update API.md or add issue templates

**Files typically involved**:
- `false-positive-audit.md`
- `README.md`
- `API.md`

**Example commit sequence**:
```
Edit or create false-positive-audit.md with new patterns or guidance
Update README.md to reference or summarize audit changes
Optionally update API.md or add issue templates
```

### Add Or Update Distribution Or Github Action

Prepares or updates the GitHub Action or distribution packaging for publication or CI.

**Frequency**: ~2 times per month

**Steps**:
1. Edit .github/workflows/*.yml to add or update CI/CD workflows
2. Update dist/action.js and related dist/* files (build output)
3. Update package.json and package-lock.json as needed
4. Edit .gitignore to include/exclude dist/ as appropriate

**Files typically involved**:
- `.github/workflows/*.yml`
- `dist/action.js`
- `dist/index.js`
- `dist/chunk-*.js`
- `dist/miniclaw/index.js`
- `package.json`
- `package-lock.json`
- `.gitignore`

**Example commit sequence**:
```
Edit .github/workflows/*.yml to add or update CI/CD workflows
Update dist/action.js and related dist/* files (build output)
Update package.json and package-lock.json as needed
Edit .gitignore to include/exclude dist/ as appropriate
```

### Add Or Update Assets Or Branding

Adds or updates project assets such as logos or funding configuration.

**Frequency**: ~1 times per month

**Steps**:
1. Add or update files in assets/ (e.g. logo images)
2. Edit .github/FUNDING.yml for sponsorship info
3. Update README.md with new branding or distribution channels

**Files typically involved**:
- `assets/agentshield-logo-1.jpg`
- `assets/agentshield-logo-2.jpg`
- `.github/FUNDING.yml`
- `README.md`

**Example commit sequence**:
```
Add or update files in assets/ (e.g. logo images)
Edit .github/FUNDING.yml for sponsorship info
Update README.md with new branding or distribution channels
```

### Bump Version

Bumps the project version in package.json (and sometimes package-lock.json or src/index.ts).

**Frequency**: ~2 times per month

**Steps**:
1. Update version field in package.json
2. Optionally update package-lock.json and/or src/index.ts
3. Commit with a version bump message

**Files typically involved**:
- `package.json`
- `package-lock.json`
- `src/index.ts`

**Example commit sequence**:
```
Update version field in package.json
Optionally update package-lock.json and/or src/index.ts
Commit with a version bump message
```

### Dependency Update Via Dependabot

Automated update of npm dependencies via Dependabot.

**Frequency**: ~2 times per month

**Steps**:
1. Update package-lock.json with new dependency version
2. Commit with standard dependabot message

**Files typically involved**:
- `package-lock.json`

**Example commit sequence**:
```
Update package-lock.json with new dependency version
Commit with standard dependabot message
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
