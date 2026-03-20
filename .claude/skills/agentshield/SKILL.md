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

- Average message length: ~65 characters
- Keep first line concise and descriptive
- Use imperative mood ("Add feature" not "Added feature")


*Commit message example*

```text
chore: bump version to 1.7.0
```

*Commit message example*

```text
feat: add MCP tool description poisoning detection (#12)
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
fix: score uses category average instead of global deduction sum
```

*Commit message example*

```text
feat: add CVE database and known-vulnerable MCP server detection (#11)
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

Adds a new static security rule to the scanner, with corresponding test coverage.

**Frequency**: ~6 times per month

**Steps**:
1. Implement new rule in src/rules/{category}.ts (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts)
2. Add or update corresponding test in tests/rules/{category}.test.ts
3. Update README.md with new rule count and/or description
4. Optionally update CLAUDE.md or example files to include new attack vectors

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
- `examples/vulnerable/*.md`
- `examples/vulnerable/*.json`

**Example commit sequence**:
```
Implement new rule in src/rules/{category}.ts (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts)
Add or update corresponding test in tests/rules/{category}.test.ts
Update README.md with new rule count and/or description
Optionally update CLAUDE.md or example files to include new attack vectors
```

### Version Bump And Release

Bumps the package version and prepares for a new release, often after major features or rule additions.

**Frequency**: ~2 times per month

**Steps**:
1. Update version in package.json
2. Optionally update package-lock.json
3. Optionally update src/index.ts or other entry points
4. Commit with version bump message

**Files typically involved**:
- `package.json`
- `package-lock.json`
- `src/index.ts`

**Example commit sequence**:
```
Update version in package.json
Optionally update package-lock.json
Optionally update src/index.ts or other entry points
Commit with version bump message
```

### Add Or Improve Test Coverage

Adds or expands test cases for new or existing rules, features, or bug fixes.

**Frequency**: ~4 times per month

**Steps**:
1. Add or update test files in tests/rules/, tests/integration.test.ts, or other relevant test directories
2. Optionally update README.md with new test counts
3. Run tests to ensure all pass

**Files typically involved**:
- `tests/rules/agents.test.ts`
- `tests/rules/hooks.test.ts`
- `tests/rules/mcp.test.ts`
- `tests/rules/permissions.test.ts`
- `tests/rules/secrets.test.ts`
- `tests/integration.test.ts`
- `README.md`

**Example commit sequence**:
```
Add or update test files in tests/rules/, tests/integration.test.ts, or other relevant test directories
Optionally update README.md with new test counts
Run tests to ensure all pass
```

### False Positive Audit And Docs Update

Audits false positives, documents recurring issues, and updates related documentation.

**Frequency**: ~4 times per month

**Steps**:
1. Update false-positive-audit.md with new findings or guidance
2. Update README.md with scan accuracy guidance or audit results
3. Optionally update API.md or release-draft.md
4. Commit documentation changes

**Files typically involved**:
- `false-positive-audit.md`
- `README.md`
- `API.md`
- `release-draft.md`

**Example commit sequence**:
```
Update false-positive-audit.md with new findings or guidance
Update README.md with scan accuracy guidance or audit results
Optionally update API.md or release-draft.md
Commit documentation changes
```

### Dependency Update

Updates dependencies in package-lock.json (and sometimes package.json), typically via automated tools.

**Frequency**: ~2 times per month

**Steps**:
1. Update package-lock.json (and optionally package.json)
2. Commit with a message referencing the dependency and version change

**Files typically involved**:
- `package-lock.json`
- `package.json`

**Example commit sequence**:
```
Update package-lock.json (and optionally package.json)
Commit with a message referencing the dependency and version change
```

### Add New Threat Intel Database Or Rule

Adds a new threat intelligence database (e.g., CVE list) and corresponding rules that reference it.

**Frequency**: ~1 times per month

**Steps**:
1. Add new database file in src/threat-intel/
2. Implement new rule in src/rules/ (e.g., mcp-cve.ts)
3. Update src/rules/index.ts to register new rule
4. Add or update corresponding test in tests/threat-intel/
5. Update package.json if needed

**Files typically involved**:
- `src/threat-intel/cve-database.ts`
- `src/rules/mcp-cve.ts`
- `src/rules/index.ts`
- `tests/threat-intel/cve-database.test.ts`
- `tests/threat-intel/cve-mcp-rules.test.ts`
- `package.json`

**Example commit sequence**:
```
Add new database file in src/threat-intel/
Implement new rule in src/rules/ (e.g., mcp-cve.ts)
Update src/rules/index.ts to register new rule
Add or update corresponding test in tests/threat-intel/
Update package.json if needed
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
