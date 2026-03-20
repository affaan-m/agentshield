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

Follow these commit message conventions based on 117 analyzed commits.

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
feat: add agentshield ECC bundle (.claude/commands/add-new-security-rule.md)
```

*Commit message example*

```text
chore: bump version to 1.6.0
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
feat: add agentshield ECC bundle (.claude/commands/test-driven-development.md)
```

*Commit message example*

```text
feat: add agentshield ECC bundle (.claude/commands/feature-development.md)
```

*Commit message example*

```text
feat: add agentshield ECC bundle (.claude/enterprise/controls.md)
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

**Frequency**: ~21 times per month

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
feat: add container escape, package install, time bomb, data harvesting, bind-all, sensitive file, IP detection rules (851 tests, 97 rules)
fix: correct README rule counts to match source (91 rules, not 97)
feat: add new security rules and fix README counts (96 rules, 876 tests)
```

### Test Driven Development

Test-first development workflow (TDD)

**Frequency**: ~4 times per month

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

### Add Or Update Security Rule

Adds or updates a security rule, typically for agent, hook, mcp, permission, or secret scanning.

**Frequency**: ~4 times per month

**Steps**:
1. Edit or add rule implementation in src/rules/{area}.ts (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts)
2. Add or update corresponding tests in tests/rules/{area}.test.ts
3. Optionally update README.md to reflect new rule counts or document the rule
4. Optionally update types in src/types.ts if new rule categories or types are added

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
- `src/types.ts`

**Example commit sequence**:
```
Edit or add rule implementation in src/rules/{area}.ts (e.g., agents.ts, hooks.ts, mcp.ts, permissions.ts, secrets.ts)
Add or update corresponding tests in tests/rules/{area}.test.ts
Optionally update README.md to reflect new rule counts or document the rule
Optionally update types in src/types.ts if new rule categories or types are added
```

### Feature Development Implementation Tests Docs

Implements a new feature or major capability, with code, tests, and documentation.

**Frequency**: ~2 times per month

**Steps**:
1. Implement feature in src/ and supporting files (may touch multiple modules)
2. Add or update tests in tests/ (unit, integration, or new test files)
3. Update dist/ files (action.js, index.js) if build artifacts are committed
4. Update documentation in README.md or other docs
5. Update types in src/types.ts if needed
6. Optionally update package.json version

**Files typically involved**:
- `src/**/*.ts`
- `tests/**/*.test.ts`
- `dist/action.js`
- `dist/index.js`
- `README.md`
- `src/types.ts`
- `package.json`

**Example commit sequence**:
```
Implement feature in src/ and supporting files (may touch multiple modules)
Add or update tests in tests/ (unit, integration, or new test files)
Update dist/ files (action.js, index.js) if build artifacts are committed
Update documentation in README.md or other docs
Update types in src/types.ts if needed
Optionally update package.json version
```

### Ecc Bundle Onboarding

Adds a new ECC bundle or onboarding configuration for AgentShield, typically for documentation, team config, or skills.

**Frequency**: ~1 times per month

**Steps**:
1. Add new file(s) under .claude/, .codex/, or .agents/skills/agentshield/
2. Commit with message referencing ECC bundle addition

**Files typically involved**:
- `.claude/commands/*.md`
- `.claude/enterprise/*.md`
- `.claude/team/*.json`
- `.claude/research/*.md`
- `.claude/rules/*.md`
- `.claude/homunculus/instincts/inherited/*.yaml`
- `.codex/agents/*.toml`
- `.codex/AGENTS.md`
- `.codex/config.toml`
- `.claude/identity.json`
- `.agents/skills/agentshield/agents/*.yaml`
- `.agents/skills/agentshield/SKILL.md`
- `.claude/skills/agentshield/SKILL.md`
- `.claude/ecc-tools.json`

**Example commit sequence**:
```
Add new file(s) under .claude/, .codex/, or .agents/skills/agentshield/
Commit with message referencing ECC bundle addition
```

### False Positive Audit And Docs Update

Performs a false positive audit and updates related documentation.

**Frequency**: ~2 times per month

**Steps**:
1. Edit false-positive-audit.md with new findings or patterns
2. Update README.md and/or API.md to reflect audit results or guidance
3. Optionally update code in src/rules/ or tests/ to reduce false positives

**Files typically involved**:
- `false-positive-audit.md`
- `README.md`
- `API.md`
- `src/rules/*.ts`
- `tests/rules/*.test.ts`

**Example commit sequence**:
```
Edit false-positive-audit.md with new findings or patterns
Update README.md and/or API.md to reflect audit results or guidance
Optionally update code in src/rules/ or tests/ to reduce false positives
```

### Version Bump And Release

Bumps the package version and prepares for a new release.

**Frequency**: ~1 times per month

**Steps**:
1. Update version in package.json (and optionally src/index.ts)
2. Optionally update package-lock.json
3. Commit with message indicating version bump

**Files typically involved**:
- `package.json`
- `package-lock.json`
- `src/index.ts`

**Example commit sequence**:
```
Update version in package.json (and optionally src/index.ts)
Optionally update package-lock.json
Commit with message indicating version bump
```

### Dependency Update Via Dependabot

Updates dependencies (e.g., rollup, minimatch) via automated PRs (Dependabot).

**Frequency**: ~1 times per month

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
