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

Follow these commit message conventions based on 132 analyzed commits.

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
feat: add agentshield ECC bundle (.claude/commands/add-or-update-security-rule.md)
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

**Frequency**: ~25 times per month

**Steps**:
1. Add feature implementation
2. Add tests for feature
3. Update documentation

**Files typically involved**:
- `src/injection/*`
- `src/opus/*`
- `src/reporter/*`
- `**/*.test.*`

**Example commit sequence**:
```
feat: add AgentShield logo (shield + neural circuit design)
Reduce false positives in example and hook scans
Improve false positive audit workflow docs
```

### Ecc Bundle Component Addition

Adds or updates a component of the agentshield ECC bundle, such as commands, skills, rules, team configs, research playbooks, or agent configs.

**Frequency**: ~10 times per month

**Steps**:
1. Create or update a file in one of the ECC bundle directories (e.g., .claude/commands/, .claude/skills/, .claude/rules/, .claude/team/, .claude/research/, .codex/agents/, .agents/skills/agentshield/).
2. Commit the file with a message in the format: 'feat: add agentshield ECC bundle (<file path>)'.

**Files typically involved**:
- `.claude/commands/*.md`
- `.claude/skills/agentshield/SKILL.md`
- `.claude/rules/*.md`
- `.claude/team/agentshield-team-config.json`
- `.claude/research/*.md`
- `.claude/enterprise/controls.md`
- `.claude/identity.json`
- `.claude/ecc-tools.json`
- `.codex/agents/*.toml`
- `.codex/AGENTS.md`
- `.codex/config.toml`
- `.agents/skills/agentshield/SKILL.md`
- `.agents/skills/agentshield/agents/openai.yaml`
- `.claude/homunculus/instincts/inherited/*.yaml`

**Example commit sequence**:
```
Create or update a file in one of the ECC bundle directories (e.g., .claude/commands/, .claude/skills/, .claude/rules/, .claude/team/, .claude/research/, .codex/agents/, .agents/skills/agentshield/).
Commit the file with a message in the format: 'feat: add agentshield ECC bundle (<file path>)'.
```

### Feature Or Rule Implementation With Tests

Implements a new feature or rule and adds or updates corresponding tests.

**Frequency**: ~3 times per month

**Steps**:
1. Implement or update rule/feature logic in src/rules/*.ts or similar source file.
2. Add or update tests in tests/rules/*.test.ts or tests/skills/*.test.ts.
3. Commit both implementation and tests together.

**Files typically involved**:
- `src/rules/*.ts`
- `tests/rules/*.test.ts`
- `src/skills/*.ts`
- `tests/skills/*.test.ts`

**Example commit sequence**:
```
Implement or update rule/feature logic in src/rules/*.ts or similar source file.
Add or update tests in tests/rules/*.test.ts or tests/skills/*.test.ts.
Commit both implementation and tests together.
```

### Documentation And False Positive Audit Update

Updates documentation and false positive audit files, often together, to refine guidance or document new patterns.

**Frequency**: ~5 times per month

**Steps**:
1. Edit README.md and/or API.md with new documentation or guidance.
2. Edit false-positive-audit.md with new audit findings or templates.
3. Commit documentation and audit updates together.

**Files typically involved**:
- `README.md`
- `API.md`
- `false-positive-audit.md`

**Example commit sequence**:
```
Edit README.md and/or API.md with new documentation or guidance.
Edit false-positive-audit.md with new audit findings or templates.
Commit documentation and audit updates together.
```

### Version Bump And Distribution Rebuild

Bumps the project version and rebuilds distribution files after significant changes.

**Frequency**: ~2 times per month

**Steps**:
1. Update version in package.json (and package-lock.json if present).
2. Rebuild distribution files (dist/action.js, dist/index.js).
3. Commit version bump and rebuilt files together.

**Files typically involved**:
- `package.json`
- `package-lock.json`
- `dist/action.js`
- `dist/index.js`

**Example commit sequence**:
```
Update version in package.json (and package-lock.json if present).
Rebuild distribution files (dist/action.js, dist/index.js).
Commit version bump and rebuilt files together.
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
