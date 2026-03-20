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

Follow these commit message conventions based on 177 analyzed commits.

### Commit Style: Conventional Commits

### Prefixes Used

- `feat`
- `chore`
- `fix`
- `docs`

### Message Guidelines

- Average message length: ~68 characters
- Keep first line concise and descriptive
- Use imperative mood ("Add feature" not "Added feature")


*Commit message example*

```text
feat: add agentshield ECC bundle (.claude/commands/add-or-update-team-config.md)
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
feat: add agentshield ECC bundle (.claude/commands/add-or-update-feature-development-workflow.md)
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

**Frequency**: ~30 times per month

**Steps**:
1. Add feature implementation
2. Add tests for feature
3. Update documentation

**Files typically involved**:
- `.claude/commands/*`
- `**/*.test.*`

**Example commit sequence**:
```
feat: add agentshield ECC bundle (.claude/team/agentshield-team-config.json)
feat: add agentshield ECC bundle (.claude/commands/feature-development.md)
feat: add agentshield ECC bundle (.claude/enterprise/controls.md)
```

### Add Or Update Command Workflow

Adds or updates a command workflow documentation for agentshield ECC bundle.

**Frequency**: ~6 times per month

**Steps**:
1. Create or update a markdown file in .claude/commands/ with the workflow details.
2. Commit the file with a message referencing the workflow.

**Files typically involved**:
- `.claude/commands/*.md`

**Example commit sequence**:
```
Create or update a markdown file in .claude/commands/ with the workflow details.
Commit the file with a message referencing the workflow.
```

### Feature Development Workflow

Documents or implements feature development workflows, including test-driven development and feature implementation.

**Frequency**: ~4 times per month

**Steps**:
1. Create or update a markdown file in .claude/commands/ describing the feature development process.
2. Optionally, create related files for test-driven development or feature/rule implementation.
3. Commit the changes.

**Files typically involved**:
- `.claude/commands/feature-development.md`
- `.claude/commands/test-driven-development.md`
- `.claude/commands/feature-or-rule-implementation-with-tests.md`

**Example commit sequence**:
```
Create or update a markdown file in .claude/commands/ describing the feature development process.
Optionally, create related files for test-driven development or feature/rule implementation.
Commit the changes.
```

### Team Config Update

Adds or updates the agentshield team configuration.

**Frequency**: ~5 times per month

**Steps**:
1. Create or update .claude/team/agentshield-team-config.json.
2. Commit the updated configuration file.

**Files typically involved**:
- `.claude/team/agentshield-team-config.json`

**Example commit sequence**:
```
Create or update .claude/team/agentshield-team-config.json.
Commit the updated configuration file.
```

### Research Playbook Update

Adds or updates the research playbook for agentshield.

**Frequency**: ~4 times per month

**Steps**:
1. Create or update .claude/research/agentshield-research-playbook.md.
2. Commit the changes.

**Files typically involved**:
- `.claude/research/agentshield-research-playbook.md`

**Example commit sequence**:
```
Create or update .claude/research/agentshield-research-playbook.md.
Commit the changes.
```

### Guardrails Rule Update

Adds or updates security guardrails or rules for agentshield.

**Frequency**: ~4 times per month

**Steps**:
1. Create or update .claude/rules/agentshield-guardrails.md.
2. Commit the changes.

**Files typically involved**:
- `.claude/rules/agentshield-guardrails.md`

**Example commit sequence**:
```
Create or update .claude/rules/agentshield-guardrails.md.
Commit the changes.
```

### Ecc Tools Update

Adds or updates ECC tools configuration for agentshield.

**Frequency**: ~4 times per month

**Steps**:
1. Create or update .claude/ecc-tools.json.
2. Commit the changes.

**Files typically involved**:
- `.claude/ecc-tools.json`

**Example commit sequence**:
```
Create or update .claude/ecc-tools.json.
Commit the changes.
```

### Skill Documentation Update

Adds or updates SKILL documentation for agentshield in both .agents and .claude directories.

**Frequency**: ~4 times per month

**Steps**:
1. Create or update .agents/skills/agentshield/SKILL.md and/or .claude/skills/agentshield/SKILL.md.
2. Commit the changes.

**Files typically involved**:
- `.agents/skills/agentshield/SKILL.md`
- `.claude/skills/agentshield/SKILL.md`

**Example commit sequence**:
```
Create or update .agents/skills/agentshield/SKILL.md and/or .claude/skills/agentshield/SKILL.md.
Commit the changes.
```

### Identity Update

Adds or updates the identity configuration for agentshield.

**Frequency**: ~4 times per month

**Steps**:
1. Create or update .claude/identity.json.
2. Commit the changes.

**Files typically involved**:
- `.claude/identity.json`

**Example commit sequence**:
```
Create or update .claude/identity.json.
Commit the changes.
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
