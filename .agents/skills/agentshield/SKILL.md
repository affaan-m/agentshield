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

Follow these commit message conventions based on 147 analyzed commits.

### Commit Style: Conventional Commits

### Prefixes Used

- `feat`
- `chore`
- `fix`
- `docs`

### Message Guidelines

- Average message length: ~67 characters
- Keep first line concise and descriptive
- Use imperative mood ("Add feature" not "Added feature")


*Commit message example*

```text
feat: add agentshield ECC bundle (.claude/commands/feature-or-rule-implementation-with-tests.md)
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
feat: add agentshield ECC bundle (.claude/commands/ecc-bundle-component-addition.md)
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

**Frequency**: ~29 times per month

**Steps**:
1. Add feature implementation
2. Add tests for feature
3. Update documentation

**Files typically involved**:
- `src/rules/*`
- `tests/rules/*`
- `.claude/commands/*`
- `**/*.test.*`

**Example commit sequence**:
```
feat: add CLAUDE.md filesystem permission check (issue #18)
chore: bump version to 1.6.0
feat: add agentshield ECC bundle (.claude/ecc-tools.json)
```

### Add Or Update Ecc Bundle Component

Adds or updates a component of the agentshield ECC bundle, such as commands, rules, skills, team config, or research playbooks.

**Frequency**: ~10 times per month

**Steps**:
1. Create or update a markdown or JSON file in the relevant .claude or .codex subdirectory (e.g., .claude/commands/, .claude/rules/, .claude/skills/, .claude/team/, .claude/research/).
2. Commit the file with a message referencing the ECC bundle and the specific component.

**Files typically involved**:
- `.claude/commands/*.md`
- `.claude/rules/*.md`
- `.claude/skills/agentshield/SKILL.md`
- `.claude/team/agentshield-team-config.json`
- `.claude/research/agentshield-research-playbook.md`
- `.claude/enterprise/controls.md`
- `.claude/identity.json`
- `.claude/ecc-tools.json`
- `.codex/agents/*.toml`
- `.codex/AGENTS.md`
- `.codex/config.toml`
- `.agents/skills/agentshield/SKILL.md`
- `.agents/skills/agentshield/agents/openai.yaml`

**Example commit sequence**:
```
Create or update a markdown or JSON file in the relevant .claude or .codex subdirectory (e.g., .claude/commands/, .claude/rules/, .claude/skills/, .claude/team/, .claude/research/).
Commit the file with a message referencing the ECC bundle and the specific component.
```

### Add Or Update Command Workflow

Adds or updates a command workflow markdown file describing a development or security process.

**Frequency**: ~4 times per month

**Steps**:
1. Create or update a markdown file in .claude/commands/ (e.g., feature-development.md, test-driven-development.md, add-or-update-security-rule.md).
2. Commit the file with a message referencing the workflow.

**Files typically involved**:
- `.claude/commands/feature-development.md`
- `.claude/commands/test-driven-development.md`
- `.claude/commands/add-or-update-security-rule.md`
- `.claude/commands/add-new-security-rule.md`
- `.claude/commands/feature-or-rule-implementation-with-tests.md`

**Example commit sequence**:
```
Create or update a markdown file in .claude/commands/ (e.g., feature-development.md, test-driven-development.md, add-or-update-security-rule.md).
Commit the file with a message referencing the workflow.
```

### Add Or Update Skill Definition

Adds or updates a skill definition for agentshield, including documentation and configuration.

**Frequency**: ~3 times per month

**Steps**:
1. Create or update SKILL.md in .agents/skills/agentshield/ or .claude/skills/agentshield/.
2. Optionally, create or update agent configuration YAML in .agents/skills/agentshield/agents/.
3. Commit the changes with a message referencing the skill.

**Files typically involved**:
- `.agents/skills/agentshield/SKILL.md`
- `.claude/skills/agentshield/SKILL.md`
- `.agents/skills/agentshield/agents/openai.yaml`

**Example commit sequence**:
```
Create or update SKILL.md in .agents/skills/agentshield/ or .claude/skills/agentshield/.
Optionally, create or update agent configuration YAML in .agents/skills/agentshield/agents/.
Commit the changes with a message referencing the skill.
```

### Add Or Update Agent Config

Adds or updates agent configuration TOML files for codex agents.

**Frequency**: ~3 times per month

**Steps**:
1. Create or update the relevant .toml file in .codex/agents/.
2. Commit the file with a message referencing the agent.

**Files typically involved**:
- `.codex/agents/docs-researcher.toml`
- `.codex/agents/reviewer.toml`
- `.codex/agents/explorer.toml`

**Example commit sequence**:
```
Create or update the relevant .toml file in .codex/agents/.
Commit the file with a message referencing the agent.
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
