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

Follow these commit message conventions based on 207 analyzed commits.

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
feat: add agentshield ECC bundle (.claude/commands/add-or-update-codex-agent-config.md)
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
feat: add agentshield ECC bundle (.claude/commands/add-or-update-ecc-bundle-component.md)
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

**Example commit sequence**:
```
feat: add agentshield ECC bundle (.claude/team/agentshield-team-config.json)
feat: add agentshield ECC bundle (.claude/enterprise/controls.md)
feat: add agentshield ECC bundle (.claude/commands/feature-development.md)
```

### Add Or Update Ecc Bundle Component

Adds or updates a component in the agentshield ECC bundle, such as configuration files, skills, rules, team configs, or tools.

**Frequency**: ~5 times per month

**Steps**:
1. Create or update a relevant markdown or json file under .claude/commands/, .claude/team/, .claude/research/, .claude/rules/, .claude/skills/, .claude/enterprise/, .claude/ecc-tools.json, or .agents/skills/agentshield/
2. Commit the change with a message referencing the ECC bundle and the specific file

**Files typically involved**:
- `.claude/commands/add-or-update-codex-agent-config.md`
- `.claude/commands/add-or-update-ecc-bundle-component.md`
- `.claude/commands/feature-development.md`
- `.claude/commands/feature-development-workflow.md`
- `.claude/commands/add-or-update-command-workflow.md`
- `.claude/commands/add-or-update-team-config.md`
- `.claude/commands/add-or-update-feature-development-workflow.md`
- `.claude/team/agentshield-team-config.json`
- `.claude/research/agentshield-research-playbook.md`
- `.claude/rules/agentshield-guardrails.md`
- `.claude/skills/agentshield/SKILL.md`
- `.claude/enterprise/controls.md`
- `.claude/ecc-tools.json`
- `.claude/identity.json`
- `.agents/skills/agentshield/SKILL.md`
- `.agents/skills/agentshield/agents/openai.yaml`
- `.codex/agents/docs-researcher.toml`
- `.codex/agents/reviewer.toml`
- `.codex/agents/explorer.toml`

**Example commit sequence**:
```
Create or update a relevant markdown or json file under .claude/commands/, .claude/team/, .claude/research/, .claude/rules/, .claude/skills/, .claude/enterprise/, .claude/ecc-tools.json, or .agents/skills/agentshield/
Commit the change with a message referencing the ECC bundle and the specific file
```

### Add Or Update Team Config

Adds or updates the team configuration for agentshield, typically by modifying the agentshield-team-config.json file.

**Frequency**: ~3 times per month

**Steps**:
1. Edit or create .claude/team/agentshield-team-config.json
2. Commit the change with a message referencing ECC bundle and team config

**Files typically involved**:
- `.claude/team/agentshield-team-config.json`

**Example commit sequence**:
```
Edit or create .claude/team/agentshield-team-config.json
Commit the change with a message referencing ECC bundle and team config
```

### Add Or Update Skill Documentation

Adds or updates skill documentation for agentshield, typically by modifying SKILL.md files.

**Frequency**: ~3 times per month

**Steps**:
1. Edit or create .agents/skills/agentshield/SKILL.md or .claude/skills/agentshield/SKILL.md
2. Commit the change with a message referencing ECC bundle and skill

**Files typically involved**:
- `.agents/skills/agentshield/SKILL.md`
- `.claude/skills/agentshield/SKILL.md`

**Example commit sequence**:
```
Edit or create .agents/skills/agentshield/SKILL.md or .claude/skills/agentshield/SKILL.md
Commit the change with a message referencing ECC bundle and skill
```

### Add Or Update Research Playbook

Adds or updates the research playbook for agentshield.

**Frequency**: ~3 times per month

**Steps**:
1. Edit or create .claude/research/agentshield-research-playbook.md
2. Commit the change with a message referencing ECC bundle and research playbook

**Files typically involved**:
- `.claude/research/agentshield-research-playbook.md`

**Example commit sequence**:
```
Edit or create .claude/research/agentshield-research-playbook.md
Commit the change with a message referencing ECC bundle and research playbook
```

### Add Or Update Guardrails

Adds or updates guardrails (rules) for agentshield.

**Frequency**: ~3 times per month

**Steps**:
1. Edit or create .claude/rules/agentshield-guardrails.md
2. Commit the change with a message referencing ECC bundle and guardrails

**Files typically involved**:
- `.claude/rules/agentshield-guardrails.md`

**Example commit sequence**:
```
Edit or create .claude/rules/agentshield-guardrails.md
Commit the change with a message referencing ECC bundle and guardrails
```

### Add Or Update Ecc Tools

Adds or updates the ECC tools configuration for agentshield.

**Frequency**: ~3 times per month

**Steps**:
1. Edit or create .claude/ecc-tools.json
2. Commit the change with a message referencing ECC bundle and tools

**Files typically involved**:
- `.claude/ecc-tools.json`

**Example commit sequence**:
```
Edit or create .claude/ecc-tools.json
Commit the change with a message referencing ECC bundle and tools
```

### Add Or Update Identity

Adds or updates the identity configuration for agentshield.

**Frequency**: ~3 times per month

**Steps**:
1. Edit or create .claude/identity.json
2. Commit the change with a message referencing ECC bundle and identity

**Files typically involved**:
- `.claude/identity.json`

**Example commit sequence**:
```
Edit or create .claude/identity.json
Commit the change with a message referencing ECC bundle and identity
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
