```markdown
# agentshield Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the `agentshield` TypeScript codebase. It covers file naming, import/export styles, commit message conventions, and testing patterns. This guide is designed to help contributors quickly align with the project's established practices and workflows.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `userAgent.ts`, `apiHandler.ts`

### Import Style
- Use **relative imports** for referencing local modules.
  - Example:
    ```typescript
    import { fetchData } from './apiHandler';
    ```

### Export Style
- Use **named exports** for all modules.
  - Example:
    ```typescript
    // In apiHandler.ts
    export function fetchData() { ... }
    ```

### Commit Messages
- Follow the **Conventional Commits** specification.
- Use the `feat` prefix for new features.
  - Example:  
    ```
    feat: add user agent parsing to middleware
    ```
- Average commit message length: ~59 characters.

## Workflows

### Feature Development
**Trigger:** When adding a new feature to the codebase  
**Command:** `/feature-development`

1. Create a new branch for your feature.
2. Implement the feature using camelCase file naming and relative imports.
3. Use named exports for any new modules.
4. Write or update corresponding tests (`*.test.*` files).
5. Commit your changes using the `feat` prefix and a descriptive message.
6. Open a pull request for review.

### Testing
**Trigger:** When verifying code changes or before merging  
**Command:** `/run-tests`

1. Identify or create test files matching the `*.test.*` pattern.
2. Run the test suite using the project's test runner (framework unknown; check project scripts).
3. Ensure all tests pass before merging or submitting a pull request.

## Testing Patterns

- Test files follow the `*.test.*` naming convention (e.g., `apiHandler.test.ts`).
- The testing framework is not specified; check for scripts or documentation in the repository.
- Place tests alongside the code they test or in a dedicated test directory.

**Example Test File:**
```typescript
// apiHandler.test.ts
import { fetchData } from './apiHandler';

describe('fetchData', () => {
  it('should return expected data', () => {
    // test implementation
  });
});
```

## Commands
| Command              | Purpose                                         |
|----------------------|-------------------------------------------------|
| /feature-development | Start the feature development workflow          |
| /run-tests           | Run the test suite for the codebase             |
```
