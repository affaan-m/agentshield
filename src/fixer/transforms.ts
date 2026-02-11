import type { Finding } from "../types.js";

/**
 * Transform result after applying a fix to file content.
 */
export interface TransformResult {
  readonly content: string;
  readonly applied: boolean;
}

/**
 * Replace a hardcoded secret value with an environment variable reference.
 *
 * Looks for the literal `fix.before` string in the content and replaces it
 * with the `fix.after` value (typically `${SECRET_NAME}`).
 */
export function replaceHardcodedSecret(
  content: string,
  finding: Finding
): TransformResult {
  if (!finding.fix) {
    return { content, applied: false };
  }

  const { before, after } = finding.fix;

  if (!content.includes(before)) {
    return { content, applied: false };
  }

  // Replace only the first occurrence to be safe
  const updatedContent = content.replace(before, after);
  return {
    content: updatedContent,
    applied: updatedContent !== content,
  };
}

/**
 * Replace an overly broad wildcard permission like `Bash(*)` with
 * scoped alternatives like `Bash(git *), Bash(npm *)`.
 *
 * This operates on the JSON string level: it finds the literal `fix.before`
 * text within the file content and replaces it with `fix.after`.
 */
export function tightenWildcardPermission(
  content: string,
  finding: Finding
): TransformResult {
  if (!finding.fix) {
    return { content, applied: false };
  }

  const { before, after } = finding.fix;

  if (!content.includes(before)) {
    return { content, applied: false };
  }

  // For permission tightening, the `before` is a single entry like `Bash(*)`
  // and `after` is the scoped replacement like `Bash(git *), Bash(npm *)`
  const updatedContent = content.replace(before, after);
  return {
    content: updatedContent,
    applied: updatedContent !== content,
  };
}

/**
 * Generic string replacement transform.
 *
 * Used as a fallback for any auto-fixable finding that does not match
 * a specialized transform. Replaces `fix.before` with `fix.after`.
 */
export function applyGenericTransform(
  content: string,
  finding: Finding
): TransformResult {
  if (!finding.fix) {
    return { content, applied: false };
  }

  const { before, after } = finding.fix;

  if (!content.includes(before)) {
    return { content, applied: false };
  }

  const updatedContent = content.replace(before, after);
  return {
    content: updatedContent,
    applied: updatedContent !== content,
  };
}

/**
 * Select and apply the appropriate transform for a finding.
 *
 * Routes to specialized transforms based on the finding category,
 * falling back to the generic transform.
 */
export function applyTransform(
  content: string,
  finding: Finding
): TransformResult {
  switch (finding.category) {
    case "secrets":
      return replaceHardcodedSecret(content, finding);
    case "permissions":
      return tightenWildcardPermission(content, finding);
    default:
      return applyGenericTransform(content, finding);
  }
}
