/**
 * Pro conversion CTA shown at the foot of human-facing reports (terminal,
 * markdown, and — via renderMarkdownReport — the GitHub Action job summary).
 *
 * Deliberately NOT added to JSON or SARIF output: those are machine-consumed and
 * must stay clean. The CTA leads with the privacy + low-noise wedge (the free,
 * local-first, zero-account scanner stays the moat) and points at the real
 * ECC Tools GitHub App. Suppressible via env so CI logs and scripted use can
 * silence it.
 */

const OPT_OUT_ENV_VARS = ["ECC_NO_CTA", "AGENTSHIELD_NO_CTA"] as const;

const PRO_URL = "https://github.com/apps/ecc-tools";

export const PRO_CTA_PLAIN =
  "Scans run locally; nothing leaves your machine. " +
  `Track fleet posture and drift over time with ECC Tools Pro: ${PRO_URL}`;

export const PRO_CTA_MARKDOWN =
  "_Scans run locally; nothing leaves your machine. " +
  `Track fleet posture and drift over time with [ECC Tools Pro](${PRO_URL})._`;

/**
 * True when the operator has opted out of the CTA via an env var. Any non-empty
 * value other than "0" / "false" counts as opt-out.
 */
export function ctaSuppressed(env: NodeJS.ProcessEnv = process.env): boolean {
  return OPT_OUT_ENV_VARS.some((key) => {
    const value = env[key];
    return (
      value !== undefined &&
      value !== "" &&
      value !== "0" &&
      value.toLowerCase() !== "false"
    );
  });
}

/** Plain-text CTA footer lines, or [] when suppressed. */
export function proCtaPlainLines(env: NodeJS.ProcessEnv = process.env): ReadonlyArray<string> {
  return ctaSuppressed(env) ? [] : [PRO_CTA_PLAIN];
}

/** Markdown CTA footer lines, or [] when suppressed. */
export function proCtaMarkdownLines(env: NodeJS.ProcessEnv = process.env): ReadonlyArray<string> {
  return ctaSuppressed(env) ? [] : ["---", "", PRO_CTA_MARKDOWN];
}
