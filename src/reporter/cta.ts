/**
 * Pro conversion CTA shown at the foot of human-facing reports (terminal,
 * markdown, and, via renderMarkdownReport, the GitHub Action job summary).
 *
 * Deliberately NOT added to JSON or SARIF output: those are machine-consumed and
 * must stay clean. The CTA leads with the privacy + low-noise wedge (the free,
 * local-first, zero-account scanner stays the moat) and points at the real
 * ECC Tools GitHub App.
 *
 * The CTA is OFF by default and opt-in: it renders only when
 * AGENTSHIELD_CTA or ECC_CTA is set to a truthy value. AGENTSHIELD_NO_CTA /
 * ECC_NO_CTA remain honored as a hard suppress that wins over opt-in, so CI
 * logs and scripted use can silence it regardless of other settings.
 */

const OPT_IN_ENV_VARS = ["ECC_CTA", "AGENTSHIELD_CTA"] as const;
const OPT_OUT_ENV_VARS = ["ECC_NO_CTA", "AGENTSHIELD_NO_CTA"] as const;

const PRO_URL = "https://github.com/apps/ecc-tools";

export const PRO_CTA_PLAIN =
  "Scans run locally; nothing leaves your machine. " +
  `Track fleet posture and drift over time with ECC Tools Pro: ${PRO_URL}`;

export const PRO_CTA_MARKDOWN =
  "_Scans run locally; nothing leaves your machine. " +
  `Track fleet posture and drift over time with [ECC Tools Pro](${PRO_URL})._`;

/** True for any non-empty value other than "0" / "false" (case-insensitive). */
function isTruthy(value: string | undefined): boolean {
  return (
    value !== undefined &&
    value !== "" &&
    value !== "0" &&
    value.toLowerCase() !== "false"
  );
}

/** True when the operator has opted in to the CTA via ECC_CTA / AGENTSHIELD_CTA. */
export function ctaOptedIn(env: NodeJS.ProcessEnv = process.env): boolean {
  return OPT_IN_ENV_VARS.some((key) => isTruthy(env[key]));
}

/** True when the operator has hard-suppressed the CTA via ECC_NO_CTA / AGENTSHIELD_NO_CTA. */
export function ctaSuppressed(env: NodeJS.ProcessEnv = process.env): boolean {
  return OPT_OUT_ENV_VARS.some((key) => isTruthy(env[key]));
}

/** True when the CTA should render: opted in and not suppressed. */
export function ctaEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return ctaOptedIn(env) && !ctaSuppressed(env);
}

/** Plain-text CTA footer lines, or [] when not enabled. */
export function proCtaPlainLines(env: NodeJS.ProcessEnv = process.env): ReadonlyArray<string> {
  return ctaEnabled(env) ? [PRO_CTA_PLAIN] : [];
}

/** Markdown CTA footer lines, or [] when not enabled. */
export function proCtaMarkdownLines(env: NodeJS.ProcessEnv = process.env): ReadonlyArray<string> {
  return ctaEnabled(env) ? ["---", "", PRO_CTA_MARKDOWN] : [];
}
