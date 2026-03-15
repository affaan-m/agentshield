import { basename, dirname, extname } from "node:path";
import YAML from "yaml";
import type { ConfigFile, SkillHealth, SkillHealthSummary } from "../types.js";

export interface SkillProfile {
  readonly skillName: string;
  readonly file: ConfigFile;
  readonly version?: string;
  readonly hasObservationHooks: boolean;
  readonly hasFeedbackHooks: boolean;
  readonly hasRollbackMetadata: boolean;
  readonly historyFiles: ReadonlyArray<ConfigFile>;
  readonly observedRuns: number;
  readonly successRate?: number;
  readonly averageFeedback?: number;
}

interface SkillFrontmatter {
  readonly version?: string;
  readonly metadata?: Record<string, unknown>;
  readonly raw: Record<string, unknown>;
  readonly body: string;
}

interface SkillRunRecord {
  readonly success?: boolean;
  readonly feedback?: number;
}

const HISTORY_SUFFIXES = [
  ".history.json",
  ".observations.json",
  ".observation.json",
  ".feedback.json",
  ".execution-history.json",
  ".metrics.json",
];

export function analyzeSkillHealth(
  files: ReadonlyArray<ConfigFile>
): SkillHealthSummary | undefined {
  const profiles = getSkillProfiles(files);
  if (profiles.length === 0) return undefined;

  const skills: SkillHealth[] = profiles.map((profile) => {
    const score = scoreSkill(profile);
    return {
      skillName: profile.skillName,
      file: profile.file.path,
      version: profile.version,
      hasObservationHooks: profile.hasObservationHooks,
      hasFeedbackHooks: profile.hasFeedbackHooks,
      hasRollbackMetadata: profile.hasRollbackMetadata,
      score,
      status: classifySkillStatus(score),
      observedRuns: profile.observedRuns,
      successRate: profile.successRate,
      averageFeedback: profile.averageFeedback,
      historyFiles: profile.historyFiles.map((file) => file.path),
    };
  });

  const scoredSkills = skills.filter((skill) => typeof skill.score === "number");
  return {
    totalSkills: skills.length,
    instrumentedSkills: skills.filter(
      (skill) => skill.hasObservationHooks && skill.hasFeedbackHooks
    ).length,
    versionedSkills: skills.filter((skill) => Boolean(skill.version)).length,
    rollbackReadySkills: skills.filter((skill) => skill.hasRollbackMetadata).length,
    observedSkills: skills.filter((skill) => skill.observedRuns > 0).length,
    averageScore:
      scoredSkills.length > 0
        ? Math.round(
            scoredSkills.reduce((sum, skill) => sum + (skill.score ?? 0), 0) /
              scoredSkills.length
          )
        : undefined,
    skills,
  };
}

export function getSkillProfiles(
  files: ReadonlyArray<ConfigFile>
): ReadonlyArray<SkillProfile> {
  const skillFiles = files.filter(isSkillDefinitionFile);
  return skillFiles.map((file) => {
    const frontmatter = parseSkillFrontmatter(file.content);
    const historyFiles = getRelatedHistoryFiles(file, files);
    const records = historyFiles.flatMap((historyFile) => parseHistoryFile(historyFile));
    const successfulRuns = records.filter((record) => record.success === true).length;
    const failedRuns = records.filter((record) => record.success === false).length;
    const observedRuns = successfulRuns + failedRuns;
    const feedbackValues = records
      .map((record) => record.feedback)
      .filter((value): value is number => typeof value === "number");

    return {
      skillName: inferSkillName(file, frontmatter.raw),
      file,
      version: extractVersion(frontmatter),
      hasObservationHooks: hasObservationHooks(frontmatter),
      hasFeedbackHooks: hasFeedbackHooks(frontmatter),
      hasRollbackMetadata: hasRollbackMetadata(frontmatter),
      historyFiles,
      observedRuns,
      successRate: observedRuns > 0 ? successfulRuns / observedRuns : undefined,
      averageFeedback:
        feedbackValues.length > 0
          ? Number(
              (
                feedbackValues.reduce((sum, value) => sum + value, 0) /
                feedbackValues.length
              ).toFixed(1)
            )
          : undefined,
    };
  });
}

export function isSkillDefinitionFile(file: ConfigFile): boolean {
  const normalizedPath = file.path.replace(/\\/g, "/").toLowerCase();
  const extension = extname(normalizedPath);
  return file.type === "skill-md" && (extension === ".md" || extension === ".markdown");
}

function parseSkillFrontmatter(content: string): SkillFrontmatter {
  const match = content.match(/^---\s*\n([\s\S]*?)\n---\s*\n?/);
  if (!match) {
    return { raw: {}, body: content };
  }

  try {
    const parsed = YAML.parse(match[1]) as Record<string, unknown> | null;
    const raw = parsed && typeof parsed === "object" ? parsed : {};
    return {
      version: typeof raw.version === "string" ? raw.version : undefined,
      metadata:
        raw.metadata && typeof raw.metadata === "object"
          ? (raw.metadata as Record<string, unknown>)
          : undefined,
      raw,
      body: content.slice(match[0].length),
    };
  } catch {
    return { raw: {}, body: content };
  }
}

function inferSkillName(
  file: ConfigFile,
  frontmatter: Record<string, unknown>
): string {
  if (typeof frontmatter.name === "string" && frontmatter.name.trim().length > 0) {
    return frontmatter.name.trim();
  }

  const stem = basename(file.path, extname(file.path));
  return stem.toLowerCase() === "skill" ? basename(dirname(file.path)) : stem;
}

function extractVersion(frontmatter: SkillFrontmatter): string | undefined {
  if (frontmatter.version) return frontmatter.version;
  const metadataVersion = frontmatter.metadata?.version;
  return typeof metadataVersion === "string" ? metadataVersion : undefined;
}

function hasObservationHooks(frontmatter: SkillFrontmatter): boolean {
  return hasKey(frontmatter, /(?:^|_)(?:observe|observation)(?:_hook|_hooks)?$/) ||
    /(?:^|\n)#{1,6}\s*(?:observe|observation|telemetry)\b/im.test(frontmatter.body) ||
    /\bobservation hooks?\b/i.test(frontmatter.body);
}

function hasFeedbackHooks(frontmatter: SkillFrontmatter): boolean {
  return hasKey(frontmatter, /(?:^|_)feedback(?:_hook|_hooks)?$/) ||
    /(?:^|\n)#{1,6}\s*feedback\b/im.test(frontmatter.body) ||
    /\bfeedback hooks?\b/i.test(frontmatter.body);
}

function hasRollbackMetadata(frontmatter: SkillFrontmatter): boolean {
  return hasKey(frontmatter, /rollback(?:_strategy|_plan|_metadata)?$/) ||
    hasKey(frontmatter, /previous_version$/) ||
    /(?:^|\n)#{1,6}\s*rollback\b/im.test(frontmatter.body);
}

function hasKey(frontmatter: SkillFrontmatter, pattern: RegExp): boolean {
  const stack: unknown[] = [frontmatter.raw];

  while (stack.length > 0) {
    const current = stack.pop();
    if (!current || typeof current !== "object") continue;

    for (const [key, value] of Object.entries(current as Record<string, unknown>)) {
      if (pattern.test(key)) {
        return truthyMetadata(value);
      }

      if (value && typeof value === "object") {
        stack.push(value);
      }
    }
  }

  return false;
}

function truthyMetadata(value: unknown): boolean {
  if (typeof value === "string") return value.trim().length > 0;
  if (typeof value === "number") return true;
  if (typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.length > 0;
  return Boolean(value);
}

function getRelatedHistoryFiles(
  skillFile: ConfigFile,
  files: ReadonlyArray<ConfigFile>
): ReadonlyArray<ConfigFile> {
  const normalizedDir = dirname(skillFile.path).replace(/\\/g, "/");
  const skillStem = basename(skillFile.path, extname(skillFile.path));
  const expectedPrefixes = new Set<string>([
    `${skillStem}.`,
    `${skillStem}-`,
    `${skillStem}_`,
  ]);

  if (skillStem.toLowerCase() === "skill") {
    const parent = basename(normalizedDir);
    expectedPrefixes.add(`${parent}.`);
    expectedPrefixes.add(`${parent}-`);
    expectedPrefixes.add(`${parent}_`);
  }

  return files.filter((file) => {
    if (file === skillFile || file.type !== "skill-md") return false;
    if (dirname(file.path).replace(/\\/g, "/") !== normalizedDir) return false;

    const lowerName = basename(file.path).toLowerCase();
    if (!lowerName.endsWith(".json")) return false;

    return HISTORY_SUFFIXES.some((suffix) => lowerName.endsWith(suffix)) &&
      [...expectedPrefixes].some((prefix) => lowerName.startsWith(prefix.toLowerCase()));
  });
}

function parseHistoryFile(file: ConfigFile): ReadonlyArray<SkillRunRecord> {
  try {
    const parsed = JSON.parse(file.content) as unknown;
    return extractRecords(parsed);
  } catch {
    return [];
  }
}

function extractRecords(value: unknown): ReadonlyArray<SkillRunRecord> {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => normalizeRunRecord(entry));
  }

  if (!value || typeof value !== "object") {
    return [];
  }

  const record = value as Record<string, unknown>;
  const arrays = [
    record.runs,
    record.history,
    record.executions,
    record.observations,
    record.events,
    record.entries,
  ];

  for (const candidate of arrays) {
    if (Array.isArray(candidate)) {
      return candidate.flatMap((entry) => normalizeRunRecord(entry));
    }
  }

  return normalizeRunRecord(record);
}

function normalizeRunRecord(value: unknown): ReadonlyArray<SkillRunRecord> {
  if (!value || typeof value !== "object") {
    return [];
  }

  const record = value as Record<string, unknown>;
  const success = extractSuccess(record);
  const feedback = extractFeedback(record);
  if (typeof success !== "boolean" && typeof feedback !== "number") {
    return [];
  }

  return [{ success, feedback }];
}

function extractSuccess(record: Record<string, unknown>): boolean | undefined {
  for (const key of ["success", "succeeded", "passed"]) {
    if (typeof record[key] === "boolean") {
      return record[key] as boolean;
    }
  }

  const status = [record.status, record.outcome, record.result]
    .find((value) => typeof value === "string");
  if (typeof status !== "string") return undefined;

  const normalized = status.toLowerCase();
  if (["success", "succeeded", "ok", "passed", "completed"].includes(normalized)) {
    return true;
  }
  if (["failure", "failed", "error", "errored", "rollback", "reverted"].includes(normalized)) {
    return false;
  }
  return undefined;
}

function extractFeedback(record: Record<string, unknown>): number | undefined {
  const candidates = [
    record.feedback,
    record.feedbackScore,
    record.rating,
    record.score,
    record.userFeedback,
  ];

  for (const candidate of candidates) {
    const normalized = normalizeFeedback(candidate);
    if (typeof normalized === "number") {
      return normalized;
    }
  }

  return undefined;
}

function normalizeFeedback(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    if (value <= 5) return clampFeedback(value);
    if (value <= 100) return clampFeedback(value / 20);
  }

  if (typeof value === "boolean") {
    return value ? 5 : 1;
  }

  if (!value || typeof value !== "object") {
    return undefined;
  }

  const record = value as Record<string, unknown>;
  if (typeof record.rating === "number") return normalizeFeedback(record.rating);
  if (typeof record.score === "number") return normalizeFeedback(record.score);
  if (typeof record.positive === "boolean") return record.positive ? 5 : 1;
  return undefined;
}

function clampFeedback(value: number): number {
  return Math.max(1, Math.min(5, Number(value.toFixed(1))));
}

function scoreSkill(profile: SkillProfile): number | undefined {
  if (typeof profile.successRate !== "number") return undefined;

  const successScore = profile.successRate * 80;
  const feedbackScore =
    typeof profile.averageFeedback === "number"
      ? (profile.averageFeedback / 5) * 20
      : 0;
  return Math.round(successScore + feedbackScore);
}

function classifySkillStatus(
  score: number | undefined
): SkillHealth["status"] {
  if (typeof score !== "number") return "unobserved";
  if (score >= 85) return "healthy";
  if (score >= 70) return "watch";
  return "at-risk";
}
