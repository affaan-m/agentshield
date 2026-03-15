import type { Rule } from "../types.js";
import { getSkillProfiles, isSkillDefinitionFile } from "../skills/health.js";

function buildMissingFieldsLabel(missingFields: string[]): string {
  if (missingFields.length === 1) {
    return missingFields[0];
  }

  return `${missingFields.slice(0, -1).join(", ")} and ${missingFields.at(-1)}`;
}

export const skillRules: ReadonlyArray<Rule> = [
  {
    id: "skills-observation-feedback-hooks",
    name: "Skill observation and feedback hooks",
    description: "Checks whether SKILL.md files define observation and feedback hooks for self-improvement loops",
    severity: "medium",
    category: "skills",
    check(file, allFiles = []) {
      if (!isSkillDefinitionFile(file)) return [];

      const profile = getSkillProfiles(allFiles).find((entry) => entry.file.path === file.path);
      if (!profile) return [];

      const missing: string[] = [];
      if (!profile.hasObservationHooks) missing.push("observation hooks");
      if (!profile.hasFeedbackHooks) missing.push("feedback hooks");
      if (missing.length === 0) return [];

      return [
        {
          id: `skills-missing-telemetry-${file.path}`,
          severity: "medium",
          category: "skills",
          title: `Skill is missing ${buildMissingFieldsLabel(missing)}`,
          description:
            `The skill "${profile.skillName}" does not define ${buildMissingFieldsLabel(missing)} in SKILL.md. ` +
            "ECC 2.0 self-improving skills need explicit observe/feedback hooks so runs can be inspected and amended safely.",
          file: file.path,
          evidence: buildMissingFieldsLabel(missing),
        },
      ];
    },
  },
  {
    id: "skills-version-rollback-metadata",
    name: "Skill version and rollback metadata",
    description: "Checks whether SKILL.md files define versioning and rollback metadata",
    severity: "medium",
    category: "skills",
    check(file, allFiles = []) {
      if (!isSkillDefinitionFile(file)) return [];

      const profile = getSkillProfiles(allFiles).find((entry) => entry.file.path === file.path);
      if (!profile) return [];

      const missing: string[] = [];
      if (!profile.version) missing.push("version metadata");
      if (!profile.hasRollbackMetadata) missing.push("rollback metadata");
      if (missing.length === 0) return [];

      return [
        {
          id: `skills-missing-governance-${file.path}`,
          severity: "medium",
          category: "skills",
          title: `Skill is missing ${buildMissingFieldsLabel(missing)}`,
          description:
            `The skill "${profile.skillName}" does not define ${buildMissingFieldsLabel(missing)}. ` +
            "Self-amending skills need explicit version and rollback markers so regressions can be evaluated and reversed.",
          file: file.path,
          evidence: buildMissingFieldsLabel(missing),
        },
      ];
    },
  },
];
