import { describe, expect, it } from "vitest";
import {
  renderPolicyJobSummary,
  statusForPolicyEvaluation,
} from "../src/action-policy.js";
import type { PolicyEvaluation } from "../src/policy/index.js";

function makeEvaluation(
  overrides: Partial<PolicyEvaluation> = {}
): PolicyEvaluation {
  return {
    policyName: "Enterprise Policy",
    policyPack: "enterprise",
    owners: ["security@example.com"],
    passed: true,
    violations: [],
    exceptionsApplied: [],
    score: 88,
    minScore: 75,
    ...overrides,
  };
}

describe("action policy helpers", () => {
  it("maps a passing policy evaluation to compliant", () => {
    expect(statusForPolicyEvaluation(makeEvaluation())).toBe("compliant");
  });

  it("maps a failing policy evaluation to non-compliant", () => {
    expect(
      statusForPolicyEvaluation(makeEvaluation({
        passed: false,
        violations: [
          {
            rule: "min_score",
            severity: "high",
            description: "Score is too low.",
            expected: "Score >= 90",
            actual: "Score = 70",
          },
        ],
      }))
    ).toBe("non-compliant");
  });

  it("renders policy results for the GitHub job summary", () => {
    const summary = renderPolicyJobSummary(makeEvaluation({
      passed: false,
      exceptionsApplied: [
        {
          id: "AS-EX-001",
          rule: "required_hooks",
          owner: "security@example.com",
          reason: "Migration window",
          expiresAt: "2026-06-30T23:59:59.000Z",
          violation: "Missing hook",
        },
      ],
      violations: [
        {
          rule: "min_score",
          severity: "high",
          description: "Score is too low.",
          expected: "Score >= 90",
          actual: "Score = 70",
        },
      ],
    }));

    expect(summary).toContain("## AgentShield Organization Policy");
    expect(summary).toContain("- Status: non-compliant");
    expect(summary).toContain("- Policy pack: enterprise");
    expect(summary).toContain("- Owners: security@example.com");
    expect(summary).toContain("### Policy Violations");
    expect(summary).toContain("min_score (high): Score is too low.");
    expect(summary).toContain("### Exceptions Applied");
    expect(summary).toContain("AS-EX-001");
  });

  it("renders exception lifecycle audit counts for branch protection evidence", () => {
    const summary = renderPolicyJobSummary(makeEvaluation({
      exceptionSummary: {
        total: 3,
        active: 2,
        expiringSoon: 1,
        expired: 1,
        entries: [
          {
            id: "AS-EX-SOON",
            rule: "min_score",
            owner: "security@example.com",
            reason: "Migration window",
            expiresAt: "2026-05-15T00:00:00.000Z",
            status: "expiring_soon",
            daysUntilExpiry: 3,
          },
          {
            id: "AS-EX-OLD",
            rule: "banned_tools",
            owner: "security@example.com",
            reason: "Expired exception",
            expiresAt: "2026-05-01T00:00:00.000Z",
            status: "expired",
            daysUntilExpiry: -11,
            ticket: "SEC-999",
          },
        ],
      },
    }));

    expect(summary).toContain("- Exceptions: 3 total, 2 active, 1 expiring soon, 1 expired");
    expect(summary).toContain("### Exception Audit");
    expect(summary).toContain("AS-EX-SOON (min_score) status=expiring_soon owner=security@example.com expires=2026-05-15T00:00:00.000Z days=3");
    expect(summary).toContain("AS-EX-OLD (banned_tools) status=expired owner=security@example.com expires=2026-05-01T00:00:00.000Z days=-11 ticket=SEC-999");
  });
});
