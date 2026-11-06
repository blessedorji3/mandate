import { describe, expect, it } from "vitest";
import { combinePolicyAndCounterpartyRisk } from "../../src/security/inspection-risk";
import type { AuthorizationDecision } from "../../src/security/types";
import type { CounterpartyRiskDecision } from "../../src/security/counterparty-risk";

const policy: AuthorizationDecision = {
  outcome: "ALLOW",
  reason: "POLICY_CHECKS_PASSED",
  policyId: "policy-1",
  policyVersion: 1,
  proposalId: "proposal-1",
  message: "Policy checks passed.",
};

function risk(outcome: "ALLOW" | "WARN" | "BLOCK"): CounterpartyRiskDecision {
  return {
    outcome,
    reasons: [`risk ${outcome.toLowerCase()}`],
    evidence: [],
    accountId: "alice.testnet",
    evaluatedAt: "2026-11-03T10:00:00.000Z",
    requiresHumanApproval: outcome === "WARN",
  };
}

describe("combinePolicyAndCounterpartyRisk", () => {
  it("preserves policy ALLOW only when the risk result is ALLOW", () => {
    expect(combinePolicyAndCounterpartyRisk(policy, risk("ALLOW"))).toEqual(policy);
  });

  it("maps risk WARN to REQUIRE_APPROVAL without treating it as execution authorization", () => {
    const result = combinePolicyAndCounterpartyRisk(policy, risk("WARN"));
    expect(result.outcome).toBe("REQUIRE_APPROVAL");
    expect(result.reason).toBe("COUNTERPARTY_RISK_REVIEW_REQUIRED");
    expect(result.message).toContain("does not authorize execution");
  });

  it("maps a confirmed risk BLOCK to a terminal policy BLOCK", () => {
    const result = combinePolicyAndCounterpartyRisk(policy, risk("BLOCK"));
    expect(result.outcome).toBe("BLOCK");
    expect(result.reason).toBe("COUNTERPARTY_RISK_BLOCKED");
  });

  it("never lets risk ALLOW override an owner-policy BLOCK", () => {
    const blockedPolicy = { ...policy, outcome: "BLOCK" as const, reason: "RECIPIENT_NOT_ALLOWED" as const };
    expect(combinePolicyAndCounterpartyRisk(blockedPolicy, risk("ALLOW"))).toEqual(blockedPolicy);
    expect(combinePolicyAndCounterpartyRisk(blockedPolicy, risk("WARN"))).toEqual(blockedPolicy);
  });

  it("retains ordinary owner-policy approval when risk is ALLOW", () => {
    const approvalPolicy = { ...policy, outcome: "REQUIRE_APPROVAL" as const, reason: "OWNER_APPROVAL_REQUIRED" as const };
    expect(combinePolicyAndCounterpartyRisk(approvalPolicy, risk("ALLOW"))).toEqual(approvalPolicy);
  });
});
