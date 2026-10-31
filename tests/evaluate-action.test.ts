import { describe, expect, it } from "vitest";
import { evaluateAction } from "../src/security/evaluate-action";
import type { ActionProposal, SecurityPolicy } from "../src/security/types";

const policy: SecurityPolicy = {
  id: "policy-demo",
  version: 1,
  active: true,
  maxAmountAtomic: "1000",
  allowedRecipients: ["alice.near"],
  allowedActionTypes: ["transfer", "token_approval"],
  requireApprovalForTokenApprovals: true,
  requireApprovalForAllActions: false
};

const proposal: ActionProposal = {
  id: "proposal-1",
  agentId: "agent-demo",
  actionType: "transfer",
  asset: "NEAR",
  amountAtomic: "500",
  target: "alice.near"
};

describe("evaluateAction", () => {
  it("allows an action within policy", () => {
    expect(evaluateAction(proposal, policy).outcome).toBe("ALLOW");
  });

  it("blocks an amount above the configured limit", () => {
    const result = evaluateAction({ ...proposal, amountAtomic: "1001" }, policy);
    expect(result.outcome).toBe("BLOCK");
    expect(result.reason).toBe("AMOUNT_LIMIT_EXCEEDED");
  });

  it("blocks an unapproved recipient", () => {
    const result = evaluateAction({ ...proposal, target: "mallory.near" }, policy);
    expect(result.outcome).toBe("BLOCK");
    expect(result.reason).toBe("RECIPIENT_NOT_ALLOWED");
  });

  it("requires owner approval for token allowances", () => {
    const result = evaluateAction({
      ...proposal,
      actionType: "token_approval",
      approvalAmountAtomic: "500"
    }, policy);
    expect(result.outcome).toBe("REQUIRE_APPROVAL");
    expect(result.reason).toBe("TOKEN_APPROVAL_REQUIRES_OWNER");
  });

  it("blocks when the policy is inactive", () => {
    const result = evaluateAction(proposal, { ...policy, active: false });
    expect(result.outcome).toBe("BLOCK");
    expect(result.reason).toBe("POLICY_INACTIVE");
  });

  it("fails closed for malformed amounts", () => {
    const result = evaluateAction({ ...proposal, amountAtomic: "1.5" }, policy);
    expect(result.outcome).toBe("BLOCK");
    expect(result.reason).toBe("INVALID_AMOUNT");
  });

  it("blocks action types not listed in policy", () => {
    const result = evaluateAction({ ...proposal, actionType: "swap" }, policy);
    expect(result.outcome).toBe("BLOCK");
    expect(result.reason).toBe("ACTION_NOT_ALLOWED");
  });

  it("requires approval when the whole policy is configured for approval", () => {
    const result = evaluateAction(proposal, { ...policy, requireApprovalForAllActions: true });
    expect(result.outcome).toBe("REQUIRE_APPROVAL");
    expect(result.reason).toBe("OWNER_APPROVAL_REQUIRED");
  });
});
