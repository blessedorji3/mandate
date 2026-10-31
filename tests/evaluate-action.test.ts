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
    const result = evaluateAction({ ...proposal, actionType: "token_approval", approvalAmountAtomic: "500" }, policy);
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
    expect(result.reason).toBe("INVALID_PROPOSAL");
  });

  it("blocks action types not listed in policy", () => {
    const result = evaluateAction({ ...proposal, actionType: "swap" }, policy);
    expect(result.outcome).toBe("BLOCK");
    expect(result.reason).toBe("ACTION_NOT_ALLOWED");
  });

  it("blocks swaps even if a policy lists them as allowed", () => {
    const result = evaluateAction(
      { ...proposal, actionType: "swap" },
      { ...policy, allowedActionTypes: ["transfer", "token_approval", "swap"] }
    );
    expect(result.outcome).toBe("BLOCK");
    expect(result.reason).toBe("ACTION_NOT_SUPPORTED");
  });

  it("blocks arbitrary contract calls even if a policy lists them as allowed", () => {
    const result = evaluateAction(
      { ...proposal, actionType: "contract_call" },
      { ...policy, allowedActionTypes: ["transfer", "token_approval", "contract_call"] }
    );
    expect(result.outcome).toBe("BLOCK");
    expect(result.reason).toBe("ACTION_NOT_SUPPORTED");
  });

  it("requires approval when the whole policy is configured for approval", () => {
    const result = evaluateAction(proposal, { ...policy, requireApprovalForAllActions: true });
    expect(result.outcome).toBe("REQUIRE_APPROVAL");
    expect(result.reason).toBe("OWNER_APPROVAL_REQUIRED");
  });

  it("blocks null and non-object proposals without throwing", () => {
    expect(evaluateAction(null, policy).reason).toBe("INVALID_PROPOSAL");
    expect(evaluateAction("proposal", policy).outcome).toBe("BLOCK");
  });

  it("blocks malformed policies without throwing", () => {
    expect(evaluateAction(proposal, null).reason).toBe("INVALID_POLICY");
    expect(evaluateAction(proposal, { ...policy, allowedRecipients: "alice.near" }).outcome).toBe("BLOCK");
    expect(evaluateAction(proposal, { ...policy, maxAmountAtomic: "not-a-number" }).reason).toBe("INVALID_POLICY");
  });

  it("blocks zero amounts", () => {
    expect(evaluateAction({ ...proposal, amountAtomic: "0" }, policy).reason).toBe("INVALID_AMOUNT");
  });

  it("blocks zero or malformed token allowances", () => {
    expect(evaluateAction({ ...proposal, actionType: "token_approval", approvalAmountAtomic: "0" }, policy).reason).toBe("APPROVAL_AMOUNT_MISSING");
    expect(evaluateAction({ ...proposal, actionType: "token_approval", approvalAmountAtomic: "1.2" }, policy).reason).toBe("INVALID_PROPOSAL");
  });

  it("blocks an allowance above the policy limit", () => {
    const result = evaluateAction({ ...proposal, actionType: "token_approval", approvalAmountAtomic: "1001" }, policy);
    expect(result.reason).toBe("APPROVAL_LIMIT_EXCEEDED");
    expect(result.outcome).toBe("BLOCK");
  });

  it("blocks unknown action types at runtime", () => {
    expect(evaluateAction({ ...proposal, actionType: "drain_wallet" }, policy).reason).toBe("INVALID_PROPOSAL");
  });

  it("requires a positive safe policy version", () => {
    expect(evaluateAction(proposal, { ...policy, version: 0 }).reason).toBe("INVALID_POLICY");
    expect(evaluateAction(proposal, { ...policy, version: 1.5 }).reason).toBe("INVALID_POLICY");
  });
});
