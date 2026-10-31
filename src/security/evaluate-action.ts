import type {
  ActionProposal,
  AuthorizationDecision,
  DecisionReason,
  SecurityPolicy
} from "./types";

const INTEGER_STRING = /^(0|[1-9][0-9]*)$/;

function decision(
  proposal: ActionProposal,
  policy: SecurityPolicy,
  outcome: AuthorizationDecision["outcome"],
  reason: DecisionReason,
  message: string
): AuthorizationDecision {
  return {
    outcome,
    reason,
    policyId: policy.id,
    policyVersion: policy.version,
    proposalId: proposal.id,
    message
  };
}

/**
 * Evaluate an agent's proposed action against an owner-confirmed policy.
 *
 * This function is deliberately deterministic and has no AI, network, wallet,
 * or database dependency. Call it only after authenticating the caller and
 * validating that the agent belongs to the policy owner.
 *
 * The caller must treat every result other than ALLOW as non-executable.
 */
export function evaluateAction(
  proposal: ActionProposal,
  policy: SecurityPolicy
): AuthorizationDecision {
  if (!policy.active) {
    return decision(proposal, policy, "BLOCK", "POLICY_INACTIVE", "This security policy is inactive. No action is authorized.");
  }

  if (
    !proposal.id ||
    !proposal.agentId ||
    !proposal.asset ||
    !proposal.target ||
    !proposal.actionType
  ) {
    return decision(proposal, policy, "BLOCK", "INVALID_PROPOSAL", "The action proposal is missing required information.");
  }

  if (
    !INTEGER_STRING.test(proposal.amountAtomic) ||
    !INTEGER_STRING.test(policy.maxAmountAtomic) ||
    BigInt(policy.maxAmountAtomic) <= 0n ||
    BigInt(proposal.amountAtomic) <= 0n
  ) {
    return decision(proposal, policy, "BLOCK", "INVALID_AMOUNT", "The amount or policy limit is invalid. The action was denied.");
  }

  if (!policy.allowedActionTypes.includes(proposal.actionType)) {
    return decision(proposal, policy, "BLOCK", "ACTION_NOT_ALLOWED", "This type of action is not permitted by the active policy.");
  }

  if (BigInt(proposal.amountAtomic) > BigInt(policy.maxAmountAtomic)) {
    return decision(proposal, policy, "BLOCK", "AMOUNT_LIMIT_EXCEEDED", "The proposed amount exceeds the maximum permitted amount.");
  }

  if (
    policy.allowedRecipients.length === 0 ||
    !policy.allowedRecipients.includes(proposal.target)
  ) {
    return decision(proposal, policy, "BLOCK", "RECIPIENT_NOT_ALLOWED", "The destination is not on the policy's approved recipient list.");
  }

  if (proposal.actionType === "token_approval") {
    if (
      !proposal.approvalAmountAtomic ||
      !INTEGER_STRING.test(proposal.approvalAmountAtomic)
    ) {
      return decision(proposal, policy, "BLOCK", "APPROVAL_AMOUNT_MISSING", "The token approval amount is missing or invalid.");
    }

    if (BigInt(proposal.approvalAmountAtomic) > BigInt(policy.maxAmountAtomic)) {
      return decision(proposal, policy, "BLOCK", "APPROVAL_LIMIT_EXCEEDED", "The requested token allowance exceeds the policy limit.");
    }

    if (policy.requireApprovalForTokenApprovals) {
      return decision(proposal, policy, "REQUIRE_APPROVAL", "TOKEN_APPROVAL_REQUIRES_OWNER", "This token approval requires explicit owner confirmation.");
    }
  }

  if (policy.requireApprovalForAllActions) {
    return decision(proposal, policy, "REQUIRE_APPROVAL", "OWNER_APPROVAL_REQUIRED", "The policy requires owner confirmation before this action can proceed.");
  }

  return decision(proposal, policy, "ALLOW", "POLICY_CHECKS_PASSED", "The action satisfies the configured policy checks.");
}
