import type {
  ActionProposal,
  AuthorizationDecision,
  DecisionReason,
  SecurityPolicy,
  ActionType
} from "./types.ts";

const INTEGER_STRING = /^(0|[1-9][0-9]*)$/;
const ACTION_TYPES = new Set<ActionType>(["transfer", "token_approval", "swap", "contract_call"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isIntegerString(value: unknown): value is string {
  return typeof value === "string" && INTEGER_STRING.test(value);
}

function isPolicy(value: unknown): value is SecurityPolicy {
  if (!isRecord(value)) return false;
  return (
    nonEmptyString(value.id) &&
    Number.isSafeInteger(value.version) &&
    (value.version as number) > 0 &&
    typeof value.active === "boolean" &&
    isIntegerString(value.maxAmountAtomic) &&
    BigInt(value.maxAmountAtomic) > 0n &&
    Array.isArray(value.allowedRecipients) &&
    value.allowedRecipients.every(nonEmptyString) &&
    Array.isArray(value.allowedActionTypes) &&
    value.allowedActionTypes.length > 0 &&
    value.allowedActionTypes.every((item) => typeof item === "string" && ACTION_TYPES.has(item as ActionType)) &&
    typeof value.requireApprovalForTokenApprovals === "boolean" &&
    typeof value.requireApprovalForAllActions === "boolean"
  );
}

function isProposal(value: unknown): value is ActionProposal {
  if (!isRecord(value)) return false;
  return (
    nonEmptyString(value.id) &&
    nonEmptyString(value.agentId) &&
    typeof value.actionType === "string" &&
    ACTION_TYPES.has(value.actionType as ActionType) &&
    nonEmptyString(value.asset) &&
    isIntegerString(value.amountAtomic) &&
    nonEmptyString(value.target) &&
    (value.protocol === undefined || nonEmptyString(value.protocol)) &&
    (value.approvalAmountAtomic === undefined || isIntegerString(value.approvalAmountAtomic))
  );
}

function decision(
  proposal: unknown,
  policy: unknown,
  outcome: AuthorizationDecision["outcome"],
  reason: DecisionReason,
  message: string
): AuthorizationDecision {
  const proposalId = isRecord(proposal) && nonEmptyString(proposal.id) ? proposal.id : "untrusted-proposal";
  const policyId = isRecord(policy) && nonEmptyString(policy.id) ? policy.id : "invalid-policy";
  const policyVersion = isRecord(policy) && Number.isSafeInteger(policy.version) && (policy.version as number) > 0
    ? policy.version as number
    : 0;

  return { outcome, reason, policyId, policyVersion, proposalId, message };
}

/**
 * Deterministic, fail-closed authorization. Inputs are treated as untrusted
 * runtime data even when TypeScript callers provide static types.
 * Only ALLOW may be passed to a future execution adapter.
 */
export function evaluateAction(proposalInput: unknown, policyInput: unknown): AuthorizationDecision {
  if (!isPolicy(policyInput)) {
    return decision(proposalInput, policyInput, "BLOCK", "INVALID_POLICY", "The security policy is malformed or incomplete. No action is authorized.");
  }

  if (!isProposal(proposalInput)) {
    return decision(proposalInput, policyInput, "BLOCK", "INVALID_PROPOSAL", "The action proposal is malformed or missing required information.");
  }

  const policy = policyInput;
  const proposal = proposalInput;

  if (!policy.active) {
    return decision(proposal, policy, "BLOCK", "POLICY_INACTIVE", "This security policy is inactive. No action is authorized.");
  }

  if (!isIntegerString(proposal.amountAtomic) || BigInt(proposal.amountAtomic) <= 0n) {
    return decision(proposal, policy, "BLOCK", "INVALID_AMOUNT", "The action amount must be a positive integer in atomic units.");
  }

  if (!policy.allowedActionTypes.includes(proposal.actionType)) {
    return decision(proposal, policy, "BLOCK", "ACTION_NOT_ALLOWED", "This type of action is not permitted by the active policy.");
  }

  // Swaps and arbitrary contract calls are intentionally disabled until
  // their calldata, token pair, slippage, and protocol semantics are decoded
  // and checked by dedicated action-specific validators.
  if (proposal.actionType === "swap" || proposal.actionType === "contract_call") {
    return decision(proposal, policy, "BLOCK", "ACTION_NOT_SUPPORTED", "This action type is not yet supported by MANDATE's verified inspection rules. No action is authorized.");
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
    if (!isIntegerString(proposal.approvalAmountAtomic) || BigInt(proposal.approvalAmountAtomic) <= 0n) {
      return decision(proposal, policy, "BLOCK", "APPROVAL_AMOUNT_MISSING", "The token approval amount is missing, zero, or invalid.");
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
