/**
 * Core domain types for MANDATE's deterministic authorization engine.
 * Monetary values are integer strings in the asset's smallest unit.
 */

export type ActionType = "transfer" | "token_approval" | "swap" | "contract_call";

export interface ActionProposal {
  id: string;
  agentId: string;
  actionType: ActionType;
  asset: string;
  amountAtomic: string;
  target: string;
  protocol?: string;
  approvalAmountAtomic?: string;
}

export interface SecurityPolicy {
  id: string;
  version: number;
  active: boolean;
  maxAmountAtomic: string;
  allowedRecipients: string[];
  allowedActionTypes: ActionType[];
  requireApprovalForTokenApprovals: boolean;
  requireApprovalForAllActions: boolean;
}

export type DecisionOutcome = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";

export type DecisionReason =
  | "POLICY_INACTIVE"
  | "INVALID_POLICY"
  | "INVALID_PROPOSAL"
  | "INVALID_AMOUNT"
  | "ACTION_NOT_ALLOWED"
  | "AMOUNT_LIMIT_EXCEEDED"
  | "RECIPIENT_NOT_ALLOWED"
  | "APPROVAL_AMOUNT_MISSING"
  | "APPROVAL_LIMIT_EXCEEDED"
  | "OWNER_APPROVAL_REQUIRED"
  | "TOKEN_APPROVAL_REQUIRES_OWNER"
  | "POLICY_CHECKS_PASSED";

export interface AuthorizationDecision {
  outcome: DecisionOutcome;
  reason: DecisionReason;
  policyId: string;
  policyVersion: number;
  proposalId: string;
  message: string;
}
