/**
 * Core domain types for MANDATE's deterministic authorization engine.
 *
 * Amounts are integer strings in the asset's smallest unit (for example,
 * yoctoNEAR or token base units). Never use floating-point numbers for money.
 */

export type ActionType = "transfer" | "token_approval" | "swap" | "contract_call";

export interface ActionProposal {
  /** Unique identifier supplied by the trusted API, not trusted from an agent. */
  id: string;
  agentId: string;
  actionType: ActionType;
  asset: string;
  /** Positive integer string in the asset's smallest unit. */
  amountAtomic: string;
  /** Destination account, recipient, or contract identifier. */
  target: string;
  /** Optional protocol identifier for protocol-specific restrictions. */
  protocol?: string;
  /** Requested token allowance for token_approval actions, in atomic units. */
  approvalAmountAtomic?: string;
}

export interface SecurityPolicy {
  id: string;
  version: number;
  active: boolean;
  /** Maximum amount per action, expressed in atomic units. */
  maxAmountAtomic: string;
  /** Optional exact-match recipient allowlist. Empty means no recipient is pre-approved. */
  allowedRecipients: string[];
  /** Action types the agent is permitted to propose. */
  allowedActionTypes: ActionType[];
  /** If true, token approvals always require owner confirmation. */
  requireApprovalForTokenApprovals: boolean;
  /** If true, every otherwise-permitted action requires owner confirmation. */
  requireApprovalForAllActions: boolean;
}

export type DecisionOutcome = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";

export type DecisionReason =
  | "POLICY_INACTIVE"
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
  /** Human-readable explanation for the activity feed. */
  message: string;
}
