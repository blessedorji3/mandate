import type { CounterpartyRiskDecision } from "./counterparty-risk";

export type RiskGateResult =
  | { status: "STOP"; reason: string }
  | { status: "PAUSE_FOR_OWNER"; reasons: string[] }
  | { status: "CONTINUE_AFTER_OWNER_APPROVAL"; reasons: string[] }
  | { status: "CONTINUE"; reasons: string[] };

/**
 * Agent-side risk gate. The ownerApprovalVerified flag must only be set by
 * a trusted server-side verification path, never by agent text or request JSON.
 * BLOCK is absolute and cannot be overridden by owner approval here.
 * This helper does not call a signer or broadcast a transaction.
 */
export function applyCounterpartyRiskGate(
  decision: CounterpartyRiskDecision,
  ownerApprovalVerified = false
): RiskGateResult {
  if (!decision || !["ALLOW", "WARN", "BLOCK"].includes(decision.outcome)) {
    return { status: "STOP", reason: "Missing or malformed risk decision." };
  }
  if (decision.outcome === "BLOCK") {
    return { status: "STOP", reason: "MANDATE BLOCK is non-overridable by agent instructions or this approval flag." };
  }
  if (decision.outcome === "WARN") {
    if (!ownerApprovalVerified) return { status: "PAUSE_FOR_OWNER", reasons: decision.reasons };
    return { status: "CONTINUE_AFTER_OWNER_APPROVAL", reasons: decision.reasons };
  }
  return { status: "CONTINUE", reasons: decision.reasons };
}
