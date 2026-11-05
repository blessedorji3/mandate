import type { AuthorizationDecision } from "./types.ts";
import type { CounterpartyRiskDecision } from "./counterparty-risk.ts";

/**
 * Combines two independent checks without allowing a positive result from one
 * to override a denial or warning from the other. A risk ALLOW is not policy
 * authorization and an effective REQUIRE_APPROVAL is not transaction approval.
 */
export function combinePolicyAndCounterpartyRisk(
  policyDecision: AuthorizationDecision,
  riskDecision: CounterpartyRiskDecision,
): AuthorizationDecision {
  if (policyDecision.outcome === "BLOCK") return policyDecision;

  if (riskDecision.outcome === "BLOCK") {
    return {
      ...policyDecision,
      outcome: "BLOCK",
      reason: "COUNTERPARTY_RISK_BLOCKED",
      message: "Counterparty risk checks blocked this destination. No action is authorized.",
    };
  }

  if (riskDecision.outcome === "WARN") {
    return {
      ...policyDecision,
      outcome: "REQUIRE_APPROVAL",
      reason: "COUNTERPARTY_RISK_REVIEW_REQUIRED",
      message: "Counterparty risk evidence is incomplete or concerning. The proposal is paused for review; this response does not authorize execution.",
    };
  }

  return policyDecision;
}
