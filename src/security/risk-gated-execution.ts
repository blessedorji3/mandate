import type { CounterpartyRiskDecision } from "./counterparty-risk.ts";

export type RiskGateResult =
  | { status: "STOP"; reason: string }
  | { status: "PAUSE_FOR_OWNER"; reasons: string[] }
  | { status: "CONTINUE_TO_POLICY_CHECK"; reasons: string[] };

/**
 * Risk is only one independent gate. ALLOW means risk checks are clear and the
 * proposal may continue to the deterministic owner-policy check; it does not
 * authorize execution. WARN always pauses. BLOCK is terminal and non-overridable.
 * Owner approval is intentionally not represented by a caller-supplied boolean.
 */
export function applyCounterpartyRiskGate(
  decision: CounterpartyRiskDecision | null | undefined,
): RiskGateResult {
  if (!decision || !["ALLOW", "WARN", "BLOCK"].includes(decision.outcome) ||
      !Array.isArray(decision.reasons) || decision.reasons.some((reason) => typeof reason !== "string")) {
    return { status: "STOP", reason: "Missing or malformed risk decision." };
  }
  if (decision.outcome === "BLOCK") {
    return { status: "STOP", reason: "MANDATE BLOCK is terminal and cannot be overridden by agent instructions or ordinary owner approval." };
  }
  if (decision.outcome === "WARN") {
    return { status: "PAUSE_FOR_OWNER", reasons: decision.reasons };
  }
  return { status: "CONTINUE_TO_POLICY_CHECK", reasons: decision.reasons };
}
