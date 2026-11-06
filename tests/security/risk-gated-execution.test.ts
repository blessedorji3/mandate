import { describe, expect, it } from "vitest";
import { applyCounterpartyRiskGate } from "../../src/security/risk-gated-execution";
import type { CounterpartyRiskDecision } from "../../src/security/counterparty-risk";

function decision(outcome: "ALLOW" | "WARN" | "BLOCK"): CounterpartyRiskDecision {
  return {
    outcome,
    reasons: ["test reason"],
    evidence: [],
    accountId: "alice.testnet",
    evaluatedAt: "2026-11-03T10:00:00.000Z",
    requiresHumanApproval: outcome === "WARN",
  };
}

describe("applyCounterpartyRiskGate", () => {
  it("moves risk ALLOW only to the separate deterministic policy check", () => {
    expect(applyCounterpartyRiskGate(decision("ALLOW")).status).toBe("CONTINUE_TO_POLICY_CHECK");
  });

  it("pauses WARN for an explicit owner-review workflow", () => {
    expect(applyCounterpartyRiskGate(decision("WARN")).status).toBe("PAUSE_FOR_OWNER");
  });

  it("stops BLOCK with no approval bypass", () => {
    expect(applyCounterpartyRiskGate(decision("BLOCK")).status).toBe("STOP");
  });

  it("stops missing and malformed decisions", () => {
    expect(applyCounterpartyRiskGate(null).status).toBe("STOP");
    expect(applyCounterpartyRiskGate({ ...decision("ALLOW"), reasons: ["ok", 7] } as unknown as CounterpartyRiskDecision).status).toBe("STOP");
  });
});
