import { describe, expect, it } from "vitest";
import { fingerprintCounterpartyRisk } from "../../src/security/counterparty-risk-review";
import type { CounterpartyRiskDecision } from "../../src/security/counterparty-risk";

const binding = (): Parameters<typeof fingerprintCounterpartyRisk>[0] => ({
  ownerId: "51000000-0000-4000-8000-000000000001",
  policyId: "52000000-0000-4000-8000-000000000001",
  policyVersion: 4,
  proposal: {
    id: "proposal-risk-001",
    agentId: "mandate-chat-prototype",
    actionType: "transfer",
    asset: "NEAR",
    amountAtomic: "1000000000000000000000",
    target: "confirmwithmandate.testnet",
    network: "testnet",
  },
  risk: {
    outcome: "WARN",
    reasons: ["Account age evidence is incomplete."],
    evidence: [{
      name: "account_age",
      status: "unavailable",
      observedAt: "2026-11-05T05:00:00.000Z",
      source: "FastNear Testnet indexed transaction details",
      summary: "Indexed creation evidence is unavailable.",
    }],
    accountId: "confirmwithmandate.testnet",
    evaluatedAt: "2026-11-05T05:00:00.000Z",
    requiresHumanApproval: true,
  } as CounterpartyRiskDecision,
});

describe("fingerprintCounterpartyRisk", () => {
  it("ignores collection timestamps while preserving the proposal and evidence state", async () => {
    const first = binding();
    const later = binding();
    later.risk.evaluatedAt = "2026-11-05T05:04:00.000Z";
    later.risk.evidence[0].observedAt = "2026-11-05T05:04:00.000Z";
    expect(await fingerprintCounterpartyRisk(first)).toBe(await fingerprintCounterpartyRisk(later));
  });

  it("changes when the warning reason or evidence status changes", async () => {
    const first = binding();
    const changedReason = binding();
    changedReason.risk.reasons = ["A different risk reason."];
    const changedEvidence = binding();
    changedEvidence.risk.evidence[0].status = "verified";
    const fingerprint = await fingerprintCounterpartyRisk(first);
    expect(await fingerprintCounterpartyRisk(changedReason)).not.toBe(fingerprint);
    expect(await fingerprintCounterpartyRisk(changedEvidence)).not.toBe(fingerprint);
  });

  it("binds the acknowledgement to owner, proposal and policy version", async () => {
    const first = binding();
    const otherOwner = binding();
    otherOwner.ownerId = "51000000-0000-4000-8000-000000000002";
    const otherProposal = binding();
    otherProposal.proposal.id = "proposal-risk-002";
    const otherPolicy = binding();
    otherPolicy.policyVersion += 1;
    const fingerprint = await fingerprintCounterpartyRisk(first);
    expect(await fingerprintCounterpartyRisk(otherOwner)).not.toBe(fingerprint);
    expect(await fingerprintCounterpartyRisk(otherProposal)).not.toBe(fingerprint);
    expect(await fingerprintCounterpartyRisk(otherPolicy)).not.toBe(fingerprint);
  });

  it("rejects an incomplete or wrong-network binding", async () => {
    const invalid = binding();
    invalid.proposal.network = "mainnet";
    await expect(fingerprintCounterpartyRisk(invalid)).rejects.toThrow(/incomplete/i);
  });
});
