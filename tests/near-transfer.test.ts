import { describe, expect, it } from "vitest";
import { MANDATE_TESTNET_TRANSFER, validateMandateTestnetTransfer } from "../src/security/near-transfer";
import type { AuthorizationDecision } from "../src/security/types";

const account = "sender.testnet";
const allowed: AuthorizationDecision = {
  outcome: "ALLOW",
  reason: "POLICY_CHECKS_PASSED",
  policyId: "policy-1",
  policyVersion: 1,
  proposalId: "near-test-1",
  message: "Allowed"
};
const intent = {
  network: "testnet",
  signerId: account,
  receiverId: MANDATE_TESTNET_TRANSFER.receiverId,
  asset: "NEAR",
  amountAtomic: MANDATE_TESTNET_TRANSFER.amountAtomic,
  actionType: "transfer"
};

describe("MANDATE NEAR test transfer gate", () => {
  it("accepts only the exact confirmed testnet transfer with an ALLOW decision", () => {
    expect(validateMandateTestnetTransfer(intent, allowed, account)).toEqual({ ok: true });
  });

  it.each([
    ["mainnet", "network"],
    ["attacker.testnet", "signerId"],
    ["attacker.testnet", "receiverId"],
    ["1", "amountAtomic"],
    ["wNEAR", "asset"],
    ["contract_call", "actionType"]
  ])("rejects a changed %s (%s)", (value, field) => {
    expect(validateMandateTestnetTransfer(
      { ...intent, [field]: value },
      allowed,
      account
    ).ok).toBe(false);
  });

  it("rejects a signer that differs from the connected account", () => {
    expect(validateMandateTestnetTransfer(intent, allowed, "other.testnet").ok).toBe(false);
  });

  it("rejects a missing connected wallet", () => {
    expect(validateMandateTestnetTransfer(intent, allowed, null).ok).toBe(false);
  });

  it.each(["BLOCK", "REQUIRE_APPROVAL"] as const)("never executes %s decisions", (outcome) => {
    expect(validateMandateTestnetTransfer(
      intent,
      { ...allowed, outcome },
      account
    ).ok).toBe(false);
  });
});
