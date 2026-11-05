import { describe, expect, it } from "vitest";
import { assessCounterpartyRisk } from "../../src/security/counterparty-risk-service";
import { evaluateCounterpartyRisk, type CounterpartyRiskDecision } from "../../src/security/counterparty-risk";
import type { CounterpartyRiskCollection } from "../../src/security/collect-counterparty-risk";

const ownerId = "a2d9b5c7-8f3e-4b1a-9c2d-6e7f8a9b0c1d";
const target = "alice.testnet";
const at = "2026-11-03T10:00:00.000Z";

function deps(overrides: Record<string, unknown> = {}) {
  const calls: unknown[][] = [];
  const collection: CounterpartyRiskCollection = {
    network: "testnet",
    accountId: target,
    status: "PARTIAL",
    collectedAt: at,
    decision: evaluateCounterpartyRisk({ accountId: target, evaluatedAt: at, signals: [] }, () => new Date(at)),
  };
  return {
    calls,
    dependencies: {
      findBlocklistRecord: async (...args: unknown[]) => { calls.push(["blocklist", ...args]); return null; },
      countPreviousInteractions: async (...args: unknown[]) => { calls.push(["interactions", ...args]); return 0; },
      collectRisk: async (_accountId: string, options: { previousInteractions: number | null }) => {
        calls.push(["collect", options.previousInteractions]);
        return collection;
      },
      now: () => new Date(at),
      ...overrides,
    },
  };
}

describe("assessCounterpartyRisk", () => {
  it("passes the exact Testnet target and authenticated owner to receipt lookup", async () => {
    const { dependencies, calls } = deps();
    await assessCounterpartyRisk(ownerId, target, dependencies as never);
    expect(calls).toContainEqual(["blocklist", "testnet", target]);
    expect(calls).toContainEqual(["interactions", ownerId, "testnet", target, undefined]);
  });

  it("excludes the proposal being evaluated from its own interaction history", async () => {
    const { dependencies, calls } = deps({ excludeProposalId: "proposal-current" });
    await assessCounterpartyRisk(ownerId, target, dependencies as never);
    expect(calls).toContainEqual(["interactions", ownerId, "testnet", target, "proposal-current"]);
  });

  it("downgrades malformed database rows to unavailable evidence", async () => {
    const { dependencies } = deps({
      findBlocklistRecord: async () => ({ status: "confirmed", evidence_ref: null, reason: "bad", reviewed_at: null, reviewer_owner_id: null }),
    });
    const result = await assessCounterpartyRisk(ownerId, target, dependencies as never);
    expect(result.collection.blocklist).toBe("UNAVAILABLE");
  });

  it("downgrades invalid interaction counts to unavailable evidence", async () => {
    const { dependencies, calls } = deps({ countPreviousInteractions: async () => -1 });
    await assessCounterpartyRisk(ownerId, target, dependencies as never);
    expect(calls).not.toContainEqual(["collect", -1]);
  });

  it("does not call database dependencies with an invalid owner identity", async () => {
    const { dependencies, calls } = deps();
    const result = await assessCounterpartyRisk("not-a-uuid", target, dependencies as never);
    expect(calls).toHaveLength(0);
    expect(result.decision.outcome).toBe("WARN");
  });

  it("fails closed for a malformed runtime target instead of throwing", async () => {
    const { dependencies, calls } = deps();
    const result = await assessCounterpartyRisk(ownerId, null as never, dependencies as never);
    expect(calls).toHaveLength(0);
    expect(result.decision.outcome).toBe("WARN");
  });

  it("fails closed when database or chain dependencies reject", async () => {
    const { dependencies } = deps({
      findBlocklistRecord: async () => { throw new Error("database unavailable"); },
      countPreviousInteractions: async () => { throw new Error("database unavailable"); },
      collectRisk: async () => { throw new Error("chain unavailable"); },
    });
    const result = await assessCounterpartyRisk(ownerId, target, dependencies as never);
    expect(result.decision.outcome).toBe("WARN");
    expect(result.collection).toEqual({ chain: "UNAVAILABLE", blocklist: "UNAVAILABLE", interactions: "UNAVAILABLE" });
  });
});
