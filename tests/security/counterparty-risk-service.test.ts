import { describe, expect, it } from "vitest";
import { assessCounterpartyRisk } from "../../src/security/counterparty-risk-service";
import type { NearCounterpartyEvidence } from "../../src/security/near-counterparty-evidence";
import type { NearTestnetHistoryEvidence } from "../../src/security/near-counterparty-history";

const at = "2026-11-03T10:00:00.000Z";
const current: NearCounterpartyEvidence = {
  status: "PARTIAL", network: "testnet", accountId: "alice.testnet", evaluatedAt: at,
  currentBlockHeight: 100, accountAgeDays: null, lastActivityDays: null,
  isContract: false, contractCodeHash: null, codeChangedRecently: null, previousInteractions: null,
  signals: [{ name: "account_type", status: "verified", observedAt: at, source: "NEAR RPC", summary: "No contract code." }],
};
const history: NearTestnetHistoryEvidence = {
  status: "PARTIAL", network: "testnet", accountId: "alice.testnet", evaluatedAt: at,
  accountCreatedAt: null, accountAgeDays: null, firstObservedActivityAt: at,
  lastActivityAt: at, lastActivityDays: 0,
  signals: [
    { name: "account_age", status: "unavailable", observedAt: at, source: "FastNear", summary: "Creation unverified." },
    { name: "recent_activity", status: "verified", observedAt: at, source: "FastNear", summary: "Recent activity.", value: 0 },
  ],
};
function deps(overrides: Record<string, unknown> = {}) {
  return {
    currentEvidence: async () => current,
    historicalEvidence: async () => history,
    findBlocklistRecord: async () => null,
    countPreviousInteractions: async () => 2,
    now: () => new Date(at),
    ...overrides,
  };
}

describe("assessCounterpartyRisk", () => {
  it("combines live evidence and still warns when account age is unverified", async () => {
    const result = await assessCounterpartyRisk("alice.testnet", deps());
    expect(result.decision.outcome).toBe("WARN");
    expect(result.collection).toEqual({ current: "PARTIAL", history: "PARTIAL", blocklist: "NOT_FOUND", interactions: "VERIFIED" });
    expect(result.decision.reasons.some((reason) => reason.includes("Account age"))).toBe(true);
  });

  it("blocks a confirmed reviewed blocklist record", async () => {
    const result = await assessCounterpartyRisk("alice.testnet", deps({
      findBlocklistRecord: async () => ({
        status: "confirmed", evidence_ref: "https://evidence.example/tx/123",
        reason: "Confirmed malicious drain", reviewed_at: at, reviewer_owner_id: "reviewer-uuid",
      }),
    }));
    expect(result.decision.outcome).toBe("BLOCK");
  });

  it("warns on pending blocklist reports", async () => {
    const result = await assessCounterpartyRisk("alice.testnet", deps({
      findBlocklistRecord: async () => ({
        status: "pending", evidence_ref: "https://evidence.example/report/123",
        reason: "Suspicious destination report", reviewed_at: null, reviewer_owner_id: null,
      }),
    }));
    expect(result.decision.outcome).toBe("WARN");
  });

  it("warns if blocklist lookup fails instead of treating it as empty", async () => {
    const result = await assessCounterpartyRisk("alice.testnet", deps({
      findBlocklistRecord: async () => { throw new Error("database unavailable"); },
    }));
    expect(result.decision.outcome).toBe("WARN");
    expect(result.collection.blocklist).toBe("UNAVAILABLE");
  });

  it("warns if previous interaction lookup fails", async () => {
    const result = await assessCounterpartyRisk("alice.testnet", deps({
      countPreviousInteractions: async () => { throw new Error("database unavailable"); },
    }));
    expect(result.decision.outcome).toBe("WARN");
    expect(result.collection.interactions).toBe("UNAVAILABLE");
  });

  it("warns if either chain evidence collector fails", async () => {
    const result = await assessCounterpartyRisk("alice.testnet", deps({
      currentEvidence: async () => { throw new Error("RPC down"); },
      historicalEvidence: async () => { throw new Error("indexer down"); },
    }));
    expect(result.decision.outcome).toBe("WARN");
    expect(result.collection.current).toBe("UNAVAILABLE");
    expect(result.collection.history).toBe("UNAVAILABLE");
  });

  it("never treats an unreviewed confirmed row as BLOCK", async () => {
    const result = await assessCounterpartyRisk("alice.testnet", deps({
      findBlocklistRecord: async () => ({
        status: "confirmed", evidence_ref: "https://evidence.example/tx/123",
        reason: "Confirmed malicious drain", reviewed_at: null, reviewer_owner_id: null,
      }),
    }));
    expect(result.decision.outcome).toBe("WARN");
  });
});
