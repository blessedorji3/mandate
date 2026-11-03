import { describe, expect, it } from "vitest";
import { assessCounterpartyRisk } from "../../src/security/counterparty-risk-service";
import { evaluateCounterpartyRisk } from "../../src/security/counterparty-risk";

const at = "2026-11-03T10:00:00.000Z";
const account = "alice.testnet";

function deps(overrides: Record<string, unknown> = {}) {
  return {
    findBlocklistRecord: async () => null,
    countPreviousInteractions: async () => 2,
    collectRisk: async (accountId: string, options: {
      previousInteractions: number | null;
      blocklist: { status: "confirmed" | "pending" | "rejected"; evidenceRef: string; reason: string; reviewedAt?: string } | null;
      blocklistLookupStatus: "verified" | "unavailable";
    }) => ({
      network: "testnet" as const,
      accountId,
      status: "PARTIAL" as const,
      collectedAt: at,
      decision: evaluateCounterpartyRisk({
        accountId,
        evaluatedAt: at,
        signals: [],
        previousInteractions: options.previousInteractions,
        blocklist: options.blocklist,
      }),
    }),
    now: () => new Date(at),
    ...overrides,
  };
}

describe("assessCounterpartyRisk", () => {
  it("delegates database evidence to the shared chain collector and remains WARN with incomplete evidence", async () => {
    const result = await assessCounterpartyRisk(account, deps());
    expect(result.decision.outcome).toBe("WARN");
    expect(result.collection).toEqual({ chain: "PARTIAL", blocklist: "NOT_FOUND", interactions: "VERIFIED" });
  });

  it("blocks a confirmed blocklist record only when reviewer identity and timestamp exist", async () => {
    const result = await assessCounterpartyRisk(account, deps({
      findBlocklistRecord: async () => ({
        status: "confirmed", evidence_ref: "https://evidence.example/tx/123",
        reason: "Confirmed malicious drain", reviewed_at: at, reviewer_owner_id: "reviewer-uuid",
      }),
    }));
    expect(result.decision.outcome).toBe("BLOCK");
    expect(result.collection.blocklist).toBe("FOUND");
  });

  it("downgrades a confirmed row missing reviewer metadata to WARN", async () => {
    const result = await assessCounterpartyRisk(account, deps({
      findBlocklistRecord: async () => ({
        status: "confirmed", evidence_ref: "https://evidence.example/tx/123",
        reason: "Confirmed malicious drain", reviewed_at: at, reviewer_owner_id: null,
      }),
    }));
    expect(result.decision.outcome).toBe("WARN");
  });

  it("warns on pending blocklist reports", async () => {
    const result = await assessCounterpartyRisk(account, deps({
      findBlocklistRecord: async () => ({
        status: "pending", evidence_ref: "https://evidence.example/report/123",
        reason: "Suspicious destination report", reviewed_at: null, reviewer_owner_id: null,
      }),
    }));
    expect(result.decision.outcome).toBe("WARN");
  });

  it("warns if blocklist lookup fails instead of treating it as empty", async () => {
    let received: unknown;
    const result = await assessCounterpartyRisk(account, deps({
      findBlocklistRecord: async () => { throw new Error("database unavailable"); },
      collectRisk: async (accountId: string, options: { previousInteractions: number | null; blocklist: null; blocklistLookupStatus: string }) => {
        received = options;
        return {
          network: "testnet" as const, accountId, status: "PARTIAL" as const, collectedAt: at,
          decision: evaluateCounterpartyRisk({ accountId, evaluatedAt: at, signals: [{
            name: "shared_blocklist_lookup", status: options.blocklistLookupStatus === "unavailable" ? "unavailable" : "verified",
            observedAt: at, source: "test", summary: "test",
          }] }),
        };
      },
    }));
    expect(result.decision.outcome).toBe("WARN");
    expect(result.collection.blocklist).toBe("UNAVAILABLE");
    expect(received).toMatchObject({ blocklistLookupStatus: "unavailable" });
  });

  it("warns if previous interaction lookup fails", async () => {
    const result = await assessCounterpartyRisk(account, deps({
      countPreviousInteractions: async () => { throw new Error("database unavailable"); },
    }));
    expect(result.decision.outcome).toBe("WARN");
    expect(result.collection.interactions).toBe("UNAVAILABLE");
  });

  it("fails closed if chain collection throws", async () => {
    const result = await assessCounterpartyRisk(account, deps({
      collectRisk: async () => { throw new Error("RPC and indexer unavailable"); },
    }));
    expect(result.decision.outcome).toBe("WARN");
    expect(result.collection.chain).toBe("UNAVAILABLE");
  });
});
