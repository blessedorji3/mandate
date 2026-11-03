import { describe, expect, it } from "vitest";
import { evaluateCounterpartyRisk } from "../../src/security/counterparty-risk";

const now = new Date().toISOString();
const complete = {
  accountId: "alice.testnet",
  evaluatedAt: now,
  accountAgeDays: 90,
  lastActivityDays: 2,
  isContract: false,
  previousInteractions: 0,
  signals: [
    { name: "account_age", status: "verified" as const, observedAt: now, source: "NEAR indexer", summary: "Account creation history verified." },
    { name: "recent_activity", status: "verified" as const, observedAt: now, source: "NEAR indexer", summary: "Recent activity history verified." },
    { name: "account_type", status: "verified" as const, observedAt: now, source: "NEAR RPC", summary: "Account type verified." },
    { name: "previous_mandate_interactions", status: "verified" as const, observedAt: now, source: "MANDATE receipts", summary: "Prior MANDATE interaction count verified." },
  ],
};

describe("evaluateCounterpartyRisk", () => {
  it("allows only when every required signal is present, verified and fresh", () => {
    expect(evaluateCounterpartyRisk(complete).outcome).toBe("ALLOW");
  });
  it("warns on account IDs shorter than the NEAR minimum", () => {
    expect(evaluateCounterpartyRisk({ ...complete, accountId: "a" }).outcome).toBe("WARN");
  });
  it("warns when historical evidence is missing", () => {
    expect(evaluateCounterpartyRisk({ ...complete, accountAgeDays: null }).outcome).toBe("WARN");
  });
  it("warns when a required evidence category is absent even if scalar values are supplied", () => {
    expect(evaluateCounterpartyRisk({ ...complete, signals: complete.signals.slice(1) }).outcome).toBe("WARN");
  });
  it("blocks a confirmed blocklist record with review evidence", () => {
    expect(evaluateCounterpartyRisk({
      ...complete,
      blocklist: { status: "confirmed", evidenceRef: "sha256:abc123", reason: "Verified malicious drain contract", reviewedAt: now },
    }).outcome).toBe("BLOCK");
  });
  it("does not block on a pending report", () => {
    expect(evaluateCounterpartyRisk({
      ...complete,
      blocklist: { status: "pending", evidenceRef: "report:123", reason: "Unverified user report" },
    }).outcome).toBe("WARN");
  });
  it("fails closed for malformed input", () => {
    const result = evaluateCounterpartyRisk({ accountId: "alice.testnet", signals: "bad" });
    expect(result.outcome).toBe("WARN");
    expect(result.requiresHumanApproval).toBe(true);
  });
  it("warns when contract history and code-hash evidence are unavailable", () => {
    expect(evaluateCounterpartyRisk({
      ...complete,
      isContract: true,
      contractCodeHash: "hash",
      codeChangedRecently: null,
    }).outcome).toBe("WARN");
  });
  it("warns on stale evidence", () => {
    const stale = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString();
    expect(evaluateCounterpartyRisk({
      ...complete,
      signals: complete.signals.map((signal) => ({ ...signal, observedAt: stale })),
    }).outcome).toBe("WARN");
  });
  it("warns when the evaluation timestamp is stale", () => {
    const stale = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    expect(evaluateCounterpartyRisk({ ...complete, evaluatedAt: stale }).outcome).toBe("WARN");
  });
  it("warns on duplicate evidence names", () => {
    expect(evaluateCounterpartyRisk({
      ...complete,
      signals: [...complete.signals, complete.signals[0]],
    }).outcome).toBe("WARN");
  });
});
