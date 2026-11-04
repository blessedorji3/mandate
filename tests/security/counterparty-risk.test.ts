import { describe, expect, it } from "vitest";
import { evaluateCounterpartyRisk, type RiskSignal } from "../../src/security/counterparty-risk";

const accountId = "alice.testnet";
const at = "2026-11-03T10:00:00.000Z";
const reviewerId = "a2d9b5c7-8f3e-4b1a-9c2d-6e7f8a9b0c1d";

function completeSignals(): RiskSignal[] {
  return [
    { name: "account_age", status: "verified", observedAt: at, source: "FastNear Testnet indexed transaction details", summary: "CreateAccount transaction verified.", value: 90 },
    { name: "recent_activity", status: "verified", observedAt: at, source: "FastNear Testnet indexed account history", summary: "Newest indexed activity verified.", value: 2 },
    { name: "account_type", status: "verified", observedAt: at, source: "NEAR Testnet RPC view_account", summary: "Current account type verified.", value: "account" },
    { name: "previous_mandate_interactions", status: "verified", observedAt: at, source: "MANDATE authorization receipts", summary: "Owner-scoped receipt count verified.", value: 0 },
    { name: "shared_blocklist_lookup", status: "verified", observedAt: at, source: "MANDATE reviewed blocklist", summary: "Complete lookup returned no active report.", value: "clear" },
  ];
}

function completeInput(overrides: Record<string, unknown> = {}) {
  return {
    accountId,
    evaluatedAt: at,
    accountAgeDays: 90,
    lastActivityDays: 2,
    isContract: false,
    contractCodeHash: null,
    codeChangedRecently: null,
    previousInteractions: 0,
    signals: completeSignals(),
    blocklist: null,
    ...overrides,
  };
}

const fixedNow = () => new Date(at);

describe("evaluateCounterpartyRisk", () => {
  it("returns ALLOW only when required signals and metric values match", () => {
    const result = evaluateCounterpartyRisk(completeInput(), fixedNow);
    expect(result.outcome).toBe("ALLOW");
    expect(result.requiresHumanApproval).toBe(false);
  });

  it("warns when a required signal is missing", () => {
    const result = evaluateCounterpartyRisk(completeInput({ signals: completeSignals().slice(1) }), fixedNow);
    expect(result.outcome).toBe("WARN");
    expect(result.requiresHumanApproval).toBe(true);
  });

  it("warns when a supplied scalar does not match its evidence signal", () => {
    const result = evaluateCounterpartyRisk(completeInput({ accountAgeDays: 999 }), fixedNow);
    expect(result.outcome).toBe("WARN");
    expect(result.reasons.join(" ")).toContain("matching historical creation evidence");
  });

  it("rejects fractional or negative day metrics", () => {
    expect(evaluateCounterpartyRisk(completeInput({ accountAgeDays: 1.5 }), fixedNow).outcome).toBe("WARN");
    expect(evaluateCounterpartyRisk(completeInput({ lastActivityDays: -1 }), fixedNow).outcome).toBe("WARN");
  });

  it("warns on evidence from an unexpected source", () => {
    const signals = completeSignals();
    signals[0] = { ...signals[0], source: "Unverified browser text" };
    expect(evaluateCounterpartyRisk(completeInput({ signals }), fixedNow).outcome).toBe("WARN");
  });

  it("warns on duplicate signals", () => {
    const signals = completeSignals();
    signals.push({ ...signals[0] });
    expect(evaluateCounterpartyRisk(completeInput({ signals }), fixedNow).outcome).toBe("WARN");
  });

  it("warns on stale and future evidence timestamps", () => {
    const stale = completeSignals().map((signal) => ({ ...signal, observedAt: "2026-11-01T00:00:00.000Z" }));
    const future = completeSignals().map((signal) => ({ ...signal, observedAt: "2026-11-03T10:02:00.000Z" }));
    expect(evaluateCounterpartyRisk(completeInput({ signals: stale }), fixedNow).outcome).toBe("WARN");
    expect(evaluateCounterpartyRisk(completeInput({ signals: future }), fixedNow).outcome).toBe("WARN");
  });

  it("warns when the evaluation itself is stale or too far in the future", () => {
    expect(evaluateCounterpartyRisk(completeInput({ evaluatedAt: "2026-11-03T09:00:00.000Z" }), fixedNow).outcome).toBe("WARN");
    expect(evaluateCounterpartyRisk(completeInput({ evaluatedAt: "2026-11-03T10:01:00.000Z" }), fixedNow).outcome).toBe("WARN");
  });

  it("warns for malformed account IDs and malformed runtime payloads", () => {
    expect(evaluateCounterpartyRisk(completeInput({ accountId: "bad..id" }), fixedNow).outcome).toBe("WARN");
    expect(evaluateCounterpartyRisk({ accountId, signals: "not-an-array" }, fixedNow).outcome).toBe("WARN");
    expect(evaluateCounterpartyRisk(null, fixedNow).outcome).toBe("WARN");
  });

  it("warns on very young accounts and long-inactive accounts", () => {
    const youngSignals = completeSignals().map((signal) => signal.name === "account_age" ? { ...signal, value: 1 } : signal);
    const inactiveSignals = completeSignals().map((signal) => signal.name === "recent_activity" ? { ...signal, value: 181 } : signal);
    expect(evaluateCounterpartyRisk(completeInput({ accountAgeDays: 1, signals: youngSignals }), fixedNow).outcome).toBe("WARN");
    expect(evaluateCounterpartyRisk(completeInput({ lastActivityDays: 181, signals: inactiveSignals }), fixedNow).outcome).toBe("WARN");
  });

  it("warns on a pending report but never treats it as a confirmed block", () => {
    const signals = completeSignals().map((signal) =>
      signal.name === "shared_blocklist_lookup" ? { ...signal, value: "pending" } : signal);
    const result = evaluateCounterpartyRisk(completeInput({
      signals,
      blocklist: { status: "pending", evidenceRef: "https://example.test/report/1", reason: "Unreviewed report" },
    }), fixedNow);
    expect(result.outcome).toBe("WARN");
  });

  it("blocks only a confirmed record with evidence, reviewer UUID and review timestamp", () => {
    const signals = completeSignals().map((signal) =>
      signal.name === "shared_blocklist_lookup" ? { ...signal, value: "confirmed" } : signal);
    const result = evaluateCounterpartyRisk(completeInput({
      signals,
      blocklist: {
        status: "confirmed",
        evidenceRef: "sha256:" + "a".repeat(64),
        reason: "Reviewed malicious counterparty",
        reviewerId,
        reviewedAt: at,
      },
    }), fixedNow);
    expect(result.outcome).toBe("BLOCK");
    expect(result.requiresHumanApproval).toBe(false);
  });

  it("does not BLOCK a confirmed record missing reviewer attribution", () => {
    const signals = completeSignals().map((signal) =>
      signal.name === "shared_blocklist_lookup" ? { ...signal, value: "confirmed" } : signal);
    const result = evaluateCounterpartyRisk(completeInput({
      signals,
      blocklist: {
        status: "confirmed",
        evidenceRef: "https://example.test/evidence/1",
        reason: "Reported malicious destination",
        reviewedAt: at,
      },
    }), fixedNow);
    expect(result.outcome).toBe("WARN");
  });

  it("warns when blocklist lookup reports confirmed without a review record", () => {
    const signals = completeSignals().map((signal) =>
      signal.name === "shared_blocklist_lookup" ? { ...signal, value: "confirmed" } : signal);
    expect(evaluateCounterpartyRisk(completeInput({ signals }), fixedNow).outcome).toBe("WARN");
  });

  it("keeps contract counterparties at WARN while code-change history is unavailable", () => {
    const hash = "FDrh13CdfGPXsmwUpZLfkZCoXWfpQmaFGj4zYWc1qfh";
    const signals = [
      ...completeSignals().map((signal) => signal.name === "account_type" ? { ...signal, value: "contract" } : signal),
      { name: "contract_code_hash" as const, status: "verified" as const, observedAt: at, source: "NEAR Testnet RPC view_account", summary: "Current contract code hash verified.", value: hash },
      { name: "contract_code_history" as const, status: "unavailable" as const, observedAt: at, source: "NEAR Testnet historical state", summary: "Historical code changes unavailable." },
    ];
    const result = evaluateCounterpartyRisk(completeInput({
      isContract: true,
      contractCodeHash: hash,
      codeChangedRecently: null,
      signals,
    }), fixedNow);
    expect(result.outcome).toBe("WARN");
    expect(result.reasons.join(" ")).toContain("Historical contract code changes");
  });

  it("does not turn a risk ALLOW into owner-policy authorization", () => {
    const result = evaluateCounterpartyRisk(completeInput(), fixedNow);
    expect(result.outcome).toBe("ALLOW");
    expect(result.reasons.join(" ")).not.toContain("policy authorized");
  });
});
