import { describe, expect, it } from "vitest";
import { collectNearTestnetHistory } from "../../src/security/near-counterparty-history";

const now = () => new Date("2026-11-03T10:00:00.000Z");
const account = "alice.testnet";
const oldHash = "A".repeat(44);
const newHash = "B".repeat(44);

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function historyRow(hash: string, timestamp: string) {
  return {
    account_id: account,
    transaction_hash: hash,
    tx_block_timestamp: timestamp,
    tx_block_height: 100,
  };
}

describe("collectNearTestnetHistory", () => {
  it("verifies recent activity but does not confuse first observed activity with account creation", async () => {
    const fetchMock = async (url: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(url).endsWith("/v0/account")) {
        return response({
          account_txs: [body.desc ? historyRow(newHash, "2026-11-02T10:00:00.000Z") : historyRow(oldHash, "2026-10-01T10:00:00.000Z")],
          txs_count: 2,
          resume_token: null,
        });
      }
      return response({ transactions: [{ transaction: { hash: oldHash, receiver_id: "creator.testnet", actions: ["Transfer"] } }] });
    };
    const result = await collectNearTestnetHistory(account, fetchMock as typeof fetch, now);
    expect(result.status).toBe("PARTIAL");
    expect(result.lastActivityDays).toBe(1);
    expect(result.accountAgeDays).toBeNull();
    expect(result.firstObservedActivityAt).toBe("2026-10-01T10:00:00.000Z");
    expect(result.signals.find((signal) => signal.name === "account_age")?.status).toBe("unavailable");
    expect(result.signals.find((signal) => signal.name === "recent_activity")?.status).toBe("verified");
  });

  it("verifies account age only when the earliest transaction proves CreateAccount", async () => {
    const fetchMock = async (url: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(url).endsWith("/v0/account")) {
        return response({
          account_txs: [body.desc ? historyRow(newHash, "2026-11-02T10:00:00.000Z") : historyRow(oldHash, "2026-10-01T10:00:00.000Z")],
          txs_count: 2,
          resume_token: null,
        });
      }
      return response({ transactions: [{ transaction: { hash: oldHash, receiver_id: account, actions: ["CreateAccount", "Transfer", "AddKey"] } }] });
    };
    const result = await collectNearTestnetHistory(account, fetchMock as typeof fetch, now);
    expect(result.accountAgeDays).toBe(33);
    expect(result.accountCreatedAt).toBe("2026-10-01T10:00:00.000Z");
    expect(result.signals.find((signal) => signal.name === "account_age")?.status).toBe("verified");
  });

  it("accepts nanosecond chain timestamps without treating them as milliseconds", async () => {
    const fetchMock = async (url: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(url).endsWith("/v0/account")) {
        return response({
          account_txs: [body.desc ? historyRow(newHash, "1793613600000000000") : historyRow(oldHash, "1790848800000000000")],
          txs_count: 2,
          resume_token: null,
        });
      }
      return response({ transactions: [{ transaction: { hash: oldHash, receiver_id: "creator.testnet", actions: ["Transfer"] } }] });
    };
    const result = await collectNearTestnetHistory(account, fetchMock as typeof fetch, now);
    expect(result.lastActivityAt).toBe("2026-11-02T10:00:00.000Z");
    expect(result.lastActivityDays).toBe(1);
  });

  it("returns unavailable when the indexer fails", async () => {
    const fetchMock = async () => response({ error: "unavailable" }, 503);
    const result = await collectNearTestnetHistory(account, fetchMock as typeof fetch, now);
    expect(result.status).toBe("UNAVAILABLE");
    expect(result.accountAgeDays).toBeNull();
    expect(result.lastActivityDays).toBeNull();
  });

  it("does not infer account age when transaction details cannot be retrieved", async () => {
    const fetchMock = async (url: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(url).endsWith("/v0/account")) {
        return response({
          account_txs: [body.desc ? historyRow(newHash, "2026-11-02T10:00:00.000Z") : historyRow(oldHash, "2026-10-01T10:00:00.000Z")],
          txs_count: 2,
          resume_token: null,
        });
      }
      return response({ transactions: [] });
    };
    const result = await collectNearTestnetHistory(account, fetchMock as typeof fetch, now);
    expect(result.firstObservedActivityAt).not.toBeNull();
    expect(result.accountAgeDays).toBeNull();
    expect(result.signals.find((signal) => signal.name === "account_age")?.status).toBe("unavailable");
  });

  it("rejects invalid account IDs before making a network request", async () => {
    let called = false;
    const fetchMock = async () => { called = true; return response({}); };
    await expect(collectNearTestnetHistory("bad..account", fetchMock as typeof fetch, now)).rejects.toThrow(TypeError);
    expect(called).toBe(false);
  });
});
