import { describe, expect, it } from "vitest";
import { collectNearTestnetHistory } from "../../src/security/near-counterparty-history";

const at = "2026-11-03T10:00:00.000Z";
const account = "alice.testnet";
const oldHash = "FDrh13CdfGPXsmwUpZLfkZCoXWfpQmaFGj4zYWc1qfh";
const newHash = "D2pt9ceGUyiGdJeeZLDd3uBGHF11DmPe4aJFMaoWMmDd";

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

function row(hash: string, timestamp: string, accountId = account) {
  return { account_id: accountId, transaction_hash: hash, tx_block_timestamp: timestamp, tx_block_height: hash === oldHash ? 100 : 200 };
}

function makeFetch(options: { createAccount?: boolean; wrongOldAccount?: boolean; futureNewest?: boolean; failed?: boolean } = {}) {
  const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
  const fetchImpl = async (url: RequestInfo | URL, init?: RequestInit) => {
    const target = String(url);
    const body = JSON.parse(String(init?.body));
    const path = new URL(target).pathname;
    calls.push({ path, body });
    if (options.failed) return response({ error: "unavailable" }, 503);
    if (path === "/v0/account") {
      const desc = body.desc === true;
      return response({
        txs_count: 2,
        account_txs: [desc
          ? row(newHash, options.futureNewest ? "2026-11-05T10:00:00.000Z" : "2026-11-02T10:00:00.000Z")
          : row(oldHash, "2026-10-01T10:00:00.000Z", options.wrongOldAccount ? "mallory.testnet" : account)],
        resume_token: null,
      });
    }
    return response({
      transactions: [{
        transaction: {
          hash: oldHash,
          receiver_id: account,
          actions: options.createAccount ? [{ CreateAccount: {} }, { Transfer: { deposit: "1" } }] : ["Transfer"],
        },
      }],
    });
  };
  return { fetchImpl: fetchImpl as typeof fetch, calls };
}

describe("collectNearTestnetHistory", () => {
  it("verifies account age only when the exact oldest transaction proves CreateAccount", async () => {
    const { fetchImpl } = makeFetch({ createAccount: true });
    const result = await collectNearTestnetHistory(account, fetchImpl, () => new Date(at));
    expect(result.status).toBe("PARTIAL");
    expect(result.accountAgeDays).toBe(33);
    expect(result.lastActivityDays).toBe(1);
    expect(result.signals.find((signal) => signal.name === "account_age")?.status).toBe("verified");
  });

  it("does not infer account age from first-observed activity", async () => {
    const { fetchImpl } = makeFetch();
    const result = await collectNearTestnetHistory(account, fetchImpl, () => new Date(at));
    expect(result.firstObservedActivityAt).toBe("2026-10-01T00:00:00.000Z");
    expect(result.accountAgeDays).toBeNull();
    expect(result.signals.find((signal) => signal.name === "account_age")?.status).toBe("unavailable");
  });

  it("rejects rows for another account", async () => {
    const { fetchImpl } = makeFetch({ wrongOldAccount: true });
    const result = await collectNearTestnetHistory(account, fetchImpl, () => new Date(at));
    expect(result.status).toBe("UNAVAILABLE");
  });

  it("rejects a provider count that contradicts the returned rows", async () => {
    const { fetchImpl } = makeFetch();
    const inconsistent = async (url: RequestInfo | URL, init?: RequestInit) => {
      const payload = await (await fetchImpl(url, init)).json() as Record<string, unknown>;
      if (new URL(String(url)).pathname === "/v0/account") payload.txs_count = 0;
      return response(payload);
    };
    const result = await collectNearTestnetHistory(account, inconsistent as typeof fetch, () => new Date(at));
    expect(result.status).toBe("UNAVAILABLE");
  });

  it("rejects future chain timestamps", async () => {
    const { fetchImpl } = makeFetch({ futureNewest: true });
    const result = await collectNearTestnetHistory(account, fetchImpl, () => new Date(at));
    expect(result.status).toBe("UNAVAILABLE");
  });

  it("returns unavailable if either history request fails", async () => {
    const { fetchImpl } = makeFetch({ failed: true });
    const result = await collectNearTestnetHistory(account, fetchImpl, () => new Date(at));
    expect(result.status).toBe("UNAVAILABLE");
  });

  it("accepts NEAR nanosecond timestamps", async () => {
    const { fetchImpl } = makeFetch({ createAccount: true });
    const wrapper = async (url: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      const path = new URL(String(url)).pathname;
      if (path !== "/v0/account") return fetchImpl(url, init);
      const desc = body.desc === true;
      return response({
        txs_count: 2,
        account_txs: [desc
          ? row(newHash, "1793613600000000000")
          : row(oldHash, "1790848800000000000")],
        resume_token: null,
      });
    };
    const result = await collectNearTestnetHistory(account, wrapper as typeof fetch, () => new Date(at));
    expect(result.lastActivityAt).toBe("2026-11-02T10:00:00.000Z");
  });

  it("makes only indexed history reads and exact-hash detail lookups", async () => {
    const { fetchImpl, calls } = makeFetch();
    await collectNearTestnetHistory(account, fetchImpl, () => new Date(at));
    expect(calls.filter((call) => call.path === "/v0/account")).toHaveLength(2);
    expect(calls.filter((call) => call.path === "/v0/transactions")[0].body).toEqual({ tx_hashes: [oldHash] });
    expect(calls.some((call) => /send|broadcast|submit/i.test(call.path))).toBe(false);
  });

  it("rejects an invalid account ID before network access", async () => {
    let called = false;
    await expect(collectNearTestnetHistory("bad..id", async () => {
      called = true;
      return response({});
    }, () => new Date(at))).rejects.toThrow(TypeError);
    expect(called).toBe(false);
  });
});
