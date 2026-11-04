import { describe, expect, it } from "vitest";
import { collectAndEvaluateNearTestnetCounterparty } from "../../src/security/collect-counterparty-risk";

const at = "2026-11-03T10:00:00.000Z";
const account = "alice.testnet";
const oldestHash = "FDrh13CdfGPXsmwUpZLfkZCoXWfpQmaFGj4zYWc1qfh";
const newestHash = "D2pt9ceGUyiGdJeeZLDd3uBGHF11DmPe4aJFMaoWMmDd";
const reviewerId = "a2d9b5c7-8f3e-4b1a-9c2d-6e7f8a9b0c1d";

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

function makeFetch(options: { contract?: boolean; createAccount?: boolean } = {}) {
  return async (url: RequestInfo | URL, init?: RequestInit) => {
    const target = String(url);
    const body = JSON.parse(String(init?.body));
    if (target === "https://rpc.testnet.near.org") {
      if (body.method === "status") {
        return response({ jsonrpc: "2.0", id: body.id, result: { chain_id: "testnet", sync_info: { latest_block_height: 12345 } } });
      }
      return response({ jsonrpc: "2.0", id: body.id, result: {
        amount: "1000", locked: "0", storage_usage: 128,
        code_hash: options.contract ? oldestHash : "1".repeat(32),
      } });
    }
    const path = new URL(target).pathname;
    if (path === "/v0/account") {
      return response({
        txs_count: 2,
        account_txs: [body.desc
          ? { account_id: account, transaction_hash: newestHash, tx_block_timestamp: "2026-11-02T10:00:00.000Z", tx_block_height: 200 }
          : { account_id: account, transaction_hash: oldestHash, tx_block_timestamp: "2026-10-01T10:00:00.000Z", tx_block_height: 100 }],
        resume_token: null,
      });
    }
    return response({ transactions: [{ transaction: {
      hash: oldestHash,
      receiver_id: account,
      actions: options.createAccount ? [{ CreateAccount: {} }] : ["Transfer"],
    } }] });
  };
}

describe("collectAndEvaluateNearTestnetCounterparty", () => {
  it("returns ALLOW only when chain, receipt and blocklist evidence are all supplied", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, {
      fetchImpl: makeFetch({ createAccount: true }) as typeof fetch,
      now: () => new Date(at),
      previousInteractions: 0,
      blocklistLookupStatus: "verified",
    });
    expect(result.status).toBe("COMPLETE");
    expect(result.decision.outcome).toBe("ALLOW");
  });

  it("returns WARN when the server-side blocklist lookup is unavailable", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, {
      fetchImpl: makeFetch({ createAccount: true }) as typeof fetch,
      now: () => new Date(at),
      previousInteractions: 0,
      blocklistLookupStatus: "unavailable",
    });
    expect(result.decision.outcome).toBe("WARN");
  });

  it("returns WARN when the owner-scoped interaction count is missing", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, {
      fetchImpl: makeFetch({ createAccount: true }) as typeof fetch,
      now: () => new Date(at),
      blocklistLookupStatus: "verified",
    });
    expect(result.decision.outcome).toBe("WARN");
  });

  it("keeps contract targets at WARN because historical code-change evidence is unavailable", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, {
      fetchImpl: makeFetch({ contract: true, createAccount: true }) as typeof fetch,
      now: () => new Date(at),
      previousInteractions: 0,
      blocklistLookupStatus: "verified",
    });
    expect(result.decision.outcome).toBe("WARN");
    expect(result.decision.reasons.join(" ")).toContain("Historical contract code changes");
  });

  it("returns BLOCK for a reviewer-attributed confirmed blocklist row", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, {
      fetchImpl: makeFetch({ createAccount: true }) as typeof fetch,
      now: () => new Date(at),
      previousInteractions: 0,
      blocklistLookupStatus: "verified",
      blocklist: {
        status: "confirmed",
        evidenceRef: "https://evidence.example/tx/123",
        reason: "Confirmed malicious destination",
        reviewerId,
        reviewedAt: at,
      },
    });
    expect(result.decision.outcome).toBe("BLOCK");
  });

  it("discards an untrusted blocklist payload when server lookup status is unavailable", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, {
      fetchImpl: makeFetch({ createAccount: true }) as typeof fetch,
      now: () => new Date(at),
      previousInteractions: 0,
      blocklistLookupStatus: "unavailable",
      blocklist: {
        status: "confirmed",
        evidenceRef: "https://evidence.example/tx/123",
        reason: "Client-supplied claim",
        reviewerId,
        reviewedAt: at,
      },
    });
    expect(result.decision.outcome).toBe("WARN");
  });
});
