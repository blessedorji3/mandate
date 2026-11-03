import { describe, expect, it } from "vitest";
import { collectAndEvaluateNearTestnetCounterparty } from "../../src/security/collect-counterparty-risk";

const fixedNow = () => new Date("2026-11-03T10:00:00.000Z");
const account = "alice.testnet";
const oldHash = "A".repeat(44);
const newHash = "B".repeat(44);

function response(payload: unknown): Response {
  return new Response(JSON.stringify(payload), { status: 200, headers: { "content-type": "application/json" } });
}

function makeFetch(options: { contract?: boolean; createAccount?: boolean; wrongNetwork?: boolean } = {}) {
  return async (url: RequestInfo | URL, init?: RequestInit) => {
    const target = String(url);
    const body = JSON.parse(String(init?.body));
    if (target === "https://rpc.testnet.near.org") {
      if (body.method === "status") return response({ result: { chain_id: options.wrongNetwork ? "mainnet" : "testnet", sync_info: { latest_block_height: 1234 } } });
      return response({ result: { code_hash: options.contract ? "AbCdEf1234567890" : "11111111111111111111111111111111" } });
    }
    if (target.endsWith("/v0/account")) {
      return response({
        account_txs: [{
          account_id: account,
          transaction_hash: body.desc ? newHash : oldHash,
          tx_block_timestamp: body.desc ? "2026-11-02T10:00:00.000Z" : "2026-10-01T10:00:00.000Z",
          tx_block_height: 100,
        }],
        txs_count: 2,
        resume_token: null,
      });
    }
    return response({
      transactions: [{
        transaction: {
          hash: oldHash,
          receiver_id: options.createAccount ? account : "creator.testnet",
          actions: options.createAccount ? ["CreateAccount", "Transfer", "AddKey"] : ["Transfer"],
        },
      }],
    });
  };
}

describe("collectAndEvaluateNearTestnetCounterparty", () => {
  it("returns WARN when historical account creation and MANDATE receipts are incomplete", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, { fetchImpl: makeFetch() as typeof fetch, now: fixedNow });
    expect(result.decision.outcome).toBe("WARN");
    expect(result.decision.requiresHumanApproval).toBe(true);
    expect(result.decision.reasons.some((reason) => reason.includes("Account age"))).toBe(true);
    expect(result.decision.reasons.some((reason) => reason.includes("Previous MANDATE interactions"))).toBe(true);
  });

  it("does not ALLOW when RPC is on the wrong network", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, { fetchImpl: makeFetch({ wrongNetwork: true }) as typeof fetch, now: fixedNow });
    expect(result.decision.outcome).toBe("WARN");
    expect(result.status).toBe("UNAVAILABLE");
  });

  it("keeps contract code history unavailable and therefore warns", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, {
      fetchImpl: makeFetch({ contract: true, createAccount: true }) as typeof fetch,
      now: fixedNow,
      previousInteractions: 0,
    });
    expect(result.decision.outcome).toBe("WARN");
    expect(result.decision.reasons.some((reason) => reason.includes("Historical contract code changes"))).toBe(true);
  });

  it("can ALLOW only when all required evidence and blocklist lookup are verified", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, {
      fetchImpl: makeFetch({ createAccount: true }) as typeof fetch,
      now: fixedNow,
      previousInteractions: 0,
      blocklistLookupStatus: "verified",
    });
    expect(result.decision.outcome).toBe("ALLOW");
    expect(result.status).toBe("COMPLETE");
  });

  it("warns when blocklist lookup completeness is unavailable", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, {
      fetchImpl: makeFetch({ createAccount: true }) as typeof fetch,
      now: fixedNow,
      previousInteractions: 0,
      blocklistLookupStatus: "unavailable",
    });
    expect(result.decision.outcome).toBe("WARN");
  });

  it("allows a confirmed reviewed blocklist record to force BLOCK", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, {
      fetchImpl: makeFetch() as typeof fetch,
      now: fixedNow,
      blocklist: {
        status: "confirmed",
        evidenceRef: "https://example.test/evidence/123",
        reason: "Confirmed malicious counterparty",
        reviewedAt: "2026-11-03T09:00:00.000Z",
      },
    });
    expect(result.decision.outcome).toBe("BLOCK");
    expect(result.decision.requiresHumanApproval).toBe(true);
  });

  it("does not trust a pending blocklist report as a hard block", async () => {
    const result = await collectAndEvaluateNearTestnetCounterparty(account, {
      fetchImpl: makeFetch() as typeof fetch,
      now: fixedNow,
      blocklist: {
        status: "pending",
        evidenceRef: "https://example.test/report/123",
        reason: "Unreviewed report",
      },
    });
    expect(result.decision.outcome).toBe("WARN");
  });
});
