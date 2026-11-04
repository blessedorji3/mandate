import { describe, expect, it } from "vitest";
import { collectNearTestnetEvidence } from "../../src/security/near-counterparty-evidence";

const at = "2026-11-03T10:00:00.000Z";
const validHash = "FDrh13CdfGPXsmwUpZLfkZCoXWfpQmaFGj4zYWc1qfh";
const emptyHash = "1".repeat(32);

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

function mockFetch(options: { network?: string; codeHash?: string; wrongId?: boolean } = {}) {
  const methods: string[] = [];
  const fetchImpl = async (_url: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body));
    methods.push(body.method);
    const id = options.wrongId ? "forged-id" : body.id;
    if (body.method === "status") {
      return response({ jsonrpc: "2.0", id, result: { chain_id: options.network ?? "testnet", sync_info: { latest_block_height: 12345 } } });
    }
    return response({ jsonrpc: "2.0", id, result: {
      amount: "1000",
      locked: "0",
      storage_usage: 128,
      code_hash: options.codeHash ?? emptyHash,
    } });
  };
  return { fetchImpl: fetchImpl as typeof fetch, methods };
}

describe("collectNearTestnetEvidence", () => {
  it("verifies finalized account type from a valid Testnet JSON-RPC response", async () => {
    const { fetchImpl } = mockFetch();
    const result = await collectNearTestnetEvidence("alice.testnet", fetchImpl, () => new Date(at));
    expect(result.status).toBe("PARTIAL");
    expect(result.network).toBe("testnet");
    expect(result.isContract).toBe(false);
    expect(result.currentBlockHeight).toBe(12345);
    expect(result.signals[0]).toMatchObject({ name: "account_type", status: "verified", value: "account" });
  });

  it("validates a Base58 32-byte contract code hash", async () => {
    const { fetchImpl } = mockFetch({ codeHash: validHash });
    const result = await collectNearTestnetEvidence("contract.testnet", fetchImpl, () => new Date(at));
    expect(result.status).toBe("PARTIAL");
    expect(result.isContract).toBe(true);
    expect(result.contractCodeHash).toBe(validHash);
    expect(result.signals.map((signal) => signal.name)).toContain("contract_code_history");
    expect(result.signals.find((signal) => signal.name === "contract_code_history")?.status).toBe("unavailable");
  });

  it("fails closed when the RPC does not confirm Testnet", async () => {
    const { fetchImpl } = mockFetch({ network: "mainnet" });
    const result = await collectNearTestnetEvidence("alice.testnet", fetchImpl, () => new Date(at));
    expect(result.status).toBe("UNAVAILABLE");
    expect(result.isContract).toBeNull();
  });

  it("rejects malformed JSON-RPC response IDs", async () => {
    const { fetchImpl } = mockFetch({ wrongId: true });
    const result = await collectNearTestnetEvidence("alice.testnet", fetchImpl, () => new Date(at));
    expect(result.status).toBe("UNAVAILABLE");
  });

  it("rejects malformed code hashes and account state fields", async () => {
    const { fetchImpl } = mockFetch({ codeHash: "not-a-real-hash" });
    const result = await collectNearTestnetEvidence("alice.testnet", fetchImpl, () => new Date(at));
    expect(result.status).toBe("UNAVAILABLE");
  });

  it("rejects invalid account IDs before making a request", async () => {
    let called = false;
    const resultPromise = collectNearTestnetEvidence("bad..account", async () => {
      called = true;
      return response({});
    }, () => new Date(at));
    await expect(resultPromise).rejects.toThrow(TypeError);
    expect(called).toBe(false);
  });

  it("uses read-only RPC methods and never invokes transaction submission", async () => {
    const { fetchImpl, methods } = mockFetch();
    await collectNearTestnetEvidence("alice.testnet", fetchImpl, () => new Date(at));
    expect(methods).toEqual(["status", "query"]);
    expect(methods.some((method) => ["send_tx", "broadcast_tx_commit"].includes(method))).toBe(false);
  });

  it("returns unavailable when the RPC transport fails", async () => {
    const result = await collectNearTestnetEvidence("alice.testnet", async () => {
      throw new Error("offline");
    }, () => new Date(at));
    expect(result.status).toBe("UNAVAILABLE");
  });
});
