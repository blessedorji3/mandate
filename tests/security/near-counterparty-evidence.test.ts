import { describe, expect, it } from "vitest";
import { collectNearTestnetEvidence } from "../../src/security/near-counterparty-evidence";

function response(payload: unknown, ok = true): Response {
  return new Response(JSON.stringify(payload), {
    status: ok ? 200 : 503,
    headers: { "content-type": "application/json" },
  });
}

const fixedNow = () => new Date("2026-11-03T10:00:00.000Z");

describe("collectNearTestnetEvidence", () => {
  it("verifies account type from Testnet RPC but leaves history unavailable", async () => {
    const fetchMock = async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (body.method === "status") return response({ result: { chain_id: "testnet", sync_info: { latest_block_height: 12345 } } });
      return response({ result: { code_hash: "11111111111111111111111111111111" } });
    };
    const result = await collectNearTestnetEvidence("alice.testnet", fetchMock as typeof fetch, fixedNow);
    expect(result.status).toBe("PARTIAL");
    if (result.status !== "PARTIAL") throw new Error("Expected partial evidence.");
    expect(result.isContract).toBe(false);
    expect(result.currentBlockHeight).toBe(12345);
    expect(result.signals.find((signal) => signal.name === "account_type")?.status).toBe("verified");
    expect(result.signals.find((signal) => signal.name === "account_age")?.status).toBe("unavailable");
    expect(result.accountAgeDays).toBeNull();
  });

  it("retrieves a current contract code hash but does not claim historical code stability", async () => {
    const fetchMock = async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (body.method === "status") return response({ result: { chain_id: "testnet", sync_info: { latest_block_height: 12345 } } });
      return response({ result: { code_hash: "AbCdEf1234567890" } });
    };
    const result = await collectNearTestnetEvidence("contract.testnet", fetchMock as typeof fetch, fixedNow);
    expect(result.status).toBe("PARTIAL");
    if (result.status !== "PARTIAL") throw new Error("Expected partial evidence.");
    expect(result.isContract).toBe(true);
    expect(result.contractCodeHash).toBe("AbCdEf1234567890");
    expect(result.codeChangedRecently).toBeNull();
    expect(result.signals.find((signal) => signal.name === "contract_code_history")?.status).toBe("unavailable");
  });

  it("fails closed when the RPC reports the wrong network", async () => {
    const fetchMock = async () => response({ result: { chain_id: "mainnet" } });
    const result = await collectNearTestnetEvidence("alice.testnet", fetchMock as typeof fetch, fixedNow);
    expect(result.status).toBe("UNAVAILABLE");
    expect(result.signals.every((signal) => signal.status === "unavailable")).toBe(true);
  });

  it("fails closed when RPC is unreachable or malformed", async () => {
    const fetchMock = async () => { throw new Error("network down"); };
    const result = await collectNearTestnetEvidence("alice.testnet", fetchMock as typeof fetch, fixedNow);
    expect(result.status).toBe("UNAVAILABLE");
    expect(result.accountAgeDays).toBeNull();
  });

  it("rejects invalid account identifiers before making a request", async () => {
    let called = false;
    const fetchMock = async () => { called = true; return response({ result: {} }); };
    await expect(collectNearTestnetEvidence("..bad..", fetchMock as typeof fetch, fixedNow)).rejects.toThrow(TypeError);
    expect(called).toBe(false);
  });

  it("never makes a transaction submission RPC call", async () => {
    const methods: string[] = [];
    const fetchMock = async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      methods.push(body.method);
      if (body.method === "status") return response({ result: { chain_id: "testnet" } });
      return response({ result: { code_hash: "11111111111111111111111111111111" } });
    };
    await collectNearTestnetEvidence("alice.testnet", fetchMock as typeof fetch, fixedNow);
    expect(methods).toEqual(["status", "query"]);
    expect(methods.some((method) => ["send_tx", "broadcast_tx_commit"].includes(method))).toBe(false);
  });
});
