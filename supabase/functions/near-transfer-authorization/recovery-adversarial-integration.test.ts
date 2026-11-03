import { assert, assertEquals } from "jsr:@std/assert@1";
import { recoveryTestUtils } from "./recovery-security.ts";

const ownerId = "10000000-0000-4000-8000-000000000001";
const attackerOwnerId = "10000000-0000-4000-8000-000000000099";
const accountId = "replacement-wallet.testnet";
const expectedCode = "MND-" + "1".repeat(64);

function hex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function signChallenge(privateKey: CryptoKey, message: string, nonceHex: string, recipientValue: string) {
  const encoder = new TextEncoder();
  const concat = (...parts: Uint8Array[]) => {
    const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
    let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.length; }
    return result;
  };
  const borsh = (value: string) => {
    const bytes = encoder.encode(value);
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, bytes.length, true);
    return concat(length, bytes);
  };
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, 0x80000000 + 413, true);
  const nonce = Uint8Array.from(nonceHex.match(/.{2}/g)!, (part) => Number.parseInt(part, 16));
  const payload = concat(prefix, borsh(message), nonce, borsh(recipientValue), new Uint8Array([0]));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", payload));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, digest));
  return btoa(String.fromCharCode(...signature));
}

Deno.test("recovery HTTP flow rejects owner/account substitution, wrong code, and challenge replay", async () => {
  const originalFetch = globalThis.fetch;
  const originalEnv = {
    url: Deno.env.get("SUPABASE_URL"),
    anon: Deno.env.get("SUPABASE_ANON_KEY"),
    service: Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"),
  };
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const publicKey = "ed25519:" + recoveryTestUtils.base58Encode(publicKeyBytes);
  let challengeId = "";
  let storedChallenge: Record<string, unknown> | null = null;
  let consumed = false;
  const ownersSeen: string[] = [];
  let startCalls = 0;

  Deno.env.set("SUPABASE_URL", "https://mandate-recovery-test.invalid");
  Deno.env.set("SUPABASE_ANON_KEY", "test-anon-key");
  Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const headers = new Headers(init?.headers);
    let body: Record<string, unknown> = {};
    if (typeof init?.body === "string") {
      try { body = JSON.parse(init.body); } catch { /* no JSON body */ }
    }

    if (url.endsWith("/auth/v1/user")) {
      return headers.get("authorization") === "Bearer valid-owner-token"
        ? Response.json({ id: ownerId })
        : Response.json({ message: "Invalid JWT" }, { status: 401 });
    }
    if (url.endsWith("/rest/v1/rpc/get_near_wallet_recovery_lifecycle_v1")) {
      ownersSeen.push(String(body.p_owner_id));
      return Response.json([{
        code_established: true, code_consumed: false, has_wallet_history: true,
        active_wallet_account_id: "old-wallet.testnet", request_id: null, request_status: null,
      }]);
    }
    if (url.endsWith("/rest/v1/rpc/create_near_wallet_recovery_action_challenge_v1")) {
      ownersSeen.push(String(body.p_owner_id));
      challengeId = String(body.p_id);
      storedChallenge = {
        id: body.p_id, action: body.p_action, account_id: body.p_account_id,
        public_key: body.p_public_key, nonce_hex: body.p_nonce_hex,
        message: body.p_message, request_id: body.p_request_id,
        expires_at: new Date(Date.now() + 300_000).toISOString(),
      };
      return Response.json(body.p_id);
    }
    if (url.endsWith("/rest/v1/rpc/get_near_wallet_recovery_action_challenge_v1")) {
      ownersSeen.push(String(body.p_owner_id));
      return Response.json(!consumed && body.p_owner_id === ownerId && storedChallenge ? [storedChallenge] : []);
    }
    if (url.endsWith("/rest/v1/rpc/start_near_wallet_recovery_v1")) {
      ownersSeen.push(String(body.p_owner_id));
      startCalls += 1;
      const expectedHash = hex(new Uint8Array(await crypto.subtle.digest(
        "SHA-256", new TextEncoder().encode(expectedCode),
      )));
      if (body.p_owner_id !== ownerId || body.p_code_hash_hex !== expectedHash || consumed || !storedChallenge) {
        return Response.json(false);
      }
      consumed = true;
      return Response.json(true);
    }
    if (url === "https://rpc.testnet.fastnear.com") {
      return Response.json({ result: { keys: [{ public_key: publicKey, access_key: { permission: "FullAccess" } }] } });
    }
    return Response.json({ message: "Unexpected test request" }, { status: 500 });
  }) as typeof fetch;

  try {
    const { handleRequest } = await import("./index.ts");
    const origin = "https://mandate-git-feat-recovery-code-reset-web3pass.vercel.app";
    const request = (action: string, payload: Record<string, unknown>) => new Request(
      "https://mandate-recovery-test.invalid/functions/v1/near-transfer-authorization",
      {
        method: "POST",
        headers: { origin, "content-type": "application/json", authorization: "Bearer valid-owner-token" },
        body: JSON.stringify({ action, ownerId: attackerOwnerId, ...payload }),
      },
    );

    const challengeResponse = await handleRequest(request("recovery_start_challenge", {
      accountId, recoveryCode: expectedCode,
    }));
    assertEquals(challengeResponse.status, 200);
    const challenge = await challengeResponse.json();
    assertEquals(challenge.challengeId, challengeId);
    assert(ownersSeen.every((seen) => seen === ownerId), "request JSON must never select the recovery owner");

    const signature = await signChallenge(pair.privateKey, challenge.message, challenge.nonceHex, challenge.recipient);
    const signedMessage = { accountId, publicKey, signature };

    const substituted = await handleRequest(request("recovery_start_verify", {
      challengeId, signedMessage: { ...signedMessage, accountId: "attacker-wallet.testnet" },
      recoveryCode: expectedCode,
    }));
    assertEquals(substituted.status, 409, "a signature from another account must not match the challenge");

    const wrongCode = "MND-" + "0".repeat(64);
    const rejectedCode = await handleRequest(request("recovery_start_verify", {
      challengeId, signedMessage, recoveryCode: wrongCode,
    }));
    assertEquals(rejectedCode.status, 403, "a valid wallet signature cannot replace the independent recovery code");
    assertEquals(consumed, false, "a rejected recovery code must not consume the valid challenge");

    const accepted = await handleRequest(request("recovery_start_verify", {
      challengeId, signedMessage, recoveryCode: expectedCode,
    }));
    assertEquals(accepted.status, 200, "the correct recovery code and matching wallet signature should start recovery");
    assertEquals((await accepted.json()).started, true);
    assertEquals(consumed, true);

    const replay = await handleRequest(request("recovery_start_verify", {
      challengeId, signedMessage, recoveryCode: expectedCode,
    }));
    assertEquals(replay.status, 409, "a consumed recovery challenge must not be replayable");
    assertEquals(startCalls, 2, "the replay must be rejected before a second start RPC call");
    assert(ownersSeen.every((seen) => seen === ownerId), "all recovery RPCs must remain bound to the authenticated owner");
  } finally {
    globalThis.fetch = originalFetch;
    for (const [key, value] of Object.entries({
      SUPABASE_URL: originalEnv.url, SUPABASE_ANON_KEY: originalEnv.anon,
      SUPABASE_SERVICE_ROLE_KEY: originalEnv.service,
    })) {
      if (value === undefined) Deno.env.delete(key);
      else Deno.env.set(key, value);
    }
  }
});
