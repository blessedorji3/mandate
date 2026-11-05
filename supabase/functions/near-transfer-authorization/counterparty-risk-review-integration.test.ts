import { assertEquals } from "jsr:@std/assert@1";

const OWNER_ID = "10000000-0000-4000-8000-000000000001";
const CHALLENGE_ID = "20000000-0000-4000-8000-000000000001";
const POLICY_ID = "30000000-0000-4000-8000-000000000001";
const ACCOUNT_ID = "owner-wallet.testnet";
const PUBLIC_KEY = "ed25519:" + "4".repeat(44);
const PHASE2_PREVIEW_ORIGIN = "https://mandate-git-feat-phase-2-counterparty-risk-web3pass.vercel.app";

Deno.test("proposal-bound risk review rejects identity and signature substitution over HTTP", async () => {
  const originalFetch = globalThis.fetch;
  const originalEnv = {
    url: Deno.env.get("SUPABASE_URL"),
    anon: Deno.env.get("SUPABASE_ANON_KEY"),
    service: Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"),
  };
  const calls: Array<{ url: string; body: Record<string, unknown> | null }> = [];
  const challenge = {
    id: CHALLENGE_ID,
    proposal_id: "phase2-risk-proposal-001",
    policy_id: POLICY_ID,
    policy_version: 1,
    target_account_id: "confirmwithmandate.testnet",
    risk_fingerprint: "a".repeat(64),
    signer_account_id: ACCOUNT_ID,
    signer_public_key: PUBLIC_KEY,
    nonce_hex: "b".repeat(64),
    message: "MANDATE COUNTERPARTY RISK REVIEW\nexact proposal only",
    expires_at: new Date(Date.now() + 180_000).toISOString(),
  };

  Deno.env.set("SUPABASE_URL", "https://mandate-review-test.invalid");
  Deno.env.set("SUPABASE_ANON_KEY", "test-anon-key");
  Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    let body: Record<string, unknown> | null = null;
    if (typeof init?.body === "string") {
      try {
        body = JSON.parse(init.body) as Record<string, unknown>;
      } catch {
        body = null;
      }
    }
    calls.push({ url, body });

    if (url.endsWith("/auth/v1/user")) {
      const headers = new Headers(init?.headers);
      return headers.get("authorization") === "Bearer valid-review-owner-token"
        ? Response.json({ id: OWNER_ID })
        : Response.json({ message: "Invalid JWT" }, { status: 401 });
    }
    if (url.endsWith("/rest/v1/rpc/get_counterparty_risk_review_challenge_v1")) {
      return Response.json(body?.p_owner_id === OWNER_ID && body?.p_id === CHALLENGE_ID ? [challenge] : []);
    }
    if (url.endsWith("/rest/v1/rpc/get_near_owner_wallet_v1")) {
      return Response.json(body?.p_owner_id === OWNER_ID && body?.p_account_id === ACCOUNT_ID
        ? [{ account_id: ACCOUNT_ID, public_key: PUBLIC_KEY, revoked_at: null }]
        : []);
    }
    if (url === "https://rpc.testnet.fastnear.com") {
      return Response.json({
        jsonrpc: "2.0",
        id: "mandate-access-key-check",
        result: { keys: [{ public_key: PUBLIC_KEY, access_key: { permission: "FullAccess" } }] },
      });
    }
    return Response.json({ message: "Unexpected test request" }, { status: 500 });
  }) as typeof fetch;

  try {
    const { handleRequest } = await import("./index.ts");
    const endpoint = "https://mandate-review-test.invalid/functions/v1/near-transfer-authorization";
    const request = (origin: string, signedMessage: Record<string, unknown>) => new Request(endpoint, {
      method: "POST",
      headers: {
        origin,
        "content-type": "application/json",
        authorization: "Bearer valid-review-owner-token",
      },
      body: JSON.stringify({
        action: "risk_review_verify",
        challengeId: CHALLENGE_ID,
        signedMessage,
        // Untrusted request JSON must never choose the database owner.
        ownerId: "10000000-0000-4000-8000-000000000099",
      }),
    });

    const preflight = await handleRequest(new Request(endpoint, {
      method: "OPTIONS",
      headers: { origin: PHASE2_PREVIEW_ORIGIN },
    }));
    assertEquals(preflight.status, 200);
    assertEquals(preflight.headers.get("access-control-allow-origin"), PHASE2_PREVIEW_ORIGIN);

    const invalidOrigin = await handleRequest(request("https://attacker.example", {
      accountId: ACCOUNT_ID,
      publicKey: PUBLIC_KEY,
      signature: "not-base64!",
    }));
    assertEquals(invalidOrigin.status, 403, "untrusted browser origins must be rejected");

    const wrongAccount = await handleRequest(request(PHASE2_PREVIEW_ORIGIN, {
      accountId: "attacker-wallet.testnet",
      publicKey: PUBLIC_KEY,
      signature: "not-base64!",
    }));
    assertEquals(wrongAccount.status, 403, "a different wallet account must not complete this challenge");

    const wrongKey = await handleRequest(request(PHASE2_PREVIEW_ORIGIN, {
      accountId: ACCOUNT_ID,
      publicKey: "ed25519:" + "5".repeat(44),
      signature: "not-base64!",
    }));
    assertEquals(wrongKey.status, 403, "a different public key must not complete this challenge");

    const malformedSignature = await handleRequest(request(PHASE2_PREVIEW_ORIGIN, {
      accountId: ACCOUNT_ID,
      publicKey: PUBLIC_KEY,
      signature: "not-base64!",
    }));
    assertEquals(malformedSignature.status, 403, "malformed NEP-413 signatures must fail closed");

    const challengeLookup = calls.find(c => c.url.endsWith("/rest/v1/rpc/get_counterparty_risk_review_challenge_v1"));
    assertEquals(challengeLookup?.body?.p_owner_id, OWNER_ID, "owner identity must come from verified Supabase Auth");
    assertEquals(
      calls.some(c => c.url.endsWith("/rest/v1/rpc/complete_counterparty_risk_review_v1")),
      false,
      "no invalid account, key, or signature may create a review record",
    );
  } finally {
    globalThis.fetch = originalFetch;
    for (const [key, value] of Object.entries({
      SUPABASE_URL: originalEnv.url,
      SUPABASE_ANON_KEY: originalEnv.anon,
      SUPABASE_SERVICE_ROLE_KEY: originalEnv.service,
    })) {
      if (value === undefined) Deno.env.delete(key);
      else Deno.env.set(key, value);
    }
  }
});
