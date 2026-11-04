import { assertEquals } from "jsr:@std/assert@1";

Deno.test("Edge Function enforces missing, invalid, and valid bearer authentication over HTTP", async () => {
  const originalFetch = globalThis.fetch;
  const originalEnv = {
    url: Deno.env.get("SUPABASE_URL"),
    anon: Deno.env.get("SUPABASE_ANON_KEY"),
    service: Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"),
  };
  const calls: Array<{ url: string; body?: unknown; authorization?: string | null }> = [];

  Deno.env.set("SUPABASE_URL", "https://mandate-http-test.invalid");
  Deno.env.set("SUPABASE_ANON_KEY", "test-anon-key");
  Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const headers = new Headers(init?.headers);
    let body: unknown;
    if (typeof init?.body === "string") {
      try { body = JSON.parse(init.body); } catch { body = init.body; }
    }
    calls.push({ url, body, authorization: headers.get("authorization") });

    if (url.endsWith("/auth/v1/user")) {
      if (headers.get("authorization") === "Bearer valid-test-user-token") {
        return Response.json({ id: "10000000-0000-4000-8000-000000000001" });
      }
      return Response.json({ message: "Invalid JWT" }, { status: 401 });
    }
    if (url.endsWith("/rest/v1/rpc/get_near_owner_wallet_v1")) {
      return Response.json([]);
    }
    if (url.endsWith("/rest/v1/rpc/get_near_wallet_recovery_lifecycle_v1")) {
      return Response.json([{
        code_established: true,
        code_consumed: false,
        has_wallet_history: true,
        active_wallet_account_id: "owner-wallet.testnet",
        request_id: "70000000-0000-4000-8000-000000000001",
        request_status: "pending",
        new_account_id: "replacement-wallet.testnet",
        seconds_remaining: 86000,
      }]);
    }
    return Response.json({ message: "Unexpected test request" }, { status: 500 });
  }) as typeof fetch;

  try {
    // Dynamic import is intentional: environment configuration must exist before
    // the Edge Function module reads its environment variables.
    const { handleRequest } = await import("./index.ts");
    const origin = "https://mandate-snowy.vercel.app";
    const releasePreviewOrigin = "https://mandate-git-release-multi-wallet-recovery-hardening-web3pass.vercel.app";
    const makeRequest = (authorization?: string, action = "wallet_status") => new Request(
      "https://mandate-http-test.invalid/functions/v1/near-transfer-authorization",
      {
        method: "POST",
        headers: {
          origin,
          "content-type": "application/json",
          ...(authorization ? { authorization } : {}),
        },
        body: JSON.stringify({
          action,
          accountId: "owner-wallet.testnet",
          signerAccountId: "owner-wallet.testnet",
          // This must never override the authenticated user identity.
          ownerId: "10000000-0000-4000-8000-000000000099",
        }),
      },
    );

    const missing = await handleRequest(makeRequest());
    assertEquals(missing.status, 401, "missing bearer token must be rejected");

    const invalid = await handleRequest(makeRequest("Bearer invalid-test-user-token"));
    assertEquals(invalid.status, 401, "invalid bearer token must be rejected");

    const previewPreflight = await handleRequest(new Request(
      "https://mandate-http-test.invalid/functions/v1/near-transfer-authorization",
      { method: "OPTIONS", headers: { origin: releasePreviewOrigin } },
    ));
    assertEquals(previewPreflight.status, 200, "the exact release preview origin should pass CORS preflight");
    assertEquals(
      previewPreflight.headers.get("access-control-allow-origin"),
      releasePreviewOrigin,
      "the allowlist must return the exact release preview origin, not a wildcard",
    );

    const rejectedOrigin = await handleRequest(new Request(
      "https://mandate-http-test.invalid/functions/v1/near-transfer-authorization",
      {
        method: "POST",
        headers: {
          origin: "https://attacker.example",
          "content-type": "application/json",
          authorization: "Bearer valid-test-user-token",
        },
        body: JSON.stringify({ action: "wallet_status", accountId: "owner-wallet.testnet" }),
      },
    ));
    assertEquals(rejectedOrigin.status, 403, "untrusted origins must remain denied");

    const valid = await handleRequest(makeRequest("Bearer valid-test-user-token"));
    assertEquals(valid.status, 200, "valid authenticated request should reach the RPC");
    assertEquals(await valid.json(), { registered: false, wallet: null });

    const frozen = await handleRequest(makeRequest("Bearer valid-test-user-token", "challenge"));
    assertEquals(frozen.status, 409, "a pending recovery must freeze transfer authorization at the HTTP boundary");
    const frozenBody = await frozen.json();
    assertEquals(
      (frozenBody as Record<string, unknown>).error,
      "Financial authorizations are frozen while wallet recovery is pending.",
    );
    assertEquals(
      calls.some((call) => call.url.includes("/rest/v1/rpc/create_near_transfer_challenge_v2")),
      false,
      "a frozen account must not create a transfer challenge",
    );

    const resetBlocked = await handleRequest(makeRequest("Bearer valid-test-user-token", "recovery_code_reset_challenge"));
    assertEquals(resetBlocked.status, 409, "a pending wallet recovery must block recovery-code reset");
    assertEquals(resetBlocked.headers.get("cache-control"), "no-store", "reset responses must not be cached");
    assertEquals(
      calls.some((call) => call.url.endsWith("/rest/v1/rpc/create_near_wallet_recovery_reset_challenge_v1")),
      false,
      "a pending recovery must not create a recovery-code reset challenge",
    );

    const malformedReset = await handleRequest(makeRequest("Bearer valid-test-user-token", "recovery_code_reset_verify"));
    assertEquals(malformedReset.status, 400, "reset verification must reject missing challenge and signature fields");
    assertEquals(malformedReset.headers.get("cache-control"), "no-store", "reset verification responses must not be cached");

    const rpcCall = calls.find((call) => call.url.endsWith("/rest/v1/rpc/get_near_owner_wallet_v1"));
    assertEquals(
      (rpcCall?.body as Record<string, unknown> | undefined)?.p_owner_id,
      "10000000-0000-4000-8000-000000000001",
      "database owner must come from the verified auth user, never request JSON",
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
