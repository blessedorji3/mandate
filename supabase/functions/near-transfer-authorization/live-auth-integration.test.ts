import { assertEquals } from "jsr:@std/assert@1";
import { handleRequest } from "./index.ts";

const projectUrl = Deno.env.get("SUPABASE_URL")!;
const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const origin = "https://mandate-snowy.vercel.app";

function headers(apiKey: string, authorization: string) {
  return {
    apikey: apiKey,
    authorization,
    "content-type": "application/json",
  };
}

async function adminRequest(path: string, init: RequestInit = {}) {
  return await fetch(projectUrl + path, {
    ...init,
    headers: {
      ...headers(serviceKey, "Bearer " + serviceKey),
      ...(init.headers as Record<string, string> | undefined),
    },
  });
}

Deno.test("Edge Function uses a real local GoTrue JWT and owner-scoped database RPCs", async () => {
  const email = "mandate-live-auth-" + crypto.randomUUID() + "@example.test";
  const password = "M4ndate-" + crypto.randomUUID() + "-Aa9!";
  let userId: string | null = null;

  try {
    const createdResponse = await adminRequest("/auth/v1/admin/users", {
      method: "POST",
      body: JSON.stringify({ email, password, email_confirm: true }),
    });
    assertEquals(createdResponse.status, 200, "local GoTrue must create the disposable test user");
    const created = await createdResponse.json();
    userId = created.id ?? created.user?.id ?? null;
    if (!userId) throw new Error("GoTrue admin response did not include a user ID");

    const loginResponse = await fetch(projectUrl + "/auth/v1/token?grant_type=password", {
      method: "POST",
      headers: headers(anonKey, "Bearer " + anonKey),
      body: JSON.stringify({ email, password }),
    });
    assertEquals(loginResponse.status, 200, "local GoTrue must issue a real access token");
    const login = await loginResponse.json();
    if (typeof login.access_token !== "string") throw new Error("GoTrue did not return an access token");
    const token = login.access_token as string;

    const makeRequest = (authorization?: string, action = "recovery_lifecycle") =>
      new Request(projectUrl + "/functions/v1/near-transfer-authorization", {
        method: "POST",
        headers: {
          origin,
          "content-type": "application/json",
          ...(authorization ? { authorization } : {}),
        },
        body: JSON.stringify({
          action,
          accountId: "securewithmandate.testnet",
          // A caller-supplied owner must never override the real GoTrue user.
          ownerId: "10000000-0000-4000-8000-000000000099",
        }),
      });

    const missing = await handleRequest(makeRequest());
    assertEquals(missing.status, 401, "missing bearer must be rejected by live auth");

    const invalid = await handleRequest(makeRequest("Bearer definitely-not-a-jwt"));
    assertEquals(invalid.status, 401, "invalid bearer must be rejected by live auth");

    const lifecycle = await handleRequest(makeRequest("Bearer " + token));
    assertEquals(lifecycle.status, 200, "real GoTrue JWT must reach the local database RPC");
    assertEquals(await lifecycle.json(), {
      codeEstablished: false,
      codeConsumed: false,
      hasWalletHistory: false,
      activeWalletAccountId: null,
      request: null,
    }, "fresh disposable auth user must have an empty recovery lifecycle");

    const status = await handleRequest(makeRequest("Bearer " + token, "wallet_status"));
    assertEquals(status.status, 200, "wallet status must use the authenticated local user");
    assertEquals(await status.json(), { registered: false, wallet: null });
    console.log("PASS: live GoTrue issued the JWT; the Edge Function verified it and queried the local database using the authenticated owner identity.");
  } finally {
    if (userId) {
      const deleted = await adminRequest("/auth/v1/admin/users/" + userId, { method: "DELETE" });
      if (!deleted.ok) throw new Error("Failed to clean up disposable local GoTrue user: " + deleted.status);
    }
  }
});
