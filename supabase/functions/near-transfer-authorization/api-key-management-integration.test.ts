import { assert, assertEquals } from "jsr:@std/assert@1";

const ownerId = "10000000-0000-4000-8000-000000000001";
const attackerOwnerId = "10000000-0000-4000-8000-000000000099";
const createdKeyId = "20000000-0000-4000-8000-000000000001";

type ApiKeyRow = {
  id: string;
  owner_id: string;
  name: string;
  key_prefix: string;
  key_hash: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
};

function hex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

Deno.test("API key management is authenticated, owner-scoped, hash-only at rest, and revocable", async () => {
  const originalFetch = globalThis.fetch;
  const originalEnv = {
    url: Deno.env.get("SUPABASE_URL"),
    anon: Deno.env.get("SUPABASE_ANON_KEY"),
    service: Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"),
    secrets: Deno.env.get("SUPABASE_SECRET_KEYS"),
  };
  const rows: ApiKeyRow[] = [];
  const observedOwners: string[] = [];
  let inserted: ApiKeyRow | null = null;
  let revoked = false;

  Deno.env.set("SUPABASE_URL", "https://mandate-key-management-test.invalid");
  Deno.env.set("SUPABASE_ANON_KEY", "test-anon-key");
  Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
  Deno.env.delete("SUPABASE_SECRET_KEYS");

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);

    if (url.pathname === "/auth/v1/user") {
      return headers.get("authorization") === "Bearer valid-owner-token"
        ? Response.json({ id: ownerId })
        : Response.json({ message: "Invalid JWT" }, { status: 401 });
    }

    if (url.pathname === "/rest/v1/api_keys") {
      const method = init?.method ?? "GET";
      const ownerFilter = url.searchParams.get("owner_id");
      if (ownerFilter) observedOwners.push(ownerFilter.replace(/^eq\./, ""));

      if (method === "GET") {
        if (ownerFilter !== `eq.${ownerId}`) {
          return Response.json({ message: "Missing owner scope" }, { status: 400 });
        }
        const visible = rows
          .filter((row) => row.owner_id === ownerId)
          .map(({ id, name, key_prefix, created_at, last_used_at, revoked_at }) => ({
            id, name, key_prefix, created_at, last_used_at, revoked_at,
          }));
        return Response.json(visible);
      }

      if (method === "POST") {
        const body = JSON.parse(String(init?.body ?? "{}"));
        if (body.owner_id !== ownerId || typeof body.key_hash !== "string" ||
            !/^[0-9a-f]{64}$/.test(body.key_hash) ||
            typeof body.key_prefix !== "string" || !body.key_prefix.startsWith("mnd_live_")) {
          return Response.json({ message: "Invalid key insert" }, { status: 400 });
        }
        const row: ApiKeyRow = {
          id: createdKeyId,
          owner_id: body.owner_id,
          name: body.name,
          key_prefix: body.key_prefix,
          key_hash: body.key_hash,
          created_at: new Date().toISOString(),
          last_used_at: null,
          revoked_at: null,
        };
        inserted = row;
        rows.push(row);
        return Response.json({
          id: row.id,
          name: row.name,
          key_prefix: row.key_prefix,
          created_at: row.created_at,
          last_used_at: row.last_used_at,
          revoked_at: row.revoked_at,
        }, { status: 201 });
      }

      if (method === "PATCH") {
        const idFilter = url.searchParams.get("id");
        if (idFilter !== `eq.${createdKeyId}` || ownerFilter !== `eq.${ownerId}` ||
            url.searchParams.get("revoked_at") !== "is.null") {
          return Response.json({ message: "Missing revoke scope" }, { status: 400 });
        }
        const row = rows.find((item) => item.id === createdKeyId && item.owner_id === ownerId);
        if (!row || row.revoked_at) return Response.json(null);
        const body = JSON.parse(String(init?.body ?? "{}"));
        row.revoked_at = body.revoked_at;
        revoked = true;
        return Response.json({ id: row.id });
      }
    }

    return Response.json({ message: `Unexpected test request: ${url.pathname}` }, { status: 500 });
  }) as typeof fetch;

  try {
    const { handleRequest } = await import("./index.ts");
    const origin = "https://mandate-snowy.vercel.app";
    const makeRequest = (action: string, payload: Record<string, unknown> = {}, token = "valid-owner-token") =>
      new Request("https://mandate-key-management-test.invalid/functions/v1/near-transfer-authorization", {
        method: "POST",
        headers: {
          origin,
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ action, ownerId: attackerOwnerId, ...payload }),
      });

    const unauthenticated = await handleRequest(makeRequest("api_keys_list", {}, "invalid-token"));
    assertEquals(unauthenticated.status, 401, "invalid owner sessions cannot list API keys");

    const listed = await handleRequest(makeRequest("api_keys_list"));
    assertEquals(listed.status, 200);
    assertEquals(await listed.json(), { keys: [] }, "a list response contains only non-secret metadata");

    const created = await handleRequest(makeRequest("api_key_create", { name: "audit-test-key" }));
    assertEquals(created.status, 201);
    const createdBody = await created.json() as Record<string, unknown>;
    assert(typeof createdBody.apiKey === "string" && createdBody.apiKey.startsWith("mnd_live_"));
    assertEquals(createdBody.key && (createdBody.key as Record<string, unknown>).key_hash, undefined);
    assert(inserted !== null, "the service-role path should persist a key record");
    assertEquals(inserted!.owner_id, ownerId, "request JSON cannot choose the owner");
    assertEquals(inserted!.name, "audit-test-key");

    const expectedHash = hex(new Uint8Array(await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(String(createdBody.apiKey)),
    )));
    assertEquals(inserted!.key_hash, expectedHash, "only the SHA-256 digest is stored");
    assertEquals(inserted!.key_prefix, String(createdBody.apiKey).slice(0, 18));
    assertEquals(observedOwners.every((seen) => seen === ownerId), true, "all reads remain bound to the authenticated owner");

    const revokedResponse = await handleRequest(makeRequest("api_key_revoke", { keyId: createdKeyId }));
    assertEquals(revokedResponse.status, 200);
    assertEquals(await revokedResponse.json(), { revoked: true, keyId: createdKeyId });
    assertEquals(revoked, true, "the authenticated owner can revoke their own key");
    assert(rows[0].revoked_at !== null, "the stored key is marked revoked");

    const badName = await handleRequest(makeRequest("api_key_create", { name: " ".repeat(100) }));
    assertEquals(badName.status, 400, "invalid key names are rejected");
  } finally {
    globalThis.fetch = originalFetch;
    for (const [key, value] of Object.entries({
      SUPABASE_URL: originalEnv.url,
      SUPABASE_ANON_KEY: originalEnv.anon,
      SUPABASE_SERVICE_ROLE_KEY: originalEnv.service,
      SUPABASE_SECRET_KEYS: originalEnv.secrets,
    })) {
      if (value === undefined) Deno.env.delete(key);
      else Deno.env.set(key, value);
    }
  }
});
