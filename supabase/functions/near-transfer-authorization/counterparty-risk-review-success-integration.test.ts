import { assert, assertEquals } from "jsr:@std/assert@1";
import { KeyPairEd25519, KeyPairSigner } from "npm:near-api-js@7.3.1";
import { collectAndEvaluateNearTestnetCounterparty } from "../../../src/security/collect-counterparty-risk.ts";
import { fingerprintCounterpartyRisk } from "../../../src/security/counterparty-risk-review.ts";

const OWNER_ID = "71000000-0000-4000-8000-000000000001";
const POLICY_ID = "72000000-0000-4000-8000-000000000001";
const REPORT_PROPOSAL_ID = "phase2-risk-positive-001";
const ACCOUNT_ID = "owner-wallet.testnet";
const COUNTERPARTY = "confirmwithmandate.testnet";
const ORIGIN = "https://mandate-git-feat-phase-2-counterparty-risk-web3pass.vercel.app";
const PROJECT_URL = "https://mandate-review-success.invalid";
const OWNER_TOKEN = "valid-review-owner-token";
const APP_RECIPIENT = "mandate-snowy.vercel.app";

function jsonBody(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
}
function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

Deno.test("valid NEP-413 WARN acknowledgement completes the proposal-bound HTTP review once", async () => {
  const originalFetch = globalThis.fetch;
  const originalEnv = {
    url: Deno.env.get("SUPABASE_URL"),
    anon: Deno.env.get("SUPABASE_ANON_KEY"),
    service: Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"),
  };
  const signer = new KeyPairSigner(KeyPairEd25519.fromRandom());
  const publicKey = (await signer.getPublicKey()).toString();
  const rpcCalls: Array<{ name: string; body: Record<string, unknown> }> = [];
  const ownerIds: string[] = [];
  const reviewId = "73000000-0000-4000-8000-000000000001";
  const challengeRows: Array<Record<string, unknown>> = [];
  let challengeConsumed = false;
  let completeCalls = 0;

  const policy = {
    id: POLICY_ID, version: 3, active: true,
    max_amount_atomic: "1000000000000000000000",
    allowed_recipients: [COUNTERPARTY],
    allowed_action_types: ["transfer"],
    require_approval_for_token_approvals: true,
    require_approval_for_all_actions: false,
  };

  const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === "string" ? jsonBody(JSON.parse(init.body)) : {};
    if (url === "https://rpc.testnet.near.org") {
      if (body.method === "status") {
        return Response.json({ jsonrpc: "2.0", id: body.id, result: {
          chain_id: "testnet", sync_info: { latest_block_height: 321 },
        } });
      }
      if (body.method === "query") {
        return Response.json({ jsonrpc: "2.0", id: body.id, result: {
          code_hash: "11111111111111111111111111111111",
          amount: "0", locked: "0", storage_usage: 0,
        } });
      }
    }
    if (url.startsWith("https://tx.test.fastnear.com/v0/account")) {
      return Response.json({ account_txs: [], txs_count: 0, resume_token: null });
    }
    if (url === "https://rpc.testnet.fastnear.com" && body.id === "mandate-access-key-check") {
      return Response.json({ jsonrpc: "2.0", id: body.id, result: {
        keys: [{ public_key: publicKey, access_key: { permission: "FullAccess" } }],
      } });
    }
    const rpcName = url.match(/\/rest\/v1\/rpc\/([^/?]+)/)?.[1];
    if (rpcName) {
      rpcCalls.push({ name: rpcName, body });
      if (body.p_owner_id) ownerIds.push(String(body.p_owner_id));
      if (rpcName === "lookup_counterparty_blocklist") return Response.json([]);
      if (rpcName === "get_near_owner_wallet_v1") {
        return Response.json(body.p_owner_id === OWNER_ID && body.p_account_id === ACCOUNT_ID
          ? [{ account_id: ACCOUNT_ID, public_key: publicKey, revoked_at: null }] : []);
      }
      if (rpcName === "create_counterparty_risk_review_challenge_v1") {
        const challengeRow: Record<string, unknown> = {
          id: body.p_id,
          proposal_id: body.p_proposal_id,
          policy_id: body.p_policy_id,
          policy_version: body.p_policy_version,
          target_account_id: body.p_target_account_id,
          risk_fingerprint: body.p_risk_fingerprint,
          signer_account_id: body.p_signer_account_id,
          signer_public_key: body.p_signer_public_key,
          nonce_hex: body.p_nonce_hex,
          message: body.p_message,
          expires_at: new Date(Date.now() + 180_000).toISOString(),
        };
        challengeRows.push(challengeRow);
        return Response.json(body.p_id);
      }
      if (rpcName === "get_counterparty_risk_review_challenge_v1") {
        const currentChallenge = challengeRows[challengeRows.length - 1];
        return Response.json(!challengeConsumed && body.p_owner_id === OWNER_ID &&
          body.p_id === currentChallenge?.id ? [currentChallenge] : []);
      }
      if (rpcName === "complete_counterparty_risk_review_v1") {
        completeCalls++;
        const currentChallenge = challengeRows[challengeRows.length - 1];
        if (body.p_owner_id !== OWNER_ID || body.p_id !== currentChallenge?.id ||
            typeof body.p_wallet_signature !== "string" || challengeConsumed) return Response.json(null);
        challengeConsumed = true;
        return Response.json(reviewId);
      }
      return Response.json({ message: "Unexpected RPC: " + rpcName }, { status: 500 });
    }
    if (url.endsWith("/auth/v1/user")) {
      return headers.get("authorization") === "Bearer " + OWNER_TOKEN
        ? Response.json({ id: OWNER_ID })
        : Response.json({ message: "Invalid JWT" }, { status: 401 });
    }
    if (url.includes("/rest/v1/security_policies")) return Response.json(policy);
    if (url.includes("/rest/v1/authorization_decisions")) {
      if (method === "HEAD") {
        return new Response(null, { status: 200, headers: { "content-range": "*/0" } });
      }
      return Response.json({
        proposal_id: REPORT_PROPOSAL_ID,
        policy_id: POLICY_ID,
        policy_version: policy.version,
        outcome: "REQUIRE_APPROVAL",
        proposal: {},
      });
    }
    return Response.json({ message: "Unexpected request", url, method }, { status: 500 });
  };

  // Compute the exact warning/fingerprint using the same deterministic collectors
  // and controlled upstream data that the Edge Function will subsequently read.
  globalThis.fetch = fetchImpl as typeof fetch;
  Deno.env.set("SUPABASE_URL", PROJECT_URL);
  Deno.env.set("SUPABASE_ANON_KEY", "test-anon-key");
  Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");

  try {
    const initial = await collectAndEvaluateNearTestnetCounterparty(COUNTERPARTY, {
      fetchImpl: fetchImpl as typeof fetch,
      previousInteractions: 0,
      blocklistLookupStatus: "verified",
    });
    assertEquals(initial.decision.outcome, "WARN");
    const proposal = {
      id: REPORT_PROPOSAL_ID,
      agentId: "phase2-review-test",
      actionType: "transfer",
      asset: "NEAR",
      amountAtomic: "1000000000000000000000",
      target: COUNTERPARTY,
      network: "testnet",
    };
    const fingerprint = await fingerprintCounterpartyRisk({
      ownerId: OWNER_ID, policyId: POLICY_ID, policyVersion: policy.version,
      proposal, risk: initial.decision,
    });
    const recordedProposal = {
      ...proposal,
      counterpartyRisk: {
        ...initial.decision,
        // Simulate an upstream reason containing Unicode punctuation and
        // diacritics; the wallet-signed challenge must still be ASCII-only.
        reasons: ["External review note — café evidence.", ...initial.decision.reasons],
      },
      counterpartyRiskFingerprint: fingerprint,
    };

    // Set the proposal after its cryptographic fingerprint has been produced.
    const responseFor = async (action: string, fields: Record<string, unknown> = {}) => {
      const request = new Request(PROJECT_URL + "/functions/v1/near-transfer-authorization", {
        method: "POST",
        headers: {
          origin: ORIGIN,
          "content-type": "application/json",
          authorization: "Bearer " + OWNER_TOKEN,
        },
        body: JSON.stringify({
          action, ...fields,
          // Untrusted client ownership must never override the Auth identity.
          ownerId: "71000000-0000-4000-8000-000000000099",
        }),
      });
      const response = await handleRequest(request);
      return { response, body: jsonBody(await response.json()) };
    };
    const { handleRequest } = await import("./index.ts");

    // Exercise the same authenticated inspection action used by the Next.js API.
    // Its evidence fingerprint must match the later signed-review challenge.
    const sharedInspection = await responseFor("counterparty_inspect", { proposal });
    assertEquals(sharedInspection.response.status, 200, JSON.stringify(sharedInspection.body));
    assertEquals(sharedInspection.body.counterpartyRiskFingerprint, fingerprint);
    const sharedRisk = sharedInspection.body.risk;
    assert(typeof sharedRisk === "object" && sharedRisk !== null && !Array.isArray(sharedRisk));
    assertEquals((sharedRisk as Record<string, unknown>).outcome, initial.decision.outcome);

    // The test fetch is swapped to serve the correctly fingerprinted inspection.
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/rest/v1/authorization_decisions")) {
        if (init?.method === "HEAD") {
          return new Response(null, { status: 200, headers: { "content-range": "*/0" } });
        }
        return Response.json({
          proposal_id: REPORT_PROPOSAL_ID, policy_id: POLICY_ID,
          policy_version: policy.version, outcome: "REQUIRE_APPROVAL",
          proposal: recordedProposal,
        });
      }
      return fetchImpl(input, init);
    }) as typeof fetch;

    const challenged = await responseFor("risk_review_challenge", {
      proposalId: REPORT_PROPOSAL_ID,
      signerAccountId: ACCOUNT_ID,
    });
    assertEquals(challenged.response.status, 200, JSON.stringify(challenged.body));
    assertEquals(challenged.body.riskFingerprint, fingerprint);
    assertEquals(challenged.body.expiresInSeconds, 300, "risk-review challenge lifetime must match the five-minute UI");
    assertEquals(typeof challenged.body.message, "string");
    assertEquals(
      String(challenged.body.message).split("").every((character) => {
        const code = character.charCodeAt(0);
        return (code >= 0x20 && code <= 0x7e) || character === "\r" || character === "\n";
      }),
      true,
      "the exact Meteor NEP-413 risk-review challenge must be ASCII-only, including sanitized external warning reasons",
    );
    assert(String(challenged.body.message).includes("External review note - cafe evidence."));

    const nonce = Uint8Array.from(
      String(challenged.body.nonceHex).match(/.{2}/g)!.map((part) => Number.parseInt(part, 16)),
    );
    const callbackUrl = ORIGIN + "/agent?review=phase2";
    const signed = await signer.signNep413Message(ACCOUNT_ID, {
      message: String(challenged.body.message),
      nonce,
      recipient: String(challenged.body.recipient ?? APP_RECIPIENT),
      callbackUrl,
    });
    const signedMessage = {
      accountId: ACCOUNT_ID,
      publicKey: signed.publicKey.toString(),
      signature: base64(signed.signature),
    };
    // A same-origin full-page callback is accepted, but a callback to any
    // other origin must fail before the challenge can be consumed.
    const foreignCallback = await responseFor("risk_review_verify", {
      challengeId: challenged.body.challengeId,
      callbackUrl: "https://attacker.example/collect",
      signedMessage,
    });
    assertEquals(foreignCallback.response.status, 400);
    assertEquals(completeCalls, 0);

    const verified = await responseFor("risk_review_verify", {
      challengeId: challenged.body.challengeId,
      callbackUrl,
      signedMessage,
    });
    assertEquals(verified.response.status, 200, JSON.stringify(verified.body));
    assertEquals(verified.body.reviewed, true);
    assertEquals(verified.body.reviewId, reviewId);
    assertEquals(verified.body.riskFingerprint, fingerprint);
    assertEquals(completeCalls, 1);

    const replay = await responseFor("risk_review_verify", {
      challengeId: challenged.body.challengeId,
      signedMessage,
    });
    assertEquals(replay.response.status, 409, "a completed review challenge cannot be replayed");
    assertEquals(completeCalls, 1, "replay must not create a second audit/review record");
    assert(ownerIds.every((ownerId) => ownerId === OWNER_ID), "all RPC actor identities must come from verified Auth");
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
