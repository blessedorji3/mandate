import { assertEquals } from "jsr:@std/assert@1";
import { KeyPairEd25519, KeyPairSigner } from "npm:near-api-js@7.3.1";
import { recoveryTestUtils } from "./recovery-security.ts";

const OWNER_ID = "10000000-0000-4000-8000-000000000001";
const ACCOUNT_ID = "owner-wallet.testnet";
const RECIPIENT_ID = "confirmwithmandate.testnet";
const POLICY_ID = "30000000-0000-4000-8000-000000000001";
const POLICY_VERSION = 7;
const ORIGIN = "https://mandate-snowy.vercel.app";
const PROJECT_URL = "https://mandate-transfer-lifecycle-test.invalid";
const OWNER_TOKEN = "valid-transfer-owner-token";
const TRANSFER_AMOUNT = "1000000000000000000000";
const APP_RECIPIENT = "mandate-snowy.vercel.app";
const BASE58 = recoveryTestUtils.base58Encode;

function jsonBody(value: unknown): Record<string, unknown> {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

Deno.test("NEAR transfer authorization completes the signed HTTP lifecycle under require_approval_for_all_actions", async () => {
  const originalFetch = globalThis.fetch;
  const originalEnv = {
    url: Deno.env.get("SUPABASE_URL"),
    anon: Deno.env.get("SUPABASE_ANON_KEY"),
    service: Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"),
    secretKeys: Deno.env.get("SUPABASE_SECRET_KEYS"),
  };

  const signer = new KeyPairSigner(KeyPairEd25519.fromRandom());
  const publicKey = (await signer.getPublicKey()).toString();
  const historyHash = BASE58(new Uint8Array(32).fill(3));
  const blockHash = BASE58(new Uint8Array(32).fill(11));
  const validTransactionHash = BASE58(new Uint8Array(32).fill(13));
  const wrongRecipientHash = BASE58(new Uint8Array(32).fill(17));
  const wrongAmountHash = BASE58(new Uint8Array(32).fill(19));
  const secondTransactionHash = BASE58(new Uint8Array(32).fill(23));
  const accountCreatedAt = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

  const policy = {
    id: POLICY_ID,
    version: POLICY_VERSION,
    active: true,
    max_amount_atomic: TRANSFER_AMOUNT,
    allowed_recipients: [RECIPIENT_ID],
    allowed_action_types: ["transfer"],
    require_approval_for_token_approvals: true,
    require_approval_for_all_actions: true,
  };

  let insertedDecision: Record<string, unknown> | null = null;
  let storedChallenge: Record<string, unknown> | null = null;
  let challengeFinalized = false;
  let expectedReceiptHash = "";
  let receiptConsumed = false;
  let boundTransactionHash = "";
  let finalizationCalls = 0;
  let consumeCalls = 0;
  let bindCalls = 0;
  const rpcCalls: Array<{ name: string; body: Record<string, unknown> }> = [];
  const ownersSeen: string[] = [];

  Deno.env.set("SUPABASE_URL", PROJECT_URL);
  Deno.env.set("SUPABASE_ANON_KEY", "test-anon-key");
  Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
  Deno.env.delete("SUPABASE_SECRET_KEYS");

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === "string" ? jsonBody(JSON.parse(init.body)) : {};
    const rpcName = url.match(/\/rest\/v1\/rpc\/([^/?]+)/)?.[1];

    if (url.endsWith("/auth/v1/user")) {
      return headers.get("authorization") === "Bearer " + OWNER_TOKEN
        ? Response.json({ id: OWNER_ID })
        : Response.json({ message: "Invalid JWT" }, { status: 401 });
    }

    if (rpcName) {
      rpcCalls.push({ name: rpcName, body });
      ownersSeen.push(String(body.p_owner_id ?? ""));

      switch (rpcName) {
        case "get_near_wallet_recovery_lifecycle_v1":
          return Response.json([{ request_status: null }]);
        case "get_near_owner_wallet_v1":
          return Response.json(body.p_owner_id === OWNER_ID && body.p_account_id === ACCOUNT_ID
            ? [{
                account_id: ACCOUNT_ID,
                public_key: publicKey,
                verified_at: new Date().toISOString(),
                revoked_at: null,
              }]
            : []);
        case "lookup_counterparty_blocklist":
          return Response.json([]);
        case "create_near_transfer_challenge_v2": {
          storedChallenge = {
            id: body.p_id,
            nonce_hex: body.p_nonce_hex,
            message: body.p_message,
            signer_account_id: body.p_signer_account_id,
            policy_id: body.p_policy_id,
            policy_version: body.p_policy_version,
            proposal_id: body.p_proposal_id,
            action_digest: body.p_action_digest,
            network: "testnet",
            receiver_id: RECIPIENT_ID,
            asset: "NEAR",
            amount_atomic: TRANSFER_AMOUNT,
            action_type: "transfer",
          };
          return Response.json(body.p_id);
        }
        case "get_near_transfer_challenge_v2":
          return Response.json(
            !challengeFinalized && body.p_owner_id === OWNER_ID &&
              body.p_id === storedChallenge?.id && storedChallenge
              ? [storedChallenge]
              : [],
          );
        case "finalize_near_transfer_challenge_v2":
          finalizationCalls++;
          if (body.p_owner_id !== OWNER_ID || body.p_id !== storedChallenge?.id ||
              typeof body.p_token_hash !== "string" || challengeFinalized) {
            return Response.json(false);
          }
          expectedReceiptHash = body.p_token_hash;
          challengeFinalized = true;
          return Response.json(true);
        case "get_near_transfer_risk_binding_v1":
          if (body.p_owner_id !== OWNER_ID || body.p_token_hash !== expectedReceiptHash ||
              !insertedDecision) return Response.json([]);
          return Response.json([{
            proposal_id: insertedDecision.proposal_id,
            policy_id: insertedDecision.policy_id,
            policy_version: insertedDecision.policy_version,
            proposal: insertedDecision.proposal,
          }]);
        case "consume_near_transfer_authorization_v2": {
          consumeCalls++;
          const exact =
            body.p_owner_id === OWNER_ID &&
            body.p_token_hash === expectedReceiptHash &&
            body.p_signer_account_id === ACCOUNT_ID &&
            body.p_network === "testnet" &&
            body.p_receiver_id === RECIPIENT_ID &&
            body.p_asset === "NEAR" &&
            body.p_amount_atomic === TRANSFER_AMOUNT &&
            body.p_action_type === "transfer" &&
            body.p_action_digest === storedChallenge?.action_digest;
          if (!exact || receiptConsumed || !challengeFinalized) return Response.json(false);
          receiptConsumed = true;
          return Response.json(true);
        }
        case "bind_near_transfer_transaction_v1": {
          bindCalls++;
          const eligible =
            body.p_owner_id === OWNER_ID &&
            body.p_token_hash === expectedReceiptHash &&
            body.p_signer_account_id === ACCOUNT_ID &&
            body.p_transaction_timestamp_ns !== undefined &&
            receiptConsumed &&
            (!boundTransactionHash || body.p_transaction_hash === boundTransactionHash);
          if (!eligible) return Response.json(false);
          boundTransactionHash = String(body.p_transaction_hash);
          return Response.json(true);
        }
        default:
          return Response.json({ message: "Unexpected RPC: " + rpcName }, { status: 500 });
      }
    }

    if (url.includes("/rest/v1/security_policies")) {
      return Response.json(policy);
    }

    if (url.includes("/rest/v1/authorization_decisions")) {
      if (method === "HEAD") {
        return new Response(null, { status: 200, headers: { "content-range": "*/0" } });
      }
      if (method === "POST") {
        insertedDecision = Array.isArray(body) ? jsonBody(body[0]) : body;
        return new Response(null, { status: 201, headers: { "content-range": "*/1" } });
      }
      if (method === "GET") {
        return insertedDecision
          ? Response.json(insertedDecision)
          : new Response(null, { status: 406 });
      }
    }

    if (url.startsWith("https://tx.test.fastnear.com/v0/account")) {
      return Response.json({
        account_txs: [{
          account_id: RECIPIENT_ID,
          transaction_hash: historyHash,
          tx_block_timestamp: accountCreatedAt,
          tx_block_height: 100,
        }],
        txs_count: 1,
        resume_token: null,
      });
    }

    if (url.endsWith("/v0/transactions")) {
      return Response.json({
        transactions: [{
          transaction: {
            hash: historyHash,
            receiver_id: RECIPIENT_ID,
            actions: [{ CreateAccount: {} }],
          },
        }],
      });
    }

    if (url === "https://rpc.testnet.near.org") {
      const rpcBody = body;
      if (rpcBody.id === "mandate-risk-status") {
        return Response.json({
          jsonrpc: "2.0",
          id: rpcBody.id,
          result: { chain_id: "testnet", sync_info: { latest_block_height: 20_000 } },
        });
      }
      if (rpcBody.id === "mandate-risk-account") {
        return Response.json({
          jsonrpc: "2.0",
          id: rpcBody.id,
          result: {
            code_hash: "11111111111111111111111111111111",
            amount: "0",
            locked: "0",
            storage_usage: 0,
          },
        });
      }
    }

    if (url === "https://rpc.testnet.fastnear.com") {
      if (body.id === "mandate-access-key-check") {
        return Response.json({
          jsonrpc: "2.0",
          id: body.id,
          result: { keys: [{ public_key: publicKey, access_key: { permission: "FullAccess" } }] },
        });
      }
      if (body.id === "mandate-verify-transfer") {
        const requestedHash = String(jsonBody(body.params).tx_hash ?? "");
        const sender = String(jsonBody(body.params).sender_account_id ?? "");
        const tx = {
          hash: requestedHash,
          signer_id: sender === "attacker-wallet.testnet" ? ACCOUNT_ID : sender,
          receiver_id: requestedHash === wrongRecipientHash ? "attacker.testnet" : RECIPIENT_ID,
          actions: [{
            Transfer: {
              deposit: requestedHash === wrongAmountHash ? "999000000000000000000" : TRANSFER_AMOUNT,
            },
          }],
        };
        return Response.json({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            transaction: tx,
            final_execution_status: "FINAL",
            status: { SuccessValue: "" },
            transaction_outcome: { block_hash: blockHash },
          },
        });
      }
      if (body.id === "mandate-verify-transfer-block") {
        return Response.json({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            header: { timestamp_nanosec: String(BigInt(Date.now() + 5_000) * 1_000_000n) },
          },
        });
      }
    }

    return Response.json({
      message: "Unexpected integration-test request",
      method,
      url,
      body,
    }, { status: 500 });
  }) as typeof fetch;

  try {
    // Load the real Edge Function after test credentials and fetch interception are installed.
    const { handleRequest } = await import("./index.ts");
    const endpoint = PROJECT_URL + "/functions/v1/near-transfer-authorization";
    const post = async (action: string, fields: Record<string, unknown> = {}) => {
      const response = await handleRequest(new Request(endpoint, {
        method: "POST",
        headers: {
          origin: ORIGIN,
          "content-type": "application/json",
          authorization: "Bearer " + OWNER_TOKEN,
        },
        body: JSON.stringify({
          action,
          ...fields,
          // Browser-supplied ownership must never override the authenticated JWT user.
          ownerId: "10000000-0000-4000-8000-000000000099",
        }),
      }));
      return { response, body: jsonBody(await response.json()) };
    };

    const challenged = await post("challenge", { signerAccountId: ACCOUNT_ID });
    assertEquals(challenged.response.status, 200, JSON.stringify(challenged.body));
    const challenge = challenged.body;
    assertEquals((challenge.decision as Record<string, unknown>).outcome, "REQUIRE_APPROVAL");
    assertEquals(policy.require_approval_for_all_actions, true);
    assertEquals(challenge.intent, {
      network: "testnet",
      receiverId: RECIPIENT_ID,
      asset: "NEAR",
      amountAtomic: TRANSFER_AMOUNT,
      actionType: "transfer",
      signerId: ACCOUNT_ID,
    });
    assert(String(challenge.message).includes("I explicitly approve this exact Testnet transfer"));
    assert(String(challenge.message).includes("Network: testnet"));
    assert(String(challenge.message).includes("Amount (yoctoNEAR): " + TRANSFER_AMOUNT));
    assert(String(challenge.message).includes("Recipient: " + RECIPIENT_ID));
    assert(String(challenge.message).includes("Policy: " + POLICY_ID + " version " + POLICY_VERSION));
    assert(String(challenge.message).includes("Proposal: "));
    assert(String(challenge.message).includes("Challenge: " + challenge.challengeId));
    assert(String(challenge.message).includes("Nonce: " + challenge.nonceHex));
    assertEquals(
      rpcCalls.find((call) => call.name === "create_near_transfer_challenge_v2")?.body.p_owner_id,
      OWNER_ID,
      "the database owner must come from the authenticated Supabase user",
    );
    assertEquals(
      (insertedDecision?.outcome),
      "REQUIRE_APPROVAL",
      "the challenged authorization decision must retain the policy-required approval outcome",
    );

    const nonce = Uint8Array.from(
      String(challenge.nonceHex).match(/.{2}/g)!.map((part) => Number.parseInt(part, 16)),
    );
    const signed = await signer.signNep413Message(ACCOUNT_ID, {
      message: String(challenge.message),
      nonce,
      recipient: String(challenge.recipient ?? APP_RECIPIENT),
    });
    const signedPayload = {
      accountId: ACCOUNT_ID,
      publicKey: signed.publicKey.toString(),
      signature: base64(signed.signature),
    };

    const invalidSignatureBytes = signed.signature.slice();
    invalidSignatureBytes[0] ^= 0x80;
    const invalidSignature = await post("verify", {
      challengeId: challenge.challengeId,
      signedMessage: { ...signedPayload, signature: base64(invalidSignatureBytes) },
    });
    assertEquals(invalidSignature.response.status, 403, "a byte-tampered NEP-413 signature must be rejected");
    assertEquals(finalizationCalls, 0, "an invalid signature must not issue a receipt");

    const wrongAccount = await post("verify", {
      challengeId: challenge.challengeId,
      signedMessage: { ...signedPayload, accountId: "attacker-wallet.testnet" },
    });
    assertEquals(wrongAccount.response.status, 403, "a substituted signer account must be rejected");
    assertEquals(finalizationCalls, 0);

    const wrongKey = await post("verify", {
      challengeId: challenge.challengeId,
      signedMessage: {
        ...signedPayload,
        publicKey: "ed25519:" + BASE58(new Uint8Array(32).fill(29)),
      },
    });
    assertEquals(wrongKey.response.status, 403, "a substituted registered public key must be rejected");
    assertEquals(finalizationCalls, 0);

    const signedWrongMessage = await signer.signNep413Message(ACCOUNT_ID, {
      message: String(challenge.message) + "\nRecipient: attacker.testnet",
      nonce,
      recipient: String(challenge.recipient ?? APP_RECIPIENT),
    });
    const substitutedMessage = await post("verify", {
      challengeId: challenge.challengeId,
      signedMessage: {
        accountId: ACCOUNT_ID,
        publicKey: signedWrongMessage.publicKey.toString(),
        signature: base64(signedWrongMessage.signature),
      },
    });
    assertEquals(substitutedMessage.response.status, 403, "a valid signature over a substituted message must fail");

    const verified = await post("verify", {
      challengeId: challenge.challengeId,
      signedMessage: signedPayload,
    });
    assertEquals(verified.response.status, 200, JSON.stringify(verified.body));
    assertEquals(verified.body.authorized, true);
    assertEquals(typeof verified.body.receipt, "string");
    assertEquals(String(verified.body.receipt).length, 64);
    assertEquals(finalizationCalls, 1, "only the valid exact-message signature may finalize the challenge");

    const replayedChallenge = await post("verify", {
      challengeId: challenge.challengeId,
      signedMessage: signedPayload,
    });
    assertEquals(replayedChallenge.response.status, 409, "the finalized challenge must not issue a second receipt");
    assertEquals(finalizationCalls, 1);

    const receipt = String(verified.body.receipt);
    const invalidReceipt = await post("consume", {
      receipt: "f".repeat(64),
      signerAccountId: ACCOUNT_ID,
    });
    assertEquals(invalidReceipt.response.status, 409, "an unissued receipt must not be consumed");
    assertEquals(consumeCalls, 0);

    const wrongSignerConsume = await post("consume", {
      receipt,
      signerAccountId: "attacker-wallet.testnet",
    });
    assertEquals(wrongSignerConsume.response.status, 409, "a receipt cannot be consumed by a substituted signer");
    assertEquals(receiptConsumed, false);

    const consumed = await post("consume", { receipt, signerAccountId: ACCOUNT_ID });
    assertEquals(consumed.response.status, 200, JSON.stringify(consumed.body));
    assertEquals(consumed.body.consumed, true);
    assertEquals(receiptConsumed, true);

    const replayedReceipt = await post("consume", { receipt, signerAccountId: ACCOUNT_ID });
    assertEquals(replayedReceipt.response.status, 409, "a consumed one-time receipt must reject replay");
    assertEquals(consumeCalls, 3, "only the signer mismatch, first valid use and replay reach the consume RPC");

    const bindsBeforeSubstitution = bindCalls;
    const malformedTransactionHash = await post("verify_transaction", {
      transactionHash: "0".repeat(43),
      signerAccountId: ACCOUNT_ID,
      receipt,
    });
    assertEquals(
      malformedTransactionHash.response.status,
      409,
      "malformed Base58 transaction hashes must be rejected as invalid input",
    );
    assertEquals(malformedTransactionHash.body.code, "TRANSACTION_DOES_NOT_MATCH_AUTHORIZATION");
    assertEquals(bindCalls, bindsBeforeSubstitution, "malformed hashes must never reach receipt binding");

    for (const transactionHash of [wrongRecipientHash, wrongAmountHash]) {
      const substitutedTransaction = await post("verify_transaction", {
        transactionHash,
        signerAccountId: ACCOUNT_ID,
        receipt,
      });
      assertEquals(
        substitutedTransaction.response.status,
        409,
        "a finalized transaction with substituted recipient or amount must be rejected",
      );
      assertEquals(substitutedTransaction.body.code, "TRANSACTION_DOES_NOT_MATCH_AUTHORIZATION");
      assertEquals(bindCalls, bindsBeforeSubstitution, "a mismatched transaction must never reach receipt binding");
    }

    const wrongTransactionSigner = await post("verify_transaction", {
      transactionHash: validTransactionHash,
      signerAccountId: "attacker-wallet.testnet",
      receipt,
    });
    assertEquals(wrongTransactionSigner.response.status, 409, "a transaction from another signer must be rejected");
    assertEquals(bindCalls, bindsBeforeSubstitution);

    const wrongReceiptBinding = await post("verify_transaction", {
      transactionHash: validTransactionHash,
      signerAccountId: ACCOUNT_ID,
      receipt: "e".repeat(64),
    });
    assertEquals(wrongReceiptBinding.response.status, 409, "a valid chain transfer cannot bind to a substituted receipt");
    assertEquals(wrongReceiptBinding.body.code, "AUTHORIZATION_RECEIPT_NOT_BOUND");
    assertEquals(boundTransactionHash, "");

    const bound = await post("verify_transaction", {
      transactionHash: validTransactionHash,
      signerAccountId: ACCOUNT_ID,
      receipt,
    });
    assertEquals(bound.response.status, 200, JSON.stringify(bound.body));
    assertEquals(bound.body.verified, true);
    assertEquals(bound.body.authorizationBound, true);
    assertEquals(bound.body.transactionHash, validTransactionHash);
    assertEquals(boundTransactionHash, validTransactionHash);

    const replayedTransaction = await post("verify_transaction", {
      transactionHash: secondTransactionHash,
      signerAccountId: ACCOUNT_ID,
      receipt,
    });
    assertEquals(replayedTransaction.response.status, 409, "the same one-time receipt must not authorize a second transaction");
    assertEquals(replayedTransaction.body.code, "AUTHORIZATION_RECEIPT_NOT_BOUND");
    assertEquals(boundTransactionHash, validTransactionHash);

    assertEquals(
      ownersSeen.filter((ownerId) => ownerId.length > 0).every((ownerId) => ownerId === OWNER_ID),
      true,
      "every privileged database call must use the authenticated owner identity",
    );
  } finally {
    globalThis.fetch = originalFetch;
    for (const [key, value] of Object.entries({
      SUPABASE_URL: originalEnv.url,
      SUPABASE_ANON_KEY: originalEnv.anon,
      SUPABASE_SERVICE_ROLE_KEY: originalEnv.service,
      SUPABASE_SECRET_KEYS: originalEnv.secretKeys,
    })) {
      if (value === undefined) Deno.env.delete(key);
      else Deno.env.set(key, value);
    }
  }
});
