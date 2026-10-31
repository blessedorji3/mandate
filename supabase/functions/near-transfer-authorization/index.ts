import { createClient } from "npm:@supabase/supabase-js@2.57.0";

const PROJECT_URL = Deno.env.get("SUPABASE_URL")!;
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ?? "";
const SECRET_KEYS = Deno.env.get("SUPABASE_SECRET_KEYS");
let SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
try { if (SECRET_KEYS) SERVICE_KEY = JSON.parse(SECRET_KEYS).default ?? SERVICE_KEY; } catch { /* retain legacy service role key */ }
const APP_RECIPIENT = "mandate-snowy.vercel.app";
const TEST_TRANSFER = {
  network: "testnet",
  receiverId: "confirmwithmandate.testnet",
  asset: "NEAR",
  amountAtomic: "1000000000000000000000",
  actionType: "transfer",
} as const;
const corsHeaders = {
  "Access-Control-Allow-Origin": "https://mandate-snowy.vercel.app",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};
const headers = { "Cache-Control": "no-store", ...corsHeaders };
const json = (body: unknown, status = 200) => Response.json(body, { status, headers });
const encoder = new TextEncoder();

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function hex(bytes: Uint8Array) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(value: string) {
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error("Invalid hex");
  return Uint8Array.from(value.match(/.{2}/g)!, (b) => parseInt(b, 16));
}
function base58Decode(value: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = 0n;
  for (const char of value) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) throw new Error("Invalid base58");
    n = n * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (n > 0n) { bytes.unshift(Number(n & 255n)); n >>= 8n; }
  for (let i = 0; i < value.length && value[i] === "1"; i++) bytes.unshift(0);
  return Uint8Array.from(bytes);
}
function base64Decode(value: string) {
  const binary = atob(value);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}
function concat(...parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
function u32(value: number) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}
function borshString(value: string) {
  const bytes = encoder.encode(value);
  return concat(u32(bytes.length), bytes);
}
function nep413Bytes(message: string, nonce: Uint8Array, recipient: string) {
  if (nonce.length !== 32) throw new Error("NEP-413 nonce must be 32 bytes");
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, 0x80000000 + 413, true);
  // callback_url is None; Borsh Option uses a single zero byte.
  return concat(prefix, borshString(message), nonce, borshString(recipient), new Uint8Array([0]));
}
async function sha256(bytes: Uint8Array) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
async function authenticate(req: Request) {
  const authorization = req.headers.get("authorization") ?? "";
  if (!authorization.startsWith("Bearer ")) return null;
  const userClient = createClient(PROJECT_URL, ANON_KEY, {
    global: { headers: { Authorization: authorization } },
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const { data, error } = await userClient.auth.getUser();
  if (error || !data.user) return null;
  return data.user;
}
async function getPolicy(admin: ReturnType<typeof createClient>, ownerId: string) {
  const { data, error } = await admin.from("security_policies")
    .select("id, version, active, max_amount_atomic, allowed_recipients, allowed_action_types, require_approval_for_token_approvals, require_approval_for_all_actions")
    .eq("owner_id", ownerId).eq("active", true)
    .order("updated_at", { ascending: false }).limit(1).maybeSingle();
  if (error) throw new Error("Could not load the active security policy");
  return data;
}
function evaluateTestTransferPolicy(policy: Record<string, unknown>) {
  if (policy.active !== true ||
      !Array.isArray(policy.allowed_action_types) || !policy.allowed_action_types.includes("transfer")) {
    return { outcome: "BLOCK", reason: "ACTION_NOT_ALLOWED", message: "The active policy does not permit NEAR transfers." };
  }
  if (typeof policy.max_amount_atomic !== "string" ||
      !/^[1-9][0-9]*$/.test(policy.max_amount_atomic) ||
      BigInt(policy.max_amount_atomic) < BigInt(TEST_TRANSFER.amountAtomic)) {
    return { outcome: "BLOCK", reason: "AMOUNT_LIMIT_EXCEEDED", message: "The test transfer exceeds the active policy amount limit." };
  }
  if (!Array.isArray(policy.allowed_recipients) ||
      !policy.allowed_recipients.includes(TEST_TRANSFER.receiverId)) {
    return { outcome: "BLOCK", reason: "RECIPIENT_NOT_ALLOWED", message: "The test recipient is not approved by the active policy." };
  }
  if (policy.require_approval_for_all_actions === true) {
    return { outcome: "REQUIRE_APPROVAL", reason: "OWNER_APPROVAL_REQUIRED", message: "The active policy requires an additional owner approval workflow." };
  }
  if (policy.require_approval_for_all_actions !== false) {
    return { outcome: "BLOCK", reason: "INVALID_POLICY", message: "The active policy approval setting is invalid." };
  }
  return { outcome: "ALLOW", reason: "POLICY_CHECKS_PASSED", message: "The exact NEAR Testnet transfer satisfies the active policy." };
}
async function rpcViewAccessKeys(accountId: string) {
  const response = await fetch("https://rpc.testnet.near.org", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: "mandate-access-key-check", method: "query",
      params: { request_type: "view_access_key_list", finality: "final", account_id: accountId },
    }),
  });
  if (!response.ok) throw new Error("NEAR Testnet RPC unavailable");
  const result = await response.json();
  if (result.error || !Array.isArray(result.result?.keys)) throw new Error("Could not verify NEAR account access keys");
  return result.result.keys as Array<{ public_key: string; access_key: { permission: unknown } }>;
}
async function verifyNep413(message: string, nonce: Uint8Array, recipient: string, publicKey: string, signature: string) {
  const [keyType, encodedKey] = publicKey.split(":");
  if (keyType !== "ed25519" || !encodedKey) return false;
  const key = base58Decode(encodedKey);
  const sig = base64Decode(signature);
  if (key.length !== 32 || sig.length !== 64) return false;
  const digest = await sha256(nep413Bytes(message, nonce, recipient));
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "Ed25519" }, false, ["verify"]);
  return await crypto.subtle.verify({ name: "Ed25519" }, cryptoKey, sig, digest);
}

async function verifyOnChainTransfer(transactionHash: string, signerAccountId: string) {
  if (base58Decode(transactionHash).length !== 32) throw new Error("Invalid NEAR transaction hash");
  const response = await fetch("https://rpc.testnet.near.org", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: "mandate-verify-transfer",
      method: "EXPERIMENTAL_tx_status",
      params: [transactionHash, signerAccountId],
    }),
  });
  if (!response.ok) throw new Error("NEAR Testnet transaction lookup failed");
  const payload = await response.json();
  if (payload.error || !payload.result?.transaction) throw new Error("Transaction is not yet available on NEAR Testnet");
  const tx = payload.result.transaction;
  if (tx.hash !== transactionHash || tx.signer_id !== signerAccountId ||
      tx.receiver_id !== TEST_TRANSFER.receiverId || !Array.isArray(tx.actions) ||
      tx.actions.length !== 1 || tx.actions[0]?.Transfer?.deposit !== TEST_TRANSFER.amountAtomic) {
    throw new Error("On-chain transaction does not match the exact MANDATE-authorized transfer");
  }
  const status = payload.result.status;
  if (!status || typeof status !== "object" || "Failure" in status) {
    throw new Error("The NEAR Testnet transaction did not complete successfully");
  }
  return {
    verified: true,
    transactionHash,
    signerAccountId,
    receiverId: tx.receiver_id,
    amountAtomic: TEST_TRANSFER.amountAtomic,
    network: "testnet",
    status,
  };
}

async function actionDigest(signerAccountId: string) {
  const canonical = [
    "NEAR", "testnet", "transfer", signerAccountId,
    TEST_TRANSFER.receiverId, TEST_TRANSFER.amountAtomic,
  ].join("\n");
  return hex(await sha256(encoder.encode(canonical)));
}
function proposalId() {
  return "near-test-" + crypto.randomUUID();
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers });
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);
  if (req.headers.get("origin") !== "https://mandate-snowy.vercel.app") {
    return json({ error: "Origin not allowed." }, 403);
  }
  const user = await authenticate(req);
  if (!user) return json({ error: "Sign in to MANDATE before authorizing a transfer." }, 401);
  const admin = createClient(PROJECT_URL, SERVICE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  let body: unknown;
  try {
    const raw = await req.text();
    if (encoder.encode(raw).length > 12_000) return json({ error: "Request too large." }, 413);
    body = JSON.parse(raw);
  } catch {
    return json({ error: "Request body must be valid JSON." }, 400);
  }
  if (!isRecord(body) || typeof body.action !== "string") return json({ error: "An action is required." }, 400);

  try {
    if (body.action === "challenge") {
      const signer = body.signerAccountId;
      if (typeof signer !== "string" || !/^[a-z0-9._-]+\.testnet$/.test(signer)) {
        return json({ error: "Connect a valid NEAR Testnet account." }, 400);
      }
      const policy = await getPolicy(admin, user.id);
      if (!policy) return json({ error: "Create and activate a security policy before requesting authorization." }, 409);
      const evaluated = evaluateTestTransferPolicy(policy);
      const decision = {
        ...evaluated,
        policyId: policy.id, policyVersion: policy.version,
        proposalId: proposalId(),
      };
      const proposal = {
        id: decision.proposalId, agentId: "mandate-wallet-panel",
        actionType: TEST_TRANSFER.actionType, asset: TEST_TRANSFER.asset,
        amountAtomic: TEST_TRANSFER.amountAtomic, target: TEST_TRANSFER.receiverId,
        network: TEST_TRANSFER.network,
      };
      const { error: decisionError } = await admin.from("authorization_decisions").insert({
        owner_id: user.id, policy_id: policy.id, policy_version: policy.version,
        proposal_id: decision.proposalId, agent_id: "mandate-wallet-panel",
        action_type: TEST_TRANSFER.actionType, outcome: decision.outcome,
        reason: decision.reason, proposal,
      });
      if (decisionError) throw new Error("Could not record the policy decision");
      if (decision.outcome !== "ALLOW") {
        return json({ error: decision.message, decision }, 403);
      }
      const digest = await actionDigest(signer);
      const nonce = crypto.getRandomValues(new Uint8Array(32));
      const challengeId = crypto.randomUUID();
      const nonceHex = hex(nonce);
      const message = [
        "MANDATE NEAR TESTNET TRANSFER AUTHORIZATION",
        "This signature proves control of the signing account. It does not move funds.",
        `Account: ${signer}`,
        `Network: ${TEST_TRANSFER.network}`,
        `Action: ${TEST_TRANSFER.actionType}`,
        `Asset: ${TEST_TRANSFER.asset}`,
        `Amount (yoctoNEAR): ${TEST_TRANSFER.amountAtomic}`,
        `Recipient: ${TEST_TRANSFER.receiverId}`,
        `Policy: ${policy.id} version ${policy.version}`,
        `Proposal: ${decision.proposalId}`,
        `Challenge: ${challengeId}`,
        `Nonce: ${nonceHex}`,
      ].join("\n");
      const { error: insertError } = await admin.rpc("create_near_transfer_challenge_v2", {
        p_owner_id: user.id, p_id: challengeId, p_nonce_hex: nonceHex,
        p_message: message, p_signer_account_id: signer, p_policy_id: policy.id,
        p_policy_version: policy.version, p_proposal_id: decision.proposalId,
        p_action_digest: digest,
      });
      if (insertError) throw new Error("Could not create a secure wallet challenge");
      return json({
        challengeId, message, nonceHex, recipient: APP_RECIPIENT,
        intent: { ...TEST_TRANSFER, signerId: signer },
        decision, expiresInSeconds: 180,
      });
    }

    if (body.action === "verify") {
      const challengeId = body.challengeId;
      const signed = body.signedMessage;
      if (typeof challengeId !== "string" || !isRecord(signed) ||
          typeof signed.accountId !== "string" || typeof signed.publicKey !== "string" ||
          typeof signed.signature !== "string") {
        return json({ error: "A valid NEP-413 signed message is required." }, 400);
      }
      const { data: challengeRows, error: challengeError } = await admin.rpc("get_near_transfer_challenge_v2", {
        p_owner_id: user.id, p_id: challengeId,
      });
      const challenge = Array.isArray(challengeRows) ? challengeRows[0] : null;
      if (challengeError || !challenge) return json({ error: "Challenge expired, missing, or already used." }, 409);
      if (signed.accountId !== challenge.signer_account_id) return json({ error: "The signature account does not match the proposed sender." }, 403);

      const accessKeys = await rpcViewAccessKeys(signed.accountId);
      const matchingKey = accessKeys.find((entry) => entry.public_key === signed.publicKey);
      if (!matchingKey || matchingKey.access_key?.permission !== "FullAccess") {
        return json({ error: "The signing key is not a verified full-access key for this NEAR account." }, 403);
      }
      const signatureValid = await verifyNep413(
        challenge.message, fromHex(challenge.nonce_hex), APP_RECIPIENT,
        signed.publicKey, signed.signature,
      );
      if (!signatureValid) return json({ error: "NEP-413 wallet signature verification failed." }, 403);

      const policy = await getPolicy(admin, user.id);
      if (!policy || policy.id !== challenge.policy_id || policy.version !== challenge.policy_version ||
          evaluateTestTransferPolicy(policy).outcome !== "ALLOW") {
        return json({ error: "The active policy changed or no longer permits this transfer. Start again." }, 409);
      }
      const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
      const token = hex(tokenBytes);
      const tokenHash = hex(await sha256(encoder.encode(token)));
      const { data: finalized, error: finalizeError } = await admin.rpc("finalize_near_transfer_challenge_v2", {
        p_owner_id: user.id, p_id: challenge.id, p_token_hash: tokenHash,
      });
      if (finalizeError || finalized !== true) return json({ error: "Challenge could not be finalized. No authorization was issued." }, 409);
      return json({
        authorized: true, receipt: token, expiresInSeconds: 90,
        intent: {
          network: challenge.network, signerId: challenge.signer_account_id,
          receiverId: challenge.receiver_id, asset: challenge.asset,
          amountAtomic: challenge.amount_atomic, actionType: challenge.action_type,
          actionDigest: challenge.action_digest,
        },
        policy: { id: challenge.policy_id, version: challenge.policy_version },
      });
    }

    if (body.action === "consume") {
      const { receipt, signerAccountId } = body;
      if (typeof receipt !== "string" || !/^[0-9a-f]{64}$/.test(receipt) ||
          typeof signerAccountId !== "string") return json({ error: "Invalid authorization receipt." }, 400);
      const policy = await getPolicy(admin, user.id);
      if (!policy || evaluateTestTransferPolicy(policy).outcome !== "ALLOW") return json({ error: "The active policy no longer permits this transfer." }, 403);
      const tokenHash = hex(await sha256(encoder.encode(receipt)));
      const digest = await actionDigest(signerAccountId);
      const { data: consumed, error: consumeError } = await admin.rpc("consume_near_transfer_authorization_v2", {
        p_owner_id: user.id, p_token_hash: tokenHash,
        p_signer_account_id: signerAccountId, p_network: TEST_TRANSFER.network,
        p_receiver_id: TEST_TRANSFER.receiverId, p_asset: TEST_TRANSFER.asset,
        p_amount_atomic: TEST_TRANSFER.amountAtomic, p_action_type: TEST_TRANSFER.actionType,
        p_action_digest: digest,
      });
      if (consumeError || consumed !== true) return json({ error: "Authorization is expired, mismatched, replayed, or invalid." }, 409);
      return json({ consumed: true, message: "One-time authorization consumed. The wallet may now request your explicit transaction approval." });
    }


    if (body.action === "verify_transaction") {
      const { transactionHash, signerAccountId } = body;
      if (typeof transactionHash !== "string" || typeof signerAccountId !== "string" ||
          !/^[a-z0-9._-]+\\.testnet$/.test(signerAccountId)) {
        return json({ error: "A valid Testnet transaction hash and signer are required." }, 400);
      }
      const result = await verifyOnChainTransfer(transactionHash, signerAccountId);
      return json(result);
    }

    return json({ error: "Unknown action." }, 400);
  } catch (error) {
    console.error("NEAR transfer authorization error:", error instanceof Error ? error.message : "unknown");
    return json({ error: "Authorization service failed closed. No transaction was signed or sent." }, 503);
  }
});
