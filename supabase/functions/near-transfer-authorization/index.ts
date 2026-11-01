import { createClient } from "npm:@supabase/supabase-js@2.57.0";
import { findActiveFullAccessKey, isDifferentReplacementWallet, recoveryChallengeMatches, verifyNep413 } from "./recovery-security.ts";

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
const ALLOWED_ORIGINS = new Set([
  "https://mandate-snowy.vercel.app",
  "https://mandate-git-feature-near-transfer-authorization-web3pass.vercel.app",
  "https://mandate-git-feat-owner-signed-near-approval-web3pass.vercel.app",
  "https://mandate-git-feat-wallet-connection-ux-web3pass.vercel.app",
]);
function responseHeaders(origin: string) {
  return {
    "Cache-Control": "no-store",
    ...(ALLOWED_ORIGINS.has(origin) ? { "Access-Control-Allow-Origin": origin } : {}),
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}
const json = (body: unknown, status = 200, origin = "") =>
  Response.json(body, { status, headers: responseHeaders(origin) });
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
const TESTNET_RPC_ENDPOINTS = [
  "https://rpc.testnet.fastnear.com",
  "https://archival-rpc.testnet.fastnear.com",
] as const;

async function nearTestnetRpc(
  request: Record<string, unknown>,
  operation: string,
): Promise<Record<string, any>> {
  let lastFailure = "No Testnet RPC endpoint responded.";
  for (const endpoint of TESTNET_RPC_ENDPOINTS) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 9000);
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
        signal: controller.signal,
      });
      if (!response.ok) {
        lastFailure = `${endpoint} returned HTTP ${response.status}`;
        continue;
      }
      const payload = await response.json();
      if (payload.error) {
        lastFailure = payload.error.message ?? "The RPC could not return the requested Testnet data.";
        continue;
      }
      if (!payload.result || typeof payload.result !== "object") {
        lastFailure = "The RPC returned an invalid response.";
        continue;
      }
      return payload.result as Record<string, any>;
    } catch (error) {
      lastFailure = error instanceof Error ? error.message : "Unknown RPC network error.";
    } finally {
      clearTimeout(timeout);
    }
  }
  throw new Error(`${operation} failed on NEAR Testnet RPC providers: ${lastFailure}`);
}

async function rpcViewAccessKeys(accountId: string) {
  const result = await nearTestnetRpc({
    jsonrpc: "2.0", id: "mandate-access-key-check", method: "query",
    params: { request_type: "view_access_key_list", finality: "final", account_id: accountId },
  }, "NEAR Testnet access-key verification");
  if (!Array.isArray(result.keys)) throw new Error("Could not verify NEAR account access keys");
  return result.keys as Array<{ public_key: string; access_key: { permission: unknown } }>;
}
async function verifyOnChainTransfer(transactionHash: string, signerAccountId: string) {
  if (base58Decode(transactionHash).length !== 32) throw new Error("Invalid NEAR transaction hash");
  const result = await nearTestnetRpc({
    jsonrpc: "2.0", id: "mandate-verify-transfer", method: "tx",
    params: { tx_hash: transactionHash, sender_account_id: signerAccountId, wait_until: "FINAL" },
  }, "NEAR Testnet transaction verification");
  const tx = result.transaction;
  if (!tx || tx.hash !== transactionHash || tx.signer_id !== signerAccountId ||
      tx.receiver_id !== TEST_TRANSFER.receiverId || !Array.isArray(tx.actions) ||
      tx.actions.length !== 1 || tx.actions[0]?.Transfer?.deposit !== TEST_TRANSFER.amountAtomic) {
    throw new Error("On-chain transaction does not match the exact MANDATE-authorized transfer");
  }
  const status = result.status;
  if (result.final_execution_status !== "FINAL" || !status || typeof status !== "object" ||
      !("SuccessValue" in status || "SuccessReceiptId" in status) || "Failure" in status) {
    throw new Error("The NEAR Testnet transaction did not complete successfully");
  }
  const blockHash = result.transaction_outcome?.block_hash;
  if (typeof blockHash !== "string" || base58Decode(blockHash).length !== 32) {
    throw new Error("The finalized transaction did not include a verifiable block reference");
  }
  const block = await nearTestnetRpc({
    jsonrpc: "2.0", id: "mandate-verify-transfer-block", method: "block",
    params: { block_id: blockHash },
  }, "NEAR Testnet transaction block verification");
  const blockTimestampNs = block.header?.timestamp_nanosec;
  if (typeof blockTimestampNs !== "string" || !/^[0-9]+$/.test(blockTimestampNs)) {
    throw new Error("The finalized transaction block timestamp could not be verified");
  }
  return {
    verified: true,
    transactionHash,
    signerAccountId,
    receiverId: tx.receiver_id,
    amountAtomic: TEST_TRANSFER.amountAtomic,
    network: "testnet",
    blockTimestampNs,
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
  const origin = req.headers.get("origin") ?? "";
  const reply = (body: unknown, status = 200) => json(body, status, origin);
  if (req.method === "OPTIONS") return new Response("ok", { headers: responseHeaders(origin) });
  if (req.method !== "POST") return reply({ error: "Method not allowed." }, 405);
  if (!ALLOWED_ORIGINS.has(origin)) return reply({ error: "Origin not allowed." }, 403);
  if (!PROJECT_URL || !ANON_KEY || !SERVICE_KEY) {
    return reply({ error: "Authorization service is not configured." }, 503);
  }
  const user = await authenticate(req);
  if (!user) return reply({ error: "Sign in to MANDATE before authorizing a transfer." }, 401);
  const admin = createClient(PROJECT_URL, SERVICE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  let body: unknown;
  try {
    const raw = await req.text();
    if (encoder.encode(raw).length > 12_000) return reply({ error: "Request too large." }, 413);
    body = JSON.parse(raw);
  } catch {
    return reply({ error: "Request body must be valid JSON." }, 400);
  }
  if (!isRecord(body) || typeof body.action !== "string") return reply({ error: "An action is required." }, 400);

  try {
    if (body.action === "wallet_status") {
      const { data, error } = await admin.rpc("get_near_owner_wallet_v1", {
        p_owner_id: user.id, p_account_id: body.accountId,
      });
      if (error) throw new Error("Could not check registered wallet status");
      const wallet = Array.isArray(data) ? data[0] : null;
      return reply({ registered: Boolean(wallet), wallet: wallet ? {
        accountId: wallet.account_id, publicKey: wallet.public_key, verifiedAt: wallet.verified_at,
      } : null });
    }

    if (body.action === "recovery_lifecycle") {
      const { data, error } = await admin.rpc("get_near_wallet_recovery_lifecycle_v1", {
        p_owner_id: user.id,
      });
      if (error) throw new Error("Could not load wallet recovery status");
      const state = Array.isArray(data) ? data[0] : null;
      return reply({
        codeEstablished: state?.code_established === true,
        codeConsumed: state?.code_consumed === true,
        hasWalletHistory: state?.has_wallet_history === true,
        activeWalletAccountId: state?.active_wallet_account_id ?? null,
        request: state?.request_id ? {
          id: state.request_id,
          status: state.request_status,
          newAccountId: state.new_account_id,
          startedAt: state.started_at,
          availableAt: state.available_at,
          secondsRemaining: Number(state.seconds_remaining ?? 0),
        } : null,
      });
    }

    if (body.action === "recovery_start_challenge" || body.action === "recovery_finalize_challenge") {
      const action = body.action === "recovery_start_challenge" ? "start" : "finalize";
      const lifecycleResult = await admin.rpc("get_near_wallet_recovery_lifecycle_v1", {
        p_owner_id: user.id,
      });
      if (lifecycleResult.error) throw new Error("Could not load wallet recovery state");
      const state = Array.isArray(lifecycleResult.data) ? lifecycleResult.data[0] : null;
      let accountId: string;
      let publicKey: string;
      let requestId: string;
      if (action === "start") {
        if (typeof body.accountId !== "string" || !/^[a-z0-9._-]{2,64}\.testnet$/.test(body.accountId)) {
          return reply({ error: "Connect the replacement NEAR Testnet wallet first." }, 400);
        }
        if (typeof body.recoveryCode !== "string" ||
            !/^MND-[0-9A-F]{64}$/.test(body.recoveryCode.trim().toUpperCase())) {
          return reply({ error: "Enter your complete MANDATE recovery code." }, 400);
        }
        if (state?.code_established !== true || state?.code_consumed === true || state?.has_wallet_history !== true) {
          return reply({ error: "This account is not eligible for wallet recovery." }, 409);
        }
        if (state?.request_status === "pending") return reply({ error: "A wallet recovery request is already pending." }, 409);
        accountId = body.accountId;
        if (!isDifferentReplacementWallet(state?.active_wallet_account_id, accountId)) {
          return reply({ error: "The replacement wallet must be different from your currently active wallet." }, 409);
        }
        const accessKeys = await rpcViewAccessKeys(accountId);
        const fullAccess = findActiveFullAccessKey(accessKeys);
        if (!fullAccess) return reply({ error: "The replacement wallet has no verifiable FullAccess key." }, 403);
        publicKey = fullAccess.public_key;
        requestId = crypto.randomUUID();
      } else {
        // The lifecycle RPC returns a flat row (request_id, request_status, etc.),
        // not the nested API response returned by the recovery_lifecycle action.
        const pending = state?.request_id && state?.request_status === "pending"
          ? {
              id: state.request_id as string,
              status: state.request_status as string,
              new_account_id: state.new_account_id as string,
              seconds_remaining: Number(state.seconds_remaining ?? 0),
            }
          : null;
        if (!pending) return reply({ error: "There is no pending wallet recovery to finalize." }, 409);
        if (pending.seconds_remaining > 0) {
          return reply({ error: "The 24-hour security waiting period has not finished.", secondsRemaining: pending.seconds_remaining }, 409);
        }
        accountId = pending.new_account_id;
        const accessKeys = await rpcViewAccessKeys(accountId);
        const fullAccess = accessKeys.find((entry) => entry.access_key?.permission === "FullAccess");
        if (!fullAccess) return reply({ error: "The replacement wallet's recorded FullAccess key is no longer active." }, 403);
        publicKey = fullAccess.public_key;
        requestId = pending.id;
      }

      const challengeId = crypto.randomUUID();
      const nonceHex = hex(crypto.getRandomValues(new Uint8Array(32)));
      const message = [
        action === "start" ? "MANDATE DELAYED WALLET RECOVERY REQUEST" : "MANDATE DELAYED WALLET RECOVERY FINALIZATION",
        action === "start"
          ? "I am requesting a wallet replacement. This starts a 24-hour security delay and freezes all financial authorizations. It does not move funds."
          : "I confirm this wallet replacement after the 24-hour security delay. This does not move funds.",
        `MANDATE owner: ${user.id}`,
        `Replacement NEAR account: ${accountId}`,
        `Replacement public key: ${publicKey}`,
        `Recovery request: ${requestId}`,
        `Challenge: ${challengeId}`,
        `Nonce: ${nonceHex}`,
      ].join("\n");
      const { error } = await admin.rpc("create_near_wallet_recovery_action_challenge_v1", {
        p_owner_id: user.id, p_id: challengeId, p_request_id: requestId,
        p_action: action, p_account_id: accountId, p_public_key: publicKey,
        p_nonce_hex: nonceHex, p_message: message,
      });
      if (error) return reply({ error: error.message }, 409);
      return reply({
        challengeId, requestId, action, accountId, publicKey,
        nonceHex, message, recipient: APP_RECIPIENT, expiresInSeconds: 300,
      });
    }

    if (body.action === "recovery_start_verify" || body.action === "recovery_finalize_verify") {
      const action = body.action === "recovery_start_verify" ? "start" : "finalize";
      const { challengeId, signedMessage } = body;
      if (typeof challengeId !== "string" || !isRecord(signedMessage) ||
          typeof signedMessage.accountId !== "string" ||
          typeof signedMessage.publicKey !== "string" ||
          typeof signedMessage.signature !== "string") {
        return reply({ error: "A valid NEP-413 wallet signature is required." }, 400);
      }
      const { data: rows, error: challengeError } = await admin.rpc(
        "get_near_wallet_recovery_action_challenge_v1",
        { p_owner_id: user.id, p_id: challengeId },
      );
      const challenge = Array.isArray(rows) ? rows[0] : null;
      if (challengeError || !recoveryChallengeMatches(
          challenge, action, signedMessage.accountId, signedMessage.publicKey,
      )) {
        return reply({ error: "Recovery challenge expired, mismatched, or already used." }, 409);
      }
      const accessKeys = await rpcViewAccessKeys(challenge.account_id);
      const fullAccess = findActiveFullAccessKey(accessKeys, challenge.public_key);
      if (!fullAccess) return reply({ error: "The signing key is no longer an active FullAccess key." }, 403);
      const valid = await verifyNep413(
        challenge.message, fromHex(challenge.nonce_hex), APP_RECIPIENT,
        challenge.public_key, signedMessage.signature,
      );
      if (!valid) return reply({ error: "The recovery wallet signature is invalid." }, 403);

      if (action === "start") {
        const recoveryCode = typeof body.recoveryCode === "string"
          ? body.recoveryCode.trim().toUpperCase() : "";
        if (!/^MND-[0-9A-F]{64}$/.test(recoveryCode)) {
          return reply({ error: "A valid MANDATE recovery code is required." }, 400);
        }
        const codeHash = hex(await sha256(encoder.encode(recoveryCode)));
        const { data: started, error } = await admin.rpc("start_near_wallet_recovery_v1", {
          p_owner_id: user.id, p_id: challenge.id, p_code_hash_hex: codeHash,
        });
        if (error || started !== true) return reply({ error: error?.message || "Recovery code or challenge is invalid. The request was not started." }, 403);
        const lifecycle = await admin.rpc("get_near_wallet_recovery_lifecycle_v1", { p_owner_id: user.id });
        const state = Array.isArray(lifecycle.data) ? lifecycle.data[0] : null;
        return reply({
          started: true,
          request: state?.request_id ? {
            id: state.request_id, status: state.request_status,
            newAccountId: state.new_account_id, startedAt: state.started_at,
            availableAt: state.available_at, secondsRemaining: Number(state.seconds_remaining ?? 86400),
          } : null,
          message: "Recovery started. All financial authorizations are frozen for 24 hours.",
        });
      }

      const newRecoveryCode = `MND-${hex(crypto.getRandomValues(new Uint8Array(32))).toUpperCase()}`;
      const newRecoveryCodeHash = hex(await sha256(encoder.encode(newRecoveryCode)));
      const { data: completed, error } = await admin.rpc("finalize_near_wallet_recovery_v1", {
        p_owner_id: user.id, p_id: challenge.id,
        p_new_code_hash_hex: newRecoveryCodeHash,
      });
      if (error || completed !== true) return reply({ error: error?.message || "Recovery is not ready or the request is no longer valid." }, 409);
      return reply({
        completed: true, accountId: challenge.account_id,
        recoveryCode: newRecoveryCode,
        message: "Wallet recovery completed. The old wallet has been revoked, the replacement is now the single active MANDATE sender, and a new independent recovery code has been issued. Save it now; it will not be shown again.",
      });
    }

    if (body.action === "recovery_cancel") {
      const { requestId, recoveryCode } = body;
      if (typeof requestId !== "string" || typeof recoveryCode !== "string" ||
          !/^MND-[0-9A-F]{64}$/.test(recoveryCode.trim().toUpperCase())) {
        return reply({ error: "The pending recovery request and independent recovery code are required." }, 400);
      }
      const codeHash = hex(await sha256(encoder.encode(recoveryCode.trim().toUpperCase())));
      const { data: cancelled, error } = await admin.rpc("cancel_near_wallet_recovery_v1", {
        p_owner_id: user.id, p_request_id: requestId, p_code_hash_hex: codeHash,
      });
      if (error || cancelled !== true) return reply({ error: error?.message || "Recovery could not be cancelled. Check the recovery code and request status." }, 403);
      return reply({ cancelled: true, message: "Pending recovery cancelled. Financial authorization may resume." });
    }

    if (body.action === "recovery_setup_status") {
      const { data, error } = await admin.rpc("get_near_wallet_recovery_status_v1", {
        p_owner_id: user.id,
      });
      if (error) throw new Error("Could not check MANDATE recovery status");
      const status = Array.isArray(data) ? data[0] : data;
      const { data: history, error: historyError } = await admin.rpc(
        "list_near_wallet_recovery_historical_wallets_v1",
        { p_owner_id: user.id },
      );
      if (historyError) throw new Error("Could not load historical wallet verification options");
      return reply({
        established: status?.code_established === true,
        consumed: status?.code_consumed === true,
        hasWalletHistory: status?.has_wallet_history === true,
        historicalWallets: (Array.isArray(history) ? history : []).map((wallet: Record<string, unknown>) => ({
          accountId: wallet.account_id,
          revoked: wallet.revoked_at !== null,
        })),
      });
    }

    if (body.action === "recovery_setup_challenge") {
      const { data: statusRows, error: statusError } = await admin.rpc(
        "get_near_wallet_recovery_status_v1", { p_owner_id: user.id },
      );
      if (statusError) throw new Error("Could not check MANDATE recovery status");
      const status = Array.isArray(statusRows) ? statusRows[0] : statusRows;
      if (status?.code_established === true) {
        return reply({ error: "A MANDATE recovery code is already established. It cannot be displayed again." }, 409);
      }

      const { data: historyRows, error: historyError } = await admin.rpc(
        "list_near_wallet_recovery_historical_wallets_v1", { p_owner_id: user.id },
      );
      if (historyError) throw new Error("Could not verify wallet history");
      const history = Array.isArray(historyRows) ? historyRows : [];
      const historicalAccountId = body.historicalAccountId;
      if (history.length > 0 && (
        typeof historicalAccountId !== "string" ||
        !history.some((wallet: Record<string, unknown>) => wallet.account_id === historicalAccountId)
      )) {
        return reply({ error: "Choose a wallet previously registered to this MANDATE account to prove existing-account ownership." }, 400);
      }
      if (history.length === 0 && historicalAccountId !== undefined && historicalAccountId !== null) {
        return reply({ error: "This new account does not have historical wallet proof to provide." }, 400);
      }

      const challengeId = crypto.randomUUID();
      const nonceHex = hex(crypto.getRandomValues(new Uint8Array(32)));
      const message = [
        "MANDATE INDEPENDENT RECOVERY CODE ENROLLMENT",
        "This signature proves control of a previously registered NEAR wallet. It does not move funds.",
        `MANDATE owner: ${user.id}`,
        `Historical NEAR account: ${historicalAccountId ?? "NONE — FIRST WALLET ENROLLMENT"}`,
        `Challenge: ${challengeId}`,
        `Nonce: ${nonceHex}`,
      ].join("\n");
      const { error } = await admin.rpc("create_near_wallet_recovery_setup_challenge_v1", {
        p_owner_id: user.id,
        p_id: challengeId,
        p_historical_account_id: historicalAccountId ?? null,
        p_nonce_hex: nonceHex,
        p_message: message,
      });
      if (error) throw new Error(error.message || "Could not create recovery setup challenge");
      return reply({
        challengeId, message, nonceHex, recipient: APP_RECIPIENT,
        historicalAccountId: historicalAccountId ?? null,
        requiresWalletSignature: history.length > 0,
        expiresInSeconds: 300,
      });
    }

    if (body.action === "recovery_setup_verify") {
      const { challengeId, signedMessage } = body;
      if (typeof challengeId !== "string") {
        return reply({ error: "A valid recovery setup challenge is required." }, 400);
      }
      const { data: challengeRows, error: challengeError } = await admin.rpc(
        "get_near_wallet_recovery_setup_challenge_v1",
        { p_owner_id: user.id, p_id: challengeId },
      );
      const challenge = Array.isArray(challengeRows) ? challengeRows[0] : null;
      if (challengeError || !challenge) {
        return reply({ error: "Recovery setup challenge expired, missing, or already used." }, 409);
      }

      let verifiedHistoricalAccountId: string | null = null;
      if (challenge.historical_account_id !== null) {
        if (!isRecord(signedMessage) ||
            typeof signedMessage.accountId !== "string" ||
            typeof signedMessage.publicKey !== "string" ||
            typeof signedMessage.signature !== "string" ||
            signedMessage.accountId !== challenge.historical_account_id) {
          return reply({ error: "Sign the recovery setup message with the selected historical NEAR wallet." }, 400);
        }
        const { data: historyRows, error: historyError } = await admin.rpc(
          "list_near_wallet_recovery_historical_wallets_v1", { p_owner_id: user.id },
        );
        const history = Array.isArray(historyRows) ? historyRows : [];
        const historicalWallet = history.find((wallet: Record<string, unknown>) =>
          wallet.account_id === challenge.historical_account_id &&
          wallet.public_key === signedMessage.publicKey
        );
        if (historyError || !historicalWallet) {
          return reply({ error: "The signing key is not the historical key recorded for this MANDATE account." }, 403);
        }
        const accessKeys = await rpcViewAccessKeys(signedMessage.accountId);
        const matchingKey = findActiveFullAccessKey(accessKeys, signedMessage.publicKey);
        if (!matchingKey || matchingKey.access_key?.permission !== "FullAccess") {
          return reply({ error: "The historical signing key is no longer a full-access key for this NEAR account." }, 403);
        }
        const valid = await verifyNep413(
          challenge.message, fromHex(challenge.nonce_hex), APP_RECIPIENT,
          signedMessage.publicKey, signedMessage.signature,
        );
        if (!valid) return reply({ error: "Recovery enrollment NEP-413 signature verification failed." }, 403);
        verifiedHistoricalAccountId = challenge.historical_account_id;
      } else if (signedMessage !== undefined && signedMessage !== null) {
        return reply({ error: "This first-wallet recovery setup does not accept an unrelated wallet signature." }, 400);
      }

      // 256 bits of cryptographically secure entropy. The plaintext is returned
      // once to the authenticated owner and is never written to the database.
      const recoveryCode = `MND-${hex(crypto.getRandomValues(new Uint8Array(32))).toUpperCase()}`;
      const codeHash = hex(await sha256(encoder.encode(recoveryCode)));
      const { data: completed, error: completeError } = await admin.rpc(
        "complete_near_wallet_recovery_setup_v1",
        {
          p_owner_id: user.id,
          p_id: challenge.id,
          p_code_hash_hex: codeHash,
          p_verified_historical_account_id: verifiedHistoricalAccountId,
        },
      );
      if (completeError || completed !== true) {
        return reply({ error: completeError?.message || "Recovery code could not be established." }, 409);
      }
      return reply({
        established: true,
        recoveryCode,
        message: "Save this recovery code now. MANDATE will never display it again.",
      });
    }

    if (body.action === "register_wallet_challenge") {
      const accountId = body.accountId;
      if (typeof accountId !== "string" || !/^[a-z0-9._-]{2,64}\.testnet$/.test(accountId)) {
        return reply({ error: "Connect a valid NEAR Testnet account first." }, 400);
      }
      const challengeId = crypto.randomUUID();
      const nonceHex = hex(crypto.getRandomValues(new Uint8Array(32)));
      const message = [
        "MANDATE NEAR TESTNET WALLET REGISTRATION",
        "This signature registers this wallet to your signed-in MANDATE account. It does not move funds.",
        `MANDATE owner: ${user.id}`,
        `NEAR account: ${accountId}`,
        `Challenge: ${challengeId}`,
        `Nonce: ${nonceHex}`,
      ].join("\n");
      const { error } = await admin.rpc("create_near_wallet_registration_challenge_v1", {
        p_owner_id: user.id, p_id: challengeId, p_account_id: accountId,
        p_nonce_hex: nonceHex, p_message: message,
      });
      if (error) throw new Error(error.message || "Could not create wallet registration challenge");
      return reply({ challengeId, message, nonceHex, recipient: APP_RECIPIENT, accountId, expiresInSeconds: 300 });
    }

    if (body.action === "register_wallet_verify") {
      const { challengeId, signedMessage } = body;
      if (typeof challengeId !== "string" || !isRecord(signedMessage) ||
          typeof signedMessage.accountId !== "string" || typeof signedMessage.publicKey !== "string" ||
          typeof signedMessage.signature !== "string") {
        return reply({ error: "A valid NEP-413 signed registration message is required." }, 400);
      }
      const { data: rows, error } = await admin.rpc("get_near_wallet_registration_challenge_v1", {
        p_owner_id: user.id, p_id: challengeId,
      });
      const challenge = Array.isArray(rows) ? rows[0] : null;
      if (error || !challenge) return reply({ error: "Wallet registration challenge expired, missing, or already used." }, 409);
      if (signedMessage.accountId !== challenge.account_id) {
        return reply({ error: "The signed account does not match the wallet being registered." }, 403);
      }
      const accessKeys = await rpcViewAccessKeys(signedMessage.accountId);
      const matchingKey = accessKeys.find((entry) => entry.public_key === signedMessage.publicKey);
      if (!matchingKey || matchingKey.access_key?.permission !== "FullAccess") {
        return reply({ error: "The signing key is not a verified full-access key for this NEAR account." }, 403);
      }
      const valid = await verifyNep413(
        challenge.message, fromHex(challenge.nonce_hex), APP_RECIPIENT,
        signedMessage.publicKey, signedMessage.signature,
      );
      if (!valid) return reply({ error: "NEP-413 wallet registration signature verification failed." }, 403);
      const { data: completed, error: completeError } = await admin.rpc("complete_near_wallet_registration_v1", {
        p_owner_id: user.id, p_id: challenge.id, p_public_key: signedMessage.publicKey,
      });
      if (completeError || completed !== true) {
        return reply({ error: completeError?.message || "Wallet registration could not be completed." }, 409);
      }
      return reply({ registered: true, accountId: challenge.account_id, publicKey: signedMessage.publicKey });
    }

    if (body.action === "challenge") {
      const signer = body.signerAccountId;
      if (typeof signer !== "string" || !/^[a-z0-9._-]+\.testnet$/.test(signer)) {
        return reply({ error: "Connect a valid NEAR Testnet account." }, 400);
      }
      const { data: registeredRows, error: registeredError } = await admin.rpc("get_near_owner_wallet_v1", {
        p_owner_id: user.id, p_account_id: signer,
      });
      const registeredWallet = Array.isArray(registeredRows) ? registeredRows[0] : null;
      if (registeredError || !registeredWallet) {
        return reply({ error: "Register and verify this NEAR wallet to your MANDATE account before authorizing a transfer." }, 403);
      }
      const policy = await getPolicy(admin, user.id);
      if (!policy) return reply({ error: "Create and activate a security policy before requesting authorization." }, 409);
      const evaluated = evaluateTestTransferPolicy(policy);
      let decision: Record<string, unknown>;
      if (body.proposalId !== undefined && typeof body.proposalId !== "string") {
        return reply({ error: "Invalid inspected proposal reference." }, 400);
      }
      if (typeof body.proposalId === "string") {
        if (!/^[a-zA-Z0-9_-]{1,128}$/.test(body.proposalId)) {
          return reply({ error: "Invalid inspected proposal reference." }, 400);
        }
        const { data: inspected, error: inspectedError } = await admin
          .from("authorization_decisions")
          .select("proposal_id, policy_id, policy_version, outcome, proposal")
          .eq("owner_id", user.id).eq("proposal_id", body.proposalId)
          .maybeSingle();
        if (inspectedError || !inspected ||
            inspected.policy_id !== policy.id ||
            inspected.policy_version !== policy.version ||
            !["ALLOW", "REQUIRE_APPROVAL"].includes(inspected.outcome) ||
            !isRecord(inspected.proposal) ||
            inspected.proposal.id !== inspected.proposal_id ||
            inspected.proposal.actionType !== "transfer" ||
            inspected.proposal.asset !== "NEAR" ||
            inspected.proposal.amountAtomic !== TEST_TRANSFER.amountAtomic ||
            inspected.proposal.target !== TEST_TRANSFER.receiverId ||
            inspected.proposal.network !== TEST_TRANSFER.network) {
          return reply({ error: "This proposal is not eligible for the fixed MANDATE Testnet transfer flow. Inspect it again or use the exact supported test transfer." }, 409);
        }
        if (inspected.outcome !== evaluated.outcome) {
          return reply({ error: "The current policy decision differs from the inspected proposal. Inspect again." }, 409);
        }
        decision = { ...evaluated, policyId: policy.id, policyVersion: policy.version, proposalId: inspected.proposal_id };
      } else {
        decision = { ...evaluated, policyId: policy.id, policyVersion: policy.version, proposalId: proposalId() };
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
      }
      if (decision.outcome === "BLOCK") {
        return reply({ error: String(decision.message), decision }, 403);
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
      return reply({
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
        return reply({ error: "A valid NEP-413 signed message is required." }, 400);
      }
      const { data: challengeRows, error: challengeError } = await admin.rpc("get_near_transfer_challenge_v2", {
        p_owner_id: user.id, p_id: challengeId,
      });
      const challenge = Array.isArray(challengeRows) ? challengeRows[0] : null;
      if (challengeError || !challenge) return reply({ error: "Challenge expired, missing, or already used." }, 409);
      if (signed.accountId !== challenge.signer_account_id) return reply({ error: "The signature account does not match the proposed sender." }, 403);
      const { data: walletRows, error: walletError } = await admin.rpc("get_near_owner_wallet_v1", {
        p_owner_id: user.id, p_account_id: signed.accountId,
      });
      const registeredWallet = Array.isArray(walletRows) ? walletRows[0] : null;
      if (walletError || !registeredWallet || registeredWallet.public_key !== signed.publicKey) {
        return reply({ error: "This signing key is not the verified key registered to your MANDATE account." }, 403);
      }

      const accessKeys = await rpcViewAccessKeys(signed.accountId);
      const matchingKey = findActiveFullAccessKey(accessKeys, signed.publicKey);
      if (!matchingKey || matchingKey.access_key?.permission !== "FullAccess") {
        return reply({ error: "The signing key is not a verified full-access key for this NEAR account." }, 403);
      }
      const signatureValid = await verifyNep413(
        challenge.message, fromHex(challenge.nonce_hex), APP_RECIPIENT,
        signed.publicKey, signed.signature,
      );
      if (!signatureValid) return reply({ error: "NEP-413 wallet signature verification failed." }, 403);

      const policy = await getPolicy(admin, user.id);
      if (!policy || policy.id !== challenge.policy_id || policy.version !== challenge.policy_version ||
          evaluateTestTransferPolicy(policy).outcome === "BLOCK") {
        return reply({ error: "The active policy changed or no longer permits this transfer. Start again." }, 409);
      }
      const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
      const token = hex(tokenBytes);
      const tokenHash = hex(await sha256(encoder.encode(token)));
      const { data: finalized, error: finalizeError } = await admin.rpc("finalize_near_transfer_challenge_v2", {
        p_owner_id: user.id, p_id: challenge.id, p_token_hash: tokenHash,
      });
      if (finalizeError || finalized !== true) return reply({ error: "Challenge could not be finalized. No authorization was issued." }, 409);
      return reply({
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
          typeof signerAccountId !== "string") return reply({ error: "Invalid authorization receipt." }, 400);
      const policy = await getPolicy(admin, user.id);
      if (!policy || evaluateTestTransferPolicy(policy).outcome === "BLOCK") return reply({ error: "The active policy no longer permits this transfer." }, 403);
      const tokenHash = hex(await sha256(encoder.encode(receipt)));
      const digest = await actionDigest(signerAccountId);
      const { data: consumed, error: consumeError } = await admin.rpc("consume_near_transfer_authorization_v2", {
        p_owner_id: user.id, p_token_hash: tokenHash,
        p_signer_account_id: signerAccountId, p_network: TEST_TRANSFER.network,
        p_receiver_id: TEST_TRANSFER.receiverId, p_asset: TEST_TRANSFER.asset,
        p_amount_atomic: TEST_TRANSFER.amountAtomic, p_action_type: TEST_TRANSFER.actionType,
        p_action_digest: digest,
      });
      if (consumeError || consumed !== true) return reply({ error: "Authorization is expired, mismatched, replayed, or invalid." }, 409);
      return reply({ consumed: true, message: "One-time authorization consumed. The wallet may now request your explicit transaction approval." });
    }


    if (body.action === "verify_transaction") {
      const { transactionHash, signerAccountId, receipt } = body;
      if (typeof transactionHash !== "string" || typeof signerAccountId !== "string" ||
          !/^[a-z0-9._-]+\.testnet$/.test(signerAccountId) ||
          typeof receipt !== "string" || !/^[0-9a-f]{64}$/.test(receipt)) {
        return reply({ error: "A valid Testnet transaction hash, signer, and one-time authorization receipt are required." }, 400);
      }
      const result = await verifyOnChainTransfer(transactionHash, signerAccountId);
      const tokenHash = hex(await sha256(encoder.encode(receipt)));
      const { data: bound, error: bindError } = await admin.rpc("bind_near_transfer_transaction_v1", {
        p_owner_id: user.id,
        p_token_hash: tokenHash,
        p_signer_account_id: signerAccountId,
        p_transaction_hash: transactionHash,
        p_transaction_timestamp_ns: result.blockTimestampNs,
      });
      if (bindError || bound !== true) {
        return reply({
          error: "The on-chain transfer is valid, but it is not linked to a fresh, consumed MANDATE authorization for this account. It cannot be recorded as MANDATE-authorized.",
          code: "AUTHORIZATION_RECEIPT_NOT_BOUND",
        }, 409);
      }
      return reply({ ...result, authorizationBound: true });
    }

    return reply({ error: "Unknown action." }, 400);
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Unknown authorization error.";
    console.error("NEAR transfer authorization error:", detail);
    if (body.action === "verify_transaction") {
      return reply({
        error: "The wallet has already submitted this transaction, but MANDATE could not verify its final Testnet status yet. Do not send it again; retry verification using the same transaction hash.",
        code: "TRANSACTION_VERIFICATION_UNAVAILABLE",
        retryable: true,
        transactionHash: typeof body.transactionHash === "string" ? body.transactionHash : null,
      }, 503);
    }
    return reply({ error: detail || "Authorization service unavailable. No transaction was submitted by this request." }, 503);
  }
});
