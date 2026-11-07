import { createClient } from "npm:@supabase/supabase-js@2.57.0";
import { evaluateAction } from "../../../src/security/evaluate-action.ts";
import { assessCounterpartyRisk } from "../../../src/security/counterparty-risk-service.ts";
import { combinePolicyAndCounterpartyRisk } from "../../../src/security/inspection-risk.ts";
import type { SecurityPolicy } from "../../../src/security/types.ts";
import { readBoundedRequestText, RequestBodyTooLargeError } from "../../../src/security/read-bounded-request-body.ts";

const json = (body: unknown, status = 200) =>
  Response.json(body, { status, headers: { "Cache-Control": "no-store" } });

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);
  let rawBody: string;
  try {
    rawBody = await readBoundedRequestText(req, 16_384);
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) return json({ error: "Request too large." }, 413);
    return json({ error: "Request body must be valid UTF-8." }, 400);
  }

  const auth = req.headers.get("authorization") ?? "";
  const match = auth.match(/^Bearer (mnd_live_[A-Za-z0-9_-]{32,})$/);
  if (!match) return json({ error: "A valid MANDATE API key is required." }, 401);

  const url = Deno.env.get("SUPABASE_URL");
  const secretKeysRaw = Deno.env.get("SUPABASE_SECRET_KEYS");
  let secretKey: string | undefined;
  try {
    secretKey = secretKeysRaw
      ? JSON.parse(secretKeysRaw).default
      : Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  } catch {
    secretKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  }
  if (!url || !secretKey) return json({ error: "Authorization service is not configured." }, 503);

  const admin = createClient(url, secretKey, { auth: { autoRefreshToken: false, persistSession: false } });
  const rawKey = match[1];
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawKey));
  const keyHash = Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");

  const { data: keyRecord, error: keyError } = await admin.from("api_keys")
    .select("id, owner_id").eq("key_hash", keyHash).is("revoked_at", null).maybeSingle();
  if (keyError || !keyRecord) return json({ error: "Invalid or revoked API key." }, 401);

  const { data: withinQuota, error: quotaError } = await admin.rpc("consume_api_key_quota", {
    p_key_id: keyRecord.id,
    p_limit: 60,
  });
  if (quotaError) return json({ error: "Rate limit service unavailable. No action is authorized." }, 503);
  if (!withinQuota) return json({ error: "Rate limit exceeded. Maximum 60 requests per minute per API key." }, 429);

  let body: unknown;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return json({ error: "Request body must be valid JSON." }, 400);
  }
  if (!isRecord(body) || !("proposal" in body)) return json({ error: "Expected { proposal: ... }." }, 400);

  const { data: saved, error: policyError } = await admin.from("security_policies")
    .select("id, version, active, max_amount_atomic, allowed_recipients, allowed_action_types, require_approval_for_token_approvals, require_approval_for_all_actions")
    .eq("owner_id", keyRecord.owner_id).eq("active", true)
    .order("updated_at", { ascending: false }).limit(1).maybeSingle();
  if (policyError) return json({ error: "Could not load the owner's active policy." }, 500);
  if (!saved) return json({ error: "No active security policy is configured." }, 409);

  const policy: SecurityPolicy = {
    id: saved.id,
    version: saved.version,
    active: saved.active,
    maxAmountAtomic: saved.max_amount_atomic,
    allowedRecipients: saved.allowed_recipients,
    allowedActionTypes: saved.allowed_action_types,
    requireApprovalForTokenApprovals: saved.require_approval_for_token_approvals,
    requireApprovalForAllActions: saved.require_approval_for_all_actions,
  };
  const proposal = body.proposal;
  const proposalRecord = isRecord(proposal) ? proposal : {};
  const policyDecision = evaluateAction(proposal, policy);
  const targetAccountId = typeof proposalRecord.target === "string" ? proposalRecord.target : "";
  const unsupportedNetwork = proposalRecord.network !== undefined && proposalRecord.network !== "testnet";

  const riskAssessment = await assessCounterpartyRisk(keyRecord.owner_id, targetAccountId, {
    findBlocklistRecord: async (network, accountId) => {
      const lookup = await admin.rpc("lookup_counterparty_blocklist", {
        p_network: network,
        p_account_id: accountId,
      });
      if (lookup.error) throw new Error("Blocklist lookup unavailable.");
      return Array.isArray(lookup.data) ? lookup.data[0] ?? null : lookup.data ?? null;
    },
    countPreviousInteractions: async (ownerId, _network, accountId) => {
      const result = await admin.from("authorization_decisions")
        .select("id", { count: "exact", head: true })
        .eq("owner_id", ownerId)
        .filter("proposal->>target", "eq", accountId);
      if (result.error || result.count === null) throw new Error("Owner-scoped interaction history unavailable.");
      return result.count;
    },
  });

  const boundedPolicyDecision = unsupportedNetwork
    ? {
        ...policyDecision,
        outcome: "BLOCK" as const,
        reason: "INVALID_PROPOSAL" as const,
        message: "Only NEAR Testnet proposals can be inspected by this environment. No action is authorized.",
      }
    : policyDecision;
  const decision = combinePolicyAndCounterpartyRisk(boundedPolicyDecision, riskAssessment.decision);

  const recordedProposal = {
    ...proposalRecord,
    network: "testnet",
    counterpartyRisk: riskAssessment.decision,
    riskCollection: riskAssessment.collection,
  };
  const { error: receiptError } = await admin.from("authorization_decisions").insert({
    owner_id: keyRecord.owner_id,
    policy_id: policy.id,
    policy_version: policy.version,
    proposal_id: decision.proposalId,
    agent_id: nonEmpty(proposalRecord.agentId) ? proposalRecord.agentId.slice(0, 128) : "unknown",
    action_type: nonEmpty(proposalRecord.actionType) ? proposalRecord.actionType.slice(0, 64) : "unknown",
    outcome: decision.outcome,
    reason: decision.reason,
    proposal: recordedProposal,
  });
  if (receiptError) return json({ error: "Decision receipt could not be saved. No action is authorized." }, 500);

  const { error: lastUsedError } = await admin.from("api_keys")
    .update({ last_used_at: new Date().toISOString() }).eq("id", keyRecord.id);
  if (lastUsedError) return json({ error: "API key usage receipt could not be updated. No action is authorized." }, 500);

  return json({
    decision,
    risk: riskAssessment.decision,
    riskCollection: riskAssessment.collection,
    policy: { id: policy.id, version: policy.version },
  });
});
