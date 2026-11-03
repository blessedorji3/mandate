import { createClient } from "npm:@supabase/supabase-js@2.57.0";
import { assessCounterpartyRisk } from "../_shared/counterparty-risk-service.ts";

type ActionType = "transfer" | "token_approval" | "swap" | "contract_call";
type Proposal = { id: string; agentId: string; actionType: ActionType; asset: string; amountAtomic: string; target: string; protocol?: string; approvalAmountAtomic?: string };
type Policy = { id: string; version: number; active: boolean; maxAmountAtomic: string; allowedRecipients: string[]; allowedActionTypes: ActionType[]; requireApprovalForTokenApprovals: boolean; requireApprovalForAllActions: boolean };
type Outcome = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
const ACTIONS = new Set(["transfer", "token_approval", "swap", "contract_call"]);
const INTEGER = /^(0|[1-9][0-9]*)$/;
const json = (body: unknown, status = 200) => Response.json(body, { status, headers: { "Cache-Control": "no-store" } });

function isRecord(v: unknown): v is Record<string, unknown> { return typeof v === "object" && v !== null && !Array.isArray(v); }
function nonEmpty(v: unknown): v is string { return typeof v === "string" && v.trim().length > 0; }
function integer(v: unknown): v is string { return typeof v === "string" && INTEGER.test(v); }
function validPolicy(v: unknown): v is Policy {
  return isRecord(v) &&
    nonEmpty(v.id) &&
    Number.isSafeInteger(v.version) && Number(v.version) > 0 &&
    typeof v.active === "boolean" &&
    integer(v.maxAmountAtomic) && BigInt(v.maxAmountAtomic) > 0n &&
    Array.isArray(v.allowedRecipients) && v.allowedRecipients.length <= 100 && v.allowedRecipients.every(nonEmpty) &&
    Array.isArray(v.allowedActionTypes) && v.allowedActionTypes.length > 0 && v.allowedActionTypes.every(x => typeof x === "string" && ACTIONS.has(x)) &&
    typeof v.requireApprovalForTokenApprovals === "boolean" &&
    typeof v.requireApprovalForAllActions === "boolean";
}

function evaluate(p: unknown, policy: Policy) {
  const base = { policyId: policy.id, policyVersion: policy.version, proposalId: isRecord(p) && nonEmpty(p.id) ? p.id : "untrusted-proposal" };
  const decide = (outcome: Outcome, reason: string, message: string) => ({ ...base, outcome, reason, message });
  if (!policy.active) return decide("BLOCK", "POLICY_INACTIVE", "The active policy is disabled.");
  if (!isRecord(p) || !nonEmpty(p.id) || !nonEmpty(p.agentId) || !ACTIONS.has(String(p.actionType)) || !nonEmpty(p.asset) || !integer(p.amountAtomic) || !nonEmpty(p.target) || (p.protocol !== undefined && !nonEmpty(p.protocol)) || (p.approvalAmountAtomic !== undefined && !integer(p.approvalAmountAtomic))) return decide("BLOCK", "INVALID_PROPOSAL", "The proposal is malformed. No action is authorized.");
  const proposal = p as unknown as Proposal;
  if (BigInt(proposal.amountAtomic) <= 0n) return decide("BLOCK", "INVALID_AMOUNT", "The action amount must be positive.");
  if (!policy.allowedActionTypes.includes(proposal.actionType)) return decide("BLOCK", "ACTION_NOT_ALLOWED", "This action type is not permitted.");
  if (proposal.actionType === "swap" || proposal.actionType === "contract_call") return decide("BLOCK", "ACTION_NOT_SUPPORTED", "This action type is not yet supported by verified inspection rules.");
  if (BigInt(proposal.amountAtomic) > BigInt(policy.maxAmountAtomic)) return decide("BLOCK", "AMOUNT_LIMIT_EXCEEDED", "The proposed amount exceeds the policy limit.");
  if (policy.allowedRecipients.length === 0 || !policy.allowedRecipients.includes(proposal.target)) return decide("BLOCK", "RECIPIENT_NOT_ALLOWED", "The destination is not approved.");
  if (proposal.actionType === "token_approval") {
    if (!integer(proposal.approvalAmountAtomic) || BigInt(proposal.approvalAmountAtomic) <= 0n) return decide("BLOCK", "APPROVAL_AMOUNT_MISSING", "A positive approval amount is required.");
    if (BigInt(proposal.approvalAmountAtomic) > BigInt(policy.maxAmountAtomic)) return decide("BLOCK", "APPROVAL_LIMIT_EXCEEDED", "The requested allowance exceeds the policy limit.");
    if (policy.requireApprovalForTokenApprovals) return decide("REQUIRE_APPROVAL", "TOKEN_APPROVAL_REQUIRES_OWNER", "Owner confirmation is required.");
  }
  if (policy.requireApprovalForAllActions) return decide("REQUIRE_APPROVAL", "OWNER_APPROVAL_REQUIRED", "Owner confirmation is required.");
  return decide("ALLOW", "POLICY_CHECKS_PASSED", "The action satisfies the configured policy checks.");
}

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);
  const contentLength = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > 16_384) return json({ error: "Request too large." }, 413);

  const auth = req.headers.get("authorization") ?? "";
  const match = auth.match(/^Bearer (mnd_live_[A-Za-z0-9_-]{32,})$/);
  if (!match) return json({ error: "A valid MANDATE API key is required." }, 401);

  const url = Deno.env.get("SUPABASE_URL");
  const secretKeysRaw = Deno.env.get("SUPABASE_SECRET_KEYS");
  let secretKey: string | undefined;
  try { secretKey = secretKeysRaw ? JSON.parse(secretKeysRaw).default : Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"); } catch { secretKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"); }
  if (!url || !secretKey) return json({ error: "Authorization service is not configured." }, 503);

  const admin = createClient(url, secretKey, { auth: { autoRefreshToken: false, persistSession: false } });
  const rawKey = match[1];
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawKey));
  const keyHash = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");

  const { data: keyRecord, error: keyError } = await admin.from("api_keys")
    .select("id, owner_id").eq("key_hash", keyHash).is("revoked_at", null).maybeSingle();
  if (keyError || !keyRecord) return json({ error: "Invalid or revoked API key." }, 401);

  const { data: withinQuota, error: quotaError } = await admin.rpc("consume_api_key_quota", {
    p_key_id: keyRecord.id,
    p_limit: 60
  });
  if (quotaError) return json({ error: "Rate limit service unavailable. No action is authorized." }, 503);
  if (!withinQuota) return json({ error: "Rate limit exceeded. Maximum 60 requests per minute per API key." }, 429);

  let body: unknown;
  try {
    const text = await req.text();
    if (new TextEncoder().encode(text).byteLength > 16_384) return json({ error: "Request too large." }, 413);
    body = JSON.parse(text);
  } catch { return json({ error: "Request body must be valid JSON." }, 400); }
  if (!isRecord(body) || !("proposal" in body)) return json({ error: "Expected { proposal: ... }." }, 400);

  const { data: saved, error: policyError } = await admin.from("security_policies")
    .select("id, version, active, max_amount_atomic, allowed_recipients, allowed_action_types, require_approval_for_token_approvals, require_approval_for_all_actions")
    .eq("owner_id", keyRecord.owner_id).eq("active", true).order("updated_at", { ascending: false }).limit(1).maybeSingle();
  if (policyError) return json({ error: "Could not load the owner's active policy." }, 500);
  if (!saved) return json({ error: "No active security policy is configured." }, 409);

  const policyCandidate = {
    id: saved.id, version: saved.version, active: saved.active, maxAmountAtomic: saved.max_amount_atomic,
    allowedRecipients: saved.allowed_recipients, allowedActionTypes: saved.allowed_action_types,
    requireApprovalForTokenApprovals: saved.require_approval_for_token_approvals,
    requireApprovalForAllActions: saved.require_approval_for_all_actions
  };
  if (!validPolicy(policyCandidate)) return json({ error: "The saved policy is invalid. No action is authorized." }, 500);
  const policy = policyCandidate;
  const policyDecision = evaluate(body.proposal, policy);
  const proposal = isRecord(body.proposal) ? body.proposal : {};
  const target = nonEmpty(proposal.target) ? proposal.target : "";

  // Risk checks are deliberately independent of owner policy. Any failed evidence
  // dependency becomes WARN in the risk service and is mapped to REQUIRE_APPROVAL,
  // because the existing database enum intentionally has no WARN value.
  const riskAssessment = await assessCounterpartyRisk(target, {
    findBlocklistRecord: async (accountId) => {
      const lookup = await admin.rpc("lookup_counterparty_blocklist", {
        p_network: "testnet",
        p_account_id: accountId,
      });
      if (lookup.error) throw new Error("Blocklist lookup unavailable.");
      return Array.isArray(lookup.data) ? lookup.data[0] ?? null : null;
    },
    countPreviousInteractions: async (accountId) => {
      const result = await admin.from("authorization_decisions")
        .select("id", { count: "exact", head: true })
        .filter("proposal->>target", "eq", accountId);
      if (result.error || result.count === null) throw new Error("Interaction history unavailable.");
      return result.count;
    },
  });

  const riskOutcome = riskAssessment.decision.outcome;
  const effectiveOutcome = policyDecision.outcome === "BLOCK" || riskOutcome === "BLOCK"
    ? "BLOCK"
    : policyDecision.outcome === "REQUIRE_APPROVAL" || riskOutcome === "WARN"
      ? "REQUIRE_APPROVAL"
      : "ALLOW";
  const effectiveReason = riskOutcome === "ALLOW"
    ? policyDecision.reason
    : "COUNTERPARTY_RISK_" + riskOutcome + ": " + riskAssessment.decision.reasons.join("; ");
  const decision = { ...policyDecision, outcome: effectiveOutcome, reason: effectiveReason,
    message: effectiveOutcome === "BLOCK"
      ? "The action is blocked by owner policy or counterparty risk."
      : effectiveOutcome === "REQUIRE_APPROVAL"
        ? "Owner confirmation is required before this action can proceed."
        : policyDecision.message };

  const { error: receiptError } = await admin.from("authorization_decisions").insert({
    owner_id: keyRecord.owner_id, policy_id: policy.id, policy_version: policy.version,
    proposal_id: decision.proposalId,
    agent_id: nonEmpty(proposal.agentId) ? proposal.agentId.slice(0, 128) : "unknown",
    action_type: nonEmpty(proposal.actionType) ? proposal.actionType.slice(0, 64) : "unknown",
    outcome: decision.outcome, reason: decision.reason,
    proposal: { ...proposal, counterpartyRisk: riskAssessment.decision }
  });
  if (receiptError) return json({ error: "Decision receipt could not be saved. No action is authorized." }, 500);

  const { error: lastUsedError } = await admin.from("api_keys").update({ last_used_at: new Date().toISOString() }).eq("id", keyRecord.id);
  if (lastUsedError) return json({ error: "API key usage receipt could not be updated. No action is authorized." }, 500);
  return json({
    decision,
    risk: riskAssessment.decision,
    riskCollection: riskAssessment.collection,
    policy: { id: policy.id, version: policy.version }
  });
});
