import { createClient } from "npm:@supabase/supabase-js@2.57.0";

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

  const policy: Policy = {
    id: saved.id, version: saved.version, active: saved.active, maxAmountAtomic: saved.max_amount_atomic,
    allowedRecipients: saved.allowed_recipients, allowedActionTypes: saved.allowed_action_types,
    requireApprovalForTokenApprovals: saved.require_approval_for_token_approvals,
    requireApprovalForAllActions: saved.require_approval_for_all_actions
  };
  const decision = evaluate(body.proposal, policy);
  const proposal = isRecord(body.proposal) ? body.proposal : {};
  const { error: receiptError } = await admin.from("authorization_decisions").insert({
    owner_id: keyRecord.owner_id, policy_id: policy.id, policy_version: policy.version,
    proposal_id: decision.proposalId,
    agent_id: nonEmpty(proposal.agentId) ? proposal.agentId.slice(0, 128) : "unknown",
    action_type: nonEmpty(proposal.actionType) ? proposal.actionType.slice(0, 64) : "unknown",
    outcome: decision.outcome, reason: decision.reason, proposal
  });
  if (receiptError) return json({ error: "Decision receipt could not be saved. No action is authorized." }, 500);

  await admin.from("api_keys").update({ last_used_at: new Date().toISOString() }).eq("id", keyRecord.id);
  return json({ decision, policy: { id: policy.id, version: policy.version } });
});
