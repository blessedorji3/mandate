import { NextResponse } from "next/server";
import { evaluateAction } from "@/security/evaluate-action";
import type { SecurityPolicy } from "@/security/types";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";
const jsonHeaders = { "Cache-Control": "no-store" };

export async function POST(request: Request) {
  const supabase = await createClient();
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) return NextResponse.json({ error: "Sign in before inspecting an action." }, { status: 401, headers: jsonHeaders });

  try {
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > 16_384) return NextResponse.json({ error: "Request is too large." }, { status: 413, headers: jsonHeaders });
    const body: unknown = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body) || !("proposal" in body)) return NextResponse.json({ error: "Expected a proposal object." }, { status: 400, headers: jsonHeaders });

    const { data: savedPolicy, error } = await supabase.from("security_policies")
      .select("id, version, active, max_amount_atomic, allowed_recipients, allowed_action_types, require_approval_for_token_approvals, require_approval_for_all_actions")
      .eq("owner_id", user.id).eq("active", true).order("updated_at", { ascending: false }).limit(1).maybeSingle();
    if (error) return NextResponse.json({ error: "Could not load your active security policy." }, { status: 500, headers: jsonHeaders });
    if (!savedPolicy) return NextResponse.json({ error: "Create and activate a security policy before inspecting actions." }, { status: 409, headers: jsonHeaders });

    const policy: SecurityPolicy = {
      id: savedPolicy.id,
      version: savedPolicy.version,
      active: savedPolicy.active,
      maxAmountAtomic: savedPolicy.max_amount_atomic,
      allowedRecipients: savedPolicy.allowed_recipients,
      allowedActionTypes: savedPolicy.allowed_action_types,
      requireApprovalForTokenApprovals: savedPolicy.require_approval_for_token_approvals,
      requireApprovalForAllActions: savedPolicy.require_approval_for_all_actions
    };
    const proposal = (body as { proposal: unknown }).proposal;
    const decision = evaluateAction(proposal, policy);
    const proposalRecord = proposal && typeof proposal === "object" && !Array.isArray(proposal)
      ? proposal as Record<string, unknown>
      : {};
    const { error: receiptError } = await supabase.from("authorization_decisions").insert({
      owner_id: user.id,
      policy_id: policy.id,
      policy_version: policy.version,
      proposal_id: decision.proposalId,
      agent_id: typeof proposalRecord.agentId === "string" ? proposalRecord.agentId.slice(0, 128) : "unknown",
      action_type: typeof proposalRecord.actionType === "string" ? proposalRecord.actionType.slice(0, 64) : "unknown",
      outcome: decision.outcome,
      reason: decision.reason,
      proposal: proposalRecord
    });
    if (receiptError) {
      return NextResponse.json({ error: "Decision could not be recorded. No action was authorized." }, { status: 500, headers: jsonHeaders });
    }
    return NextResponse.json({ decision, policy: { id: policy.id, version: policy.version } }, { headers: jsonHeaders });
  } catch {
    return NextResponse.json({ error: "Could not inspect this proposal. No action was authorized." }, { status: 400, headers: jsonHeaders });
  }
}
