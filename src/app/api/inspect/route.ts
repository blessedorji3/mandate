import { NextResponse } from "next/server";
import { createClient as createSupabaseAdminClient } from "@supabase/supabase-js";
import { createClient } from "@/lib/supabase/server";
import { evaluateAction } from "@/security/evaluate-action";
import type { SecurityPolicy } from "@/security/types";
import { assessCounterpartyRisk } from "@/security/counterparty-risk-service";
import { evaluateCounterpartyRisk } from "@/security/counterparty-risk";
import { combinePolicyAndCounterpartyRisk } from "@/security/inspection-risk";
import { createSupabaseRiskDependencies } from "@/security/supabase-risk-dependencies";

export const runtime = "nodejs";
const jsonHeaders = { "Cache-Control": "no-store" };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function POST(request: Request) {
  try {
    const supabase = await createClient();
    const { data: { user }, error: authError } = await supabase.auth.getUser();
    if (authError || !user) {
      return NextResponse.json({ error: "Sign in before inspecting an action." }, { status: 401, headers: jsonHeaders });
    }

    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > 16_384) {
      return NextResponse.json({ error: "Request is too large." }, { status: 413, headers: jsonHeaders });
    }

    const body: unknown = await request.json();
    if (!isRecord(body) || !("proposal" in body)) {
      return NextResponse.json({ error: "Expected a proposal object." }, { status: 400, headers: jsonHeaders });
    }

    const { data: savedPolicy, error } = await supabase.from("security_policies")
      .select("id, version, active, max_amount_atomic, allowed_recipients, allowed_action_types, require_approval_for_token_approvals, require_approval_for_all_actions")
      .eq("owner_id", user.id).eq("active", true).order("updated_at", { ascending: false }).limit(1).maybeSingle();
    if (error) {
      return NextResponse.json({ error: "Could not load your active security policy." }, { status: 500, headers: jsonHeaders });
    }
    if (!savedPolicy) {
      return NextResponse.json({ error: "Create and activate a security policy before inspecting actions." }, { status: 409, headers: jsonHeaders });
    }

    const policy: SecurityPolicy = {
      id: savedPolicy.id,
      version: savedPolicy.version,
      active: savedPolicy.active,
      maxAmountAtomic: savedPolicy.max_amount_atomic,
      allowedRecipients: savedPolicy.allowed_recipients,
      allowedActionTypes: savedPolicy.allowed_action_types,
      requireApprovalForTokenApprovals: savedPolicy.require_approval_for_token_approvals,
      requireApprovalForAllActions: savedPolicy.require_approval_for_all_actions,
    };

    const proposal = body.proposal;
    const proposalRecord = isRecord(proposal) ? proposal : {};
    const policyDecision = evaluateAction(proposal, policy);
    const targetAccountId = typeof proposalRecord.target === "string" ? proposalRecord.target : "";
    const unsupportedNetwork = proposalRecord.network !== undefined && proposalRecord.network !== "testnet";
    const now = () => new Date();

    let riskAssessment;
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (supabaseUrl && serviceRoleKey) {
      const admin = createSupabaseAdminClient(supabaseUrl, serviceRoleKey, {
        auth: { autoRefreshToken: false, persistSession: false },
      });
      riskAssessment = await assessCounterpartyRisk(
        user.id,
        targetAccountId,
        createSupabaseRiskDependencies(admin),
      );
    } else {
      const evaluatedAt = now().toISOString();
      riskAssessment = {
        decision: evaluateCounterpartyRisk({
          accountId: targetAccountId,
          evaluatedAt,
          signals: [],
        }, now),
        collection: {
          chain: "UNAVAILABLE" as const,
          blocklist: "UNAVAILABLE" as const,
          interactions: "UNAVAILABLE" as const,
        },
      };
    }

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
    const { error: receiptError } = await supabase.from("authorization_decisions").insert({
      owner_id: user.id,
      policy_id: policy.id,
      policy_version: policy.version,
      proposal_id: decision.proposalId,
      agent_id: typeof proposalRecord.agentId === "string" ? proposalRecord.agentId.slice(0, 128) : "unknown",
      action_type: typeof proposalRecord.actionType === "string" ? proposalRecord.actionType.slice(0, 64) : "unknown",
      outcome: decision.outcome,
      reason: decision.reason,
      proposal: recordedProposal,
    });
    if (receiptError) {
      return NextResponse.json({ error: "Decision could not be recorded. No action was authorized." }, { status: 500, headers: jsonHeaders });
    }

    return NextResponse.json({
      decision,
      risk: riskAssessment.decision,
      riskCollection: riskAssessment.collection,
      policy: { id: policy.id, version: policy.version },
    }, { headers: jsonHeaders });
  } catch {
    return NextResponse.json({ error: "Could not inspect this proposal. No action was authorized." }, { status: 400, headers: jsonHeaders });
  }
}
