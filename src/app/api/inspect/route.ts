import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { evaluateAction } from "@/security/evaluate-action";
import type { SecurityPolicy } from "@/security/types";
import { combinePolicyAndCounterpartyRisk } from "@/security/inspection-risk";
import { readBoundedRequestText, RequestBodyTooLargeError } from "@/security/read-bounded-request-body";

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
    const { data: { session }, error: sessionError } = await supabase.auth.getSession();
    if (sessionError || !session?.access_token) {
      return NextResponse.json({ error: "Your MANDATE session could not be verified. Sign in again." }, { status: 401, headers: jsonHeaders });
    }

    let rawBody: string;
    try {
      rawBody = await readBoundedRequestText(request, 16_384);
    } catch (error) {
      if (error instanceof RequestBodyTooLargeError) {
        return NextResponse.json({ error: "Request is too large." }, { status: 413, headers: jsonHeaders });
      }
      return NextResponse.json({ error: "Request body must be valid UTF-8." }, { status: 400, headers: jsonHeaders });
    }
    let body: unknown;
    try {
      body = JSON.parse(rawBody) as unknown;
    } catch {
      return NextResponse.json({ error: "Request body must be valid JSON." }, { status: 400, headers: jsonHeaders });
    }
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

    const boundedPolicyDecision = unsupportedNetwork
      ? {
          ...policyDecision,
          outcome: "BLOCK" as const,
          reason: "INVALID_PROPOSAL" as const,
          message: "Only NEAR Testnet proposals can be inspected by this environment. No action is authorized.",
        }
      : policyDecision;

    // Inspect counterparty evidence through the same authenticated Edge Function
    // used for signed WARN acknowledgement and transfer authorization. This
    // prevents environment-specific service-role fallbacks from creating a
    // different fingerprint at the next authorization boundary.
    const { data: riskData, error: riskError } = await supabase.functions.invoke(
      "near-transfer-authorization",
      {
        headers: { Authorization: `Bearer ${session.access_token}` },
        body: {
          action: "counterparty_inspect",
          proposal: {
            ...proposalRecord,
            network: "testnet",
          },
        },
      },
    );
    if (riskError || !isRecord(riskData) ||
        !isRecord(riskData.risk) ||
        !["ALLOW", "WARN", "BLOCK"].includes(String(riskData.risk.outcome)) ||
        riskData.risk.accountId !== targetAccountId ||
        typeof riskData.counterpartyRiskFingerprint !== "string" ||
        !/^[0-9a-f]{64}$/.test(riskData.counterpartyRiskFingerprint) ||
        !isRecord(riskData.policy) ||
        riskData.policy.id !== policy.id ||
        riskData.policy.version !== policy.version) {
      return NextResponse.json({
        error: "Counterparty risk inspection is unavailable or inconsistent. No action was authorized.",
      }, { status: 503, headers: jsonHeaders });
    }

    const riskAssessment = {
      decision: riskData.risk as unknown as import("@/security/counterparty-risk").CounterpartyRiskDecision,
      collection: isRecord(riskData.riskCollection)
        ? riskData.riskCollection
        : { chain: "UNAVAILABLE", blocklist: "UNAVAILABLE", interactions: "UNAVAILABLE" },
    };
    const decision = combinePolicyAndCounterpartyRisk(boundedPolicyDecision, riskAssessment.decision);

    const fingerprintableProposal = {
      ...proposalRecord,
      network: "testnet",
    };
    const counterpartyRiskFingerprint = riskData.counterpartyRiskFingerprint;
    const recordedProposal = {
      ...fingerprintableProposal,
      counterpartyRisk: riskAssessment.decision,
      counterpartyRiskFingerprint,
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
