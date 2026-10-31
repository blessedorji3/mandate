import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import type { ActionType } from "@/security/types";

export const runtime = "nodejs";
const headers = { "Cache-Control": "no-store" };
const ACTIONS = new Set<ActionType>(["transfer", "token_approval", "swap", "contract_call"]);

function validPolicyBody(value: unknown): value is {
  name: string; maxAmountAtomic: string; allowedRecipients: string[];
  allowedActionTypes: ActionType[]; requireApprovalForTokenApprovals: boolean;
  requireApprovalForAllActions: boolean; active: boolean;
} {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return typeof v.name === "string" && v.name.trim().length > 0 && v.name.length <= 100 &&
    typeof v.maxAmountAtomic === "string" && /^[1-9][0-9]*$/.test(v.maxAmountAtomic) &&
    Array.isArray(v.allowedRecipients) && v.allowedRecipients.length <= 100 &&
    v.allowedRecipients.every(x => typeof x === "string" && x.trim().length > 0 && x.length <= 128) &&
    Array.isArray(v.allowedActionTypes) && v.allowedActionTypes.length > 0 &&
    v.allowedActionTypes.every(x => typeof x === "string" && ACTIONS.has(x as ActionType)) &&
    typeof v.requireApprovalForTokenApprovals === "boolean" &&
    typeof v.requireApprovalForAllActions === "boolean" && typeof v.active === "boolean";
}

export async function GET() {
  const supabase = await createClient();
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) return NextResponse.json({ error: "Authentication required." }, { status: 401, headers });
  const { data, error } = await supabase.from("security_policies")
    .select("id, name, version, active, max_amount_atomic, allowed_recipients, allowed_action_types, require_approval_for_token_approvals, require_approval_for_all_actions, updated_at")
    .eq("owner_id", user.id).order("updated_at", { ascending: false }).limit(1).maybeSingle();
  if (error) return NextResponse.json({ error: "Could not load your security policy." }, { status: 500, headers });
  return NextResponse.json({ policy: data ?? null }, { headers });
}

export async function PUT(request: Request) {
  const supabase = await createClient();
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) return NextResponse.json({ error: "Authentication required." }, { status: 401, headers });

  try {
    const body: unknown = await request.json();
    if (!validPolicyBody(body)) return NextResponse.json({ error: "Invalid policy details. Check the amount, recipients and action types." }, { status: 400, headers });

    const { data: current, error: readError } = await supabase.from("security_policies")
      .select("id, version").eq("owner_id", user.id).order("updated_at", { ascending: false }).limit(1).maybeSingle();
    if (readError) return NextResponse.json({ error: "Could not load your current policy." }, { status: 500, headers });

    const values = {
      name: body.name.trim(),
      version: (current?.version ?? 0) + 1,
      active: body.active,
      max_amount_atomic: body.maxAmountAtomic,
      allowed_recipients: body.allowedRecipients.map(x => x.trim()),
      allowed_action_types: body.allowedActionTypes,
      require_approval_for_token_approvals: body.requireApprovalForTokenApprovals,
      require_approval_for_all_actions: body.requireApprovalForAllActions,
      updated_at: new Date().toISOString()
    };

    const query = current
      ? supabase.from("security_policies").update(values).eq("id", current.id).eq("owner_id", user.id)
      : supabase.from("security_policies").insert({ ...values, owner_id: user.id });

    const { data, error } = await query.select("id, name, version, active, max_amount_atomic, allowed_recipients, allowed_action_types, require_approval_for_token_approvals, require_approval_for_all_actions, updated_at").single();
    if (error || !data) return NextResponse.json({ error: "Policy could not be saved." }, { status: 500, headers });
    return NextResponse.json({ policy: data }, { headers });
  } catch {
    return NextResponse.json({ error: "Invalid policy request." }, { status: 400, headers });
  }
}
