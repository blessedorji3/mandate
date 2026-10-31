import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";
const headers = { "Cache-Control": "no-store" };

export async function GET() {
  const supabase = await createClient();
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) return NextResponse.json({ error: "Authentication required." }, { status: 401, headers });

  const { data, error } = await supabase.from("authorization_decisions")
    .select("id, policy_id, policy_version, proposal_id, agent_id, action_type, outcome, reason, created_at")
    .eq("owner_id", user.id).order("created_at", { ascending: false }).limit(50);
  if (error) return NextResponse.json({ error: "Could not load decision history." }, { status: 500, headers });
  return NextResponse.json({ decisions: data ?? [] }, { headers });
}
