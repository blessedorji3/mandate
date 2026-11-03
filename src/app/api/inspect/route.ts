import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";
const jsonHeaders = { "Cache-Control": "no-store" };

export async function POST(request: Request) {
  const supabase = await createClient();
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) {
    return NextResponse.json({ error: "Sign in before inspecting an action." }, { status: 401, headers: jsonHeaders });
  }

  try {
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > 16_384) {
      return NextResponse.json({ error: "Request is too large." }, { status: 413, headers: jsonHeaders });
    }
    const body: unknown = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body) || !("proposal" in body)) {
      return NextResponse.json({ error: "Expected a proposal object." }, { status: 400, headers: jsonHeaders });
    }

    const { data: { session }, error: sessionError } = await supabase.auth.getSession();
    if (sessionError || !session?.access_token) {
      return NextResponse.json({ error: "Your authenticated session could not be verified." }, { status: 401, headers: jsonHeaders });
    }

    // All inspection decisions, including counterparty evidence and the saved
    // receipt, are produced by the authenticated server-side Edge Function.
    const { data, error } = await supabase.functions.invoke("near-transfer-authorization", {
      body: { action: "inspect", proposal: body.proposal },
      headers: { Authorization: "Bearer " + session.access_token },
    });
    if (error || !data || typeof data !== "object") {
      return NextResponse.json({ error: "The server-side inspection service is unavailable. No action was authorized." }, { status: 503, headers: jsonHeaders });
    }
    return NextResponse.json(data, { headers: jsonHeaders });
  } catch {
    return NextResponse.json({ error: "Could not inspect this proposal. No action was authorized." }, { status: 400, headers: jsonHeaders });
  }
}
