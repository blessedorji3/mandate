import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
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
    if (!isRecord(body) || !isRecord(body.proposal)) {
      return NextResponse.json({ error: "Expected a proposal object." }, { status: 400, headers: jsonHeaders });
    }

    // The Edge Function is the trusted decision writer. It independently loads
    // this authenticated owner's active policy, evaluates the proposal and
    // inserts the immutable decision receipt with service-role privileges.
    const { data, error } = await supabase.functions.invoke("near-transfer-authorization", {
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        Origin: "https://mandate-snowy.vercel.app",
      },
      body: {
        action: "inspect_proposal",
        proposal: body.proposal,
      },
    });

    if (error || !isRecord(data) || !isRecord(data.decision) ||
        !["ALLOW", "BLOCK", "REQUIRE_APPROVAL"].includes(String(data.decision.outcome)) ||
        !isRecord(data.risk) || !isRecord(data.policy)) {
      return NextResponse.json({
        error: "Inspection failed or the trusted authorization service returned an inconsistent response. No action was authorized.",
      }, { status: 503, headers: jsonHeaders });
    }

    return NextResponse.json(data, { headers: jsonHeaders });
  } catch {
    return NextResponse.json({
      error: "Could not inspect this proposal. No action was authorized.",
    }, { status: 503, headers: jsonHeaders });
  }
}
