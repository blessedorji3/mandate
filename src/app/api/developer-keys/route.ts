import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { readBoundedRequestText, RequestBodyTooLargeError } from "@/security/read-bounded-request-body";

export const runtime = "nodejs";
const headers = { "Cache-Control": "no-store" };
const trustedAppOrigin = "https://mandate-snowy.vercel.app";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function POST(request: Request) {
  const supabase = await createClient();
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401, headers });
  }
  const { data: { session }, error: sessionError } = await supabase.auth.getSession();
  if (sessionError || !session?.access_token) {
    return NextResponse.json({ error: "Your MANDATE session could not be verified. Sign in again." }, { status: 401, headers });
  }

  let rawBody: string;
  try {
    rawBody = await readBoundedRequestText(request, 8_192);
  } catch (error) {
    if (error instanceof RequestBodyTooLargeError) {
      return NextResponse.json({ error: "Request is too large." }, { status: 413, headers });
    }
    return NextResponse.json({ error: "Request body must be valid UTF-8." }, { status: 400, headers });
  }

  let body: unknown;
  try {
    body = JSON.parse(rawBody) as unknown;
  } catch {
    return NextResponse.json({ error: "Request body must be valid JSON." }, { status: 400, headers });
  }
  if (!isRecord(body) || typeof body.action !== "string") {
    return NextResponse.json({ error: "A supported API-key action is required." }, { status: 400, headers });
  }

  let edgeBody: Record<string, unknown>;
  if (body.action === "api_keys_list") {
    edgeBody = { action: "api_keys_list" };
  } else if (body.action === "api_key_create" &&
      typeof body.name === "string" && body.name.trim().length >= 1 && body.name.trim().length <= 80) {
    edgeBody = { action: "api_key_create", name: body.name.trim() };
  } else if (body.action === "api_key_revoke" &&
      typeof body.keyId === "string" &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(body.keyId)) {
    edgeBody = { action: "api_key_revoke", keyId: body.keyId };
  } else {
    return NextResponse.json({ error: "Invalid API-key action or parameters." }, { status: 400, headers });
  }

  const { data, error } = await supabase.functions.invoke("near-transfer-authorization", {
    headers: {
      Authorization: `Bearer ${session.access_token}`,
      Origin: trustedAppOrigin,
    },
    body: edgeBody,
  });
  if (error || !isRecord(data)) {
    return NextResponse.json({ error: "The trusted API-key service is unavailable. No key change was made." }, { status: 503, headers });
  }
  return NextResponse.json(data, { status: body.action === "api_key_create" ? 201 : 200, headers });
}
