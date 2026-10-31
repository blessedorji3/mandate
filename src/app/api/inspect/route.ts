import { NextResponse } from "next/server";
import { evaluateAction } from "@/security/evaluate-action";
import type { SecurityPolicy } from "@/security/types";

export const runtime = "nodejs";

const demoPolicy: SecurityPolicy = {
  id: "mandate-demo-policy",
  version: 1,
  active: true,
  maxAmountAtomic: "1000000000000000000000000",
  allowedRecipients: ["alice.near", "treasury.near"],
  allowedActionTypes: ["transfer", "token_approval"],
  requireApprovalForTokenApprovals: true,
  requireApprovalForAllActions: false
};

const jsonHeaders = { "Cache-Control": "no-store" };

export async function POST(request: Request) {
  try {
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > 16_384) {
      return NextResponse.json({ error: "Request is too large." }, { status: 413, headers: jsonHeaders });
    }

    const body: unknown = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body) || !("proposal" in body)) {
      return NextResponse.json({ error: "Expected a proposal object." }, { status: 400, headers: jsonHeaders });
    }

    const proposal = (body as { proposal: unknown }).proposal;
    const decision = evaluateAction(proposal, demoPolicy);
    return NextResponse.json(
      { decision, policy: { id: demoPolicy.id, version: demoPolicy.version } },
      { status: 200, headers: jsonHeaders }
    );
  } catch {
    return NextResponse.json(
      { error: "Could not inspect this proposal. The request was not authorized." },
      { status: 400, headers: jsonHeaders }
    );
  }
}
