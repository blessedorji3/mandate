import { NextResponse } from "next/server";
import { evaluateAction } from "@/security/evaluate-action";
import type { ActionProposal, SecurityPolicy } from "@/security/types";

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

export async function POST(request: Request) {
  try {
    const body: unknown = await request.json();
    if (!body || typeof body !== "object" || !("proposal" in body)) {
      return NextResponse.json({ error: "Expected a proposal object." }, { status: 400 });
    }

    const proposal = (body as { proposal: ActionProposal }).proposal;
    if (!proposal || typeof proposal !== "object") {
      return NextResponse.json({ error: "Invalid proposal." }, { status: 400 });
    }

    const decision = evaluateAction(proposal, demoPolicy);
    return NextResponse.json({ decision, policy: { id: demoPolicy.id, version: demoPolicy.version } });
  } catch {
    return NextResponse.json({ error: "Could not inspect this proposal. The request was not authorized." }, { status: 400 });
  }
}
