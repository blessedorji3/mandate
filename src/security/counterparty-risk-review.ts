import type { CounterpartyRiskDecision } from "./counterparty-risk.ts";

export type RiskReviewProposal = {
  id: string;
  agentId?: string;
  actionType: string;
  asset: string;
  amountAtomic: string;
  target: string;
  network?: string;
  protocol?: string;
  approvalAmountAtomic?: string;
};

export type RiskReviewBinding = {
  ownerId: string;
  policyId: string;
  policyVersion: number;
  proposal: RiskReviewProposal;
  risk: CounterpartyRiskDecision;
};

/**
 * Stable fingerprint for a signed owner risk acknowledgement.
 * Observation timestamps are intentionally excluded; freshness is represented
 * by each signal's verified/stale/unavailable status and its evidence value.
 * The binding includes the complete proposal identity and policy version.
 */
export async function fingerprintCounterpartyRisk(binding: RiskReviewBinding): Promise<string> {
  const { ownerId, policyId, policyVersion, proposal, risk } = binding;
  if (!ownerId || !policyId || !Number.isSafeInteger(policyVersion) || policyVersion < 1 ||
      !proposal || !proposal.id || !proposal.actionType || !proposal.asset ||
      !proposal.amountAtomic || !proposal.target || (proposal.network ?? "testnet") !== "testnet" ||
      !risk || risk.accountId !== proposal.target || !["ALLOW", "WARN", "BLOCK"].includes(risk.outcome) ||
      !Array.isArray(risk.reasons) || !Array.isArray(risk.evidence)) {
    throw new Error("Cannot fingerprint an incomplete counterparty risk review binding.");
  }

  const evidence = risk.evidence.map((signal) => ({
    name: signal.name,
    status: signal.status,
    source: signal.source,
    summary: signal.summary,
    ...(signal.value === undefined ? {} : { value: signal.value }),
  })).sort((a, b) =>
    a.name.localeCompare(b.name) ||
    a.source.localeCompare(b.source) ||
    a.summary.localeCompare(b.summary)
  );

  const canonical = JSON.stringify({
    schema: "MANDATE_COUNTERPARTY_RISK_REVIEW_V1",
    ownerId,
    policyId,
    policyVersion,
    proposal: {
      id: proposal.id,
      agentId: proposal.agentId ?? "",
      actionType: proposal.actionType,
      asset: proposal.asset,
      amountAtomic: proposal.amountAtomic,
      target: proposal.target,
      network: proposal.network ?? "testnet",
      protocol: proposal.protocol ?? null,
      approvalAmountAtomic: proposal.approvalAmountAtomic ?? null,
    },
    risk: {
      accountId: risk.accountId,
      outcome: risk.outcome,
      reasons: [...risk.reasons],
      requiresHumanApproval: risk.requiresHumanApproval,
      evidence,
    },
  });

  const bytes = new TextEncoder().encode(canonical);
  const digest = await crypto.subtle.digest("SHA-256", bytes.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
