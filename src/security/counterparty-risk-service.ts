import { evaluateCounterpartyRisk, type BlocklistEvidence, type CounterpartyRiskDecision } from "./counterparty-risk";
import { collectAndEvaluateNearTestnetCounterparty, type CounterpartyRiskCollection } from "./collect-counterparty-risk";

export type CounterpartyRiskDependencies = {
  findBlocklistRecord: (accountId: string) => Promise<{
    status: "confirmed" | "pending" | "rejected";
    evidence_ref: string;
    reason: string;
    reviewed_at: string | null;
    reviewer_owner_id: string | null;
  } | null>;
  countPreviousInteractions: (accountId: string) => Promise<number>;
  collectRisk?: (
    accountId: string,
    options: {
      previousInteractions: number | null;
      blocklist: BlocklistEvidence | null;
      blocklistLookupStatus: "verified" | "unavailable";
    },
  ) => Promise<CounterpartyRiskCollection>;
  now?: () => Date;
};

export type CounterpartyRiskAssessment = {
  decision: CounterpartyRiskDecision;
  collection: {
    chain: "COMPLETE" | "PARTIAL" | "UNAVAILABLE";
    blocklist: "FOUND" | "NOT_FOUND" | "UNAVAILABLE";
    interactions: "VERIFIED" | "UNAVAILABLE";
  };
};

/**
 * Retrieves server-only database evidence and delegates chain collection to the
 * tested collector. All failures become unavailable signals and therefore WARN.
 * This service never authorizes execution or invokes a signer.
 */
export async function assessCounterpartyRisk(
  accountId: string,
  dependencies: CounterpartyRiskDependencies,
): Promise<CounterpartyRiskAssessment> {
  const now = dependencies.now ?? (() => new Date());
  const evaluatedAt = now().toISOString();
  const [blocklistResult, interactionResult] = await Promise.allSettled([
    dependencies.findBlocklistRecord(accountId),
    dependencies.countPreviousInteractions(accountId),
  ]);

  const blocklistLookupStatus = blocklistResult.status === "fulfilled" ? "verified" : "unavailable";
  const blocklistRow = blocklistResult.status === "fulfilled" ? blocklistResult.value : null;
  const interactionCount = interactionResult.status === "fulfilled" &&
    Number.isSafeInteger(interactionResult.value) && interactionResult.value >= 0
      ? interactionResult.value
      : null;

  const reviewedRow = blocklistRow?.status === "confirmed" &&
    (!blocklistRow.reviewer_owner_id || !blocklistRow.reviewed_at)
      ? { ...blocklistRow, status: "pending" as const }
      : blocklistRow;
  const blocklist: BlocklistEvidence | null = reviewedRow
    ? {
        status: reviewedRow.status,
        evidenceRef: reviewedRow.evidence_ref,
        reason: reviewedRow.reason,
        ...(reviewedRow.reviewed_at ? { reviewedAt: reviewedRow.reviewed_at } : {}),
      }
    : null;

  let collected: CounterpartyRiskCollection | null = null;
  try {
    collected = await (dependencies.collectRisk ?? collectAndEvaluateNearTestnetCounterparty)(
      accountId,
      {
        previousInteractions: interactionCount,
        blocklist,
        blocklistLookupStatus,
        now,
      },
    );
  } catch {
    // Invalid target IDs and unexpected collector failures must never escape as ALLOW.
  }

  const decision = collected?.decision ?? evaluateCounterpartyRisk({
    accountId,
    evaluatedAt,
    signals: [],
    previousInteractions: interactionCount,
    blocklist,
  });

  return {
    decision,
    collection: {
      chain: collected?.status ?? "UNAVAILABLE",
      blocklist: blocklistResult.status === "rejected"
        ? "UNAVAILABLE"
        : blocklistRow ? "FOUND" : "NOT_FOUND",
      interactions: interactionCount === null ? "UNAVAILABLE" : "VERIFIED",
    },
  };
}
