import { collectAndEvaluateNearTestnetCounterparty, type CounterpartyRiskCollection } from "./collect-counterparty-risk";
import { evaluateCounterpartyRisk, type BlocklistEvidence, type CounterpartyRiskDecision } from "./counterparty-risk";

type DatabaseBlocklistRow = {
  status: "confirmed" | "pending" | "rejected";
  evidence_ref: string;
  reason: string;
  reviewed_at: string | null;
  reviewer_owner_id: string | null;
};

export type CounterpartyRiskServiceDependencies = {
  /** This dependency must query the shared list for this exact network + account ID. */
  findBlocklistRecord: (network: "testnet", accountId: string) => Promise<unknown | null>;
  /** Must filter authorization_decisions by both ownerId and targetAccountId. */
  countPreviousInteractions: (ownerId: string, network: "testnet", targetAccountId: string) => Promise<number>;
  collectRisk?: (
    accountId: string,
    options: {
      previousInteractions: number | null;
      blocklist: BlocklistEvidence | null;
      blocklistLookupStatus: "verified" | "unavailable";
      fastNearApiKey?: string;
      now?: () => Date;
    },
  ) => Promise<CounterpartyRiskCollection>;
  fastNearApiKey?: string;
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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ACCOUNT_ID = /^(?:[a-z0-9]+(?:[-_][a-z0-9]+)*)(?:\.[a-z0-9]+(?:[-_][a-z0-9]+)*)*$/;
const TEXT = (value: unknown): value is string =>
  typeof value === "string" && value.trim().length > 0 && value.length <= 500;

function normalizeBlocklistRow(value: unknown): { evidence: BlocklistEvidence | null; found: boolean } | null {
  if (value === null) return { evidence: null, found: false };
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (!["confirmed", "pending", "rejected"].includes(String(row.status)) ||
      !TEXT(row.evidence_ref) || !TEXT(row.reason) ||
      (row.reviewed_at !== null && typeof row.reviewed_at !== "string") ||
      (row.reviewer_owner_id !== null && typeof row.reviewer_owner_id !== "string")) return null;
  const evidence: BlocklistEvidence = {
    status: row.status as BlocklistEvidence["status"],
    evidenceRef: row.evidence_ref,
    reason: row.reason,
    ...(typeof row.reviewer_owner_id === "string" ? { reviewerId: row.reviewer_owner_id } : {}),
    ...(typeof row.reviewed_at === "string" ? { reviewedAt: row.reviewed_at } : {}),
  };
  return { evidence, found: true };
}

/**
 * Trusted server-side coordinator. Owner identity is an explicit input from
 * the authenticated API-key/session context; callers must never pass a
 * browser-supplied owner ID. Target interaction queries receive owner and
 * counterparty separately so implementations cannot omit either predicate.
 */
export async function assessCounterpartyRisk(
  ownerId: string,
  targetAccountId: string,
  dependencies: CounterpartyRiskServiceDependencies,
): Promise<CounterpartyRiskAssessment> {
  const now = dependencies.now ?? (() => new Date());
  const evaluatedAt = now().toISOString();
  if (typeof ownerId !== "string" || !UUID.test(ownerId) || typeof targetAccountId !== "string" || targetAccountId.length < 2 || targetAccountId.length > 64 || !ACCOUNT_ID.test(targetAccountId)) {
    return {
      decision: evaluateCounterpartyRisk({ accountId: targetAccountId, evaluatedAt, signals: [] }, now),
      collection: { chain: "UNAVAILABLE", blocklist: "UNAVAILABLE", interactions: "UNAVAILABLE" },
    };
  }

  const [blocklistResult, interactionResult] = await Promise.allSettled([
    dependencies.findBlocklistRecord("testnet", targetAccountId),
    dependencies.countPreviousInteractions(ownerId, "testnet", targetAccountId),
  ]);

  const normalized = blocklistResult.status === "fulfilled"
    ? normalizeBlocklistRow(blocklistResult.value) : null;
  const blocklistLookupStatus: "verified" | "unavailable" =
    blocklistResult.status === "fulfilled" && normalized !== null ? "verified" : "unavailable";
  const interactionCount = interactionResult.status === "fulfilled" &&
      Number.isSafeInteger(interactionResult.value) && interactionResult.value >= 0
    ? interactionResult.value : null;

  let collected: CounterpartyRiskCollection | null = null;
  try {
    collected = await (dependencies.collectRisk ?? collectAndEvaluateNearTestnetCounterparty)(
      targetAccountId,
      {
        previousInteractions: interactionCount,
        blocklist: blocklistLookupStatus === "verified" ? normalized!.evidence : null,
        blocklistLookupStatus,
        fastNearApiKey: dependencies.fastNearApiKey,
        now,
      },
    );
  } catch {
    // Failed or malformed chain collectors never become an ALLOW result.
  }

  const decision = collected?.decision ?? evaluateCounterpartyRisk({
    accountId: targetAccountId,
    evaluatedAt,
    accountAgeDays: null,
    lastActivityDays: null,
    isContract: null,
    contractCodeHash: null,
    codeChangedRecently: null,
    previousInteractions: interactionCount,
    signals: [],
    blocklist: blocklistLookupStatus === "verified" ? normalized?.evidence ?? null : null,
  }, now);

  return {
    decision,
    collection: {
      chain: collected?.status ?? "UNAVAILABLE",
      blocklist: blocklistLookupStatus === "unavailable" ? "UNAVAILABLE" : normalized!.found ? "FOUND" : "NOT_FOUND",
      interactions: interactionCount === null ? "UNAVAILABLE" : "VERIFIED",
    },
  };
}
