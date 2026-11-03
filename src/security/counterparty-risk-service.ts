import { evaluateCounterpartyRisk, type BlocklistEvidence, type CounterpartyRiskDecision, type RiskSignal } from "./counterparty-risk";
import { collectNearTestnetEvidence, type NearCounterpartyEvidence } from "./near-counterparty-evidence";
import { collectNearTestnetHistory, type NearTestnetHistoryEvidence } from "./near-counterparty-history";

export type CounterpartyRiskDependencies = {
  currentEvidence?: (accountId: string) => Promise<NearCounterpartyEvidence>;
  historicalEvidence?: (accountId: string) => Promise<NearTestnetHistoryEvidence>;
  findBlocklistRecord: (accountId: string) => Promise<{
    status: "confirmed" | "pending" | "rejected";
    evidence_ref: string;
    reason: string;
    reviewed_at: string | null;
    reviewer_owner_id: string | null;
  } | null>;
  countPreviousInteractions: (accountId: string) => Promise<number>;
  now?: () => Date;
};

export type CounterpartyRiskAssessment = {
  decision: CounterpartyRiskDecision;
  collection: {
    current: "PARTIAL" | "UNAVAILABLE";
    history: "PARTIAL" | "UNAVAILABLE";
    blocklist: "FOUND" | "NOT_FOUND" | "UNAVAILABLE";
    interactions: "VERIFIED" | "UNAVAILABLE";
  };
};

const signal = (
  name: string,
  status: RiskSignal["status"],
  observedAt: string,
  source: string,
  summary: string,
  value?: RiskSignal["value"],
): RiskSignal => ({ name, status, observedAt, source, summary, ...(value === undefined ? {} : { value }) });

/**
 * Orchestrates evidence collection only. It never authorizes execution.
 * Every dependency failure is represented as unavailable evidence and therefore WARN.
 */
export async function assessCounterpartyRisk(
  accountId: string,
  dependencies: CounterpartyRiskDependencies,
): Promise<CounterpartyRiskAssessment> {
  const now = dependencies.now ?? (() => new Date());
  const evaluatedAt = now().toISOString();

  let current: NearCounterpartyEvidence | null = null;
  let history: NearTestnetHistoryEvidence | null = null;
  let blocklistRow: Awaited<ReturnType<CounterpartyRiskDependencies["findBlocklistRecord"]>> = null;
  let blocklistLookupFailed = false;
  let interactionCount: number | null = null;

  const [currentResult, historyResult, blocklistResult, interactionResult] = await Promise.allSettled([
    (dependencies.currentEvidence ?? ((id) => collectNearTestnetEvidence(id)))(accountId),
    (dependencies.historicalEvidence ?? ((id) => collectNearTestnetHistory(id)))(accountId),
    dependencies.findBlocklistRecord(accountId),
    dependencies.countPreviousInteractions(accountId),
  ]);

  if (currentResult.status === "fulfilled" &&
      currentResult.value.accountId === accountId &&
      currentResult.value.network === "testnet") current = currentResult.value;
  if (historyResult.status === "fulfilled" &&
      historyResult.value.accountId === accountId &&
      historyResult.value.network === "testnet") history = historyResult.value;
  if (blocklistResult.status === "fulfilled") blocklistRow = blocklistResult.value;
  else blocklistLookupFailed = true;
  if (interactionResult.status === "fulfilled" &&
      Number.isSafeInteger(interactionResult.value) &&
      interactionResult.value >= 0) interactionCount = interactionResult.value;

  const observedAt = evaluatedAt;
  const signals: RiskSignal[] = [];

  const currentAccountType = current?.signals.find((item) => item.name === "account_type");
  signals.push(currentAccountType
    ? { ...currentAccountType }
    : signal("account_type", "unavailable", observedAt, "NEAR Testnet RPC", "Current account type could not be retrieved."));

  const currentCodeHash = current?.signals.find((item) => item.name === "contract_code_hash");
  if (currentCodeHash) signals.push({ ...currentCodeHash });

  const historyAge = history?.signals.find((item) => item.name === "account_age");
  signals.push(historyAge
    ? { ...historyAge }
    : signal("account_age", "unavailable", observedAt, "NEAR Testnet indexed history", "Account creation date could not be verified."));

  const recentActivity = history?.signals.find((item) => item.name === "recent_activity");
  signals.push(recentActivity
    ? { ...recentActivity }
    : signal("recent_activity", "unavailable", observedAt, "NEAR Testnet indexed history", "Recent activity could not be verified."));

  signals.push(interactionCount === null
    ? signal("previous_mandate_interactions", "unavailable", observedAt, "MANDATE authorization receipts", "Previous interactions could not be retrieved from the owner-scoped receipt store.")
    : signal("previous_mandate_interactions", "verified", observedAt, "MANDATE authorization receipts", "Count of previous authorization decisions involving this destination.", interactionCount));

  if (blocklistLookupFailed) {
    signals.push(signal("shared_blocklist_lookup", "unavailable", observedAt, "MANDATE reviewed blocklist", "Shared blocklist lookup failed; absence of a record cannot be assumed."));
  } else {
    signals.push(signal("shared_blocklist_lookup", "verified", observedAt, "MANDATE reviewed blocklist", blocklistRow ? "A blocklist record was retrieved." : "No blocklist record was found."));
  }

  const isContract = current?.status === "PARTIAL" ? current.isContract : null;
  const codeChangedRecently = null;
  const reviewedBlocklistRow = blocklistRow?.status === "confirmed" &&
    (!blocklistRow.reviewer_owner_id || !blocklistRow.reviewed_at)
      ? { ...blocklistRow, status: "pending" as const }
      : blocklistRow;
  const blocklist: BlocklistEvidence | null = reviewedBlocklistRow
    ? {
        status: reviewedBlocklistRow.status,
        evidenceRef: reviewedBlocklistRow.evidence_ref,
        reason: reviewedBlocklistRow.reason,
        ...(reviewedBlocklistRow.reviewed_at ? { reviewedAt: reviewedBlocklistRow.reviewed_at } : {}),
      }
    : null;

  const decision = evaluateCounterpartyRisk({
    accountId,
    evaluatedAt,
    accountAgeDays: history?.accountAgeDays ?? null,
    lastActivityDays: history?.lastActivityDays ?? null,
    isContract,
    contractCodeHash: current?.status === "PARTIAL" ? current.contractCodeHash : null,
    codeChangedRecently,
    previousInteractions: interactionCount,
    signals,
    blocklist,
  });

  return {
    decision,
    collection: {
      current: current?.status ?? "UNAVAILABLE",
      history: history?.status ?? "UNAVAILABLE",
      blocklist: blocklistLookupFailed ? "UNAVAILABLE" : blocklistRow ? "FOUND" : "NOT_FOUND",
      interactions: interactionCount === null ? "UNAVAILABLE" : "VERIFIED",
    },
  };
}
