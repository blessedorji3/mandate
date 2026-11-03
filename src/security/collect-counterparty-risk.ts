import { evaluateCounterpartyRisk, type BlocklistEvidence, type CounterpartyRiskDecision, type RiskSignal } from "./counterparty-risk";
import { collectNearTestnetEvidence, type NearEvidenceSignal } from "./near-counterparty-evidence";
import { collectNearTestnetHistory, type HistoricalSignal } from "./near-counterparty-history";

export type CounterpartyRiskCollection = {
  network: "testnet";
  accountId: string;
  status: "COMPLETE" | "PARTIAL" | "UNAVAILABLE";
  decision: CounterpartyRiskDecision;
  collectedAt: string;
};

export type RiskCollectionOptions = {
  fetchImpl?: typeof fetch;
  now?: () => Date;
  fastNearApiKey?: string;
  previousInteractions?: number | null;
  blocklist?: BlocklistEvidence | null;
  blocklistLookupStatus?: "verified" | "unavailable";
};

function toRiskSignal(signal: NearEvidenceSignal | HistoricalSignal): RiskSignal {
  return {
    name: signal.name,
    status: signal.status,
    observedAt: signal.observedAt,
    source: signal.source,
    summary: signal.summary,
    ...(signal.value !== undefined ? { value: signal.value } : {}),
  };
}

/**
 * Combines current Testnet RPC state and indexed account history into the
 * existing deterministic risk evaluator. Missing MANDATE receipt history
 * stays unavailable unless supplied by a trusted server-side caller.
 *
 * This is collection/evaluation only. It does not authorize, sign or broadcast.
 */
export async function collectAndEvaluateNearTestnetCounterparty(
  accountId: string,
  options: RiskCollectionOptions = {},
): Promise<CounterpartyRiskCollection> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? (() => new Date());
  const [current, history] = await Promise.all([
    collectNearTestnetEvidence(accountId, fetchImpl, now),
    collectNearTestnetHistory(accountId, fetchImpl, now, options.fastNearApiKey),
  ]);

  const evaluatedAt = now().toISOString();
  const currentByName = new Map(current.signals.map((signal) => [signal.name, signal]));
  const historyByName = new Map(history.signals.map((signal) => [signal.name, signal]));

  // Prefer indexed historical values for age/activity; current RPC remains
  // authoritative for account type and the current contract code hash.
  const merged: RiskSignal[] = [];
  for (const name of ["account_age", "recent_activity"] as const) {
    const signal = historyByName.get(name);
    if (signal) merged.push(toRiskSignal(signal));
  }
  const accountType = currentByName.get("account_type");
  if (accountType) merged.push(toRiskSignal(accountType));
  for (const name of ["contract_code_hash", "contract_code_history"] as const) {
    const signal = currentByName.get(name);
    if (signal) merged.push(toRiskSignal(signal));
  }

  const interactionCount = options.previousInteractions;
  merged.push({
    name: "shared_blocklist_lookup",
    status: options.blocklistLookupStatus === "verified" ? "verified" : "unavailable",
    observedAt: evaluatedAt,
    source: "MANDATE reviewed blocklist",
    summary: options.blocklistLookupStatus === "verified"
      ? options.blocklist ? "Shared blocklist lookup completed and returned a record." : "Shared blocklist lookup completed; no report was found."
      : "Shared blocklist lookup failed or was not supplied; absence of a report cannot be assumed.",
  });
  merged.push({
    name: "previous_mandate_interactions",
    status: Number.isSafeInteger(interactionCount) && Number(interactionCount) >= 0 ? "verified" : "unavailable",
    observedAt: evaluatedAt,
    source: "MANDATE authorization receipts",
    summary: Number.isSafeInteger(interactionCount) && Number(interactionCount) >= 0
      ? "Trusted server-side receipt count supplied."
      : "Receipt history was not supplied by a trusted server-side lookup.",
    value: Number.isSafeInteger(interactionCount) && Number(interactionCount) >= 0 ? Number(interactionCount) : null,
  });

  const decision = evaluateCounterpartyRisk({
    accountId,
    evaluatedAt,
    accountAgeDays: history.accountAgeDays,
    lastActivityDays: history.lastActivityDays,
    isContract: current.isContract,
    contractCodeHash: current.contractCodeHash,
    codeChangedRecently: current.codeChangedRecently,
    previousInteractions: Number.isSafeInteger(interactionCount) && Number(interactionCount) >= 0
      ? Number(interactionCount) : null,
    signals: merged,
    blocklist: options.blocklist ?? null,
  });

  const unavailable = current.status === "UNAVAILABLE" || history.status === "UNAVAILABLE";
  return {
    network: "testnet",
    accountId,
    status: unavailable ? "UNAVAILABLE" : decision.outcome === "ALLOW" ? "COMPLETE" : "PARTIAL",
    decision,
    collectedAt: evaluatedAt,
  };
}
