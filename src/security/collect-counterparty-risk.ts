import {
  evaluateCounterpartyRisk,
  type BlocklistEvidence,
  type CounterpartyRiskDecision,
  type RiskSignal,
} from "./counterparty-risk.ts";
import { collectNearTestnetEvidence } from "./near-counterparty-evidence.ts";
import { collectNearTestnetHistory } from "./near-counterparty-history.ts";

export type CounterpartyRiskCollection = {
  network: "testnet";
  accountId: string;
  status: "COMPLETE" | "PARTIAL" | "UNAVAILABLE";
  collectedAt: string;
  decision: CounterpartyRiskDecision;
};

export type RiskCollectionOptions = {
  fetchImpl?: typeof fetch;
  now?: () => Date;
  fastNearApiKey?: string;
  previousInteractions?: number | null;
  blocklist?: BlocklistEvidence | null;
  blocklistLookupStatus?: "verified" | "unavailable";
};

/**
 * Server-side orchestration only. Supplemental database evidence must be
 * supplied by a trusted service-role caller and scoped to the authenticated
 * owner. Client-provided interaction counts or blocklist records are untrusted.
 */
export async function collectAndEvaluateNearTestnetCounterparty(
  accountId: string,
  options: RiskCollectionOptions = {},
): Promise<CounterpartyRiskCollection> {
  const now = options.now ?? (() => new Date());
  const fetchImpl = options.fetchImpl ?? fetch;
  const evaluatedAt = now().toISOString();

  const [current, history] = await Promise.all([
    collectNearTestnetEvidence(accountId, fetchImpl, now),
    collectNearTestnetHistory(accountId, fetchImpl, now, options.fastNearApiKey),
  ]);

  const signals: RiskSignal[] = [
    ...history.signals.map((signal) => ({ ...signal })),
    ...current.signals.map((signal) => ({ ...signal })),
  ];

  const interactions = Number.isSafeInteger(options.previousInteractions) &&
    Number(options.previousInteractions) >= 0
    ? Number(options.previousInteractions)
    : null;
  signals.push({
    name: "previous_mandate_interactions",
    status: interactions === null ? "unavailable" : "verified",
    observedAt: evaluatedAt,
    source: "MANDATE authorization receipts",
    summary: interactions === null
      ? "An owner-scoped server-side authorization-receipt count was not supplied."
      : "A trusted owner-scoped authorization-receipt count was supplied.",
    ...(interactions === null ? {} : { value: interactions }),
  });

  const blocklistLookupVerified = options.blocklistLookupStatus === "verified";
  const trustedBlocklist = blocklistLookupVerified ? options.blocklist ?? null : null;
  const blocklistValue = !blocklistLookupVerified
    ? "unavailable"
    : trustedBlocklist?.status === "confirmed"
      ? "confirmed"
      : trustedBlocklist?.status === "pending"
        ? "pending"
        : "clear";
  signals.push({
    name: "shared_blocklist_lookup",
    status: blocklistLookupVerified ? "verified" : "unavailable",
    observedAt: evaluatedAt,
    source: "MANDATE reviewed blocklist",
    summary: !blocklistLookupVerified
      ? "The server-side blocklist lookup failed; absence of a report cannot be assumed."
      : trustedBlocklist
        ? "The server-side blocklist lookup returned a review record."
        : "The server-side blocklist lookup completed with no active report.",
    value: blocklistValue,
  });
  if (blocklistLookupVerified && trustedBlocklist?.status === "pending") {
    const pendingCanonical = JSON.stringify({
      reportId: trustedBlocklist.reportId ?? null,
      status: trustedBlocklist.status,
      evidenceRef: trustedBlocklist.evidenceRef,
      reason: trustedBlocklist.reason,
    });
    const pendingDigest = new Uint8Array(await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(pendingCanonical),
    ));
    const pendingFingerprint = "sha256:" +
      Array.from(pendingDigest, (byte) => byte.toString(16).padStart(2, "0")).join("");
    signals.push({
      name: "shared_blocklist_pending_detail",
      status: "verified",
      observedAt: evaluatedAt,
      source: "MANDATE reviewed blocklist",
      summary: ("Pending report " + (trustedBlocklist.reportId ?? "without stable report ID") +
        ": " + trustedBlocklist.reason).slice(0, 500),
      value: pendingFingerprint,
    });
  }

  const decision = evaluateCounterpartyRisk({
    accountId,
    evaluatedAt,
    accountAgeDays: history.accountAgeDays,
    lastActivityDays: history.lastActivityDays,
    isContract: current.isContract,
    contractCodeHash: current.contractCodeHash,
    codeChangedRecently: current.codeChangedRecently,
    previousInteractions: interactions,
    signals,
    blocklist: trustedBlocklist,
  }, now);

  const unavailable = current.status === "UNAVAILABLE" || history.status === "UNAVAILABLE";
  return {
    network: "testnet",
    accountId,
    status: unavailable ? "UNAVAILABLE" : decision.outcome === "ALLOW" ? "COMPLETE" : "PARTIAL",
    collectedAt: evaluatedAt,
    decision,
  };
}
