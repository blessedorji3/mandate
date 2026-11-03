export type RiskOutcome = "ALLOW" | "WARN" | "BLOCK";
export type EvidenceStatus = "verified" | "unavailable" | "stale" | "unverified";
export type RiskSignal = {
  name: string;
  status: EvidenceStatus;
  observedAt: string;
  source: string;
  summary: string;
  value?: string | number | boolean | null;
};
export type BlocklistEvidence = {
  status: "confirmed" | "pending" | "rejected";
  evidenceRef: string;
  reason: string;
  reviewedAt?: string;
};
export type CounterpartyRiskInput = {
  accountId: string;
  evaluatedAt: string;
  accountAgeDays?: number | null;
  lastActivityDays?: number | null;
  isContract?: boolean | null;
  contractCodeHash?: string | null;
  codeChangedRecently?: boolean | null;
  previousInteractions?: number | null;
  signals: RiskSignal[];
  blocklist?: BlocklistEvidence | null;
};
export type CounterpartyRiskDecision = {
  outcome: RiskOutcome;
  reasons: string[];
  evidence: RiskSignal[];
  accountId: string;
  evaluatedAt: string;
  requiresHumanApproval: boolean;
};

const ACCOUNT_ID = /^(?:[a-z0-9_-]+\.)*[a-z0-9_-]+$/;
const MAX_SIGNALS = 32;
const MAX_TEXT = 500;
const MAX_EVIDENCE_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_EVALUATION_AGE_MS = 5 * 60 * 1000;
const REQUIRED_SIGNALS = [
  "account_age",
  "recent_activity",
  "account_type",
  "previous_mandate_interactions",
  "shared_blocklist_lookup",
] as const;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function validDate(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}
function validText(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= MAX_TEXT;
}
function validSignal(value: unknown): value is RiskSignal {
  if (!record(value)) return false;
  return validText(value.name) &&
    ["verified", "unavailable", "stale", "unverified"].includes(String(value.status)) &&
    validText(value.source) &&
    validText(value.summary) &&
    validDate(value.observedAt) &&
    (value.value === undefined || value.value === null ||
      ["string", "number", "boolean"].includes(typeof value.value)) &&
    (typeof value.value !== "number" || Number.isFinite(value.value));
}
function validBlocklist(value: unknown): value is BlocklistEvidence {
  if (!record(value)) return false;
  return ["confirmed", "pending", "rejected"].includes(String(value.status)) &&
    validText(value.evidenceRef) &&
    validText(value.reason) &&
    (value.reviewedAt === undefined || validDate(value.reviewedAt));
}

/** Risk result only: never signs, broadcasts, or replaces owner policy authorization. */
export function evaluateCounterpartyRisk(input: unknown): CounterpartyRiskDecision {
  const now = Date.now();
  const fallback: CounterpartyRiskDecision = {
    outcome: "WARN",
    reasons: ["Risk input is incomplete or malformed; human review is required."],
    evidence: [],
    accountId: record(input) && typeof input.accountId === "string" ? input.accountId.slice(0, 128) : "unknown",
    evaluatedAt: new Date(now).toISOString(),
    requiresHumanApproval: true,
  };

  if (!record(input) ||
      typeof input.accountId !== "string" ||
      input.accountId.length < 2 ||
      input.accountId.length > 64 ||
      !ACCOUNT_ID.test(input.accountId) ||
      !validDate(input.evaluatedAt) ||
      !Array.isArray(input.signals) ||
      input.signals.length > MAX_SIGNALS ||
      !input.signals.every(validSignal) ||
      (input.blocklist !== undefined && input.blocklist !== null && !validBlocklist(input.blocklist))) {
    return fallback;
  }

  const data = input as unknown as CounterpartyRiskInput;
  const evaluatedAtMs = Date.parse(data.evaluatedAt);
  if (Math.abs(now - evaluatedAtMs) > MAX_EVALUATION_AGE_MS) {
    return { ...fallback, accountId: data.accountId, evaluatedAt: data.evaluatedAt,
      reasons: ["Risk evaluation timestamp is stale or in the future; human review is required."] };
  }

  const reasons: string[] = [];
  const evidence = data.signals.slice();
  let outcome: RiskOutcome = "ALLOW";
  const warn = (reason: string) => {
    if (outcome !== "BLOCK") outcome = "WARN";
    reasons.push(reason);
  };
  const block = (reason: string) => {
    outcome = "BLOCK";
    reasons.push(reason);
  };

  if (data.blocklist?.status === "confirmed") {
    if (!validText(data.blocklist.evidenceRef) || !validText(data.blocklist.reason) ||
        !validDate(data.blocklist.reviewedAt)) {
      warn("Blocklist record lacks complete reviewer evidence; it cannot be treated as confirmed.");
    } else {
      block("Counterparty is on the reviewed MANDATE blocklist: " + data.blocklist.reason);
    }
  } else if (data.blocklist?.status === "pending") {
    warn("A blocklist report is pending review; owner approval is required.");
  }

  const signalNames = new Set<string>();
  for (const item of evidence) {
    if (signalNames.has(item.name)) warn("Duplicate evidence signal: " + item.name + ".");
    signalNames.add(item.name);
    const age = evaluatedAtMs - Date.parse(item.observedAt);
    if (age < -60_000) warn(item.name + " evidence timestamp is in the future.");
    else if (age > MAX_EVIDENCE_AGE_MS) warn(item.name + " evidence is older than 24 hours.");
    if (item.status !== "verified") warn(item.name + " evidence is " + item.status + ".");
  }

  for (const required of REQUIRED_SIGNALS) {
    if (!signalNames.has(required)) warn("Required evidence is missing: " + required + ".");
  }

  if (data.accountAgeDays == null || !Number.isFinite(data.accountAgeDays) || data.accountAgeDays < 0) {
    warn("Account age is not verified from historical chain data.");
  } else if (data.accountAgeDays < 7) {
    warn("Counterparty account is less than seven days old.");
  }

  if (data.lastActivityDays == null || !Number.isFinite(data.lastActivityDays) || data.lastActivityDays < 0) {
    warn("Recent activity is not verified from indexed chain history.");
  } else if (data.lastActivityDays > 180) {
    warn("Counterparty has been inactive for more than 180 days.");
  }

  if (typeof data.isContract !== "boolean") {
    warn("Account type could not be verified from NEAR RPC.");
  } else if (data.isContract) {
    if (!validText(data.contractCodeHash)) warn("Contract code hash is unavailable.");
    if (data.codeChangedRecently == null) warn("Historical contract code changes could not be verified.");
    else if (data.codeChangedRecently) warn("Contract code changed recently; review deployed code.");
    if (!signalNames.has("contract_code_hash")) warn("Contract code hash evidence is missing.");
    if (!signalNames.has("contract_code_history")) warn("Contract code history evidence is missing.");
  }

  if (data.previousInteractions == null ||
      !Number.isSafeInteger(data.previousInteractions) ||
      data.previousInteractions < 0) {
    warn("Previous MANDATE interactions could not be verified.");
  }

  if (!reasons.length) {
    reasons.push("All required risk signals are verified and no adverse indicators were found.");
  }

  return {
    outcome,
    reasons: [...new Set(reasons)].slice(0, 20),
    evidence,
    accountId: data.accountId,
    evaluatedAt: data.evaluatedAt,
    requiresHumanApproval: outcome !== "ALLOW",
  };
}
