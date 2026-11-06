export type RiskOutcome = "ALLOW" | "WARN" | "BLOCK";
export type EvidenceStatus = "verified" | "unavailable" | "stale" | "unverified";
export type RiskSignalName =
  | "account_age" | "recent_activity" | "first_observed_activity"
  | "account_type" | "previous_mandate_interactions" | "shared_blocklist_lookup"
  | "contract_code_hash" | "contract_code_history" | "global_contract_reference"
  | "shared_blocklist_pending_detail";

export type RiskSignal = {
  name: RiskSignalName;
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
  reviewerId?: string;
  reviewedAt?: string;
  reportId?: string;
};

export type CounterpartyRiskInput = {
  accountId: string;
  evaluatedAt: string;
  accountAgeDays: number | null;
  lastActivityDays: number | null;
  isContract: boolean | null;
  contractCodeHash: string | null;
  codeChangedRecently: boolean | null;
  previousInteractions: number | null;
  signals: RiskSignal[];
  blocklist: BlocklistEvidence | null;
};

export type CounterpartyRiskDecision = {
  outcome: RiskOutcome;
  reasons: string[];
  evidence: RiskSignal[];
  accountId: string;
  evaluatedAt: string;
  requiresHumanApproval: boolean;
};

const ACCOUNT_ID = /^(?:[a-z0-9]+(?:[-_][a-z0-9]+)*)(?:\.[a-z0-9]+(?:[-_][a-z0-9]+)*)*$/;
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAX_SIGNALS = 32;
const MAX_TEXT = 500;
const MAX_EVIDENCE_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_EVALUATION_AGE_MS = 5 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 30_000;
const REQUIRED_SIGNALS: RiskSignalName[] = [
  "account_age", "recent_activity", "account_type",
  "previous_mandate_interactions", "shared_blocklist_lookup",
];
const SIGNAL_NAMES = new Set<RiskSignalName>([
  ...REQUIRED_SIGNALS, "first_observed_activity", "contract_code_hash", "contract_code_history", "global_contract_reference",
  "shared_blocklist_pending_detail",
]);
const EXPECTED_SOURCES: Record<RiskSignalName, string> = {
  account_age: "FastNear Testnet indexed transaction details",
  recent_activity: "FastNear Testnet indexed account history",
  first_observed_activity: "FastNear Testnet indexed account history",
  account_type: "NEAR Testnet RPC view_account",
  previous_mandate_interactions: "MANDATE authorization receipts",
  shared_blocklist_lookup: "MANDATE reviewed blocklist",
  contract_code_hash: "NEAR Testnet RPC view_account",
  contract_code_history: "NEAR Testnet historical state",
  global_contract_reference: "NEAR Testnet RPC view_account",
  shared_blocklist_pending_detail: "MANDATE reviewed blocklist",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isIsoUtc(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}
function validText(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 &&
    value.length <= MAX_TEXT && !/[\u0000-\u001f\u007f]/.test(value);
}
function isBase58Hash32(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 32 || value.length > 44) return false;
  let number = 0n;
  for (const character of value) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) return false;
    number = number * 58n + BigInt(digit);
  }
  let byteLength = 0;
  while (number > 0n) { byteLength++; number >>= 8n; }
  let leadingZeroBytes = 0;
  while (leadingZeroBytes < value.length && value[leadingZeroBytes] === "1") leadingZeroBytes++;
  return byteLength + leadingZeroBytes === 32;
}
function validSignal(value: unknown): value is RiskSignal {
  if (!isRecord(value) || typeof value.name !== "string" || !SIGNAL_NAMES.has(value.name as RiskSignalName)) return false;
  if (!["verified", "unavailable", "stale", "unverified"].includes(String(value.status))) return false;
  if (!isIsoUtc(value.observedAt) || !validText(value.source) || !validText(value.summary)) return false;
  if (value.source !== EXPECTED_SOURCES[value.name as RiskSignalName]) return false;
  if (value.value !== undefined && value.value !== null &&
      !["string", "number", "boolean"].includes(typeof value.value)) return false;
  if (typeof value.value === "number" && !Number.isFinite(value.value)) return false;
  if (typeof value.value === "string" && value.value.length > MAX_TEXT) return false;
  if (value.name === "shared_blocklist_pending_detail" && value.status === "verified" &&
      (typeof value.value !== "string" || !/^sha256:[a-f0-9]{64}$/.test(value.value))) return false;
  if (value.name === "global_contract_reference" && value.status === "verified") {
    if (typeof value.value !== "string") return false;
    const hashPrefix = "global_contract_hash:";
    const accountPrefix = "global_contract_account_id:";
    if (value.value.startsWith(hashPrefix)) {
      if (!isBase58Hash32(value.value.slice(hashPrefix.length))) return false;
    } else if (value.value.startsWith(accountPrefix)) {
      if (!ACCOUNT_ID.test(value.value.slice(accountPrefix.length))) return false;
    } else {
      return false;
    }
  }
  return true;
}
function validTimestamp(value: unknown): value is string {
  return typeof value === "string" && value.length <= 64 && Number.isFinite(Date.parse(value));
}
function validEvidenceRef(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 2_048) return false;
  if (isBase58Hash32(value) || /^sha256:[a-f0-9]{64}$/i.test(value)) return true;
  try { const url = new URL(value); return url.protocol === "https:" && Boolean(url.hostname); }
  catch { return false; }
}
function isUuid(value: unknown): value is string {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
function validBlocklistShape(value: unknown): value is BlocklistEvidence {
  if (!isRecord(value) || !["confirmed", "pending", "rejected"].includes(String(value.status)) ||
      !validEvidenceRef(value.evidenceRef) || !validText(value.reason)) return false;
  if (value.reviewerId !== undefined && value.reviewerId !== null && !isUuid(value.reviewerId)) return false;
  if (value.reviewedAt !== undefined && value.reviewedAt !== null && !validTimestamp(value.reviewedAt)) return false;
  if (value.reportId !== undefined && value.reportId !== null && !isUuid(value.reportId)) return false;
  return true;
}
function fallback(accountId: string, evaluatedAt: string, reason: string): CounterpartyRiskDecision {
  return { outcome: "WARN", reasons: [reason], evidence: [], accountId, evaluatedAt, requiresHumanApproval: true };
}
function signalByName(signals: RiskSignal[], name: RiskSignalName): RiskSignal | undefined {
  return signals.find((signal) => signal.name === name);
}

/** Pure risk assessment only. It never authorizes policy actions, signs, or broadcasts. */
export function evaluateCounterpartyRisk(
  input: unknown,
  now: () => Date = () => new Date(),
): CounterpartyRiskDecision {
  let nowDate: Date;
  try { nowDate = now(); } catch { nowDate = new Date(Number.NaN); }
  if (!(nowDate instanceof Date) || !Number.isFinite(nowDate.getTime())) {
    return fallback("unknown", new Date().toISOString(), "The risk evaluator clock is unavailable; human review is required.");
  }
  const nowMs = nowDate.getTime();
  const nowIso = nowDate.toISOString();
  if (!isRecord(input)) return fallback("unknown", nowIso, "Risk input is missing or malformed; human review is required.");

  const safeAccountId = typeof input.accountId === "string" ? input.accountId.slice(0, 128) : "unknown";
  if (
    typeof input.accountId !== "string" || input.accountId.length < 2 || input.accountId.length > 64 ||
    !ACCOUNT_ID.test(input.accountId) || !isIsoUtc(input.evaluatedAt) ||
    !Array.isArray(input.signals) || input.signals.length > MAX_SIGNALS ||
    !input.signals.every(validSignal) ||
    (input.blocklist !== undefined && input.blocklist !== null && !validBlocklistShape(input.blocklist)) ||
    (input.accountAgeDays !== null && input.accountAgeDays !== undefined && (typeof input.accountAgeDays !== "number" || !Number.isSafeInteger(input.accountAgeDays) || input.accountAgeDays < 0)) ||
    (input.lastActivityDays !== null && input.lastActivityDays !== undefined && (typeof input.lastActivityDays !== "number" || !Number.isSafeInteger(input.lastActivityDays) || input.lastActivityDays < 0)) ||
    (input.isContract !== null && input.isContract !== undefined && typeof input.isContract !== "boolean") ||
    (input.contractCodeHash !== null && input.contractCodeHash !== undefined && typeof input.contractCodeHash !== "string") ||
    (input.codeChangedRecently !== null && input.codeChangedRecently !== undefined && typeof input.codeChangedRecently !== "boolean") ||
    (input.previousInteractions !== null && input.previousInteractions !== undefined && (typeof input.previousInteractions !== "number" || !Number.isSafeInteger(input.previousInteractions)))
  ) {
    return fallback(safeAccountId, nowIso, "Risk input is incomplete or malformed; human review is required.");
  }

  const evaluatedAt = input.evaluatedAt;
  const evaluatedAtMs = Date.parse(evaluatedAt);
  if (evaluatedAtMs > nowMs + MAX_FUTURE_SKEW_MS || nowMs - evaluatedAtMs > MAX_EVALUATION_AGE_MS) {
    return fallback(input.accountId, evaluatedAt, "Risk evaluation timestamp is stale or in the future; human review is required.");
  }

  const data = input as unknown as CounterpartyRiskInput;
  const signals = data.signals;
  const reasons: string[] = [];
  let outcome: RiskOutcome = "ALLOW";
  let requiresHumanApproval = false;
  const warn = (reason: string) => {
    if (outcome !== "BLOCK") {
      outcome = "WARN";
      requiresHumanApproval = true;
    }
    reasons.push(reason);
  };
  const block = (reason: string) => {
    outcome = "BLOCK";
    requiresHumanApproval = false;
    reasons.push(reason);
  };

  const seen = new Set<string>();
  for (const signal of signals) {
    if (seen.has(signal.name)) warn("Duplicate evidence signal: " + signal.name + ".");
    seen.add(signal.name);
    const ageMs = evaluatedAtMs - Date.parse(signal.observedAt);
    if (ageMs < -MAX_FUTURE_SKEW_MS) warn(signal.name + " evidence timestamp is in the future.");
    else if (ageMs > MAX_EVIDENCE_AGE_MS) warn(signal.name + " evidence is older than 24 hours.");
    if (signal.status !== "verified") warn(signal.name + " evidence is " + signal.status + ".");
  }
  for (const required of REQUIRED_SIGNALS) {
    if (!seen.has(required)) warn("Required evidence is missing: " + required + ".");
  }

  const accountAgeSignal = signalByName(signals, "account_age");
  if (data.accountAgeDays == null || data.accountAgeDays < 0 || !accountAgeSignal ||
      typeof accountAgeSignal.value !== "number" || accountAgeSignal.value !== data.accountAgeDays) {
    warn("Account age is not verified by matching historical creation evidence.");
  } else if (data.accountAgeDays < 7) warn("Counterparty account is less than seven days old.");

  const activitySignal = signalByName(signals, "recent_activity");
  if (data.lastActivityDays == null || data.lastActivityDays < 0 || !activitySignal ||
      typeof activitySignal.value !== "number" || activitySignal.value !== data.lastActivityDays) {
    warn("Recent activity is not verified by matching indexed chain history.");
  } else if (data.lastActivityDays > 180) warn("Counterparty has been inactive for more than 180 days.");

  const accountTypeSignal = signalByName(signals, "account_type");
  if (typeof data.isContract !== "boolean" || !accountTypeSignal ||
      accountTypeSignal.value !== (data.isContract ? "contract" : "account")) {
    warn("Account type could not be verified by matching NEAR RPC evidence.");
  }

  const interactionSignal = signalByName(signals, "previous_mandate_interactions");
  if (data.previousInteractions == null || !Number.isSafeInteger(data.previousInteractions) ||
      data.previousInteractions < 0 || !interactionSignal ||
      interactionSignal.value !== data.previousInteractions) {
    warn("Previous MANDATE interactions could not be verified by matching owner-scoped receipts.");
  }

  const blocklistSignal = signalByName(signals, "shared_blocklist_lookup");
  const expectedBlocklistValue = data.blocklist?.status === "confirmed" ? "confirmed"
    : data.blocklist?.status === "pending" ? "pending" : "clear";
  if (!blocklistSignal || !["clear", "pending", "confirmed"].includes(String(blocklistSignal.value))) {
    warn("A complete shared blocklist lookup was not verified.");
  } else if (blocklistSignal.value !== expectedBlocklistValue) {
    warn("Shared blocklist lookup evidence conflicts with the supplied review record.");
  }
  if (blocklistSignal?.value === "pending" || data.blocklist?.status === "pending") {
    const pendingDetail = signalByName(signals, "shared_blocklist_pending_detail");
    if (!pendingDetail || pendingDetail.status !== "verified" ||
        typeof pendingDetail.value !== "string" || !/^sha256:[a-f0-9]{64}$/.test(pendingDetail.value)) {
      warn("A shared blocklist report is pending review, but its report identity and evidence details are incomplete.");
    }
    warn("A shared blocklist report is pending review" +
      (data.blocklist?.reason ? ": " + data.blocklist.reason : "."));
  }

  if (data.blocklist?.status === "confirmed") {
    const completeReview = validEvidenceRef(data.blocklist.evidenceRef) &&
      validText(data.blocklist.reason) && isUuid(data.blocklist.reviewerId) &&
      validTimestamp(data.blocklist.reviewedAt) &&
      Date.parse(data.blocklist.reviewedAt) <= nowMs + MAX_FUTURE_SKEW_MS;
    if (completeReview) block("Counterparty is on the reviewer-attributed MANDATE blocklist: " + data.blocklist.reason);
    else warn("A purported confirmed blocklist record lacks valid evidence, reviewer identity, or review timestamp.");
  }

  if (data.isContract === true) {
    if (!isBase58Hash32(data.contractCodeHash)) warn("Current contract code hash is missing or malformed.");
    const codeHashSignal = signalByName(signals, "contract_code_hash");
    if (!codeHashSignal || codeHashSignal.value !== data.contractCodeHash) {
      warn("Contract code hash evidence is missing or does not match current RPC state.");
    }
    const historySignal = signalByName(signals, "contract_code_history");
    if (data.codeChangedRecently == null || typeof data.codeChangedRecently !== "boolean" ||
        !historySignal || historySignal.value !== data.codeChangedRecently) {
      warn("Historical contract code changes could not be verified.");
    } else if (data.codeChangedRecently) warn("Contract code changed recently; review deployed code before proceeding.");
  } else if (data.isContract === false &&
      (signalByName(signals, "contract_code_hash") || signalByName(signals, "contract_code_history") ||
        signalByName(signals, "global_contract_reference"))) {
    warn("Contract evidence conflicts with the verified non-contract account type.");
  }

  if (!reasons.length) reasons.push("All required risk signals are verified and no configured risk indicators were triggered.");

  return {
    outcome,
    reasons: [...new Set(reasons)].slice(0, 20),
    evidence: signals.map((signal) => ({ ...signal })),
    accountId: data.accountId,
    evaluatedAt: data.evaluatedAt,
    requiresHumanApproval,
  };
}
