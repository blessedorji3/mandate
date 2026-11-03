export type HistoricalSignal = {
  name: "account_age" | "recent_activity" | "first_observed_activity";
  status: "verified" | "unavailable" | "unverified";
  observedAt: string;
  source: string;
  summary: string;
  value?: string | number | null;
};

export type NearTestnetHistoryEvidence = {
  status: "PARTIAL" | "UNAVAILABLE";
  network: "testnet";
  accountId: string;
  evaluatedAt: string;
  accountCreatedAt: string | null;
  accountAgeDays: number | null;
  firstObservedActivityAt: string | null;
  lastActivityAt: string | null;
  lastActivityDays: number | null;
  signals: HistoricalSignal[];
  reason?: string;
};

const HISTORY_API = "https://tx.test.fastnear.com";
const ACCOUNT_ID = /^(?:[a-z0-9]+(?:[-_][a-z0-9]+)*)(?:\.[a-z0-9]+(?:[-_][a-z0-9]+)*)*$/;
const MAX_ACCOUNT_ID_LENGTH = 64;
const REQUEST_TIMEOUT_MS = 8_000;
const HISTORY_PAGE_SIZE = 1;

type AccountHistoryRow = {
  account_id: string;
  transaction_hash: string;
  tx_block_timestamp: string;
  tx_block_height: number;
};
type AccountHistoryResponse = {
  account_txs: AccountHistoryRow[];
  txs_count: number;
  resume_token: string | null;
};
type TransactionDetail = {
  transaction: {
    hash: string;
    receiver_id: string;
    actions: unknown[];
  };
};
type TransactionResponse = { transactions: TransactionDetail[] };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseChainTimestamp(value: unknown): Date | null {
  if (typeof value !== "string" || value.length === 0 || value.length > 64) return null;
  const parsed = Date.parse(value);
  if (Number.isFinite(parsed)) return new Date(parsed);

  if (!/^\d{10,20}$/.test(value)) return null;
  try {
    const integer = BigInt(value);
    let milliseconds: number;
    if (value.length >= 16) milliseconds = Number(integer / 1_000_000n);
    else if (value.length >= 13) milliseconds = Number(integer);
    else milliseconds = Number(integer) * 1_000;
    if (!Number.isSafeInteger(milliseconds)) return null;
    const date = new Date(milliseconds);
    return Number.isFinite(date.getTime()) ? date : null;
  } catch {
    return null;
  }
}

function validHistoryRow(value: unknown, accountId: string): value is AccountHistoryRow {
  return isRecord(value) &&
    value.account_id === accountId &&
    typeof value.transaction_hash === "string" &&
    value.transaction_hash.length >= 32 &&
    value.transaction_hash.length <= 64 &&
    typeof value.tx_block_timestamp === "string" &&
    parseChainTimestamp(value.tx_block_timestamp) !== null &&
    Number.isSafeInteger(value.tx_block_height) &&
    Number(value.tx_block_height) >= 0;
}

function isCreateAccountAction(value: unknown): boolean {
  if (value === "CreateAccount") return true;
  return isRecord(value) && Object.prototype.hasOwnProperty.call(value, "CreateAccount");
}

function daysBetween(earlier: Date, later: Date): number | null {
  const difference = later.getTime() - earlier.getTime();
  if (difference < 0) return null;
  return Math.floor(difference / 86_400_000);
}

async function postJson<T>(
  url: string,
  body: Record<string, unknown>,
  fetchImpl: typeof fetch,
): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: "error",
    });
    if (!response.ok) throw new Error("History provider returned a non-success HTTP status.");
    const payload: unknown = await response.json();
    if (!isRecord(payload)) throw new Error("History provider returned malformed JSON.");
    return payload as T;
  } finally {
    clearTimeout(timeout);
  }
}

function unavailable(
  accountId: string,
  evaluatedAt: string,
  reason: string,
): NearTestnetHistoryEvidence {
  return {
    status: "UNAVAILABLE",
    network: "testnet",
    accountId,
    evaluatedAt,
    accountCreatedAt: null,
    accountAgeDays: null,
    firstObservedActivityAt: null,
    lastActivityAt: null,
    lastActivityDays: null,
    reason,
    signals: [
      { name: "account_age", status: "unavailable", observedAt: evaluatedAt, source: "FastNear Testnet indexed history", summary: "Account creation could not be verified." },
      { name: "recent_activity", status: "unavailable", observedAt: evaluatedAt, source: "FastNear Testnet indexed history", summary: "Recent activity could not be verified." },
      { name: "first_observed_activity", status: "unavailable", observedAt: evaluatedAt, source: "FastNear Testnet indexed history", summary: "Earliest indexed account activity could not be retrieved." },
    ],
  };
}

/**
 * Read-only historical evidence. It calls POST /v0/account and, when possible,
 * POST /v0/transactions. It never signs, submits, or broadcasts a transaction.
 *
 * The earliest indexed activity is not treated as account creation. Account age
 * is verified only when the earliest returned transaction explicitly contains
 * CreateAccount and names this account as its receiver.
 */
export async function collectNearTestnetHistory(
  accountId: string,
  fetchImpl: typeof fetch = fetch,
  now: () => Date = () => new Date(),
): Promise<NearTestnetHistoryEvidence> {
  if (
    typeof accountId !== "string" ||
    accountId.length > MAX_ACCOUNT_ID_LENGTH ||
    !ACCOUNT_ID.test(accountId)
  ) {
    throw new TypeError("A valid NEAR account ID is required.");
  }

  const evaluatedAt = now().toISOString();
  const evaluationDate = new Date(evaluatedAt);
  try {
    const [oldestPayload, newestPayload] = await Promise.all([
      postJson<AccountHistoryResponse>(HISTORY_API + "/v0/account", {
        account_id: accountId,
        desc: false,
        limit: HISTORY_PAGE_SIZE,
      }, fetchImpl),
      postJson<AccountHistoryResponse>(HISTORY_API + "/v0/account", {
        account_id: accountId,
        desc: true,
        limit: HISTORY_PAGE_SIZE,
      }, fetchImpl),
    ]);

    const oldestRows = isRecord(oldestPayload) && Array.isArray(oldestPayload.account_txs)
      ? oldestPayload.account_txs : null;
    const newestRows = isRecord(newestPayload) && Array.isArray(newestPayload.account_txs)
      ? newestPayload.account_txs : null;
    if (!oldestRows || !newestRows) {
      return unavailable(accountId, evaluatedAt, "History provider response did not contain valid account history.");
    }

    const oldest = oldestRows.length && validHistoryRow(oldestRows[0], accountId)
      ? oldestRows[0] : null;
    const newest = newestRows.length && validHistoryRow(newestRows[0], accountId)
      ? newestRows[0] : null;

    if (!oldest && !newest) {
      return unavailable(accountId, evaluatedAt, "No indexed account activity was returned.");
    }

    const signals: HistoricalSignal[] = [];
    let accountCreatedAt: string | null = null;
    let accountAgeDays: number | null = null;
    let firstObservedActivityAt: string | null = null;
    let lastActivityAt: string | null = null;
    let lastActivityDays: number | null = null;

    if (oldest) {
      const firstDate = parseChainTimestamp(oldest.tx_block_timestamp)!;
      firstObservedActivityAt = firstDate.toISOString();
      signals.push({
        name: "first_observed_activity",
        status: "verified",
        observedAt: evaluatedAt,
        source: "FastNear Testnet indexed account history",
        summary: "Earliest indexed transaction involving this account was retrieved. This is not, by itself, proof of account creation.",
        value: firstObservedActivityAt,
      });

      try {
        const txPayload = await postJson<TransactionResponse>(HISTORY_API + "/v0/transactions", {
          tx_hashes: [oldest.transaction_hash],
        }, fetchImpl);
        const tx = isRecord(txPayload) && Array.isArray(txPayload.transactions)
          ? txPayload.transactions[0] : null;
        const transaction = isRecord(tx) && isRecord(tx.transaction) ? tx.transaction : null;
        const actions = transaction && Array.isArray(transaction.actions) ? transaction.actions : [];
        const hasCreateAccount = actions.some(isCreateAccountAction);
        if (
          transaction &&
          transaction.hash === oldest.transaction_hash &&
          transaction.receiver_id === accountId &&
          hasCreateAccount
        ) {
          accountCreatedAt = firstDate.toISOString();
          accountAgeDays = daysBetween(firstDate, evaluationDate);
          if (accountAgeDays !== null) {
            signals.push({
              name: "account_age",
              status: "verified",
              observedAt: evaluatedAt,
              source: "FastNear Testnet indexed transaction details",
              summary: "The earliest indexed transaction explicitly contains CreateAccount and names this account as its receiver.",
              value: accountAgeDays,
            });
          }
        }
      } catch {
        // Preserve first-observed activity, but do not infer account creation.
      }
    }

    if (accountAgeDays === null) {
      signals.push({
        name: "account_age",
        status: "unavailable",
        observedAt: evaluatedAt,
        source: "FastNear Testnet indexed transaction details",
        summary: "Account creation was not proven by the earliest indexed transaction; first observed activity is not substituted for account age.",
      });
    }

    if (newest) {
      const lastDate = parseChainTimestamp(newest.tx_block_timestamp)!;
      lastActivityAt = lastDate.toISOString();
      lastActivityDays = daysBetween(lastDate, evaluationDate);
      if (lastActivityDays !== null) {
        signals.push({
          name: "recent_activity",
          status: "verified",
          observedAt: evaluatedAt,
          source: "FastNear Testnet indexed account history",
          summary: "Newest indexed transaction involving this account was retrieved.",
          value: lastActivityDays,
        });
      } else {
        signals.push({
          name: "recent_activity",
          status: "unavailable",
          observedAt: evaluatedAt,
          source: "FastNear Testnet indexed account history",
          summary: "Newest indexed activity timestamp is in the future relative to evaluation time.",
        });
        lastActivityDays = null;
      }
    } else {
      signals.push({
        name: "recent_activity",
        status: "unavailable",
        observedAt: evaluatedAt,
        source: "FastNear Testnet indexed account history",
        summary: "Newest indexed activity could not be verified.",
      });
    }

    return {
      status: "PARTIAL",
      network: "testnet",
      accountId,
      evaluatedAt,
      accountCreatedAt,
      accountAgeDays,
      firstObservedActivityAt,
      lastActivityAt,
      lastActivityDays,
      signals,
    };
  } catch {
    return unavailable(accountId, evaluatedAt, "FastNear Testnet history could not be retrieved. No risk approval is implied.");
  }
}
