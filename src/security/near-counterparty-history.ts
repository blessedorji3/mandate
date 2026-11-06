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
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAX_ACCOUNT_ID_LENGTH = 64;
const REQUEST_TIMEOUT_MS = 8_000;
const MAX_RESPONSE_BYTES = 256 * 1024;

type AccountHistoryRow = {
  account_id: string;
  transaction_hash: string;
  tx_block_timestamp: string | number;
  tx_block_height: number;
};
type AccountHistoryResponse = {
  account_txs: AccountHistoryRow[];
  txs_count: number;
  resume_token: string | null;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validAccountId(value: unknown): value is string {
  return typeof value === "string" &&
    value.length >= 2 &&
    value.length <= MAX_ACCOUNT_ID_LENGTH &&
    ACCOUNT_ID.test(value);
}

function isBase58Hash32(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 32 || value.length > 44) return false;
  let number = 0n;
  for (const character of value) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) return false;
    number = number * 58n + BigInt(digit);
  }
  let bytes = 0;
  while (number > 0n) {
    bytes++;
    number >>= 8n;
  }
  let leadingZeroBytes = 0;
  while (leadingZeroBytes < value.length && value[leadingZeroBytes] === "1") leadingZeroBytes++;
  return bytes + leadingZeroBytes === 32;
}

function parseChainTimestamp(value: unknown): Date | null {
  if (typeof value === "string" && value.length > 0 && value.length <= 64) {
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return new Date(parsed);
  }
  if ((typeof value !== "string" && typeof value !== "number") || String(value).length < 10 || String(value).length > 20) return null;
  const text = String(value);
  if (!/^\d{10,20}$/.test(text)) return null;
  try {
    const integer = BigInt(text);
    let milliseconds: bigint;
    if (text.length >= 16) milliseconds = integer / 1_000_000n; // NEAR nanoseconds
    else if (text.length >= 13) milliseconds = integer;
    else milliseconds = integer * 1_000n;
    if (milliseconds > BigInt(Number.MAX_SAFE_INTEGER) || milliseconds < 0n) return null;
    const date = new Date(Number(milliseconds));
    return Number.isFinite(date.getTime()) ? date : null;
  } catch {
    return null;
  }
}

function validHistoryRow(value: unknown, accountId: string): value is AccountHistoryRow {
  return isRecord(value) &&
    value.account_id === accountId &&
    isBase58Hash32(value.transaction_hash) &&
    parseChainTimestamp(value.tx_block_timestamp) !== null &&
    Number.isSafeInteger(value.tx_block_height) &&
    Number(value.tx_block_height) >= 0;
}

function isCreateAccountAction(value: unknown): boolean {
  if (value === "CreateAccount") return true;
  return isRecord(value) && isRecord(value.CreateAccount);
}

function daysBetween(earlier: Date, later: Date): number | null {
  const difference = later.getTime() - earlier.getTime();
  if (difference < 0) return null;
  return Math.floor(difference / 86_400_000);
}

async function postJson(
  path: string,
  body: Record<string, unknown>,
  fetchImpl: typeof fetch,
  apiKey?: string,
): Promise<unknown> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetchImpl(HISTORY_API + path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        ...(apiKey ? { authorization: "Bearer " + apiKey } : {}),
      },
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: "error",
    });
    if (!response.ok || response.redirected) throw new Error("FastNear history request failed.");
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) {
      throw new Error("FastNear history response exceeded the permitted size.");
    }
    return JSON.parse(text) as unknown;
  } finally {
    clearTimeout(timeout);
  }
}

function unavailable(accountId: string, evaluatedAt: string, reason: string): NearTestnetHistoryEvidence {
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
      { name: "account_age", status: "unavailable", observedAt: evaluatedAt, source: "FastNear Testnet indexed transaction details", summary: "Account creation could not be verified." },
      { name: "recent_activity", status: "unavailable", observedAt: evaluatedAt, source: "FastNear Testnet indexed account history", summary: "Recent activity could not be verified." },
      { name: "first_observed_activity", status: "unavailable", observedAt: evaluatedAt, source: "FastNear Testnet indexed account history", summary: "Earliest indexed activity could not be retrieved." },
    ],
  };
}

function accountRows(value: unknown): { rows: unknown[]; count: number } | null {
  if (!isRecord(value) || !Array.isArray(value.account_txs) ||
      !Number.isSafeInteger(value.txs_count) || Number(value.txs_count) < 0 ||
      value.account_txs.length > 1 ||
      (value.resume_token !== undefined && value.resume_token !== null && typeof value.resume_token !== "string")) {
    return null;
  }
  const count = Number(value.txs_count);
  if ((count === 0 && value.account_txs.length !== 0) ||
      (count > 0 && value.account_txs.length !== 1)) return null;
  return { rows: value.account_txs, count };
}

/**
 * Read-only historical collector. FastNear's account endpoint documents
 * desc ordering and cursor pagination; this requests one oldest and newest
 * item and validates identity/order before using those observations.
 * First observed activity is never substituted for proven account creation.
 */
export async function collectNearTestnetHistory(
  accountId: string,
  fetchImpl: typeof fetch = fetch,
  now: () => Date = () => new Date(),
  apiKey?: string,
): Promise<NearTestnetHistoryEvidence> {
  if (!validAccountId(accountId)) throw new TypeError("A valid NEAR account ID is required.");

  const evaluatedAt = now().toISOString();
  const evaluationDate = new Date(evaluatedAt);
  try {
    const [oldestPayload, newestPayload] = await Promise.all([
      postJson("/v0/account", { account_id: accountId, desc: false, limit: 1 }, fetchImpl, apiKey),
      postJson("/v0/account", { account_id: accountId, desc: true, limit: 1 }, fetchImpl, apiKey),
    ]);
    const oldestPage = accountRows(oldestPayload);
    const newestPage = accountRows(newestPayload);
    if (!oldestPage || !newestPage || oldestPage.count !== newestPage.count) {
      return unavailable(accountId, evaluatedAt, "FastNear returned an inconsistent account-history response.");
    }
    if (oldestPage.count === 0 && oldestPage.rows.length === 0 && newestPage.rows.length === 0) {
      return unavailable(accountId, evaluatedAt, "No indexed account activity was returned.");
    }

    const oldest = oldestPage.rows.length === 1 && validHistoryRow(oldestPage.rows[0], accountId)
      ? oldestPage.rows[0] : null;
    const newest = newestPage.rows.length === 1 && validHistoryRow(newestPage.rows[0], accountId)
      ? newestPage.rows[0] : null;
    if (!oldest || !newest) {
      return unavailable(accountId, evaluatedAt, "FastNear did not return valid oldest and newest rows for the requested account.");
    }

    const oldestDate = parseChainTimestamp(oldest.tx_block_timestamp)!;
    const newestDate = parseChainTimestamp(newest.tx_block_timestamp)!;
    if (
      oldest.tx_block_height > newest.tx_block_height ||
      oldestDate.getTime() > newestDate.getTime() ||
      oldestDate.getTime() > evaluationDate.getTime() + 30_000 ||
      newestDate.getTime() > evaluationDate.getTime() + 30_000
    ) {
      return unavailable(accountId, evaluatedAt, "FastNear account-history ordering or timestamps could not be verified.");
    }

    const signals: HistoricalSignal[] = [];
    const firstObservedActivityAt = oldestDate.toISOString();
    const lastActivityAt = newestDate.toISOString();
    const lastActivityDays = daysBetween(newestDate, evaluationDate);
    let accountCreatedAt: string | null = null;
    let accountAgeDays: number | null = null;

    signals.push({
      name: "first_observed_activity",
      status: "verified",
      observedAt: evaluatedAt,
      source: "FastNear Testnet indexed account history",
      summary: "The oldest indexed transaction row was retrieved. This alone is not proof of account creation.",
      value: firstObservedActivityAt,
    });

    try {
      const txPayload = await postJson("/v0/transactions", { tx_hashes: [oldest.transaction_hash] }, fetchImpl, apiKey);
      const tx = isRecord(txPayload) && Array.isArray(txPayload.transactions) ? txPayload.transactions[0] : null;
      const transaction = isRecord(tx) && isRecord(tx.transaction) ? tx.transaction : null;
      const actions = transaction && Array.isArray(transaction.actions) ? transaction.actions : [];
      if (
        transaction &&
        transaction.hash === oldest.transaction_hash &&
        transaction.receiver_id === accountId &&
        actions.some(isCreateAccountAction)
      ) {
        accountCreatedAt = oldestDate.toISOString();
        accountAgeDays = daysBetween(oldestDate, evaluationDate);
      }
    } catch {
      // Preserve activity evidence, but never infer account creation from a failed lookup.
    }

    signals.push(accountAgeDays !== null
      ? {
          name: "account_age",
          status: "verified",
          observedAt: evaluatedAt,
          source: "FastNear Testnet indexed transaction details",
          summary: "The oldest indexed transaction explicitly contains CreateAccount and names this account as its receiver.",
          value: accountAgeDays,
        }
      : {
          name: "account_age",
          status: "unavailable",
          observedAt: evaluatedAt,
          source: "FastNear Testnet indexed transaction details",
          summary: "Account creation was not proven by the oldest indexed transaction.",
        });

    signals.push(lastActivityDays !== null
      ? {
          name: "recent_activity",
          status: "verified",
          observedAt: evaluatedAt,
          source: "FastNear Testnet indexed account history",
          summary: "The newest indexed transaction involving this account was retrieved.",
          value: lastActivityDays,
        }
      : {
          name: "recent_activity",
          status: "unavailable",
          observedAt: evaluatedAt,
          source: "FastNear Testnet indexed account history",
          summary: "Newest indexed activity timestamp is in the future relative to evaluation time.",
        });

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
    return unavailable(accountId, evaluatedAt, "FastNear Testnet history is unavailable; no risk approval is implied.");
  }
}
