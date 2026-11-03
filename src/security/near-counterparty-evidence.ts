export type NearEvidenceSignal = {
  name: string;
  status: "verified" | "unavailable" | "stale" | "unverified";
  observedAt: string;
  source: string;
  summary: string;
  value?: string | number | boolean | null;
};

export type NearCounterpartyEvidence =
  | {
      status: "UNAVAILABLE";
      network: "testnet";
      accountId: string;
      evaluatedAt: string;
      reason: string;
      accountAgeDays: null;
      lastActivityDays: null;
      isContract: null;
      contractCodeHash: null;
      codeChangedRecently: null;
      previousInteractions: null;
      signals: NearEvidenceSignal[];
    }
  | {
      status: "PARTIAL";
      network: "testnet";
      accountId: string;
      evaluatedAt: string;
      currentBlockHeight: number | null;
      accountAgeDays: null;
      lastActivityDays: null;
      isContract: boolean;
      contractCodeHash: string | null;
      codeChangedRecently: null;
      previousInteractions: null;
      signals: NearEvidenceSignal[];
    };

const TESTNET_RPC = "https://rpc.testnet.near.org";
const NO_CONTRACT_CODE_HASH = "11111111111111111111111111111111";
const ACCOUNT_ID = /^(?:[a-z0-9]+(?:[-_][a-z0-9]+)*)(?:\.[a-z0-9]+(?:[-_][a-z0-9]+)*)*$/;
const MAX_ACCOUNT_ID_LENGTH = 64;
const REQUEST_TIMEOUT_MS = 8_000;

type RpcEnvelope = {
  result?: Record<string, unknown>;
  error?: { code?: number; message?: string };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unavailable(
  accountId: string,
  evaluatedAt: string,
  reason: string,
): NearCounterpartyEvidence {
  const observedAt = evaluatedAt;
  const signals: NearEvidenceSignal[] = [
    { name: "account_age", status: "unavailable", observedAt, source: "NEAR Testnet history", summary: "Account creation history is not supplied by this current-state RPC collector." },
    { name: "recent_activity", status: "unavailable", observedAt, source: "NEAR Testnet history", summary: "Indexed transaction history is not configured; recent activity is unknown." },
    { name: "account_type", status: "unavailable", observedAt, source: "NEAR Testnet RPC", summary: "Current account state could not be verified." },
    { name: "previous_mandate_interactions", status: "unavailable", observedAt, source: "MANDATE authorization receipts", summary: "MANDATE receipt lookup is not part of this collector." },
  ];
  return {
    status: "UNAVAILABLE",
    network: "testnet",
    accountId,
    evaluatedAt,
    reason,
    accountAgeDays: null,
    lastActivityDays: null,
    isContract: null,
    contractCodeHash: null,
    codeChangedRecently: null,
    previousInteractions: null,
    signals,
  };
}

/**
 * Read-only Testnet evidence collector.
 * It calls only NEAR status and query/view_account. It never signs or submits transactions.
 * Historical signals intentionally remain unavailable until a separately verified indexer is integrated.
 */
export async function collectNearTestnetEvidence(
  accountId: string,
  fetchImpl: typeof fetch = fetch,
  now: () => Date = () => new Date(),
): Promise<NearCounterpartyEvidence> {
  if (
    typeof accountId !== "string" ||
    accountId.length > MAX_ACCOUNT_ID_LENGTH ||
    !ACCOUNT_ID.test(accountId)
  ) {
    throw new TypeError("A valid NEAR account ID is required.");
  }

  const evaluatedAt = now().toISOString();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  const rpc = async (body: Record<string, unknown>): Promise<RpcEnvelope> => {
    const response = await fetchImpl(TESTNET_RPC, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error("NEAR RPC returned a non-success HTTP status.");
    const payload: unknown = await response.json();
    if (!isRecord(payload) || (!isRecord(payload.result) && !isRecord(payload.error))) {
      throw new Error("NEAR RPC returned a malformed response.");
    }
    return payload as RpcEnvelope;
  };

  try {
    const status = await rpc({
      jsonrpc: "2.0",
      id: "mandate-evidence-status",
      method: "status",
      params: [],
    });
    if (status.error || status.result?.chain_id !== "testnet") {
      return unavailable(accountId, evaluatedAt, "The configured RPC did not confirm the NEAR Testnet network.");
    }

    const account = await rpc({
      jsonrpc: "2.0",
      id: "mandate-evidence-account",
      method: "query",
      params: {
        request_type: "view_account",
        finality: "final",
        account_id: accountId,
      },
    });
    if (account.error || !account.result) {
      return unavailable(accountId, evaluatedAt, "NEAR Testnet could not verify this account's current state.");
    }

    const codeHash = account.result.code_hash;
    if (typeof codeHash !== "string" || codeHash.length < 8 || codeHash.length > 128) {
      return unavailable(accountId, evaluatedAt, "NEAR Testnet returned an invalid account code hash.");
    }

    const isContract = codeHash !== NO_CONTRACT_CODE_HASH;
    const observedAt = evaluatedAt;
    const signals: NearEvidenceSignal[] = [
      { name: "account_age", status: "unavailable", observedAt, source: "NEAR Testnet history", summary: "Account creation date requires indexed historical chain data." },
      { name: "recent_activity", status: "unavailable", observedAt, source: "NEAR Testnet history", summary: "Recent activity requires indexed transaction history." },
      { name: "account_type", status: "verified", observedAt, source: "NEAR Testnet RPC view_account", summary: isContract ? "RPC confirms deployed contract code." : "RPC confirms no contract code is deployed to this account.", value: isContract ? "contract" : "account" },
      { name: "previous_mandate_interactions", status: "unavailable", observedAt, source: "MANDATE authorization receipts", summary: "Previous MANDATE interactions require a separate owner-scoped receipt lookup." },
    ];

    if (isContract) {
      signals.push(
        { name: "contract_code_hash", status: "verified", observedAt, source: "NEAR Testnet RPC view_account", summary: "Current deployed contract code hash retrieved.", value: codeHash },
        { name: "contract_code_history", status: "unavailable", observedAt, source: "NEAR Testnet historical state", summary: "Historical code changes are not established by the current-state query." },
      );
    }

    const blockHeight = status.result?.sync_info;
    const height = isRecord(blockHeight) && Number.isSafeInteger(blockHeight.latest_block_height)
      ? Number(blockHeight.latest_block_height)
      : null;

    return {
      status: "PARTIAL",
      network: "testnet",
      accountId,
      evaluatedAt,
      currentBlockHeight: height,
      accountAgeDays: null,
      lastActivityDays: null,
      isContract,
      contractCodeHash: isContract ? codeHash : null,
      codeChangedRecently: null,
      previousInteractions: null,
      signals,
    };
  } catch {
    return unavailable(accountId, evaluatedAt, "NEAR Testnet evidence could not be retrieved. No risk approval is implied.");
  } finally {
    clearTimeout(timeout);
  }
}
