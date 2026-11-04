export type NearEvidenceSignal = {
  name: "account_type" | "contract_code_hash" | "contract_code_history";
  status: "verified" | "unavailable" | "stale" | "unverified";
  observedAt: string;
  source: string;
  summary: string;
  value?: string | number | boolean | null;
};

export type NearCounterpartyEvidence = {
  status: "PARTIAL" | "UNAVAILABLE";
  network: "testnet";
  accountId: string;
  evaluatedAt: string;
  currentBlockHeight: number | null;
  isContract: boolean | null;
  contractCodeHash: string | null;
  codeChangedRecently: null;
  signals: NearEvidenceSignal[];
  reason?: string;
};

const TESTNET_RPC = "https://rpc.testnet.near.org";
const NO_CONTRACT_CODE_HASH = "11111111111111111111111111111111";
const ACCOUNT_ID = /^(?:[a-z0-9]+(?:[-_][a-z0-9]+)*)(?:\.[a-z0-9]+(?:[-_][a-z0-9]+)*)*$/;
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAX_ACCOUNT_ID_LENGTH = 64;
const REQUEST_TIMEOUT_MS = 8_000;
const MAX_RESPONSE_BYTES = 64 * 1024;

type RpcEnvelope = {
  jsonrpc: "2.0";
  id: string;
  result?: Record<string, unknown>;
  error?: { code?: number; message?: string };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validAccountId(accountId: unknown): accountId is string {
  return typeof accountId === "string" &&
    accountId.length >= 2 &&
    accountId.length <= MAX_ACCOUNT_ID_LENGTH &&
    ACCOUNT_ID.test(accountId);
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

function unavailable(accountId: string, evaluatedAt: string, reason: string): NearCounterpartyEvidence {
  return {
    status: "UNAVAILABLE",
    network: "testnet",
    accountId,
    evaluatedAt,
    currentBlockHeight: null,
    isContract: null,
    contractCodeHash: null,
    codeChangedRecently: null,
    reason,
    signals: [{
      name: "account_type",
      status: "unavailable",
      observedAt: evaluatedAt,
      source: "NEAR Testnet RPC view_account",
      summary: "Current account type could not be verified.",
    }],
  };
}

async function readJson(response: Response): Promise<unknown> {
  if (!response.ok || response.redirected) throw new Error("NEAR RPC request failed.");
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) {
    throw new Error("NEAR RPC response exceeded the permitted size.");
  }
  return JSON.parse(text) as unknown;
}

function validRpcEnvelope(value: unknown, id: string): value is RpcEnvelope {
  return isRecord(value) &&
    value.jsonrpc === "2.0" &&
    value.id === id &&
    (isRecord(value.result) || isRecord(value.error));
}

function nonNegativeIntegerString(value: unknown): value is string {
  return typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value);
}

/**
 * Read-only NEAR Testnet collector. It calls status and query/view_account
 * only; it has no wallet, signing, key-management, or transaction-submit path.
 */
export async function collectNearTestnetEvidence(
  accountId: string,
  fetchImpl: typeof fetch = fetch,
  now: () => Date = () => new Date(),
): Promise<NearCounterpartyEvidence> {
  if (!validAccountId(accountId)) throw new TypeError("A valid NEAR account ID is required.");

  const evaluatedAt = now().toISOString();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  const rpc = async (id: string, method: string, params: unknown): Promise<RpcEnvelope> => {
    const response = await fetchImpl(TESTNET_RPC, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      signal: controller.signal,
      redirect: "error",
    });
    const payload = await readJson(response);
    if (!validRpcEnvelope(payload, id)) throw new Error("NEAR RPC returned an invalid JSON-RPC envelope.");
    return payload;
  };

  try {
    const status = await rpc("mandate-risk-status", "status", []);
    if (status.error || status.result?.chain_id !== "testnet") {
      return unavailable(accountId, evaluatedAt, "The RPC did not verify NEAR Testnet.");
    }

    const account = await rpc("mandate-risk-account", "query", {
      request_type: "view_account",
      finality: "final",
      account_id: accountId,
    });
    if (account.error || !account.result) {
      return unavailable(accountId, evaluatedAt, "NEAR Testnet could not verify the account's finalized state.");
    }

    const state = account.result;
    const codeHash = state.code_hash;
    if (
      !isBase58Hash32(codeHash) ||
      !nonNegativeIntegerString(state.amount) ||
      !nonNegativeIntegerString(state.locked) ||
      !Number.isSafeInteger(state.storage_usage) ||
      Number(state.storage_usage) < 0
    ) {
      return unavailable(accountId, evaluatedAt, "NEAR RPC returned malformed account state.");
    }

    const isContract = codeHash !== NO_CONTRACT_CODE_HASH;
    const syncInfo = status.result?.sync_info;
    const blockHeight = isRecord(syncInfo) && Number.isSafeInteger(syncInfo.latest_block_height) &&
      Number(syncInfo.latest_block_height) >= 0
      ? Number(syncInfo.latest_block_height)
      : null;

    const signals: NearEvidenceSignal[] = [{
      name: "account_type",
      status: "verified",
      observedAt: evaluatedAt,
      source: "NEAR Testnet RPC view_account",
      summary: isContract ? "Finalized Testnet account state contains deployed contract code." : "Finalized Testnet account state contains no deployed contract code.",
      value: isContract ? "contract" : "account",
    }];

    if (isContract) {
      signals.push(
        {
          name: "contract_code_hash",
          status: "verified",
          observedAt: evaluatedAt,
          source: "NEAR Testnet RPC view_account",
          summary: "Current finalized contract code hash was retrieved.",
          value: codeHash,
        },
        {
          name: "contract_code_history",
          status: "unavailable",
          observedAt: evaluatedAt,
          source: "NEAR Testnet historical state",
          summary: "Historical contract code changes are not collected by this current-state RPC reader.",
        },
      );
    }

    return {
      status: "PARTIAL",
      network: "testnet",
      accountId,
      evaluatedAt,
      currentBlockHeight: blockHeight,
      isContract,
      contractCodeHash: isContract ? codeHash : null,
      codeChangedRecently: null,
      signals,
    };
  } catch {
    return unavailable(accountId, evaluatedAt, "NEAR Testnet current-state evidence is unavailable; no risk approval is implied.");
  } finally {
    clearTimeout(timeout);
  }
}
