export type ConnectedNearAccount = {
  accountId?: unknown;
};

/**
 * Normalize the identities returned by the wallet connector without guessing
 * or manufacturing an account. The wallet, not a text field in MANDATE,
 * determines which account is connected.
 */
export function uniqueConnectedAccountIds(accounts: readonly ConnectedNearAccount[]): string[] {
  return [...new Set(
    accounts
      .map(account => account.accountId)
      .filter((accountId): accountId is string =>
        typeof accountId === "string" && accountId.length > 0,
      ),
  )];
}

/**
 * Validate an owner-selected account against the exact connection result,
 * current MANDATE wallet inventory and (during finalization) the pending
 * replacement identity.
 *
 * Returns null only when the selected account is safe to challenge.
 */
export function validateReplacementWalletSelection(input: {
  accountId: string;
  connectedAccountIds: readonly string[];
  activeWalletAccountIds: readonly string[];
  expectedAccountId?: string;
}): string | null {
  const { accountId, connectedAccountIds, activeWalletAccountIds, expectedAccountId } = input;

  if (!accountId) return "Connect a replacement wallet and select an account first.";
  if (!/^[a-z0-9._-]{2,64}\.testnet$/.test(accountId)) {
    return "The selected account is not a valid NEAR Testnet account.";
  }
  if (!connectedAccountIds.includes(accountId)) {
    return "The selected account is not part of the wallet connection currently open in this browser.";
  }
  if (activeWalletAccountIds.includes(accountId)) {
    return "The replacement must be different from every currently active MANDATE wallet.";
  }
  if (expectedAccountId && accountId !== expectedAccountId) {
    return `This pending recovery requires the replacement account ${expectedAccountId}.`;
  }
  return null;
}
