import type { AuthorizationDecision } from "./types";

export const MANDATE_TESTNET_TRANSFER = Object.freeze({
  network: "testnet",
  asset: "NEAR",
  receiverId: "confirmwithmandate.testnet",
  amountAtomic: "1000000000000000000000",
  actionType: "transfer"
} as const);

export interface NearTransferIntent {
  network: unknown;
  signerId: unknown;
  receiverId: unknown;
  asset: unknown;
  amountAtomic: unknown;
  actionType: unknown;
}

/**
 * Narrow execution gate for the first MANDATE test transaction.
 * This is deliberately not a receipt issuer and never signs or broadcasts.
 * The caller must additionally prove wallet ownership and obtain a fresh,
 * one-time server authorization before invoking a wallet.
 */
export function validateMandateTestnetTransfer(
  intent: NearTransferIntent,
  decision: AuthorizationDecision,
  connectedAccountId: string | null
): { ok: true } | { ok: false; reason: string } {
  if (decision.outcome !== "ALLOW" || decision.reason !== "POLICY_CHECKS_PASSED") {
    return { ok: false, reason: "The policy engine did not return an executable ALLOW decision." };
  }
  if (!connectedAccountId || intent.signerId !== connectedAccountId) {
    return { ok: false, reason: "The proposed signer does not match the connected wallet account." };
  }
  if (intent.network !== MANDATE_TESTNET_TRANSFER.network) {
    return { ok: false, reason: "Only NEAR Testnet is enabled." };
  }
  if (intent.receiverId !== MANDATE_TESTNET_TRANSFER.receiverId) {
    return { ok: false, reason: "The recipient does not match the confirmed test recipient." };
  }
  if (intent.asset !== MANDATE_TESTNET_TRANSFER.asset ||
      intent.amountAtomic !== MANDATE_TESTNET_TRANSFER.amountAtomic ||
      intent.actionType !== MANDATE_TESTNET_TRANSFER.actionType) {
    return { ok: false, reason: "The asset, amount, or action differs from the fixed test transfer." };
  }
  return { ok: true };
}
