import type { MeteorWallet } from "@meteorwallet/sdk";
import { normalizeNearSignedMessage } from "@/lib/near-signed-message";

export type MeteorRecoverySigner = Pick<MeteorWallet, "requestSignIn" | "signMessage">;

export type MeteorRecoveryChallenge = {
  accountId: string;
  publicKey: string;
  message: string;
  recipient: string;
  nonceHex: string;
};

export type NormalizedRecoverySignature = ReturnType<typeof normalizeNearSignedMessage>;

function challengeNonce(nonceHex: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2}){32}$/.test(nonceHex)) {
    throw new Error("MANDATE returned an invalid 32-byte recovery nonce.");
  }
  return Uint8Array.from(
    nonceHex.match(/.{2}/g)!,
    (part) => Number.parseInt(part, 16),
  );
}

/**
 * Create the official Meteor SDK client once on the client side, before the
 * user presses the sign button. This is important because Meteor opens its
 * signing popup synchronously from the signMessage call and browsers block
 * popups opened after an unrelated async operation.
 *
 * The SDK key store is the same Meteor-owned browser store used by Meteor's
 * own NEAR Wallet Selector adapter. MANDATE never reads or exports private
 * keys from it.
 */
export async function createMeteorRecoverySigner(): Promise<MeteorRecoverySigner> {
  if (typeof window === "undefined") {
    throw new Error("Meteor signing is available only in the browser.");
  }

  const [{ MeteorWallet }, { BrowserLocalStorageKeyStore }] = await Promise.all([
    import("@meteorwallet/sdk"),
    import("@near-js/keystores-browser"),
  ]);

  return new MeteorWallet({
    networkId: "testnet",
    keyStore: new BrowserLocalStorageKeyStore(window.localStorage, "_meteor_wallet"),
  });
}

/**
 * Establish the dApp-to-wallet connection before asking Meteor to sign.
 * Meteor's V1 SDK requires this separate sign-in action; a NEP-413 request
 * alone does not create an external-app account connection.
 *
 * Meteor displays its account picker. MANDATE accepts only the exact account
 * requested by the server challenge and refuses to proceed on any mismatch.
 */
export async function connectExactMeteorRecoveryAccount(
  signer: MeteorRecoverySigner,
  expectedAccountId: string,
): Promise<string> {
  const response = await signer.requestSignIn({});
  if (!response.success) {
    throw new Error(response.message || "Meteor did not connect an account to MANDATE.");
  }

  const connectedAccountId = response.payload.accountId;
  if (connectedAccountId !== expectedAccountId) {
    throw new Error(
      `Meteor connected ${connectedAccountId || "an unidentified account"}, not the requested replacement account ${expectedAccountId}. No recovery signature was requested.`,
    );
  }
  return connectedAccountId;
}

/**
 * Ask Meteor to sign for the explicit challenge account, not whichever
 * account HOT Connector currently reports as selected. The response is
 * checked against both the account and FullAccess public key already bound
 * into the server challenge. The server repeats these checks and verifies
 * the NEP-413 signature before it changes recovery state.
 *
 * callbackUrl is intentionally omitted: the deployed MANDATE recovery
 * verifier expects Meteor's NEP-413 callback_url=None representation.
 */
export async function signExactMeteorRecoveryChallenge(
  signer: MeteorRecoverySigner,
  challenge: MeteorRecoveryChallenge,
): Promise<NormalizedRecoverySignature> {
  if (!/^[a-z0-9._-]{2,64}\.testnet$/.test(challenge.accountId)) {
    throw new Error("The replacement account must be a valid NEAR Testnet account.");
  }
  if (!/^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$/.test(challenge.publicKey)) {
    throw new Error("MANDATE returned an invalid replacement FullAccess public key.");
  }
  if (!challenge.message || !challenge.recipient) {
    throw new Error("MANDATE returned an incomplete recovery challenge.");
  }

  const nonce = challengeNonce(challenge.nonceHex);
  const response = await signer.signMessage({
    message: challenge.message,
    nonce,
    recipient: challenge.recipient,
    accountIdentifier: {
      blockchain: "near",
      network: "testnet",
      accountId: challenge.accountId,
    },
  });

  if (!response.success) {
    throw new Error(response.message || "Meteor did not complete the recovery signature request.");
  }

  const signed = normalizeNearSignedMessage(response.payload);
  if (signed.accountId !== challenge.accountId) {
    throw new Error(
      "Meteor signed with a different NEAR account than the replacement account requested. No recovery request was started.",
    );
  }
  if (signed.publicKey !== challenge.publicKey) {
    throw new Error(
      "Meteor used a different key from the FullAccess key bound to the recovery challenge. No recovery request was started.",
    );
  }

  let signatureLength = 0;
  try {
    signatureLength = atob(signed.signature).length;
  } catch {
    throw new Error("Meteor returned an invalid Base64 recovery signature.");
  }
  if (signatureLength !== 64) {
    throw new Error("Meteor returned an invalid NEP-413 signature length.");
  }

  return signed;
}
