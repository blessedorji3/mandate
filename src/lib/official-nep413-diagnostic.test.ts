import { describe, expect, it } from "vitest";
import { KeyPairEd25519, KeyPairSigner } from "near-api-js";
import { inspectOfficialNep413Response } from "./official-nep413-diagnostic";

const accountId = "mandate-diagnostic.testnet";
const recipient = "mandate-snowy.vercel.app";
const message = [
  "MANDATE ASCII NEP-413 DIAGNOSTIC",
  "Purpose: verify wallet message signing only.",
  "No recovery code, wallet link, or funds will be changed.",
  `Account: ${accountId}`,
  "Challenge: diagnostic-unit-test",
].join("\n");
const nonce = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const walletProvider = {
  id: "meteor-wallet",
  version: "1.1.1",
  executorHost: "raw.githubusercontent.com",
  cachedExecutorCleared: true,
};

async function makeSignedMessage() {
  const signer = new KeyPairSigner(KeyPairEd25519.fromRandom());
  const publicKey = (await signer.getPublicKey()).toString();
  const signedMessage = await signer.signNep413Message(accountId, {
    message,
    recipient,
    nonce,
  });
  return { publicKey, signedMessage };
}

describe("official NEP-413 wallet diagnostic", () => {
  it("accepts a valid message signed with NEAR's official NEP-413 implementation", async () => {
    const { publicKey, signedMessage } = await makeSignedMessage();
    const result = await inspectOfficialNep413Response({
      expectedAccountId: accountId,
      expectedPublicKey: publicKey,
      message,
      recipient,
      nonce,
      walletResponse: signedMessage,
      walletProvider,
    });

    expect(result.messageAsciiOnly).toBe(true);
    expect(result.callbackUrlIncluded).toBe(false);
    expect(result.nonceLengthValid).toBe(true);
    expect(result.signerAccountMatchesRegisteredWallet).toBe(true);
    expect(result.signerPublicKeyMatchesRegisteredWallet).toBe(true);
    expect(result.signatureLengthBytes).toBe(64);
    expect(result.signatureEncodingValid).toBe(true);
    expect(result.officialNep413Verification).toBe("valid");
    expect(result.accessKeyPermissionCheck).toBe("not-performed-in-browser");
    expect(result.recoveryCredentialChanged).toBe(false);
    expect(result.walletLinksChanged).toBe(false);
    expect(result.fundsMoved).toBe(false);
  });

  it("rejects a signature when the exact signed message is changed", async () => {
    const { publicKey, signedMessage } = await makeSignedMessage();
    const result = await inspectOfficialNep413Response({
      expectedAccountId: accountId,
      expectedPublicKey: publicKey,
      message: `${message}\nchanged`,
      recipient,
      nonce,
      walletResponse: signedMessage,
      walletProvider,
    });

    expect(result.officialNep413Verification).toBe("invalid");
  });

  it("does not run cryptographic verification for a mismatched account or registered key", async () => {
    const { publicKey, signedMessage } = await makeSignedMessage();
    const accountMismatch = await inspectOfficialNep413Response({
      expectedAccountId: "another-account.testnet",
      expectedPublicKey: publicKey,
      message,
      recipient,
      nonce,
      walletResponse: signedMessage,
      walletProvider,
    });
    const keyMismatch = await inspectOfficialNep413Response({
      expectedAccountId: accountId,
      expectedPublicKey: "ed25519:11111111111111111111111111111111",
      message,
      recipient,
      nonce,
      walletResponse: signedMessage,
      walletProvider,
    });

    expect(accountMismatch.signerAccountMatchesRegisteredWallet).toBe(false);
    expect(accountMismatch.officialNep413Verification).toBe("not-run");
    expect(keyMismatch.signerPublicKeyMatchesRegisteredWallet).toBe(false);
    expect(keyMismatch.officialNep413Verification).toBe("not-run");
  });

  it("does not run the wallet diagnostic for a non-ASCII message", async () => {
    const { publicKey, signedMessage } = await makeSignedMessage();
    const result = await inspectOfficialNep413Response({
      expectedAccountId: accountId,
      expectedPublicKey: publicKey,
      message: "MANDATE café diagnostic",
      recipient,
      nonce,
      walletResponse: signedMessage,
      walletProvider,
    });

    expect(result.messageAsciiOnly).toBe(false);
    expect(result.officialNep413Verification).toBe("not-run");
  });
});
