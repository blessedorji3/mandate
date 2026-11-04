import { describe, expect, it } from "vitest";
import {
  isSafeRecoveryWalletResponseToSubmit,
  type SafeWalletDiagnostic,
} from "./recovery-wallet-diagnostic";

const structurallyValid: SafeWalletDiagnostic = {
  walletProvider: {
    id: "meteor-wallet",
    name: "Meteor Wallet",
    version: "1.1.1",
    adapterClass: "S",
    executorHost: "raw.githubusercontent.com",
    cachedExecutorCleared: true,
  },
  challengeMessageForwardedUnchanged: true,
  challengeRecipientForwardedUnchanged: true,
  callbackUrlSuppliedToConnectorUnchanged: true,
  serverExpectedRecipientMatches: true,
  nonceLengthBytes: 32,
  nonceLengthValid: true,
  returnedAccountMatches: true,
  publicKeyRepresentation: "string",
  returnedPublicKeyMatches: true,
  signatureRepresentation: "string",
  signatureLengthBytes: 64,
  signatureEncodingValid: true,
  serverPayloadReconstruction: "SHA-256 digest generated",
  localEd25519Verification: "invalid",
  callbackVariantVerification: {
    none: "invalid",
    challengeCallbackUrl: "invalid",
    browserOrigin: "invalid",
    browserHref: "invalid",
  },
};

describe("recovery wallet response submission gate", () => {
  it("submits exact Meteor responses for authoritative server verification when local diagnostics fail", () => {
    expect(isSafeRecoveryWalletResponseToSubmit(structurallyValid)).toBe(true);
  });
  it("blocks wrong account, public key, nonce, challenge and signature data", () => {
    expect(isSafeRecoveryWalletResponseToSubmit({ ...structurallyValid, returnedAccountMatches: false })).toBe(false);
    expect(isSafeRecoveryWalletResponseToSubmit({ ...structurallyValid, returnedPublicKeyMatches: false })).toBe(false);
    expect(isSafeRecoveryWalletResponseToSubmit({ ...structurallyValid, nonceLengthValid: false })).toBe(false);
    expect(isSafeRecoveryWalletResponseToSubmit({ ...structurallyValid, challengeMessageForwardedUnchanged: false })).toBe(false);
    expect(isSafeRecoveryWalletResponseToSubmit({ ...structurallyValid, challengeRecipientForwardedUnchanged: false })).toBe(false);
    expect(isSafeRecoveryWalletResponseToSubmit({ ...structurallyValid, signatureLengthBytes: 63, signatureEncodingValid: false })).toBe(false);
  });
});
