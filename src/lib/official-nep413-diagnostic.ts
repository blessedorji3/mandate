import { PublicKey } from "near-api-js";
import { serializeMessage } from "near-api-js/nep413";
import { normalizeNearSignedMessage } from "@/lib/near-signed-message";

export type OfficialNep413Diagnostic = {
  walletProvider: {
    id: string;
    version: string;
    executorHost: string | null;
    cachedExecutorCleared: boolean;
  };
  messageAsciiOnly: boolean;
  callbackUrlIncluded: false;
  nonceLengthBytes: number;
  nonceLengthValid: boolean;
  signerAccountMatchesRegisteredWallet: boolean;
  signerPublicKeyMatchesRegisteredWallet: boolean;
  signatureLengthBytes: number | null;
  signatureEncodingValid: boolean;
  officialNep413Verification: "valid" | "invalid" | "not-run";
  accessKeyPermissionCheck: "not-performed-in-browser";
  recoveryCredentialChanged: false;
  walletLinksChanged: false;
  fundsMoved: false;
};

const ASCII_MESSAGE = /^[\x20-\x7E\r\n]*$/;
const BASE64_SIGNATURE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function decodeBase64(value: string): Uint8Array | null {
  if (!BASE64_SIGNATURE.test(value)) return null;
  try {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

/**
 * Checks a real wallet response using near-api-js's official NEP-413
 * Borsh serializer and PublicKey.verify implementation. It performs no network
 * request and makes no database or wallet changes. Only safe metadata is returned.
 */
export async function inspectOfficialNep413Response(input: {
  expectedAccountId: string;
  expectedPublicKey: string;
  message: string;
  recipient: string;
  nonce: Uint8Array;
  walletResponse: unknown;
  walletProvider: OfficialNep413Diagnostic["walletProvider"];
}): Promise<OfficialNep413Diagnostic> {
  let normalized: ReturnType<typeof normalizeNearSignedMessage> | null = null;
  try {
    normalized = normalizeNearSignedMessage(input.walletResponse);
  } catch {
    // Keep the diagnostic safe and report structural checks as failed.
  }

  const signatureBytes = normalized ? decodeBase64(normalized.signature) : null;
  const messageAsciiOnly = ASCII_MESSAGE.test(input.message);
  const nonceLengthValid = input.nonce.length === 32;
  const signerAccountMatchesRegisteredWallet =
    normalized?.accountId === input.expectedAccountId;
  const signerPublicKeyMatchesRegisteredWallet =
    normalized?.publicKey === input.expectedPublicKey;
  const signatureEncodingValid =
    signatureBytes !== null && signatureBytes.length === 64;

  let officialNep413Verification: OfficialNep413Diagnostic["officialNep413Verification"] =
    "not-run";

  if (
    messageAsciiOnly &&
    nonceLengthValid &&
    signerAccountMatchesRegisteredWallet &&
    signerPublicKeyMatchesRegisteredWallet &&
    signatureEncodingValid &&
    signatureBytes
  ) {
    try {
      const publicKey = PublicKey.from(input.expectedPublicKey);
      if (
        !input.expectedPublicKey.startsWith("ed25519:") ||
        publicKey.toString() !== input.expectedPublicKey
      ) {
        throw new Error("Unsupported NEAR signing key.");
      }
      const canonicalNep413Digest = serializeMessage({
        message: input.message,
        recipient: input.recipient,
        nonce: input.nonce,
      });
      if (!publicKey.verify(canonicalNep413Digest, signatureBytes)) {
        throw new Error("NEP-413 signature verification failed.");
      }
      officialNep413Verification = "valid";
    } catch {
      // Do not expose the raw signature, key, payload, or provider error.
      officialNep413Verification = "invalid";
    }
  }

  return {
    walletProvider: input.walletProvider,
    messageAsciiOnly,
    callbackUrlIncluded: false,
    nonceLengthBytes: input.nonce.length,
    nonceLengthValid,
    signerAccountMatchesRegisteredWallet,
    signerPublicKeyMatchesRegisteredWallet,
    signatureLengthBytes: signatureBytes?.length ?? null,
    signatureEncodingValid,
    officialNep413Verification,
    accessKeyPermissionCheck: "not-performed-in-browser",
    recoveryCredentialChanged: false,
    walletLinksChanged: false,
    fundsMoved: false,
  };
}
