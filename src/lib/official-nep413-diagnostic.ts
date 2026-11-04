import { verifyMessage } from "near-api-js/nep413";
import { normalizeNearSignedMessage } from "./near-signed-message";

export type OfficialNep413Diagnostic = {
  walletProvider: {
    id: string;
    version: string;
    executorHost: string | null;
    cachedExecutorCleared: boolean;
  };
  messageAsciiOnly: boolean;
  callbackVariantVerification: {
    none: "valid" | "invalid" | "not-run";
    challengeCallbackUrl: "valid" | "invalid" | "not-run";
  };
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

// The official verifyMessage API also performs an on-chain FullAccess lookup.
// This diagnostic-only stub allows its canonical NEP-413 Borsh serialization
// and signature verification to run locally without an RPC call. It is NOT an
// access-key assertion. The result is explicitly labelled as unchecked, and
// this browser diagnostic is never used to authorize recovery. Supabase still
// performs the authoritative on-chain FullAccess check before any reset.
const diagnosticOnlyProvider = {
  viewAccessKey: async () => ({ permission: "FullAccess" }),
} as unknown as Parameters<typeof verifyMessage>[0]["provider"];

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
 * verifyMessage implementation. A diagnostic-only provider stub prevents an
 * RPC call; its access-key result is deliberately not treated as a security
 * check. No network, database, or wallet changes are performed.
 */
export async function inspectOfficialNep413Response(input: {
  expectedAccountId: string;
  expectedPublicKey: string;
  message: string;
  recipient: string;
  nonce: Uint8Array;
  walletResponse: unknown;
  callbackUrl?: string;
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
  const callbackVariantVerification: OfficialNep413Diagnostic["callbackVariantVerification"] = {
    none: "not-run",
    challengeCallbackUrl: "not-run",
  };

  if (
    nonceLengthValid &&
    signerAccountMatchesRegisteredWallet &&
    signerPublicKeyMatchesRegisteredWallet &&
    signatureEncodingValid &&
    signatureBytes
  ) {
    try {
      if (!input.expectedPublicKey.startsWith("ed25519:")) {
        throw new Error("Unsupported NEAR signing key.");
      }

      const verifyVariant = async (callbackUrl?: string) => {
        try {
          await verifyMessage({
            signerAccountId: input.expectedAccountId,
            signerPublicKey: input.expectedPublicKey,
            payload: {
              message: input.message,
              recipient: input.recipient,
              nonce: input.nonce,
              ...(callbackUrl === undefined ? {} : { callbackUrl }),
            },
            signature: signatureBytes,
            provider: diagnosticOnlyProvider,
          });
          return "valid" as const;
        } catch {
          // Do not expose the raw signature, key, payload, or provider error.
          return "invalid" as const;
        }
      };

      // Match the server's accepted NEP-413 forms: trusted callback first,
      // then Option::None. The message, nonce, recipient and public key never
      // change between variants.
      if (typeof input.callbackUrl === "string" && input.callbackUrl.length > 0) {
        callbackVariantVerification.challengeCallbackUrl =
          await verifyVariant(input.callbackUrl);
      }
      callbackVariantVerification.none = await verifyVariant();

      officialNep413Verification =
        callbackVariantVerification.challengeCallbackUrl === "valid" ||
        callbackVariantVerification.none === "valid"
          ? "valid"
          : "invalid";
    } catch {
      officialNep413Verification = "invalid";
    }
  }

  return {
    walletProvider: input.walletProvider,
    messageAsciiOnly,
    callbackVariantVerification,
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
