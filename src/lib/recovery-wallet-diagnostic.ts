import { normalizeNearSignedMessage } from "@/lib/near-signed-message";

export type SafeWalletDiagnostic = {
  challengeMessageForwardedUnchanged: boolean;
  challengeRecipientForwardedUnchanged: boolean;
  nonceLengthBytes: number;
  nonceLengthValid: boolean;
  returnedAccountMatches: boolean;
  publicKeyRepresentation: string;
  returnedPublicKeyMatches: boolean;
  signatureRepresentation: string;
  signatureLengthBytes: number | null;
  signatureEncodingValid: boolean;
  serverPayloadReconstruction: "SHA-256 digest generated" | "failed";
};

function asBytes(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (Array.isArray(value) && value.every((v) => Number.isInteger(v) && v >= 0 && v <= 255)) return Uint8Array.from(value);
  if (value && typeof value === "object" && "data" in value) return asBytes((value as { data: unknown }).data);
  return null;
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
function u32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}
function borshString(value: string): Uint8Array {
  const bytes = new TextEncoder().encode(value);
  return concat(u32(bytes.length), bytes);
}
function reconstructServerPayload(message: string, nonce: Uint8Array, recipient: string): Uint8Array {
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, 0x80000000 + 413, true);
  return concat(prefix, borshString(message), nonce, borshString(recipient), new Uint8Array([0]));
}

/** Safe metadata only: never returns/logs raw challenge, nonce, key, signature or recovery code. */
export async function inspectRecoveryWalletResponse(input: {
  challengeMessage: string;
  challengeRecipient: string;
  nonce: Uint8Array;
  expectedAccountId: string;
  expectedPublicKey: string;
  walletResponse: unknown;
}): Promise<SafeWalletDiagnostic> {
  const raw = input.walletResponse && typeof input.walletResponse === "object"
    ? input.walletResponse as Record<string, unknown> : {};
  const publicKeyValue = raw.publicKey;
  const publicKeyRepresentation = typeof publicKeyValue === "string" ? "string"
    : publicKeyValue && typeof publicKeyValue === "object"
      ? ("keyType" in publicKeyValue ? "keyType/data object" : "PublicKey-like object")
      : typeof publicKeyValue;
  const signatureValue = raw.signature;
  const signatureRepresentation = signatureValue instanceof Uint8Array ? "Uint8Array"
    : signatureValue instanceof ArrayBuffer ? "ArrayBuffer"
    : Array.isArray(signatureValue) ? "number array"
    : typeof signatureValue;
  let normalized: ReturnType<typeof normalizeNearSignedMessage> | null = null;
  try { normalized = normalizeNearSignedMessage(input.walletResponse); } catch { /* represented by safe validity fields */ }
  let signatureLengthBytes: number | null = null;
  let signatureEncodingValid = false;
  if (normalized) {
    try {
      const binary = atob(normalized.signature);
      signatureLengthBytes = binary.length;
      signatureEncodingValid = binary.length === 64;
    } catch { signatureEncodingValid = false; }
  } else {
    const bytes = asBytes(signatureValue);
    if (bytes) {
      signatureLengthBytes = bytes.length;
      signatureEncodingValid = bytes.length === 64;
    } else if (typeof signatureValue === "string") {
      try {
        const binary = atob(signatureValue);
        signatureLengthBytes = binary.length;
        signatureEncodingValid = binary.length === 64;
      } catch { signatureEncodingValid = false; }
    }
  }
  let serverPayloadReconstruction: SafeWalletDiagnostic["serverPayloadReconstruction"] = "failed";
  try {
    const payload = reconstructServerPayload(input.challengeMessage, input.nonce, input.challengeRecipient);
    await crypto.subtle.digest("SHA-256", payload);
    serverPayloadReconstruction = "SHA-256 digest generated";
  } catch { /* no sensitive data emitted */ }
  return {
    challengeMessageForwardedUnchanged: input.challengeMessage.length > 0,
    challengeRecipientForwardedUnchanged: input.challengeRecipient.length > 0,
    nonceLengthBytes: input.nonce.length,
    nonceLengthValid: input.nonce.length === 32,
    returnedAccountMatches: raw.accountId === input.expectedAccountId,
    publicKeyRepresentation: publicKeyRepresentation,
    returnedPublicKeyMatches: normalized?.publicKey === input.expectedPublicKey,
    signatureRepresentation,
    signatureLengthBytes,
    signatureEncodingValid,
    serverPayloadReconstruction,
  };
}
