import { normalizeNearSignedMessage } from "@/lib/near-signed-message";

export type SafeWalletDiagnostic = {
  challengeMessageForwardedUnchanged: boolean;
  challengeRecipientForwardedUnchanged: boolean;
  challengeCallbackUrlForwardedUnchanged: boolean;
  serverExpectedRecipientMatches: boolean;
  nonceLengthBytes: number;
  nonceLengthValid: boolean;
  returnedAccountMatches: boolean;
  publicKeyRepresentation: string;
  returnedPublicKeyMatches: boolean;
  signatureRepresentation: string;
  signatureLengthBytes: number | null;
  signatureEncodingValid: boolean;
  serverPayloadReconstruction: "SHA-256 digest generated" | "failed";
  localEd25519Verification: "valid" | "invalid" | "unavailable";
  callbackVariantVerification: {
    none: "valid" | "invalid" | "unavailable";
    challengeCallbackUrl: "valid" | "invalid" | "unavailable";
    browserOrigin: "valid" | "invalid" | "unavailable";
    browserHref: "valid" | "invalid" | "unavailable";
  };
};

const SERVER_EXPECTED_RECIPIENT = "mandate-snowy.vercel.app";

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
function reconstructServerPayload(message: string, nonce: Uint8Array, recipient: string, callbackUrl?: string): Uint8Array {
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, 0x80000000 + 413, true);
  const callback = callbackUrl === undefined ? new Uint8Array([0]) : concat(new Uint8Array([1]), borshString(callbackUrl));
  return concat(prefix, borshString(message), nonce, borshString(recipient), callback);
}
function base58Decode(value: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let number = 0n;
  for (const char of value) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) throw new Error("Invalid base58");
    number = number * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (number > 0n) { bytes.unshift(Number(number & 255n)); number >>= 8n; }
  for (let i = 0; i < value.length && value[i] === "1"; i++) bytes.unshift(0);
  return Uint8Array.from(bytes);
}
function base64Decode(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

/** Safe metadata only: never returns/logs raw challenge, nonce, key, signature or recovery code. */
export async function inspectRecoveryWalletResponse(input: {
  challengeMessage: string;
  challengeRecipient: string;
  challengeCallbackUrl?: string;
  walletRequestCallbackUrl?: string;
  walletRequestMessage: string;
  walletRequestRecipient: string;
  browserOrigin: string;
  browserHref: string;
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
  try { normalized = normalizeNearSignedMessage(input.walletResponse); } catch { /* safe failure below */ }

  let signatureLengthBytes: number | null = null;
  let signatureEncodingValid = false;
  if (normalized) {
    try {
      const bytes = base64Decode(normalized.signature);
      signatureLengthBytes = bytes.length;
      signatureEncodingValid = bytes.length === 64;
    } catch { /* invalid encoding */ }
  }

  let serverPayloadReconstruction: SafeWalletDiagnostic["serverPayloadReconstruction"] = "failed";
  let localEd25519Verification: SafeWalletDiagnostic["localEd25519Verification"] = "unavailable";
  const callbackVariantVerification: SafeWalletDiagnostic["callbackVariantVerification"] = {
    none: "unavailable", challengeCallbackUrl: "unavailable",
    browserOrigin: "unavailable", browserHref: "unavailable",
  };
  try {
    if (!normalized || input.nonce.length !== 32) throw new Error("Missing valid signed message or nonce");
    const [keyType, encodedKey, extra] = normalized.publicKey.split(":");
    if (keyType !== "ed25519" || !encodedKey || extra !== undefined) throw new Error("Unsupported key type");
    const keyBytes = base58Decode(encodedKey);
    const signatureBytes = base64Decode(normalized.signature);
    if (keyBytes.length !== 32 || signatureBytes.length !== 64) throw new Error("Invalid key or signature length");
    const cryptoKey = await crypto.subtle.importKey("raw", asArrayBuffer(keyBytes), { name: "Ed25519" }, false, ["verify"]);
    const candidates: Array<[keyof SafeWalletDiagnostic["callbackVariantVerification"], string | undefined]> = [
      ["none", undefined],
      ["challengeCallbackUrl", input.challengeCallbackUrl],
      ["browserOrigin", input.browserOrigin],
      ["browserHref", input.browserHref],
    ];
    for (const [name, callbackUrl] of candidates) {
      try {
        const payload = reconstructServerPayload(input.challengeMessage, input.nonce, input.challengeRecipient, callbackUrl);
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(payload)));
        serverPayloadReconstruction = "SHA-256 digest generated";
        const valid = await crypto.subtle.verify({ name: "Ed25519" }, cryptoKey, asArrayBuffer(signatureBytes), asArrayBuffer(digest));
        callbackVariantVerification[name] = valid ? "valid" : "invalid";
      } catch {
        callbackVariantVerification[name] = "unavailable";
      }
    }
    localEd25519Verification = callbackVariantVerification.none;
  } catch {
    if (serverPayloadReconstruction === "SHA-256 digest generated") localEd25519Verification = "invalid";
  }

  return {
    challengeMessageForwardedUnchanged: input.walletRequestMessage === input.challengeMessage,
    challengeRecipientForwardedUnchanged: input.walletRequestRecipient === input.challengeRecipient,
    challengeCallbackUrlForwardedUnchanged: input.walletRequestCallbackUrl === input.challengeCallbackUrl,
    serverExpectedRecipientMatches: input.challengeRecipient === SERVER_EXPECTED_RECIPIENT,
    nonceLengthBytes: input.nonce.length,
    nonceLengthValid: input.nonce.length === 32,
    returnedAccountMatches: raw.accountId === input.expectedAccountId,
    publicKeyRepresentation,
    returnedPublicKeyMatches: normalized?.publicKey === input.expectedPublicKey,
    signatureRepresentation,
    signatureLengthBytes,
    signatureEncodingValid,
    serverPayloadReconstruction,
    localEd25519Verification,
    callbackVariantVerification,
  };
}
