type SafeWalletDiagnostic = {
  challengeMessageUnchanged: boolean;
  challengeRecipientUnchanged: boolean;
  nonceIs32Bytes: boolean;
  returnedAccountMatches: boolean;
  returnedPublicKeyMatches: boolean;
  signatureRepresentation: string;
  signatureLengthBytes: number | null;
  signatureBase64Valid: boolean;
  clientPayloadDigestCreated: boolean;
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
function serverStyleNep413Bytes(message: string, nonce: Uint8Array, recipient: string): Uint8Array {
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, 0x80000000 + 413, true);
  return concat(prefix, borshString(message), nonce, borshString(recipient), new Uint8Array([0]));
}
function validBase64(value: string): boolean {
  return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value) && value.length > 0;
}

/**
 * Produces metadata only. Never returns or logs the message, nonce, signature,
 * public-key bytes, or recovery credential.
 */
export async function inspectRecoveryWalletResponse(input: {
  challengeMessage: string;
  challengeRecipient: string;
  nonce: Uint8Array;
  expectedAccountId: string;
  expectedPublicKey: string;
  walletResponse: unknown;
}): Promise<SafeWalletDiagnostic> {
  const record = input.walletResponse && typeof input.walletResponse === "object"
    ? input.walletResponse as Record<string, unknown>
    : {};
  const returnedAccount = typeof record.accountId === "string" ? record.accountId : "";
  const returnedKey = record.publicKey;
  let publicKeyText = "";
  if (typeof returnedKey === "string") publicKeyText = returnedKey;
  else if (returnedKey && typeof returnedKey === "object" && typeof (returnedKey as { toString?: unknown }).toString === "function") {
    const rendered = (returnedKey as { toString(): string }).toString();
    if (typeof rendered === "string") publicKeyText = rendered;
  }
  const sigValue = record.signature;
  const sigBytes = asBytes(sigValue);
  const sigText = typeof sigValue === "string" ? sigValue : "";
  let signatureLengthBytes: number | null = null;
  let signatureBase64Valid = false;
  if (sigBytes) {
    signatureLengthBytes = sigBytes.length;
    signatureBase64Valid = sigBytes.length === 64;
  } else if (sigText) {
    signatureBase64Valid = validBase64(sigText);
    if (signatureBase64Valid) {
      try { signatureLengthBytes = atob(sigText).length; } catch { signatureBase64Valid = false; }
    }
  }
  let clientPayloadDigestCreated = false;
  try {
    const payload = serverStyleNep413Bytes(input.challengeMessage, input.nonce, input.challengeRecipient);
    await crypto.subtle.digest("SHA-256", payload);
    clientPayloadDigestCreated = true;
  } catch { /* report false without leaking input values */ }
  return {
    challengeMessageUnchanged: input.challengeMessage.length > 0,
    challengeRecipientUnchanged: input.challengeRecipient.length > 0,
    nonceIs32Bytes: input.nonce.length === 32,
    returnedAccountMatches: returnedAccount === input.expectedAccountId,
    returnedPublicKeyMatches: publicKeyText === input.expectedPublicKey,
    signatureRepresentation: sigBytes ? "byte-array" : typeof sigValue,
    signatureLengthBytes,
    signatureBase64Valid,
    clientPayloadDigestCreated,
  };
}
