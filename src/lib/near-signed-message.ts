/**
 * Converts NEAR SDK SignedMessage values into the JSON-safe representation
 * expected by the MANDATE Edge Function. NEAR SDKs may return PublicKey
 * instances and Uint8Array signatures; a TypeScript cast does not serialize
 * those values into strings.
 */
type SignedMessageLike = {
  accountId?: unknown;
  publicKey?: unknown;
  signature?: unknown;
};

function asBytes(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (Array.isArray(value) && value.every(
    (item) => Number.isInteger(item) && item >= 0 && item <= 255,
  )) return Uint8Array.from(value);
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    if ("data" in record) return asBytes(record.data);
  }
  return null;
}

function base58Encode(bytes: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  let encoded = "";
  while (value > 0n) {
    const remainder = Number(value % 58n);
    encoded = alphabet[remainder] + encoded;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    encoded = "1" + encoded;
  }
  return encoded || "1";
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

export function normalizeNearSignedMessage(value: unknown): {
  accountId: string;
  publicKey: string;
  signature: string;
} {
  if (!value || typeof value !== "object") {
    throw new Error("The NEAR wallet returned an invalid signed message.");
  }
  const signed = value as SignedMessageLike;
  if (typeof signed.accountId !== "string" || !signed.accountId) {
    throw new Error("The NEAR wallet did not identify the signing account.");
  }

  let publicKey: string | null = null;
  if (typeof signed.publicKey === "string") {
    publicKey = signed.publicKey;
  } else if (signed.publicKey && typeof signed.publicKey === "object") {
    const key = signed.publicKey as Record<string, unknown>;
    if (typeof key.toString === "function") {
      const rendered = key.toString();
      if (typeof rendered === "string" && /^ed25519:[1-9A-HJ-NP-Za-km-z]+$/.test(rendered)) {
        publicKey = rendered;
      }
    }
    if (!publicKey && typeof key.keyType === "string") {
      const keyType = key.keyType.toLowerCase();
      const keyBytes = asBytes(key.data);
      if (keyType === "ed25519" && keyBytes?.length === 32) {
        publicKey = `ed25519:${base58Encode(keyBytes)}`;
      }
    }
  }

  const signatureBytes = asBytes(signed.signature);
  const signature = typeof signed.signature === "string"
    ? signed.signature
    : signatureBytes?.length === 64
      ? bytesToBase64(signatureBytes)
      : null;

  if (!publicKey || !/^ed25519:[1-9A-HJ-NP-Za-km-z]+$/.test(publicKey)) {
    throw new Error("The NEAR wallet returned an unsupported signing public key.");
  }
  if (!signature || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(signature)) {
    throw new Error("The NEAR wallet returned an invalid signature encoding.");
  }
  return { accountId: signed.accountId, publicKey, signature };
}
