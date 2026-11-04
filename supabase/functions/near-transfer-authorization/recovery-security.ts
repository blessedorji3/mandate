import { PublicKey } from "@near-js/crypto";
const encoder = new TextEncoder();

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

function base58Encode(bytes: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = 0n;
  for (const byte of bytes) n = (n << 8n) | BigInt(byte);
  let encoded = "";
  while (n > 0n) {
    const remainder = Number(n % 58n);
    encoded = alphabet[remainder] + encoded;
    n /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    encoded = "1" + encoded;
  }
  return encoded || "1";
}

function base64Decode(value: string): Uint8Array {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("Invalid base64");
  }
  const binary = atob(value);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function concat(...parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

function u32(value: number) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}

function borshString(value: string) {
  const bytes = encoder.encode(value);
  return concat(u32(bytes.length), bytes);
}

function nep413Bytes(message: string, nonce: Uint8Array, recipient: string, callbackUrl?: string) {
  if (nonce.length !== 32) throw new Error("NEP-413 nonce must be 32 bytes");
  if (callbackUrl !== undefined && (!/^https:\/\//.test(callbackUrl) || callbackUrl.length > 2048)) {
    throw new Error("Invalid NEP-413 callback URL");
  }
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, 0x80000000 + 413, true);
  const callback = callbackUrl === undefined
    ? new Uint8Array([0])
    : concat(new Uint8Array([1]), borshString(callbackUrl));
  return concat(prefix, borshString(message), nonce, borshString(recipient), callback);
}

async function sha256(bytes: Uint8Array) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(bytes)));
}

export async function verifyNep413(
  message: string,
  nonce: Uint8Array,
  recipient: string,
  publicKey: string,
  signature: string,
  callbackUrl?: string,
): Promise<boolean> {
  try {
    if (!publicKey.startsWith("ed25519:") || nonce.length !== 32) return false;
    const key = PublicKey.fromString(publicKey);
    const sig = base64Decode(signature);
    if (key.data.length !== 32 || sig.length !== 64) return false;
    const digest = await sha256(nep413Bytes(message, nonce, recipient, callbackUrl));
    // Use the same NEAR SDK Ed25519 verifier as Meteor/NEAR Connect rather
    // than WebCrypto, so the reference signing and verification stack agrees.
    return key.verify(digest, sig);
  } catch {
    // Malformed key/signature encodings are an authentication failure, not a server error.
    return false;
  }
}

/**
 * NEP-413 defines callback_url as optional. Some compatible wallets (including
 * the current Meteor Wallet adapter) sign the Option::None form even when the
 * caller's connector-level request contains a callback URL.
 *
 * Keep the stored trusted callback as the preferred verification form, then
 * accept the standards-compliant None form. In both cases the signature still
 * covers the exact challenge message, nonce, relying-party recipient and key.
 */
export async function verifyNep413WithOptionalCallback(
  message: string,
  nonce: Uint8Array,
  recipient: string,
  publicKey: string,
  signature: string,
  callbackUrl: string,
): Promise<boolean> {
  if (await verifyNep413(message, nonce, recipient, publicKey, signature, callbackUrl)) {
    return true;
  }
  return await verifyNep413(message, nonce, recipient, publicKey, signature);
}

export function recoveryChallengeMatches(
  challenge: { action: string; account_id: string; public_key: string } | null,
  action: "start" | "finalize",
  accountId: string,
  publicKey: string,
): boolean {
  return !!challenge &&
    challenge.action === action &&
    challenge.account_id === accountId &&
    challenge.public_key === publicKey;
}

export function isDifferentReplacementWallet(activeAccountId: unknown, replacementAccountId: string): boolean {
  return typeof activeAccountId !== "string" || activeAccountId !== replacementAccountId;
}

export const recoveryTestUtils = { base58Encode };

export interface NearAccessKey {
  public_key: string;
  access_key?: { permission?: unknown } | null;
}

export function findActiveFullAccessKey(
  keys: NearAccessKey[],
  expectedPublicKey?: string,
): NearAccessKey | null {
  return keys.find((entry) =>
    (expectedPublicKey === undefined || entry.public_key === expectedPublicKey) &&
    entry.access_key?.permission === "FullAccess"
  ) ?? null;
}
