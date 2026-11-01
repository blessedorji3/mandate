const encoder = new TextEncoder();

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

function base58Decode(value: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = 0n;
  for (const char of value) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) throw new Error("Invalid base58");
    n = n * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (n > 0n) { bytes.unshift(Number(n & 255n)); n >>= 8n; }
  for (let i = 0; i < value.length && value[i] === "1"; i++) bytes.unshift(0);
  return Uint8Array.from(bytes);
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

function nep413Bytes(message: string, nonce: Uint8Array, recipient: string) {
  if (nonce.length !== 32) throw new Error("NEP-413 nonce must be 32 bytes");
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, 0x80000000 + 413, true);
  return concat(prefix, borshString(message), nonce, borshString(recipient), new Uint8Array([0]));
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
): Promise<boolean> {
  try {
    const [keyType, encodedKey, extra] = publicKey.split(":");
    if (keyType !== "ed25519" || !encodedKey || extra !== undefined) return false;
    const key = base58Decode(encodedKey);
    const sig = base64Decode(signature);
    if (key.length !== 32 || sig.length !== 64 || nonce.length !== 32) return false;
    const digest = await sha256(nep413Bytes(message, nonce, recipient));
    const cryptoKey = await crypto.subtle.importKey("raw", asArrayBuffer(key), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, cryptoKey, asArrayBuffer(sig), asArrayBuffer(digest));
  } catch {
    // Malformed key/signature encodings are an authentication failure, not a server error.
    return false;
  }
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
