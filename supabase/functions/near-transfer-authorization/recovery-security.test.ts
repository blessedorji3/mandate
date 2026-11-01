import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  isDifferentReplacementWallet,
  recoveryChallengeMatches,
  recoveryTestUtils,
  verifyNep413,
} from "./recovery-security.ts";

const recipient = "mandate-snowy.vercel.app";
const message = "MANDATE delayed wallet recovery test vector";
const nonce = Uint8Array.from({ length: 32 }, (_, i) => i + 1);

Deno.test("accepts a valid NEP-413 Ed25519 signature", async () => {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const publicKey = "ed25519:" + recoveryTestUtils.base58Encode(rawPublicKey);
  // The NEP-413 payload is SHA-256 of the Borsh-encoded message envelope.
  const signature = await signNep413(pair.privateKey, message, nonce, recipient);
  assert(await verifyNep413(message, nonce, recipient, publicKey, signature));
});

Deno.test("rejects a signature if message, nonce, or recipient is substituted", async () => {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = "ed25519:" + recoveryTestUtils.base58Encode(
    new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)),
  );
  const signature = await signNep413(pair.privateKey, message, nonce, recipient);
  const changedNonce = nonce.slice();
  changedNonce[0] ^= 0xff;
  assertEquals(await verifyNep413(message + " changed", nonce, recipient, publicKey, signature), false);
  assertEquals(await verifyNep413(message, changedNonce, recipient, publicKey, signature), false);
  assertEquals(await verifyNep413(message, nonce, "attacker.example", publicKey, signature), false);
});

Deno.test("rejects signature-byte tampering and malformed encodings without throwing", async () => {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = "ed25519:" + recoveryTestUtils.base58Encode(
    new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)),
  );
  const signature = await signNep413(pair.privateKey, message, nonce, recipient);
  const raw = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));
  raw[0] ^= 1;
  const tampered = btoa(String.fromCharCode(...raw));
  assertEquals(await verifyNep413(message, nonce, recipient, publicKey, tampered), false);
  assertEquals(await verifyNep413(message, nonce, recipient, "ed25519:not-base58!", signature), false);
  assertEquals(await verifyNep413(message, nonce, recipient, publicKey, "not-base64!"), false);
});

Deno.test("rejects account, key, and action substitution against a recovery challenge", () => {
  const challenge = {
    action: "start",
    account_id: "replacement.testnet",
    public_key: "ed25519:registered-key",
  };
  assert(recoveryChallengeMatches(challenge, "start", "replacement.testnet", "ed25519:registered-key"));
  assertEquals(recoveryChallengeMatches(challenge, "finalize", "replacement.testnet", "ed25519:registered-key"), false);
  assertEquals(recoveryChallengeMatches(challenge, "start", "attacker.testnet", "ed25519:registered-key"), false);
  assertEquals(recoveryChallengeMatches(challenge, "start", "replacement.testnet", "ed25519:attacker-key"), false);
  assertEquals(recoveryChallengeMatches(null, "start", "replacement.testnet", "ed25519:registered-key"), false);
});

Deno.test("requires the replacement account to differ from the active wallet", () => {
  assertEquals(isDifferentReplacementWallet("old-wallet.testnet", "new-wallet.testnet"), true);
  assertEquals(isDifferentReplacementWallet("old-wallet.testnet", "old-wallet.testnet"), false);
  assertEquals(isDifferentReplacementWallet(null, "new-wallet.testnet"), true);
});

async function signNep413(
  privateKey: CryptoKey,
  message: string,
  nonceBytes: Uint8Array,
  recipientValue: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const concat = (...parts: Uint8Array[]) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) { out.set(part, offset); offset += part.length; }
    return out;
  };
  const u32 = (n: number) => {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, n, true);
    return out;
  };
  const borsh = (value: string) => {
    const bytes = encoder.encode(value);
    return concat(u32(bytes.length), bytes);
  };
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, 0x80000000 + 413, true);
  const payload = concat(prefix, borsh(message), nonceBytes, borsh(recipientValue), new Uint8Array([0]));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", payload.slice().buffer as ArrayBuffer));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, digest.slice().buffer as ArrayBuffer));
  return btoa(String.fromCharCode(...signature));
}
