import { assert, assertEquals } from "jsr:@std/assert@1";
import { ed25519 } from "npm:@noble/curves@2.2.0/ed25519.js";
import { KeyPairEd25519, KeyPairSigner } from "npm:near-api-js@7.3.1";
import {
  findActiveFullAccessKey,
  isDifferentReplacementWallet,
  recoveryChallengeMatches,
  recoveryTestUtils,
  verifyNep413,
  verifyNep413WithOptionalCallback,
} from "./recovery-security.ts";

const recipient = "mandate-snowy.vercel.app";
const message = "MANDATE delayed wallet recovery test vector";
const nonce = Uint8Array.from({ length: 32 }, (_, i) => i + 1);

Deno.test("accepts a valid NEP-413 signature from the NEAR-compatible Noble Ed25519 implementation", async () => {
  const secretKey = crypto.getRandomValues(new Uint8Array(32));
  const rawPublicKey = ed25519.getPublicKey(secretKey);
  const publicKey = "ed25519:" + recoveryTestUtils.base58Encode(rawPublicKey);
  const signature = await signNep413(secretKey, message, nonce, recipient);
  assert(await verifyNep413(message, nonce, recipient, publicKey, signature));
});

Deno.test("accepts the exact Unicode recovery-reset message from the official NEAR NEP-413 signer", async () => {
  const signer = new KeyPairSigner(KeyPairEd25519.fromRandom());
  const publicKey = (await signer.getPublicKey()).toString();
  const challengeNonce = crypto.getRandomValues(new Uint8Array(32));
  const nonceHex = Array.from(challengeNonce, (value) => value.toString(16).padStart(2, "0")).join("");
  const callbackUrl = "https://mandate-snowy.vercel.app/wallet";
  const challengeMessage = [
    "MANDATE RECOVERY CODE RESET — WALLET OWNERSHIP PROOF",
    "I authorize replacing only my MANDATE independent recovery code. This does not replace or revoke any wallet, move funds, or start the 24-hour wallet recovery process.",
    "MANDATE owner: 00000000-0000-4000-8000-000000000001",
    "Active NEAR account: mandate-diagnostic.testnet",
    `Active NEAR public key: ${publicKey}`,
    "Challenge: 00000000-0000-4000-8000-000000000002",
    `Nonce: ${nonceHex}`,
  ].join("\n");

  // Match the production reset flow: Meteor signs the message with no NEP-413
  // callback URL even though the connector request may contain one.
  const noneSigned = await signer.signNep413Message("mandate-diagnostic.testnet", {
    message: challengeMessage,
    recipient,
    nonce: challengeNonce,
  });
  const noneSignature = btoa(String.fromCharCode(...noneSigned.signature));
  assert(await verifyNep413WithOptionalCallback(
    challengeMessage,
    challengeNonce,
    recipient,
    noneSigned.publicKey.toString(),
    noneSignature,
    callbackUrl,
  ));

  // Also prove the explicit Some(callbackUrl) form is verified when a wallet
  // actually signs that form.
  const callbackSigned = await signer.signNep413Message("mandate-diagnostic.testnet", {
    message: challengeMessage,
    recipient,
    nonce: challengeNonce,
    callbackUrl,
  });
  const callbackSignature = btoa(String.fromCharCode(...callbackSigned.signature));
  assert(await verifyNep413WithOptionalCallback(
    challengeMessage,
    challengeNonce,
    recipient,
    callbackSigned.publicKey.toString(),
    callbackSignature,
    callbackUrl,
  ));

  assertEquals(
    await verifyNep413WithOptionalCallback(
      challengeMessage.replace("—", "-"),
      challengeNonce,
      recipient,
      noneSigned.publicKey.toString(),
      noneSignature,
      callbackUrl,
    ),
    false,
    "the exact Unicode message remains bound to the signature",
  );
});

Deno.test("rejects a signature if message, nonce, or recipient is substituted", async () => {
  const secretKey = crypto.getRandomValues(new Uint8Array(32));
  const rawPublicKey = ed25519.getPublicKey(secretKey);
  const publicKey = "ed25519:" + recoveryTestUtils.base58Encode(rawPublicKey);
  const signature = await signNep413(secretKey, message, nonce, recipient);
  const changedNonce = nonce.slice();
  changedNonce[0] ^= 0xff;
  assertEquals(await verifyNep413(message + " changed", nonce, recipient, publicKey, signature), false);
  assertEquals(await verifyNep413(message, changedNonce, recipient, publicKey, signature), false);
  assertEquals(await verifyNep413(message, nonce, "attacker.example", publicKey, signature), false);
});

Deno.test("rejects signature-byte tampering and malformed encodings without throwing", async () => {
  const secretKey = crypto.getRandomValues(new Uint8Array(32));
  const rawPublicKey = ed25519.getPublicKey(secretKey);
  const publicKey = "ed25519:" + recoveryTestUtils.base58Encode(rawPublicKey);
  const signature = await signNep413(secretKey, message, nonce, recipient);
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
  secretKey: Uint8Array,
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
  const signature = ed25519.sign(digest, secretKey);
  return btoa(String.fromCharCode(...signature));
}
