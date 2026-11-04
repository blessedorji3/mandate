import { assert, assertEquals } from "jsr:@std/assert@1";
import { normalizeNearSignedMessage } from "../../../src/lib/near-signed-message.ts";
import { verifyNep413, verifyNep413WithOptionalCallback, recoveryTestUtils } from "./recovery-security.ts";

// Test-only Meteor contract harness. It uses the same signMessage inputs and
// NEP-413 envelope shape as the Meteor executor; it never connects to a wallet.
const recipient = "mandate-snowy.vercel.app";
const accountId = "mandate-diagnostic.testnet";
const message = [
  "MANDATE RECOVERY CODE RESET — WALLET OWNERSHIP PROOF",
  "I authorize replacing only my MANDATE independent recovery code. This does not replace or revoke any wallet, move funds, or start the 24-hour wallet recovery process.",
  "MANDATE owner: diagnostic-owner-id",
  `Active NEAR account: ${accountId}`,
  "Active NEAR public key: __PUBLIC_KEY__",
  "Challenge: diagnostic-challenge-id",
  `Nonce: ${"ab".repeat(32)}`,
].join("\n");

function concat(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}
function u32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
}
function borshString(value: string): Uint8Array {
  const bytes = new TextEncoder().encode(value);
  return concat(u32(bytes.length), bytes);
}
function meteorNep413Payload(messageValue: string, nonceBytes: Uint8Array, recipientValue: string): Uint8Array {
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, 0x80000000 + 413, true);
  // NEP-413 callback_url: None (Borsh Option tag 0).
  return concat(prefix, borshString(messageValue), nonceBytes, borshString(recipientValue), new Uint8Array([0]));
}
function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

Deno.test("recovery reset: Meteor signMessage inputs and server NEP-413 reconstruction agree", async () => {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const publicKey = `ed25519:${recoveryTestUtils.base58Encode(rawPublicKey)}`;
  const challengeMessage = message.replace("__PUBLIC_KEY__", publicKey);
  const challengeNonceHex = "ab".repeat(32);
  const challengeNonceBytes = Uint8Array.from(challengeNonceHex.match(/.{2}/g)!, (byte) => Number.parseInt(byte, 16));
  const challengeRecipient = recipient;

  // These are the exact values supplied by recovery-code-panel to wallet.signMessage.
  const meteorInput = {
    message: challengeMessage,
    recipient: challengeRecipient,
    nonce: challengeNonceBytes.slice(),
    network: "testnet",
    signerId: accountId,
  };
  assertEquals(meteorInput.message, challengeMessage, "challenge message must be passed unchanged");
  assertEquals(meteorInput.recipient, challengeRecipient, "challenge recipient must be passed unchanged");
  assertEquals(meteorInput.nonce.length, 32, "Meteor must receive the decoded 32-byte nonce");
  assertEquals(Array.from(meteorInput.nonce), Array.from(challengeNonceBytes), "Meteor nonce bytes must match challenge nonceHex");

  // Simulate Meteor's NEP-413 executor output using a fresh disposable Ed25519 key.
  const meteorPayload = meteorNep413Payload(meteorInput.message, meteorInput.nonce, meteorInput.recipient);
  const meteorDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", meteorPayload.slice().buffer as ArrayBuffer));
  const rawSignature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" }, pair.privateKey, meteorDigest.slice().buffer as ArrayBuffer,
  ));
  assertEquals(rawSignature.length, 64, "Ed25519 signature must be 64 bytes");
  const returnedByMeteor = {
    accountId,
    publicKey: { keyType: "ed25519", data: rawPublicKey },
    signature: rawSignature,
  };

  // Run the actual application normalizer against Meteor-shaped return values.
  const normalized = normalizeNearSignedMessage(returnedByMeteor);
  assertEquals(normalized.accountId, accountId, "returned account ID must be preserved");
  assertEquals(normalized.publicKey, publicKey, "returned PublicKey bytes must normalize to the registered ed25519 key");
  assertEquals(normalized.signature.length, 88, "64-byte signature must become padded Base64");
  assertEquals(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(normalized.signature), true);
  const normalizedSignatureBytes = Uint8Array.from(atob(normalized.signature), (char) => char.charCodeAt(0));
  assertEquals(normalizedSignatureBytes.length, 64, "normalized Base64 must decode to 64 signature bytes");

  // Independently reconstruct the server's envelope and compare its digest to
  // the digest signed by the Meteor harness, then invoke the actual server verifier.
  const serverPayload = meteorNep413Payload(challengeMessage, challengeNonceBytes, recipient);
  assertEquals(Array.from(serverPayload), Array.from(meteorPayload), "server payload bytes must exactly equal Meteor-signed payload bytes");
  const serverDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", serverPayload.slice().buffer as ArrayBuffer));
  assertEquals(Array.from(serverDigest), Array.from(meteorDigest), "server SHA-256 digest must equal Meteor signing digest");
  assertEquals(
    await verifyNep413(challengeMessage, challengeNonceBytes, recipient, normalized.publicKey, normalized.signature),
    true,
    "actual MANDATE verifier must accept the normalized Meteor-shaped signature",
  );

  // Negative controls: a changed challenge message, recipient, or nonce must fail.
  const changedNonce = challengeNonceBytes.slice();
  changedNonce[0] ^= 1;
  assertEquals(await verifyNep413(challengeMessage + " altered", challengeNonceBytes, recipient, publicKey, normalized.signature), false);
  assertEquals(await verifyNep413(challengeMessage, challengeNonceBytes, "wrong-recipient.example", publicKey, normalized.signature), false);
  assertEquals(await verifyNep413(challengeMessage, changedNonce, recipient, publicKey, normalized.signature), false);
});


Deno.test("recovery reset: callback URL option is explicitly None; a Some payload is not interchangeable", async () => {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const publicKey = `ed25519:${recoveryTestUtils.base58Encode(rawPublicKey)}`;
  const nonceBytes = new Uint8Array(32).fill(7);
  const challengeMessage = message.replace("__PUBLIC_KEY__", publicKey);

  // NEP-413 Borsh Option<string>: None = 0; Some(url) = 1 + Borsh string.
  const nonePayload = meteorNep413Payload(challengeMessage, nonceBytes, recipient);
  const someCallbackPayload = concat(
    nonePayload.slice(0, nonePayload.length - 1),
    new Uint8Array([1]),
    borshString("https://mandate-snowy.vercel.app/callback"),
  );
  assertEquals(nonePayload.at(-1), 0, "Meteor action without callbackUrl must serialize Option::None");
  assertEquals(someCallbackPayload.at(-1 - new TextEncoder().encode("https://mandate-snowy.vercel.app/callback").length - 4), 1);

  const noneDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", nonePayload.slice().buffer as ArrayBuffer));
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" }, pair.privateKey, noneDigest.slice().buffer as ArrayBuffer,
  ));
  const signatureBase64 = base64(signature);

  assertEquals(await verifyNep413(challengeMessage, nonceBytes, recipient, publicKey, signatureBase64), true);
  const someDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", someCallbackPayload.slice().buffer as ArrayBuffer));
  const someKey = await crypto.subtle.importKey("raw", rawPublicKey.slice().buffer as ArrayBuffer, { name: "Ed25519" }, false, ["verify"]);
  assertEquals(await crypto.subtle.verify(
    { name: "Ed25519" }, someKey, signature.slice().buffer as ArrayBuffer, someDigest.slice().buffer as ArrayBuffer,
  ), false, "signature over callbackUrl=None must not verify against callbackUrl=Some");
});

Deno.test("recovery reset: server accepts both valid NEP-413 callback option forms", async () => {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const publicKey = `ed25519:${recoveryTestUtils.base58Encode(rawPublicKey)}`;
  const nonce = new Uint8Array(32).fill(11);
  const challengeMessage = message.replace("__PUBLIC_KEY__", publicKey);
  const callbackUrl = "https://mandate-snowy.vercel.app/wallet";

  const nonePayload = meteorNep413Payload(challengeMessage, nonce, recipient);
  const noneDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", nonePayload.slice().buffer as ArrayBuffer));
  const noneSignature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" }, pair.privateKey, noneDigest.slice().buffer as ArrayBuffer,
  ));
  const noneSignatureBase64 = base64(noneSignature);

  assertEquals(
    await verifyNep413WithOptionalCallback(challengeMessage, nonce, recipient, publicKey, noneSignatureBase64, callbackUrl),
    true,
    "Meteor's callbackUrl=None signature should verify against the same stored challenge",
  );
  assertEquals(
    await verifyNep413(challengeMessage, nonce, recipient, publicKey, noneSignatureBase64, callbackUrl),
    false,
    "a None signature must not be mistaken for a Some(callbackUrl) signature",
  );

  const somePayload = concat(
    new Uint8Array([0x9d, 0x01, 0x00, 0x80]),
    borshString(challengeMessage),
    nonce,
    borshString(recipient),
    new Uint8Array([1]),
    borshString(callbackUrl),
  );
  const someDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", somePayload.slice().buffer as ArrayBuffer));
  const someSignature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" }, pair.privateKey, someDigest.slice().buffer as ArrayBuffer,
  ));
  const someSignatureBase64 = base64(someSignature);

  assertEquals(
    await verifyNep413WithOptionalCallback(challengeMessage, nonce, recipient, publicKey, someSignatureBase64, callbackUrl),
    true,
    "a Some(callbackUrl) signature remains accepted",
  );
  assertEquals(
    await verifyNep413WithOptionalCallback(challengeMessage + " changed", nonce, recipient, publicKey, noneSignatureBase64, callbackUrl),
    false,
    "the exact message remains bound to the signature",
  );
  const alteredNonce = nonce.slice(); alteredNonce[0] ^= 1;
  assertEquals(
    await verifyNep413WithOptionalCallback(challengeMessage, alteredNonce, recipient, publicKey, noneSignatureBase64, callbackUrl),
    false,
    "the exact challenge nonce remains bound to the signature",
  );
  assertEquals(
    await verifyNep413WithOptionalCallback(challengeMessage, nonce, "wrong-recipient.example", publicKey, noneSignatureBase64, callbackUrl),
    false,
    "the relying-party recipient remains bound to the signature",
  );
});

Deno.test("recovery reset: explicit trusted callback URL is part of the NEP-413 signature", async () => {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const publicKey = `ed25519:${recoveryTestUtils.base58Encode(rawPublicKey)}`;
  const nonce = new Uint8Array(32).fill(9);
  const challengeMessage = message.replace("__PUBLIC_KEY__", publicKey);
  const callbackUrl = "https://mandate-snowy.vercel.app";
  const payload = concat(
    new Uint8Array([0x9d, 0x01, 0x00, 0x80]),
    borshString(challengeMessage),
    nonce,
    borshString(recipient),
    new Uint8Array([1]),
    borshString(callbackUrl),
  );
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", payload.slice().buffer as ArrayBuffer));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, digest.slice().buffer as ArrayBuffer));
  const signatureBase64 = base64(signature);

  assertEquals(await verifyNep413(challengeMessage, nonce, recipient, publicKey, signatureBase64, callbackUrl), true);
  assertEquals(await verifyNep413(challengeMessage, nonce, recipient, publicKey, signatureBase64, "https://mandate-snowy.vercel.app.evil.example"), false);
  assertEquals(await verifyNep413(challengeMessage, nonce, "wrong-recipient.example", publicKey, signatureBase64, callbackUrl), false);
  const alteredNonce = nonce.slice(); alteredNonce[0] ^= 1;
  assertEquals(await verifyNep413(challengeMessage, alteredNonce, recipient, publicKey, signatureBase64, callbackUrl), false);
});
