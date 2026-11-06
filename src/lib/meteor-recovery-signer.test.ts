import { describe, expect, it, vi } from "vitest";
import type { MeteorWallet } from "@meteorwallet/sdk";
import {
  connectExactMeteorRecoveryAccount,
  signExactMeteorRecoveryChallenge,
  type MeteorRecoverySigner,
} from "@/lib/meteor-recovery-signer";

const challenge = {
  accountId: "replacement.testnet",
  publicKey: "ed25519:11111111111111111111111111111111",
  message: "MANDATE delayed wallet recovery request",
  recipient: "mandate-snowy.vercel.app",
  nonceHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
};

const validSignature = btoa(String.fromCharCode(...new Uint8Array(64)));

function signerReturning(response: {
  success: true;
  payload: { accountId: string; publicKey: string; signature: string };
}) {
  const signMessage = vi.fn(async (_input: Parameters<MeteorWallet["signMessage"]>[0]) => response);
  return {
    signer: { signMessage } as unknown as MeteorRecoverySigner,
    signMessage,
  };
}

describe("Meteor recovery account connection", () => {
  it("connects MANDATE to the exact replacement account before message signing", async () => {
    const requestSignIn = vi.fn(async (_input: Parameters<MeteorWallet["requestSignIn"]>[0]) => ({
      success: true as const,
      endTags: [],
      payload: { accountId: challenge.accountId },
    }));
    const signer = { requestSignIn } as unknown as MeteorRecoverySigner;
    await expect(connectExactMeteorRecoveryAccount(signer, challenge.accountId))
      .resolves.toBe(challenge.accountId);
    expect(requestSignIn).toHaveBeenCalledTimes(1);
    expect(requestSignIn).toHaveBeenCalledWith({});
  });

  it("rejects a different account selected during Meteor connection", async () => {
    const requestSignIn = vi.fn(async (_input: Parameters<MeteorWallet["requestSignIn"]>[0]) => ({
      success: true as const,
      endTags: [],
      payload: { accountId: "old-wallet.testnet" },
    }));
    const signer = { requestSignIn } as unknown as MeteorRecoverySigner;
    await expect(connectExactMeteorRecoveryAccount(signer, challenge.accountId))
      .rejects.toThrow(/not the requested replacement account/);
  });
});

describe("account-targeted Meteor recovery signing", () => {
  it("requests the exact replacement account on NEAR Testnet and omits callbackUrl", async () => {
    const { signer, signMessage } = signerReturning({
      success: true,
      payload: {
        accountId: challenge.accountId,
        publicKey: challenge.publicKey,
        signature: validSignature,
      },
    });

    const signed = await signExactMeteorRecoveryChallenge(signer, challenge);

    expect(signMessage).toHaveBeenCalledTimes(1);
    const request = signMessage.mock.calls[0][0];
    expect(request.accountIdentifier).toEqual({
      blockchain: "near",
      network: "testnet",
      accountId: challenge.accountId,
    });
    expect(request.message).toBe(challenge.message);
    expect(request.recipient).toBe(challenge.recipient);
    expect(request.nonce).toBeInstanceOf(Uint8Array);
    expect(Array.from(request.nonce as Uint8Array)).toEqual(Array.from({ length: 32 }, (_, index) => index));
    expect("callbackUrl" in request).toBe(false);
    expect(signed).toEqual({
      accountId: challenge.accountId,
      publicKey: challenge.publicKey,
      signature: validSignature,
    });
  });

  it("rejects a signature returned for another account", async () => {
    const { signer } = signerReturning({
      success: true,
      payload: {
        accountId: "old-wallet.testnet",
        publicKey: challenge.publicKey,
        signature: validSignature,
      },
    });
    await expect(signExactMeteorRecoveryChallenge(signer, challenge))
      .rejects.toThrow(/different NEAR account/);
  });

  it("rejects a signature made with a key other than the challenge FullAccess key", async () => {
    const { signer } = signerReturning({
      success: true,
      payload: {
        accountId: challenge.accountId,
        publicKey: "ed25519:11111111111111111111111111111112",
        signature: validSignature,
      },
    });
    await expect(signExactMeteorRecoveryChallenge(signer, challenge))
      .rejects.toThrow(/different key from the FullAccess key/);
  });

  it("rejects malformed or non-64-byte signatures", async () => {
    const { signer } = signerReturning({
      success: true,
      payload: {
        accountId: challenge.accountId,
        publicKey: challenge.publicKey,
        signature: btoa("too short"),
      },
    });
    await expect(signExactMeteorRecoveryChallenge(signer, challenge))
      .rejects.toThrow(/signature length/);
  });

  it("rejects malformed challenge nonces before opening Meteor", async () => {
    const { signer, signMessage } = signerReturning({
      success: true,
      payload: {
        accountId: challenge.accountId,
        publicKey: challenge.publicKey,
        signature: validSignature,
      },
    });
    await expect(signExactMeteorRecoveryChallenge(signer, {
      ...challenge,
      nonceHex: "abcd",
    })).rejects.toThrow(/32-byte recovery nonce/);
    expect(signMessage).not.toHaveBeenCalled();
  });
});
