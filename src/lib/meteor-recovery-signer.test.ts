import { describe, expect, it, vi } from "vitest";
import type { MeteorWallet } from "@meteorwallet/sdk";
import {
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
  const signMessage = vi.fn(async () => response);
  return {
    signer: { signMessage } as unknown as MeteorRecoverySigner,
    signMessage,
  };
}

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
    const request = signMessage.mock.calls[0][0] as Parameters<MeteorWallet["signMessage"]>[0];
    expect(request.accountIdentifier).toEqual({
      blockchain: "near",
      network: "testnet",
      accountId: challenge.accountId,
    });
    expect(request.message).toBe(challenge.message);
    expect(request.recipient).toBe(challenge.recipient);
    expect(request.nonce).toEqual({
      0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7,
      8: 8, 9: 9, 10: 10, 11: 11, 12: 12, 13: 13, 14: 14, 15: 15,
      16: 16, 17: 17, 18: 18, 19: 19, 20: 20, 21: 21, 22: 22, 23: 23,
      24: 24, 25: 25, 26: 26, 27: 27, 28: 28, 29: 29, 30: 30, 31: 31,
    });
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
