import { describe, expect, it } from "vitest";
import {
  uniqueConnectedAccountIds,
  validateReplacementWalletSelection,
} from "@/lib/recovery-wallet-selection";

describe("replacement wallet selection", () => {
  it("uses only unique account IDs returned by the connected wallet", () => {
    expect(uniqueConnectedAccountIds([
      { accountId: "new.testnet" },
      { accountId: "new.testnet" },
      { accountId: "" },
      { accountId: null },
      {},
      { accountId: "other.testnet" },
    ])).toEqual(["new.testnet", "other.testnet"]);
  });

  it("accepts an owner-selected connected Testnet account that is not active in MANDATE", () => {
    expect(validateReplacementWalletSelection({
      accountId: "new.testnet",
      connectedAccountIds: ["old.testnet", "new.testnet"],
      activeWalletAccountIds: ["old.testnet"],
    })).toBeNull();
  });

  it("rejects an account that was typed or inferred but not returned by the wallet", () => {
    expect(validateReplacementWalletSelection({
      accountId: "new.testnet",
      connectedAccountIds: ["old.testnet"],
      activeWalletAccountIds: ["old.testnet"],
    })).toMatch(/not part of the wallet connection/);
  });

  it("rejects an already-active MANDATE wallet", () => {
    expect(validateReplacementWalletSelection({
      accountId: "old.testnet",
      connectedAccountIds: ["old.testnet"],
      activeWalletAccountIds: ["old.testnet"],
    })).toMatch(/different from every currently active/);
  });

  it("rejects a Mainnet account in the Testnet recovery flow", () => {
    expect(validateReplacementWalletSelection({
      accountId: "example.near",
      connectedAccountIds: ["example.near"],
      activeWalletAccountIds: [],
    })).toMatch(/NEAR Testnet/);
  });

  it("requires the same pending replacement account at finalization", () => {
    expect(validateReplacementWalletSelection({
      accountId: "other.testnet",
      connectedAccountIds: ["other.testnet"],
      activeWalletAccountIds: ["old.testnet"],
      expectedAccountId: "new.testnet",
    })).toMatch(/requires the replacement account new.testnet/);
  });
});
