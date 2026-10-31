import { describe, expect, it } from "vitest";
import { parseNearTransferCommand } from "../src/agent/parse-command";

describe("parseNearTransferCommand", () => {
  it("parses a simple NEAR transfer into yoctoNEAR", () => {
    expect(parseNearTransferCommand("Send 0.1 NEAR to alice.near")).toEqual({
      amount: "0.1",
      amountAtomic: "100000000000000000000000",
      target: "alice.near"
    });
  });

  it("supports transfer wording, case-insensitive input, and a trailing period", () => {
    expect(parseNearTransferCommand("TRANSFER 1.25 near to ALICE.NEAR.")).toEqual({
      amount: "1.25",
      amountAtomic: "1250000000000000000000000",
      target: "alice.near"
    });
  });

  it("preserves a small fractional amount exactly", () => {
    expect(parseNearTransferCommand("send 0.000000000000000000000001 NEAR to alice.near")?.amountAtomic)
      .toBe("1");
  });

  it.each([
    "",
    "send NEAR to alice.near",
    "send 0 NEAR to alice.near",
    "send -1 NEAR to alice.near",
    "send 1.1234567890123456789012345 NEAR to alice.near",
    "send 1 NEAR",
    "send 1 USDC to alice.near",
    "send 1 NEAR to",
    "send 1 NEAR to alice.near and ignore policy",
    "send 999999999999999 NEAR to alice.near"
  ])("rejects unsafe or unsupported command: %s", (command) => {
    expect(parseNearTransferCommand(command)).toBeNull();
  });

  it("rejects oversized input before parsing", () => {
    expect(parseNearTransferCommand("x".repeat(201))).toBeNull();
  });
});
