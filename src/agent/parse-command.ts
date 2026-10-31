const YOCTO_PER_NEAR = 10n ** 24n;
const MAX_U128 = (1n << 128n) - 1n;

export type ParsedNearTransfer = {
  amount: string;
  amountAtomic: string;
  target: string;
};

export function parseNearTransferCommand(input: string): ParsedNearTransfer | null {
  if (typeof input !== "string" || input.length > 200) return null;

  const normalizedInput = input.trim().replace(/\.$/, "");
  const match = normalizedInput.match(
    /^(?:send|transfer)\s+([0-9]{1,14}(?:\.[0-9]{1,24})?)\s+near\s+to\s+([a-z0-9._-]{2,64})\.?$/i
  );
  if (!match) return null;

  const [whole, fraction = ""] = match[1].split(".");
  const amountAtomic =
    BigInt(whole) * YOCTO_PER_NEAR +
    BigInt((fraction + "0".repeat(24)).slice(0, 24));

  if (amountAtomic <= 0n || amountAtomic > MAX_U128) return null;

  return {
    amount: match[1],
    amountAtomic: amountAtomic.toString(),
    target: match[2].replace(/\.$/, "").toLowerCase()
  };
}
