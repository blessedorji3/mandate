/**
 * MANDATE first connected agent — safe simulation only.
 *
 * This agent never signs, broadcasts, or executes transactions.
 * It demonstrates the authorization gate: only ALLOW reaches the
 * simulated execution function. BLOCK, REQUIRE_APPROVAL, API errors,
 * and malformed responses all stop the action.
 *
 * Run with Node.js 20.6+:
 *   node --env-file=.env.local examples/first-agent/agent.mjs
 */

const ENDPOINT =
  process.env.MANDATE_API_URL ??
  "https://abyyyehfivahedvjrcwj.supabase.co/functions/v1/agent-inspect";

const API_KEY = process.env.MANDATE_API_KEY;

if (!API_KEY || !API_KEY.startsWith("mnd_live_")) {
  console.error("Missing or invalid MANDATE_API_KEY. Set it in your local .env.local file.");
  process.exit(1);
}

async function askMandate(proposal) {
  const response = await fetch(ENDPOINT, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ proposal }),
    signal: AbortSignal.timeout(15_000),
  });

  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error(`MANDATE returned a non-JSON response (HTTP ${response.status}).`);
  }

  if (!response.ok) {
    throw new Error(result?.error ?? `MANDATE request failed (HTTP ${response.status}).`);
  }

  if (!["ALLOW", "BLOCK", "REQUIRE_APPROVAL"].includes(result?.decision?.outcome)) {
    throw new Error("MANDATE response did not contain a recognized authorization decision.");
  }

  return result.decision;
}

async function simulateExecution(proposal) {
  // Demonstration only. Replace with a real execution adapter only after
  // implementing owner approval, wallet checks, chain-specific validation,
  // transaction simulation, and a separate security review.
  console.log(`SIMULATION ONLY: ${proposal.actionType} of ${proposal.amountAtomic} atomic ${proposal.asset} to ${proposal.target}`);
}

async function runProposal(label, proposal) {
  console.log(`\n--- ${label} ---`);
  console.log("Agent proposal:", proposal);

  try {
    const decision = await askMandate(proposal);
    console.log(`MANDATE: ${decision.outcome} — ${decision.reason}`);

    if (decision.outcome === "ALLOW") {
      console.log("Authorization passed. Passing to simulated execution.");
      await simulateExecution(proposal);
    } else {
      console.log("STOPPED. No execution was attempted.");
    }
  } catch (error) {
    console.error("MANDATE check failed:", error.message);
    console.log("STOPPED. Fail-closed: no execution was attempted.");
  }
}

const allowedProposal = {
  id: `demo-allowed-${Date.now()}`,
  agentId: "mandate-first-agent",
  actionType: "transfer",
  asset: "NEAR",
  amountAtomic: "100000000000000000000000",
  target: "alice.near",
};

const blockedProposal = {
  id: `demo-blocked-${Date.now()}`,
  agentId: "mandate-first-agent",
  actionType: "transfer",
  asset: "NEAR",
  amountAtomic: "100000000000000000000000",
  target: "unapproved-recipient.near",
};

console.log("MANDATE First Agent — authorization-gate demonstration");
console.log("No wallet is connected. No funds can move.");

await runProposal("Test 1: policy-approved recipient", allowedProposal);
await runProposal("Test 2: unapproved recipient (must be blocked)", blockedProposal);

console.log("\nDemo complete. Review both decisions in your MANDATE dashboard.");
