# Phase 2 — Inspection and execution-boundary integration

This feature branch integrates the independent counterparty-risk engine into both inspection APIs and the fixed NEAR Testnet wallet-authorization boundary.

## Shared inspection decision path

1. The inspection caller loads the active owner policy.
2. The deterministic policy engine evaluates the proposal.
3. A server-side risk service obtains current NEAR Testnet state, indexed account history, the reviewed blocklist result, and the authenticated owner's prior decision count for the target.
4. The decision combiner preserves a policy BLOCK, maps risk BLOCK to BLOCK, maps risk WARN to REQUIRE_APPROVAL, and otherwise preserves the policy result.
5. The risk decision and collection status are stored in the decision receipt and returned separately.

## Identity and data access

- The signed-in web route derives the owner from the Supabase Auth session.
- The Developer API derives the owner from the validated API-key database record.
- The wallet-authorization Edge Function derives owner identity from the authenticated Supabase user.
- Receipt counts are filtered by both owner ID and target account.
- The blocklist lookup is available only through a service-role-only database function.
- The web route uses a server-only Supabase service-role secret. Missing configuration produces unavailable evidence and WARN, never a clear result.

## Wallet-authorization boundary

The fixed Testnet wallet endpoint independently re-evaluates counterparty risk before creating a challenge, issuing a receipt after signature verification, and consuming the one-time receipt. It also requires the inspected proposal to carry a recorded risk ALLOW. The database challenge, finalization and consumption functions independently require a matching owner-scoped decision receipt whose `proposal.counterpartyRisk.outcome` is ALLOW.

A WARN never reveals the Agent Chat wallet panel and never becomes an approval bypass. Risk ALLOW remains separate from the policy decision and from the wallet's explicit owner signature.

## Deployment status

- Feature branch only.
- The blocklist and wallet risk-gate migrations are included for review and disposable CI; they have not been applied to hosted Supabase.
- No production Edge Function deployment has taken place.
- No wallet transaction or Mainnet feature is included.
- Until the migrations and Edge Functions are deployed together, the missing lookup RPC causes risk to fail closed and prevents new wallet challenges.
- Contract historical code-change evidence remains unavailable, so contract counterparties remain WARN.

## Proposal-bound owner review for WARN

The fixed Testnet wallet flow supports a separate owner-signed acknowledgement for an eligible WARN result. It does not edit the risk evaluator's output:
- The acknowledgement is tied to the owner, proposal ID, target, policy ID/version, registered signing wallet, and a stable risk-evidence fingerprint.
- The owner signs the full warning context and bounded warning reasons in a NEP-413 message using a registered active Testnet wallet.
- The review challenge expires after 3 minutes; a completed review expires after 5 minutes and is consumed once when a transfer challenge is created.
- The review row retains the verified wallet signature, signer account/public key, exact proposal and evidence fingerprint for audit.
- A review does not approve the transaction. The existing transfer authorization signature and wallet's explicit transaction approval remain separate.
- The risk engine continues to report WARN; it is never rewritten as ALLOW.
- A BLOCK result has no review action. The Edge Function and database reject BLOCK, and the database also rechecks the confirmed shared blocklist at review and execution transitions.
- Policy version changes, evidence fingerprint changes, wallet revocation, expiry, recovery freeze, replay, or a newly confirmed blocklist entry invalidate the path.

The Agent Chat presents a dedicated “Review warning & sign acknowledgement” step for exact supported proposals. After the review is recorded, the ordinary transfer authorization flow becomes available. A failure or expired review locks the transfer again and requires a fresh review.

The database tests cover owner-bound review creation, replay rejection, stored signature retention, WARN challenge gating, policy approval-required mode, and the inability of a previous WARN acknowledgement to override a later BLOCK or confirmed blocklist entry.

## Remaining constraints

- The current review flow applies only to the fixed 0.001 NEAR NEAR Testnet transfer to confirmwithmandate.testnet; it is not a general-purpose approval framework for swaps, arbitrary contract calls, or other targets.
- Human review decisions are currently signed by the owner's registered NEAR wallet; there is not a separate administrator/reviewer workflow for curating shared blocklist reports.
- Contract historical code-change evidence remains unavailable, so contract counterparties continue to receive WARN.
