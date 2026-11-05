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
