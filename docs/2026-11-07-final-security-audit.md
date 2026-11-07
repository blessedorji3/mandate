# MANDATE final security audit

**Audit date:** 2026-11-07  
**Repository:** `blessedorji3/mandate`  
**Hosted Supabase project:** `abyyyehfivahedvjrcwj`  
**Scope:** controlled NEAR Testnet demo only

## Executive result

The existing release has a strong owner-bound wallet and recovery foundation, server-side policy revalidation, one-time transfer receipts, and explicit Testnet restrictions. The audit found three implementation gaps worth correcting:

1. Authenticated browser clients could insert owner-scoped `authorization_decisions` rows. The wallet challenge path still recomputes current risk and policy and requires a valid wallet signature, so this finding is an integrity and audit-trust issue rather than evidence that a forged row alone can move funds. Decision receipts should nevertheless only be written by trusted server code.
2. The Developer API panel attempted direct browser reads/writes to `api_keys`, although browser table privileges had been removed. That made key management inconsistent with the intended least-privilege design.
3. Both Edge Functions checked request size after reading the full body. A missing or understated `Content-Length` could evade the early header check and still cause unbounded buffering before rejection.

The corrections are prepared in PR #18 on branch `security/final-audit-hardening`. They are not yet merged, and no production Supabase migration or Edge Function deployment was performed during this audit.

## Live implementation inspected

Before changes, the hosted project reported 25 applied migrations. The active `near-transfer-authorization` Edge Function was v30 with JWT verification enabled; all eight deployed source files matched the repository's `main` branch. The `agent-inspect` Edge Function was v5 with JWT verification disabled because it performs its own `mnd_live_` API-key authentication; its deployed source matched `main`.

RLS was enabled on the private wallet, recovery, transfer-receipt, and counterparty tables inspected. Recovery, wallet, transfer-challenge, transfer-receipt, and counterparty-review RPCs that mutate sensitive state were restricted to the service role. No anonymous or authenticated direct execution was found for those sensitive RPCs.

## 1. Wallet ownership and authorization

**Assessment: controls present; no change required in this PR.**

- The owner identity used by the authorization Edge Function comes from the verified Supabase user session, not an `ownerId` supplied in the request body.
- NEAR account IDs are constrained to Testnet formats and remain associated with one MANDATE owner; revoked account history is retained to prevent reassignment.
- Wallet registration and removal use short-lived, owner-bound challenges and NEP-413 signatures. The signer must be a currently registered wallet with a current FullAccess key.
- A wallet may only be removed from MANDATE when a different active registered wallet authorizes the removal. The last active wallet must use the delayed recovery path.
- MANDATE wallet removal only revokes the wallet's association with MANDATE. It does not remove the NEAR on-chain access key or move funds.

## 2. Recovery and wallet revocation

**Assessment: controls present; live end-to-end recovery reset remains a separate verification item.**

- Recovery requires the independent recovery-code verifier and a wallet-authorized signed challenge.
- Recovery has a 24-hour delay. A pending recovery freezes financial authorization and invalidates outstanding unbound transfer challenges/receipts.
- Recovery-code attempts are limited to five per owner per hour. Recovery action challenges are limited to five per owner per hour; recovery-code reset challenges are limited to three per owner per hour.
- Recovery and wallet events are stored in private audit tables. Challenge records and recovery credential material are not directly readable by browser roles.
- A fresh real-wallet recovery-code reset round trip was not run as part of this audit. The database and signature test suites passing do not substitute for that live-wallet test.

## 3. API key security and rate limits

**Assessment: authentication and quota controls present; dashboard path corrected in PR #18.**

- Developer API credentials use a random `mnd_live_` secret; only the SHA-256 digest is stored. Revoked keys are rejected.
- The API inspection endpoint uses a service-role-only quota routine with a limit of 60 requests per minute per API key.
- API key management is now routed through an authenticated Next.js server endpoint and the owner-authenticated authorization Edge Function. Listing, creation, and revocation are scoped to the verified owner. The full key is returned only at creation.
- The existing browser component's direct table access was inconsistent with the database's restricted privileges; PR #18 removes those direct calls.

## 4. Policy enforcement and transfer approvals

**Assessment: execution checks are layered; decision receipt write integrity corrected in PR #18.**

- Policy evaluation is deterministic and fails closed for malformed policies/proposals, unsupported swap/contract-call actions, disallowed recipients, amount limits, and owner-approval requirements.
- Transfer challenges are bound to the active policy ID/version, exact proposal ID, registered signer, and fixed transfer parameters.
- Counterparty risk is refreshed before challenge creation and again before issuing an authorization receipt. A stale fingerprint or changed risk decision rejects the flow.
- A WARN requires a signed, proposal-bound owner acknowledgement; that acknowledgement is not transaction approval. BLOCK cannot be overridden.
- Transfer challenge creation is limited to ten per owner per five minutes. Signature attempts are capped at three. The transfer challenge expires after three minutes and the resulting one-time receipt is limited to 90 seconds.
- Before PR #18, authenticated users had INSERT access to their own `authorization_decisions` rows. PR #18 removes that permission and the browser INSERT policy. Signed-in proposal inspection now asks the trusted Edge Function to evaluate the active policy and write the decision using the service role.

## 5. NEAR Testnet restrictions

**Assessment: constrained to the controlled Testnet demo.**

- The wallet transfer adapter fixes the network to `testnet`, receiver to `confirmwithmandate.testnet`, asset to `NEAR`, action to `transfer`, and amount to `0.001 NEAR`.
- NEAR RPC verification uses Testnet endpoints, requires final transaction status, validates signer/receiver/action/amount, and binds the verified transaction to a consumed MANDATE authorization receipt.
- Unsupported networks are rejected; arbitrary contract calls and swaps are blocked by the deterministic evaluator.
- Mainnet execution and public production financial use are not approved by this audit.

## 6. Failure handling and audit logs

**Assessment: core financial paths fail closed; request buffering corrected in PR #18.**

- Recovery, wallet, transfer, receipt, and counterparty review events are retained in private audit records. Authorization decisions and consumed transfer receipts preserve policy/proposal evidence.
- If on-chain transaction verification is temporarily unavailable, MANDATE returns a retryable status tied to the same transaction hash and tells the user not to submit the transaction again.
- The bounded streaming body reader already existed with tests for missing/understated `Content-Length` and invalid UTF-8. PR #18 connects it to both Edge Functions before JSON parsing.
- Unexpected transfer-verification failures do not issue a receipt; policy, database, or risk errors reject authorization.

## Changes in PR #18

- Revoke `INSERT` on `public.authorization_decisions` from `anon` and `authenticated`; remove the browser INSERT policy.
- Route app proposal inspection through a trusted server-side decision writer.
- Route Developer API key list/create/revoke through authenticated server/Edge Function operations.
- Enforce streaming request-byte limits in both Edge Functions.
- Add API-key lifecycle HTTP coverage and database privilege assertions.

## Verification on the audit branch

- MANDATE application workflow #587: passed — tests, type-check, production build, and dependency audit.
- MANDATE database/security workflow #452: passed — Edge Function type-checks, recovery signature tests, API-key lifecycle HTTP test, transfer approval/risk/recovery tests, local migration replay, and pgTAP.
- Vercel preview deployment for `security/final-audit-hardening`: READY.
- PR #18 remains open and unmerged. The live Supabase project remains unchanged.

## Safe release sequence

After approval, keep these steps coordinated:

1. Deploy the updated `near-transfer-authorization` Edge Function (the next deployment should be v31) and the updated `agent-inspect` function (the next deployment should be v6).
2. Deploy the updated web app so inspection and key management use the new Edge Function actions.
3. Apply `20261107203500_revoke_browser_decision_receipt_inserts.sql`.
4. Verify proposal inspection, key list/create/revoke, browser database grants, bounded-body rejection, and the fixed Testnet transfer flow.

Do not apply the privilege migration while the old web app is still the active version: the old inspection route writes directly to `authorization_decisions`. Do not treat this Testnet audit as Mainnet approval.
