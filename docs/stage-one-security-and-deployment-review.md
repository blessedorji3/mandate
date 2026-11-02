# MANDATE Stage One — Security and Deployment Review

**Review date:** 2026-11-02  
**Reviewed PR:** #6 — `feat/wallet-connection-ux`  
**Production Supabase project:** `abyyyehfivahedvjrcwj`  
**Status:** Review in progress. This document is not a production-readiness approval.

## Verified evidence

- Recovery migration tests run against a disposable local Supabase stack.
- The database suite passed 44 assertions on commit `ce5ccb9c5d9c52313919213b7012557137027fca`.
- The independent PostgreSQL concurrency test passed: two sessions attempted recovery start for one owner; exactly one succeeded and exactly one pending request remained.
- Application CI passed on `7b8f871c66ef78c34d519309eda76ac8d3f3785c` (authorization tests, dependency audit, type-check, and build).
- The mocked HTTP-boundary test checks missing/invalid bearer tokens and confirms that the owner ID is taken from the authenticated Supabase user, not caller-supplied JSON.
- **Live local GoTrue integration passes** on `7b8f871c66ef78c34d519309eda76ac8d3f3785c` and was rerun successfully on review commit `7d077cc98fe5f9485abd170699a2fb46725f05ce`: the CI script starts a disposable local Supabase stack, creates a disposable Auth user, obtains a real password-grant JWT from local GoTrue, and calls the Edge Function handler with missing, invalid, and real tokens. The real token reaches owner-scoped local database RPCs for recovery lifecycle and wallet status; the test also supplies a conflicting caller `ownerId` and confirms the authenticated user remains authoritative. The disposable Auth user is deleted in `finally`. This test does not call hosted production Supabase.
- The recovery database tests verify that pending recovery blocks new transfer challenges, receipt consumption, and transaction binding; outstanding receipts are invalidated.
- Production was inspected read-only. The recovery migrations are not applied there and the deployed Edge Function is still version 9 without this PR's recovery implementation.

## Supabase Security Advisor findings

### RLS enabled with no policies — INFO (2 tables)

- `mandate_private.near_owner_wallets`
- `mandate_private.near_wallet_registration_challenges`

**Disposition: intentionally deny-all for API roles; accepted as informational, not silently dismissed.**

These tables are in the private schema, have RLS enabled, and have no policies. Direct table privileges for `anon` and `authenticated` are revoked. The application accesses them through narrowly scoped, service-role-only RPCs in the Edge Function. Adding permissive policies would weaken this boundary. A future reviewer should verify that the private schema is not exposed through PostgREST and that each security-definer RPC has a fixed safe search_path, explicit owner scoping, and service_role-only EXECUTE grants.

### Leaked password protection disabled — WARN (1 finding)

**Disposition: outstanding launch hardening requirement.**

Supabase Auth's compromised-password protection is currently disabled. The connected Supabase management interface used for this review exposes project, migration, Edge Function, SQL, and advisor operations, but no Auth configuration update operation. It has therefore not been changed. Before public launch, an authorized project administrator must enable leaked-password protection in Supabase Dashboard → Authentication → Settings → Password Security, then re-run the Security Advisor and test signup/password update behavior.

Reference: https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection

## NEAR Testnet access-key removal — critical distinction

The PR's recovery finalization revokes the old wallet row **inside MANDATE's database** and makes the replacement wallet the only active MANDATE sender. It does not submit a NEAR `DeleteKey` action to the old NEAR account.

A NEAR access key can only be removed by an authorized transaction signed by a remaining key that has permission to manage keys on that same account. If the old wallet is lost and no other authorized key remains, MANDATE cannot cryptographically delete its key from-chain. A replacement wallet cannot remove keys from an unrelated old account.

Consequently:
- MANDATE database revocation must never be described as on-chain key removal.
- A disposable Testnet `DeleteKey` demonstration would prove NEAR protocol key deletion works, but would not prove recovery can revoke a lost old wallet.
- The recovery design must retain the distinction and clearly disclose that old NEAR account keys remain on-chain unless the account owner separately authorizes their removal.
- No user wallet keys or funds may be used for this test.

## Migration and deployment sequence review

The PR contains new wallet single-sender and recovery migrations, including:
- `20261101170000_enforce_single_active_near_owner_wallet.sql`
- `20261101190000_create_near_wallet_recovery_credentials.sql`
- `20261101200000_add_delayed_near_wallet_recovery.sql`

Production migration history currently ends at `20261101150802`. None of the three PR migrations is applied in production. The deployed Edge Function version 9 does not include this recovery implementation. Applying only the migration or deploying only the function would leave the system inconsistent.

**Required order after all gates pass:**
1. Review the complete migration diff and grants against the production schema; take a verified backup/rollback plan.
2. Apply migrations in version order during an approved change window.
3. Verify migration history, RLS, table privileges, RPC grants, constraints, indexes, and owner isolation.
4. Deploy the matching Edge Function source and all imported files with JWT verification enabled.
5. Verify function version/source hash and required secrets without printing secret values.
6. Run authenticated smoke tests: wallet status, recovery lifecycle, start/freeze, blocked transfer challenge/consume/bind, cancel, and finalization.
7. Verify NEAR Testnet key lists and MANDATE's registered-wallet state independently.
8. Re-run Security Advisor, CI, and the production smoke tests; keep rollback steps ready.

**Latest CI verification (2026-11-02):** both application CI and database integration CI completed successfully on `7d077cc98fe5f9485abd170699a2fb46725f05ce`. Database CI completed signature/challenge tests, HTTP authentication integration tests, live local GoTrue authentication integration tests, migration replay, and pgTAP recovery tests. Application CI completed dependency audit, authorization tests, type-check, and build.

**Current production state:** untouched. Remaining Stage One gates are independent Testnet access-key baseline/deletion evidence; enabling leaked-password protection and re-running the advisor; and completing the external Testnet wallet registration/recovery exercise. Database tests cover recovery initiation, 24-hour delay, transfer challenge/receipt/binding freeze, finalization, old-wallet database revocation, replacement activation, replay prevention, cancellation, expired challenge rejection, cross-owner replacement rejection, and recovery-code rate limiting. These local tests do not substitute for the external Testnet exercise. Do not merge, apply migrations, or deploy until the remaining gates and final review are complete.

## Current decision

Stage One is **not yet certified complete**. Application CI, database CI, and live local GoTrue/JWT integration have passed. Remaining gates are external NEAR Testnet baseline and wallet lifecycle evidence, the project's leaked-password protection setting and a clean follow-up Security Advisor review, and final end-to-end verification. This is a documented risk disposition, not a claim that all findings are resolved.

## Follow-up verification — 2026-11-02 (latest branch head)

- Latest reviewed branch head: `aba14e8d368215b6bb87ed4d4f0dd619b048c81f`.
- Both GitHub Actions workflows passed on this exact head: application checks (dependency audit, authorization tests, type-check, build) and database integration (recovery signature/challenge tests, HTTP bearer-auth tests, disposable local GoTrue JWT integration, migration replay/pgTAP, and concurrency test runner).
- The database integration workflow explicitly invokes `.github/scripts/run-live-auth-integration-test.sh` from the disposable local Supabase stack before pgTAP. The live GoTrue test is therefore part of the passing CI run on this head.
- Vercel created a READY Preview deployment for this exact branch/head: `https://mandate-nyozcguve-web3pass.vercel.app`. The Vercel integration currently denies the connected session access to fetch this deployment (403 at deployment-protection lookup). The deployment is confirmed READY, but page-level browser/HTTP verification is still blocked pending authorization of the MANDATE project/team in the Vercel connection.
- The wallet page source on this head renders `NearWalletPanel`, then `RecoveryCodePanel`, then `RecoveryLifecyclePanel` (steps 01/02/03). This confirms source order, not a successful interactive preview test.
- Production Supabase remains unchanged: migration history still ends at `20261101150802`; all three recovery migrations remain unapplied; `near-transfer-authorization` remains deployed at version 9 with JWT verification enabled.
- Current Security Advisor still reports the two private-schema RLS/no-policy INFO findings and leaked-password-protection WARN. The private tables are intentionally deny-all for API roles; do not add public/authenticated policies. Leaked-password protection is not enabled because it is unavailable within the project's no-spend constraint. Record this as an accepted pre-launch limitation requiring a documented owner decision; do not represent the advisor as clean.
- No independent read-only NEAR Testnet access-key response for `securewithmandate.testnet` has yet been captured in this review. The external Testnet wallet registration/recovery lifecycle remains unverified. No on-chain key has been deleted and no funds have been moved.

**Revised Stage One decision:** not certified complete. Code and CI evidence are stronger and current on head `aba14e8d`, and a matching Vercel Preview is READY. Remaining gates are Vercel-authorized page-level preview testing, a read-only NEAR Testnet access-key baseline and approved wallet lifecycle exercise, and an explicit documented risk acceptance for the disabled leaked-password check before any public launch. Production stays untouched until separately authorized.


## Live production verification update — 2026-11-02

**This section supersedes earlier statements above that production migrations were unapplied and the Edge Function remained at version 9. Those statements were a pre-deployment snapshot and are no longer current.**

- The three recovery migrations are now applied to the production Supabase project, and `near-transfer-authorization` is deployed at active version 11 with JWT verification enabled.
- **Live same-wallet replacement rejection passed:** the browser sent `recovery_start_challenge` using the currently active `securewithmandate.testnet` wallet as its own replacement. The Edge Function rejected it with: `The replacement wallet must be different from your currently active wallet.`
- **Post-rejection lifecycle verification passed:** `code_established=true`, `code_consumed=false`, `has_wallet_history=true`, active wallet `securewithmandate.testnet`; request ID, request status, replacement account, start time, and availability time were all null; seconds remaining was 0. No pending recovery or 24-hour freeze was created.
- **Live recovery database boundary audit passed:** all six `mandate_private.near_wallet_recovery_*` tables have RLS enabled; `anon` and `authenticated` have no SELECT privilege; `service_role` retains the required SELECT privilege. All 11 public recovery RPCs are SECURITY DEFINER with an explicit fixed search_path; EXECUTE is denied to `anon` and `authenticated` and granted to `service_role`.
- **Live single-sender integrity query passed:** one active wallet row exists; zero owners have multiple active wallets; zero active wallet account IDs are shared across different owners.
- No recovery was started, no 24-hour freeze was triggered, no funds were moved, and no NEAR on-chain access key was deleted.

**Next security gate:** exercise cross-owner replacement rejection at the live Edge Function boundary (the database integration suite already contains a synthetic cross-owner rejection test), then verify replacement-account FullAccess-key checks without signing or starting a recovery. The full 24-hour recovery lifecycle remains a separate controlled Testnet exercise and must not be initiated without explicit approval.
