# MANDATE audit and demo-readiness record

## Current release status — 2026-11-06, post-merge

**This status note supersedes earlier snapshots in this audit that describe PR #16 as open/draft, say the Phase 2 Meteor Wallet acknowledgement is still awaiting its first live browser test, or say a fresh PR workflow run is required before merging.** Those statements were true at earlier points in the investigation but are no longer current.

- PR #15 (multi-wallet ownership and recovery hardening) remains merged.
- PR #16 (Phase 2 counterparty-risk and proposal-bound owner WARN acknowledgement) was merged into `main` on 2026-11-06.
- The merged `main` commit is `d26d20ea6209be7e88f8561f7c13de3f5ce357c6`.
- The Phase 2 preview is READY for the tested PR head. The production Vercel build has been created from the merge commit; its final READY state and public demo alias still require confirmation.
- Hosted Supabase records 25 migrations, including the five Phase 2 migrations. The `near-transfer-authorization` Edge Function is ACTIVE at v29 with JWT verification enabled. All eight deployed function source files matched the PR #16 source files byte-for-byte before merge.
- The live Meteor Wallet proposal-bound WARN acknowledgement passed on the Phase 2 preview on 2026-11-06. The application displayed that the risk remained WARN and separate transaction approval was still required. No NEAR transfer was submitted during that verification.
- A fresh real-wallet recovery-code reset round trip remains a separate outstanding test. The WARN-acknowledgement test does not prove the recovery-reset journey.
- The merge has triggered fresh application and database workflows on `main`; these must complete successfully. Do not replay the hosted Phase 2 migrations or redeploy the already-matching Edge Function during release reconciliation.
- Scope remains a controlled NEAR Testnet demo. Mainnet and public-production financial use are not approved.

**Audit date:** 2026-11-05; updated 2026-11-06  
**Repository:** `blessedorji3/mandate`  
**Production/hosted Supabase project:** `abyyyehfivahedvjrcwj`  
**Demo scope:** NEAR Testnet only; no Mainnet assets.

## Executive finding

The project does not need a wholesale rebuild. The evidence points to a real mismatch between the Meteor Wallet adapter contract and the integration test that had been used as proof:

1. A prior Meteor Wallet compatibility change made the recovery-reset challenge ASCII-only.
2. Phase 2 reintroduced a Unicode em dash and inserted dynamic risk-reason text into the signed message without normalization.
3. The exact `@hot-labs/near-connect` 0.11.4 Meteor adapter drops `callbackUrl` before it calls Meteor Wallet, so the real adapter signs NEP-413 `callback_url=None`.
4. The old positive Phase 2 integration test signed with an explicit page callback. It tested a different payload from the actual Meteor adapter and therefore gave false confidence about the browser path.
5. Hosted diagnostics from the failed Meteor attempt showed the signer account/key matched, with a 64-byte signature and 32-byte nonce, but page, origin and omitted-callback reconstruction all failed. This was before the ASCII and adapter-shaped Option::None corrections.

The current fix sanitizes dynamic warning text to printable ASCII, hard-checks the complete challenge before storing it, pins the audited adapter version, and models Meteor's omitted callback in the positive integration test. The test suite now verifies the positive HTTP acknowledgement lifecycle and replay rejection.

**Important cryptographic nuance:** NEP-413 supports UTF-8 strings. The saved `nep413_local_test.py` uses a freshly generated local Ed25519 key and verifies a Unicode message with callback `None`; it is an offline serialization regression test, not a test against Meteor Wallet. Therefore the em dash alone is not proven to be the sole cause. The confirmed gap was that tests did not match the actual Meteor adapter contract. The printable-ASCII safeguard restores the prior Meteor compatibility discipline, but only the next real Meteor browser signature can prove the external path is fixed.

**Historical qualification (superseded on 2026-11-06):** When this audit draft was first written, the Meteor Wallet browser round trip had not yet passed after the v29 correction. The subsequent successful browser verification is recorded in the current release-status note and the external wallet test section below.

## What was inspected

- Repository history, branch tree and migration set.
- PRs #1–#16 and their merge/draft state where available.
- README, architecture, product brief, security model, database-security note, Stage One review, Phase 2 risk audit and Phase 2 inspection/authorization document.
- App CI and database CI workflows, positive risk-review tests, adversarial review tests, Meteor reset diagnostic and recovery-signature tests.
- Hosted Supabase migration ledger, Edge Function deployment/version, RLS/table privileges and security-definer RPC grants.
- Hosted Edge Function request logs for the failed Meteor browser attempt.
- Public Meteor Wallet SDK and NEAR Connect Meteor adapter source contracts.

This is a source and infrastructure audit, not a full independent penetration test or production security certification.

## Confirmed release lineage

| Item | State | Meaning |
|---|---|---|
| PR #15 multi-wallet release | Merged 2026-11-04 | Current merged release baseline; controlled rollout recorded in Supabase |
| PR #16 Phase 2 owner WARN review | Merged 2026-11-06 | Phase 2 counterparty-risk integration and proposal-bound owner WARN acknowledgement are part of `main` |
| PR #2 Testnet transfer documentation | Open, non-draft | Separate documentation-only proof; not part of the Phase 2 release candidate |
| PR #5–#12 (excluding #2) | Closed, not merged | Superseded implementation and diagnostic branches; commits and discussions remain available for audit |

Specific supersessions: PR #5/#6/#7/#11/#12 were replaced by the merged multi-wallet/recovery release PR #15; PR #8 was the earlier risk foundation superseded by the PR #16 integration; PR #9's migration-history issue was corrected by aligning all five Phase 2 migration filenames to the hosted ledger and replaying the complete suite; PR #10's explicit-callback experiment was superseded by the verified Meteor adapter contract and Option::None test.

The older PR and review documents contain historical snapshots. Treat them as implementation history, not as the current open-PR list or deployed state.

## Wallet dependency version pin

- The application now pins `@hot-labs/near-connect` to exactly `0.11.4`, the version used during the audit. Its tagged Meteor adapter source explicitly calls `wallet.signMessage({ message, nonce, recipient, accountId, state })` and does not forward `callbackUrl`. The Phase 2 integration test mirrors that contract. This removes direct adapter-version drift; a committed npm lockfile is still a separate reproducibility improvement.

## Current wallet signing contract

The current Meteor adapter source omits the callback URL when invoking `MeteorWallet.signMessage`. MANDATE therefore sends the browser's page URL to the Edge Function for same-origin validation, but the exact Meteor signature must be verified against the NEP-413 optional callback `None` form.

The current implementation preserves these security checks:

- Authenticated owner identity comes from the validated Supabase JWT, not caller JSON.
- Challenge binds the exact proposal, target, policy ID/version, registered wallet key, nonce and risk fingerprint.
- Registered wallet must still be active and hold the expected NEAR Testnet FullAccess key.
- Callback URLs, when supplied, must be canonical HTTPS URLs on an allowlisted MANDATE origin.
- The server verifies the exact message, 32-byte nonce, recipient, public key and 64-byte signature.
- The server accepts only callback variants that independently pass cryptographic verification.
- Review challenge expires after five minutes and is single-use.
- WARN remains WARN; review is acknowledgement only and never substitutes for the ordinary transaction approval.
- BLOCK cannot be overridden by an owner review.

## Hosted Supabase verification

As of the audit:

- `near-transfer-authorization` is ACTIVE at **v29**.
- `verify_jwt=true`.
- The five Phase 2 migrations are present in the hosted migration ledger.
- Their branch filenames have been aligned to the exact version numbers recorded by hosted Supabase:
  - `20261105114849_phase2_create_counterparty_blocklist.sql`
  - `20261105114908_phase2_require_counterparty_risk_allow_for_wallet_authorization.sql`
  - `20261105114922_phase2_proposal_bound_owner_risk_review.sql`
  - `20261105114936_phase2_counterparty_blocklist_reviewer_workflow.sql`
  - `20261105201103_extend_counterparty_risk_review_challenge_ttl.sql`
- The Phase 2 private tables have RLS enabled and browser-role SELECT is denied.
- The Phase 2 review/transfer/reviewer RPCs inspected are SECURITY DEFINER with fixed search paths; EXECUTE is denied to `anon` and `authenticated` and granted to `service_role`.

The filename alignment changes repository metadata only. It does not rerun or mutate hosted schema.

## CI and preview

The exact tested code revision `9667f340fb43ba21efa7bf5a97535342c57f5bb0` passed:

- Application workflow: tests, type-check, dependency audit and build.
- Database workflow: type-check of Edge Functions, recovery and Meteor NEP-413 tests, HTTP authentication, signed NEAR transfer lifecycle, blocklist reviewer integration, positive Meteor Option::None risk-review acknowledgement, proposal-bound review security tests, adversarial recovery tests, migration replay and pgTAP.

After those passes, the five SQL migration filenames were aligned to hosted version IDs and documentation was updated. PR #16 was subsequently merged into `main` on 2026-11-06. Fresh application and database workflows on the final post-merge documentation commit both completed successfully; the Vercel production deployment for that commit reached READY and the `mandate-snowy.vercel.app` alias was confirmed on that deployment.

The Vercel preview is READY at:
`https://mandate-git-feat-phase-2-counterparty-risk-web3pass.vercel.app`

## Risk decision for the demo target

The current fixed target `confirmwithmandate.testnet` is reported as WARN because account-creation evidence could not be proven from the indexed historical transaction data. The blocklist lookup was clear and recent activity was available. This is an expected fail-closed risk outcome. It must not be changed to ALLOW just to make the demo proceed.

The owner acknowledgement is an intended stage in this design. A successful acknowledgement should record only that the owner reviewed this warning for this exact proposal. The separate transaction authorization and wallet confirmation remain in force.

## External wallet test and demo sign-off (updated 2026-11-06)

The final external Meteor Wallet acknowledgement round trip has now passed on the Phase 2 preview.

- The application CI workflow and full database integration workflow both passed on branch head `bb6d91d89a83b8491c9ab3df8296f4946d8762ca`.
- The maintainer connected the registered NEAR Testnet wallet, inspected a fresh proposal to `confirmwithmandate.testnet`, received the expected `WARN`, and completed the Meteor Wallet NEP-413 acknowledgement.
- The browser displayed: “Risk acknowledgement recorded for this proposal only. The underlying risk outcome remains WARN; transaction approval is still required separately.”
- The UI only displays that success state after the authorization endpoint returns `reviewed: true` and the response matches the exact proposal ID and risk-evidence fingerprint. This is stronger than merely observing that the wallet signature prompt closed.
- The separate 0.001 NEAR transfer-approval control became available after acknowledgement. It was intentionally not activated. No NEAR transaction was submitted or broadcast as part of this check.

The live demo can now demonstrate the end-to-end counterparty WARN acknowledgement using Meteor Wallet. The risk result remains WARN; acknowledgement is not transaction approval and cannot override BLOCK.

## Remaining demo boundary

- The successful test validates the proposal-bound owner acknowledgement only. The actual 0.001 NEAR transfer was deliberately not submitted during this validation and must not be described as tested in this browser session.
- Keep the demo on NEAR Testnet with the fixed 0.001 NEAR recipient `confirmwithmandate.testnet`.
- Do not merge any change that weakens the WARN/BLOCK gate, proposal binding, challenge expiry, one-time use, authenticated owner identity, or separate transaction approval.
- Mainnet and public-production launch remain out of scope. This source/integration audit and successful browser round trip are not an independent penetration test or production security certification.

## Not approved

- Mainnet.
- Public-production launch.
- Treating an owner acknowledgement as transaction approval.
- Removing the fail-closed risk gate or weakening signature checks.
- Claiming the real-wallet recovery-code reset journey is verified before that separate fresh browser test passes.

The Supabase leaked-password-protection advisor finding remains a documented pre-launch limitation under the project's no-spend constraint. It is not the cause of the current NEP-413 failure.

## PR and version cleanup performed during this audit

The following superseded implementation and diagnostic PRs are closed. Their branches, commits and discussions were not deleted: PR #5, #6, #7, #8, #9, #10, #11 and #12.

PR #15 remains the merged multi-wallet/recovery baseline. PR #16 was merged into `main` on 2026-11-06 and contains the Phase 2 counterparty-risk integration and proposal-bound WARN acknowledgement. PR #2 remains open as a separate Testnet-transfer documentation item and is not a dependency of the Phase 2 demo.


## Post-merge release reconciliation record — 2026-11-06

### GitHub

- PR #16 was marked ready for review and merged using expected head SHA `6dbd80efc14cbc5a44f9ebd3cd4ac8da988c6e30`.
- Merge commit: `d26d20ea6209be7e88f8561f7c13de3f5ce357c6`.
- The default branch `main` was read back and confirmed at that merge commit.
- The PR-head application workflow and database integration workflow both completed successfully before merge. A fresh pair of push-triggered workflows also started for the merge commit; their final outcomes must be checked separately.

### Supabase

- Hosted migration ledger: 25 migrations, including the five Phase 2 migrations.
- `near-transfer-authorization`: ACTIVE v29; `verify_jwt=true`.
- The deployed function's eight source files matched the corresponding PR #16 files exactly before merge.
- No migration replay or Edge Function redeployment was performed as part of this merge.

### Vercel

- The PR #16 preview was READY at commit `6dbd80efc14cbc5a44f9ebd3cd4ac8da988c6e30`.
- A production deployment was created from `main` merge commit `d26d20ea6209be7e88f8561f7c13de3f5ce357c6`.
- At the time this note was written, that production deployment was still BUILDING. The final deployment status and assignment of `mandate-snowy.vercel.app` must be confirmed before declaring all release surfaces reconciled.

### Remaining release gates

1. Confirm both post-merge GitHub workflows on `d26d20e` succeed.
2. Confirm the Vercel production deployment reaches READY and the intended public demo domain resolves to it.
3. Run a fresh real-wallet recovery-code reset separately, without initiating a recovery freeze or NEAR transfer.

No additional NEAR transaction is needed for these release checks.
