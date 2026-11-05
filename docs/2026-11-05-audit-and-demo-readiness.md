# MANDATE audit and demo-readiness record

**Audit date:** 2026-11-05  
**Repository:** `blessedorji3/mandate`  
**Production/hosted Supabase project:** `abyyyehfivahedvjrcwj`  
**Demo scope:** NEAR Testnet only; no Mainnet assets.

## Executive finding

The project does not need a wholesale rebuild. The repeated Agent Chat failure is best explained by a specific NEP-413 interoperability regression in the Phase 2 owner-risk acknowledgement:

1. A prior Meteor Wallet compatibility fix made the recovery-reset message ASCII-only.
2. Phase 2 reintroduced a Unicode em dash and directly included dynamic risk-reason text in the message being signed.
3. The real `@hot-labs/near-connect` Meteor adapter drops `callbackUrl` before it calls Meteor Wallet, so the actual signer uses NEP-413 `callback_url=None`.
4. The previous positive integration test signed with an explicit page callback. It therefore tested a different wallet contract from the actual Meteor adapter.
5. The custom browser/network diagnostics then showed all three tested callback reconstructions failing for the real Meteor result. This was before the ASCII and Option::None test corrections.

The current fix sanitizes the complete challenge to printable ASCII, asserts that property before writing the challenge, and models Meteor's omitted callback in the integration test. The test suite now verifies the positive HTTP acknowledgement lifecycle and replay rejection.

**Important qualification:** CI and synthetic NEP-413 integration tests are green, but the actual Meteor Wallet browser round trip has not yet passed after the v29 correction. The final external wallet acknowledgement remains the decisive demo gate.

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
| PR #16 Phase 2 owner WARN review | Open, draft | Current Phase 2 integration under test |
| PR #5/#6/#11/#12 | Older drafts | Superseded by the merged multi-wallet release |
| PR #8 | Earlier risk foundation | Historical implementation; PR #16 carries the active integration |
| PR #9 | Open draft | Migration replay/history issue; the Phase 2 filename mismatch has now been corrected in the branch |
| PR #10 | Open draft | Earlier explicit callback URL recovery-reset experiment; it is not the current Meteor adapter contract |

The older PR and review documents contain historical snapshots. Do not treat statements in an old section as the current live deployment state when a later dated section supersedes them.

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

After those passes, the five SQL migration filenames were aligned to hosted version IDs and documentation was updated. A fresh workflow run on the new branch head is required before merging.

The Vercel preview is READY at:
`https://mandate-git-feat-phase-2-counterparty-risk-web3pass.vercel.app`

## Risk decision for the demo target

The current fixed target `confirmwithmandate.testnet` is reported as WARN because account-creation evidence could not be proven from the indexed historical transaction data. The blocklist lookup was clear and recent activity was available. This is an expected fail-closed risk outcome. It must not be changed to ALLOW just to make the demo proceed.

The owner acknowledgement is an intended stage in this design. A successful acknowledgement should record only that the owner reviewed this warning for this exact proposal. The separate transaction authorization and wallet confirmation remain in force.

## What remains before demo sign-off

1. Confirm GitHub application and database workflows pass on the newest branch head after migration-file alignment.
2. Open the READY preview and hard-refresh.
3. Generate a new inspected proposal; do not reuse earlier challenges.
4. Complete one fresh Meteor Wallet risk acknowledgement within five minutes.
5. Verify in the UI/logs that the acknowledgement is recorded for the exact proposal and that the transfer remains locked until normal wallet approval.
6. Do not send the 0.001 NEAR transfer during this acknowledgement check. A transaction test needs separate explicit authorization.

## Not approved

- Mainnet.
- Public-production launch.
- Treating an owner acknowledgement as transaction approval.
- Removing the fail-closed risk gate or weakening signature checks.
- Claiming the live Meteor browser signature is verified before the actual fresh browser test passes.

The Supabase leaked-password-protection advisor finding remains a documented pre-launch limitation under the project's no-spend constraint. It is not the cause of the current NEP-413 failure.
