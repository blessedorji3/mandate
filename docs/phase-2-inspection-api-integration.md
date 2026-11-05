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
- The blocklist lookup, queue, report submission/review, reviewer provisioning, and audit history are available only through service-role RPCs. Direct client and service-role table access is revoked.
- The web route uses a server-only Supabase service-role secret. Missing configuration produces unavailable evidence and WARN, never a clear result.

## Wallet-authorization boundary

The fixed Testnet wallet endpoint independently re-evaluates counterparty risk before creating a challenge, issuing a receipt after signature verification, and consuming the one-time receipt. The database challenge, finalization and consumption functions accept risk ALLOW, or a current one-time owner review bound to the exact WARN proposal. They independently reject BLOCK and any missing or stale risk evidence.

A WARN can reveal only the dedicated Agent Chat owner-review step for the exact supported Testnet proposal. Until that acknowledgement is signed and recorded, the transfer action remains locked. The acknowledgement does not change WARN to ALLOW or approve the transaction; the ordinary transfer signature and explicit wallet confirmation remain separate. The Developer API exposes WARN as REQUIRE_APPROVAL and does not provide a generic execution path.

## Deployment status

**Historical note:** the original bullets in this section described the pre-deployment review state and were superseded by the controlled Testnet rollout on 2026-11-05. They are retained here as design history only.

**Verified state as of 2026-11-05:**

- The five Phase 2 migrations are applied to hosted Supabase. Their repository filenames have been aligned to the exact version numbers in the hosted migration ledger.
- Hosted `near-transfer-authorization` is active at **v29** with `verify_jwt=true`.
- Phase 2 application and database CI passed on tested code revision `9667f340fb43ba21efa7bf5a97535342c57f5bb0`. The subsequent migration-filename-only commits require their own final CI confirmation before merge.
- The Vercel branch preview is READY at `https://mandate-git-feat-phase-2-counterparty-risk-web3pass.vercel.app`.
- The hosted database security boundary was checked read-only: the Phase 2 private tables have RLS enabled; client roles cannot read them; the Phase 2 security-definer RPCs use fixed search paths and are executable only by `service_role`.
- No Mainnet functionality is included. The actual Meteor Wallet browser acknowledgement remains unverified; synthetic integration tests are not a substitute for that live signer round trip.
- Contract historical code-change evidence remains unavailable, so contract counterparties remain WARN.

The Phase 2 rollout is a controlled NEAR Testnet demo, not a public-production certification. Do not enable Mainnet or describe the real Meteor signing path as verified until the browser acknowledgement is accepted and audited.

## Proposal-bound owner review for WARN

The fixed Testnet wallet flow supports a separate owner-signed acknowledgement for an eligible WARN result. It does not edit the risk evaluator's output:
- The acknowledgement is tied to the owner, proposal ID, target, policy ID/version, registered signing wallet, and a stable risk-evidence fingerprint.
- The owner signs the full warning context and bounded warning reasons in a NEP-413 message using a registered active Testnet wallet.
- The review challenge expires after 5 minutes (the deployed database TTL and Edge Function response are aligned); a completed review expires after 5 minutes and is consumed once when a transfer challenge is created.
- The exact wallet-signed review message is normalized to printable ASCII before challenge creation for Meteor Wallet compatibility. Dynamic warning reasons are sanitized, the final message is asserted ASCII-only, and the exact sanitized message is stored and verified without alteration.
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


## Shared blocklist reviewer governance and bootstrap

The shared blocklist is a reviewer-managed Testnet evidence source. Reporter submissions are not BLOCK signals; they remain pending until a different, actively provisioned reviewer confirms or rejects them.

- A project owner must bootstrap the first administrator once from the Supabase SQL Editor or another trusted database-admin connection. Replace the UUID below with the verified Auth user ID of the designated operator. Never expose this SQL in the client or an API.

```sql
insert into mandate_private.counterparty_blocklist_reviewer_roles
  (owner_id, role, is_active, granted_by, grant_reason)
select id, 'admin', true, null, 'Initial administrator provisioned by the project database owner'
from auth.users
where id = '<VERIFIED_AUTH_USER_UUID>'::uuid
on conflict (owner_id) do nothing;

insert into mandate_private.counterparty_blocklist_audit
  (actor_owner_id, subject_owner_id, action, reason, after_state)
select null, id, 'admin_bootstrapped',
       'Initial administrator provisioned by the project database owner',
       jsonb_build_object('owner_id', id, 'role', 'admin', 'is_active', true)
from auth.users
where id = '<VERIFIED_AUTH_USER_UUID>'::uuid
  and exists (
    select 1 from mandate_private.counterparty_blocklist_reviewer_roles r
    where r.owner_id = id and r.role = 'admin' and r.is_active
  )
  and not exists (
    select 1 from mandate_private.counterparty_blocklist_audit a
    where a.action = 'admin_bootstrapped' and a.subject_owner_id = id
  );
```

- After bootstrap, administrators grant and revoke reviewer assignments through `provision_counterparty_blocklist_reviewer_v1`; reviewers cannot grant roles, approve their own submissions, or mutate rows directly.
- The Edge Function authenticates the Supabase JWT and always passes the verified `user.id` as actor identity. The database RPC independently checks the active role assignment.
- Report submissions, confirmations, rejections, reviewer grants, and revocations append before/after snapshots to `mandate_private.counterparty_blocklist_audit`. Audit rows are protected by an append-only trigger and have no direct client/service-role mutation grants.
- Confirmations are non-overridable BLOCK evidence. Rejected reports remain retained in the private table and audit history but are not returned by the lookup.
- The review queue and audit history are available only through service-role RPCs after a verified JWT and role check. Admin roles are bootstrap-only; the API can provision reviewer roles, not new administrators.
- There is no first-admin identity hardcoded in migrations. The bootstrap SQL is a deliberate one-time manual operator step and must be completed before accepting or reviewing shared blocklist reports in a deployed environment.
