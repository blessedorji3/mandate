# MANDATE counterparty risk model

## Outcomes
- **ALLOW** means mandatory signals were verified and fresh with no adverse indicators. It is a risk result only, never transaction authorization.
- **WARN** means a signal is missing, stale, unverified or concerning. Pause for owner approval; never execute automatically.
- **BLOCK** means reviewed confirmed blocklist evidence or a hard policy rule rejects the action. Do not invoke a signer.

## Evidence sources and limits
- Current account/contract state and code hash: NEAR JSON-RPC `query` methods for account and contract state on the selected network.
- Account age, recent activity, and historical contract code changes require indexed historical chain data (e.g. NEAR Lake); current RPC state alone cannot prove history.
- Previous MANDATE interactions come from MANDATE authorization decision receipts and do not represent all chain activity.
- Shared blocklist records live in `mandate_private.counterparty_blocklist`. New reports are pending; only a reviewer-attributed, timestamped, evidence-backed confirmation can become BLOCK.

## Fail-closed requirements
1. RPC/indexer failures, malformed data, stale evidence, and missing policy are never ALLOW.
2. Pending/rejected reports never BLOCK.
3. Agent instructions and prompt text cannot alter risk results, policy, evidence, or signer behavior.
4. BLOCK stops before signer invocation; WARN pauses for authenticated owner approval.
5. Risk evaluation never signs or broadcasts.

## Integration status
This branch now contains a pure evaluator, current-state and indexed-history collectors, a server-side evidence orchestrator, a private blocklist schema and lookup RPC, tests, and an `agent-inspect` integration. These changes are still under PR review and are not deployed to production. Historical contract-code-change evidence and the reviewer workflow/UI are not implemented. The endpoint maps risk `WARN` to the existing database-compatible `REQUIRE_APPROVAL` result; this is a decision response, not proof that the wallet signer independently enforces owner approval. Do not advertise this as active production protection until the migration, endpoint, and signer-side enforcement are deployed and independently tested.


## Read-only NEAR Testnet collector

`src/security/near-counterparty-evidence.ts` currently performs only:
- JSON-RPC `status`, requiring the returned chain ID to be exactly `testnet`.
- JSON-RPC `query/view_account` at finality `final`, to inspect current account state and code hash.

It never calls transaction submission methods and never requests wallet credentials. The collector returns `PARTIAL` when current state is available and explicitly marks account age, recent activity, prior MANDATE interactions, and contract code-change history as unavailable. RPC/network failures return `UNAVAILABLE`. Neither result is sufficient for ALLOW; the risk evaluator must remain WARN until the required historical and receipt evidence is integrated.

The collector uses a fixed Testnet RPC endpoint and an eight-second abort timeout. It is not yet called by `agent-inspect`, has no Mainnet mode, and is not a production control.


## Read-only NEAR Testnet historical evidence

`src/security/near-counterparty-history.ts` queries FastNear's public Testnet indexed history:
- `POST /v0/account` in ascending and descending order to retrieve the earliest and newest indexed transactions.
- `POST /v0/transactions` to inspect the earliest transaction's actions and receiver.

Recent activity is calculated from the newest indexed transaction timestamp. The collector reports the earliest indexed activity separately. It marks account age as verified only if the earliest indexed transaction explicitly contains `CreateAccount` and its receiver is the account being evaluated. Otherwise account age remains unavailable. Indexer failures, malformed data and unprovable creation events never become an ALLOW signal.

This collector is read-only, uses an eight-second request timeout, rejects redirects, validates account IDs and history rows, and does not invoke wallet or transaction-submission methods. It is a data-source integration only; it is not yet wired into `agent-inspect` or the wallet execution path.


The history collector accepts an optional FastNear bearer API key as a server-supplied argument. If the provider requires authentication and no key is configured, the collector returns `UNAVAILABLE`; it does not attempt to bypass authentication. Do not place a provider key in browser code or commit it to the repository. Account IDs shorter than NEAR's two-character minimum or longer than 64 characters are rejected before network access.


## Server-side integration (PR branch only)

`agent-inspect` now calls the risk service after loading the owner's policy. It queries prior authorization receipts for the destination and calls a service-role-only RPC to read the private shared blocklist. RPC/indexer/database failures become unavailable evidence. A reviewed confirmed blocklist entry forces `BLOCK`; a pending report or incomplete evidence produces `WARN`. The endpoint maps `WARN` to `REQUIRE_APPROVAL` because the existing `authorization_decisions.outcome` constraint supports only `ALLOW`, `BLOCK`, and `REQUIRE_APPROVAL`. The full risk decision and evidence summary are returned and stored with the authorization receipt.

The blocklist migration and lookup RPC are committed on this branch only. The connected Supabase production project has not applied this migration; its current database does not yet contain `mandate_private.counterparty_blocklist`. Therefore deploying the updated Edge Function before applying and verifying the migration would cause blocklist lookup to fail and requests to require owner approval (fail-closed). No production migration or Edge Function deployment has been performed.

The current contract-code-change signal remains unavailable. Contract counterparties therefore remain `WARN` until historical code-change ingestion is implemented. The owner approval response also still needs end-to-end signer-path enforcement; this endpoint alone cannot guarantee that an agent obeys the pause.
