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
This change adds a pure evaluator, tests, private storage schema, and this design note. It does not yet wire RPC/indexer ingestion, reviewer workflow, API integration, or signer-side enforcement. It must not be advertised as active production protection until those are implemented and independently tested.


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
