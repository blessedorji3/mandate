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
