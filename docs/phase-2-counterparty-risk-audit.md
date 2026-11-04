# Phase 2 — PR #8 Counterparty Risk Audit

**Audited source:** `feat/hackathon-counterparty-risk` at `af47c402e812a9d5e45a8514f4e57af18bbe4156`  
**Implementation baseline:** `main` at `196856f2efa72dff32bd37e2c97a543f83adf44f`  
**Scope:** pure risk evaluator, read-only NEAR state/history collectors, and their server-side composition. No production Supabase, Edge Function, Vercel, wallet, or transaction changes are included.

## Summary

PR #8 contains useful design decisions: it keeps risk evaluation separate from the owner policy engine, treats incomplete history as a warning, uses finalized current account state, and refuses to infer account creation from first-observed activity. It is not safe to merge wholesale into the release baseline. Its shared implementation is placed in Deno Edge Function modules and then re-exported into the app test tree; its PR branch also carries recovery, migration and UI work unrelated to this phase.

The Phase 2 implementation ports the risk engine into framework-neutral TypeScript modules under `src/security`, with injected network access for deterministic tests.

## Findings and dispositions

1. **Reviewer attribution was not retained in the evaluator input.** The prior service downgraded a confirmed row when reviewer ID or timestamp was absent, but then discarded reviewer identity before the pure evaluator saw it. The new evaluator requires a valid reviewer UUID, review timestamp, evidence reference and reason before a confirmed record can produce BLOCK.
2. **Evidence scalar values were not bound to signal values.** A caller could supply an age/activity/interaction scalar that differed from its corresponding signal. The new evaluator requires matching values and the expected source for each signal name.
3. **Evidence source identity was weakly checked.** The new evaluator limits signal names and requires the source label associated with each known evidence class. This is an integrity check inside the pure engine, not a cryptographic attestation; the collector and server boundary remain trusted.
4. **The current-state RPC accepted overly broad code-hash strings.** The new collector requires the known empty-code hash or a Base58 value decoding to 32 bytes. It also validates the JSON-RPC version/request ID and the account amount, locked balance and storage usage fields.
5. **The history reader trusted too little of the provider envelope.** The new collector validates the account response count, row count, requested account ID, Base58 transaction hash, timestamp and block height; it verifies oldest/newest order before deriving activity measures.
6. **First activity could be confused with account age.** The prior code already avoided this inference; the new collector preserves that invariant and only reports account age when the exact oldest transaction detail matches the hash, names the target account as receiver, and contains a CreateAccount action.
7. **Contract-history evidence is not implemented.** The current-state RPC supplies a current code hash only. Historical code changes remain unavailable, so contracts remain WARN until a separate archival/history implementation exists.
8. **Owner scope was missing in the PR #8 API interaction lookup.** The queried authorization receipts were filtered by destination but not by the API key owner's ID. No database query was copied into this engine. A future server integration must scope this query by authenticated owner and target together.
9. **The old execution gate accepted a boolean as proof of owner approval.** The new risk gate has no approval bypass parameter. WARN pauses, BLOCK stops, and ALLOW proceeds only to the separate policy check.
10. **FastNear provider behavior was checked against current docs.** The Transactions API documents `POST /v0/account`, `desc` ordering, `limit`, and opaque `resume_token` pagination; `POST /v0/transactions` returns raw transaction data by hash. Public history reads often work without an API key, so the collector supports an optional server-side bearer key. It never puts a key in browser-visible code.

## Deliberate limits

- Testnet only; there is no Mainnet switch.
- The collectors are read-only and expose no wallet or transaction submission method.
- Account age is unknown unless the oldest indexed transaction proves CreateAccount.
- Contract code-change history is unavailable and contracts therefore remain WARN.
- MANDATE interaction counts and blocklist status must come from a trusted server-side lookup. These modules do not accept client-supplied proof.
- A risk ALLOW is not policy ALLOW and never authorizes signing or transaction submission.
- No live provider integration, hosted migration, Edge Function deployment or on-chain transfer is part of this commit.

## Validation approach

- Pure evaluator tests cover malformed inputs, source/value mismatch, stale/future evidence, age/activity thresholds, blocklist review attribution and contract-history gaps.
- Collector tests use injected fetch implementations and deterministic clocks. They verify account/network/hash/response validation, history ordering, proven account creation, timeout/failure behavior and that only read methods are called.
- Composition tests verify missing server evidence never becomes ALLOW.
- Risk-gate tests verify that WARN pauses, BLOCK stops, and ALLOW only moves to the policy check.
