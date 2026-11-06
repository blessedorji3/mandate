# Initial Architecture

> **Historical architecture baseline — 2026-10-31.** This describes the intended first architecture, not the final implemented topology. Current functionality and demo limitations are in `README.md`; current release/deployment facts are in `docs/2026-11-05-audit-and-demo-readiness.md`.

This is the intended architecture and will evolve as implementation and integration research establish feasibility.

## Trust boundary

The browser and agent are untrusted clients. The server-side authorization service is the decision point. An agent can propose an action but cannot set permissions or override the owner's active policy.

```text
Owner / Developer
      |
      v
MANDATE Web App ---- Policy setup and review
      |
      v
MANDATE API <------- Agent submits action proposal
      |
      v
Input validation
      |
      v
Deterministic policy engine <---- Confirmed policy
      |
      +---- BLOCK ----------------> Record decision; stop
      |
      +---- REQUIRE_APPROVAL -----> Owner approval workflow
      |                                  |
      |                                  v
      |                           Re-check proposal/policy
      |
      +---- ALLOW ----------------> Execution adapter
                                         |
                                         v
                                  NEAR testnet (target)
```

## Components

- **Web application:** policy setup, review, approvals, activity history, and Attack Lab.
- **API:** authenticated endpoints for policies, agents, proposals, decisions, approvals, and audit history.
- **Authorization engine:** deterministic TypeScript module with typed reason codes; no AI or network dependency.
- **Policy interpretation:** AI may draft a structured policy, but strict validation and explicit owner confirmation are required before activation.
- **Persistence:** Supabase is proposed for identity and records, subject to RLS and server-side authorization design.
- **Execution adapters:** receive only the exact proposal that passed authorization and any required approval.

## Request lifecycle

1. Authenticate the caller.
2. Verify agent ownership and policy association.
3. Load the active, confirmed policy version.
4. Validate and normalize the proposal.
5. Evaluate deterministic rules.
6. Persist proposal and decision.
7. If needed, create an approval bound to the exact proposal and policy version.
8. On approval, re-check that proposal and policy are unchanged and active.
9. Pass only the authorized action to an execution adapter.
10. Record execution outcome and transaction reference.

## Questions to resolve

- Exact schemas for transfers, swaps, token approvals, and contract calls.
- Authentication and agent credential lifecycle.
- Policy version invalidation and proposal expiry.
- Replay protection and idempotency.
- How approval is bound to the exact action.
- Appropriate NEAR signing and execution model.
- Feasibility and cost of confidential compute during the hackathon.

## Cost discipline

Begin locally with deterministic tests. Do not make paid models, paid RPC, or paid infrastructure a requirement for the core security engine. Verify current free-tier limits and NEAR testnet requirements before selecting dependencies.
