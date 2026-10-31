# MANDATE — Product Brief

## Product statement
MANDATE is an independent authorization and security layer for autonomous AI financial agents. It checks whether a proposed action is permitted by the asset owner's policy before the action can reach a signing or execution system.

**Tagline:** Intelligence with boundaries.

## Initial users
- AI agent developers who need a reusable authorization API.
- Crypto and fintech businesses deploying agents that can move assets or interact with protocols.
- Advanced users who want understandable controls over their agents.

The initial go-to-market focus is developers and businesses.

## Core journey
1. A user creates a policy in plain language or with structured controls.
2. MANDATE produces a proposed structured policy.
3. The owner reviews and confirms the exact policy.
4. An agent submits a structured action proposal.
5. MANDATE evaluates it against the active policy.
6. The engine returns ALLOW, BLOCK, or REQUIRE_APPROVAL.
7. The owner explicitly approves sensitive actions when required.
8. An approved action may pass to a supported execution adapter.
9. The decision and outcome appear in the audit history.

## MVP proof
- Create and confirm a policy.
- Submit a structured financial action.
- Allow a permitted action.
- Block an over-limit or unauthorized action.
- Require explicit human approval for configured sensitive actions.
- Record decision history.
- Run adversarial proposals through the same backend engine.
- Integrate one genuine NEAR testnet operation only after the authorization-to-execution boundary is proven.

## Attack Lab
Initial scenarios: permitted transfer, over-limit transfer, unapproved recipient, excessive token approval, disallowed action type, attempted policy override, malformed proposal, replayed or expired approval.

Attack Lab must show actual backend decisions, not frontend-only labels.

## Business model hypotheses
- Free developer tier with limited policy evaluations.
- Paid usage tiers for higher API volume and advanced controls.
- Business subscriptions for teams, monitoring, audit history, and approval workflows.
- Enterprise contracts for custom deployment and security requirements.

Pricing must be validated with prospective customers.

## Boundaries
- MANDATE is not a general-purpose wallet.
- It should be agent-framework and model agnostic.
- AI explanations and risk scores are advisory; deterministic policy enforcement is authoritative.
- No live funds or mainnet execution in the early MVP.
- Do not claim integrations, certifications, audits, or guarantees that have not been verified.
