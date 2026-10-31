# Security Model and Invariants

## Objective
Prevent an autonomous agent from causing a financial action that is not authorized by the owner's active policy and any required human approval. This does not guarantee protocol safety or detect every exploit.

## Untrusted inputs
Agent prompts and outputs, transaction proposals, natural-language instructions, token metadata, protocol descriptions, external content, and AI-generated policy drafts are untrusted.

## Mandatory invariants
1. **No AI self-authorization.** An AI model cannot issue the authoritative allow decision.
2. **Fail closed.** Invalid, unsupported, missing, stale, or ambiguous data must not be allowed.
3. **Exact proposal binding.** Approval applies to one exact proposal, not a mutable description.
4. **Policy version binding.** A decision records the policy version used.
5. **No bypass path.** A blocked or approval-pending proposal cannot call signing or execution code.
6. **Server-side enforcement.** Frontend checks are UX only, not the security boundary.
7. **Least privilege.** Agents receive only required capabilities.
8. **No secret custody in MVP.** Never collect or store user seed phrases or private keys.
9. **Auditability.** Record proposal, policy version, outcome, and reason codes without secrets.
10. **Replay resistance.** Proposals and approvals require expiry and replay/idempotency controls before live execution.

## Decisions
- `ALLOW`: all required deterministic checks pass.
- `BLOCK`: a mandatory rule fails or the proposal is invalid/unsupported.
- `REQUIRE_APPROVAL`: the policy requires explicit owner confirmation.

Approval is not a policy bypass. Revalidate the exact proposal and active policy before execution.

## Separation of responsibilities
- AI interpretation: proposes policies/actions.
- Deterministic evaluator: decides whether structured actions are authorized.
- Human owner: confirms policies and approvals.
- Execution adapter: executes only an exact authorized proposal.

## Threat scenarios
Prompt injection, agent permission escalation, recipient substitution, amount substitution, excessive allowance, unsupported transaction, replayed approval, policy changes between proposal and execution, cross-user database access, API bypass, evaluator failure.

## Before mainnet
Authorization boundary, execution adapter, authentication, database access, replay protection, monitoring, and failure handling require security review and extensive tests. A hackathon demo is not a security audit.
