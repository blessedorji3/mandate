# MANDATE

**Intelligence with boundaries.**

An independent authorization and security layer for autonomous AI financial agents.

MANDATE inspects proposed financial actions, evaluates them against owner-defined policies, and returns an allow, block, or require-approval decision before execution.

## Current status

- Deterministic authorization engine with fail-closed validation.
- Demo Attack Lab with simulated proposals.
- Authenticated NEAR Testnet wallet connection through the open-source NEAR Connect SDK.
- Policy-bound NEAR Testnet transfer authorization, explicit wallet confirmation, signing/broadcast, and final transaction verification through the dedicated `near-transfer-authorization` flow.
- Supabase Auth integration using the official `@supabase/ssr` cookie-based client.
- Protected dashboard and inspection API.
- Owner-scoped policy and decision tables protected by Postgres Row Level Security.
- Swaps and arbitrary contract calls remain blocked until action-specific validators exist.

This is an early prototype, not a production financial execution system.

## Local setup

1. Install dependencies with `npm install`.
2. Copy `.env.example` to `.env.local`.
3. Add the **MANDATE project's** Supabase URL and publishable key.
4. Run `npm run dev`.

Never put a Supabase secret/service-role key in a browser environment variable or commit credentials.

## Supabase Auth setup

In the MANDATE Supabase dashboard, open **Authentication → URL Configuration**:

- Set the Site URL to the deployed MANDATE domain.
- Add the exact redirect URL `https://mandate-web3pass.vercel.app/auth/callback`.
- For local development, add `http://localhost:3000/auth/callback`.

Email confirmation should remain enabled. Configure the sender/SMTP only if a suitable free option is available; do not assume Supabase's default test email service is suitable for public production signups.

## Security boundaries

- Use only the separate MANDATE Supabase project.
- Public/publishable key is intended for client use; database access is constrained by RLS.
- No service-role key is required by the current application.
- Policy and history rows are scoped to `auth.uid()`.
- Authorization history is not directly insertable from the authenticated browser role.
- The authenticated dashboard inspection route loads the owner's active saved policy. The external Developer API independently loads that same owner's active policy.

## CI

GitHub Actions runs authorization tests, TypeScript type-checking, and a production build on pushes and pull requests to `main`.


## Agent Developer API

The Supabase Edge Function `agent-inspect` is the external agent endpoint:

`https://abyyyehfivahedvjrcwj.supabase.co/functions/v1/agent-inspect`

Create an API key in the authenticated dashboard under **Developer API**. The raw key is displayed once. Only its SHA-256 hash and short prefix are stored in the database. Keys can be revoked at any time.

Send requests from a trusted agent backend (not browser code):

```ts
const response = await fetch(
  "https://abyyyehfivahedvjrcwj.supabase.co/functions/v1/agent-inspect",
  {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.MANDATE_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      proposal: {
        id: "proposal-001",
        agentId: "my-agent",
        actionType: "transfer",
        asset: "NEAR",
        amountAtomic: "200000000000000000000000",
        target: "alice.near"
      }
    })
  }
);
const result = await response.json();
```

The endpoint resolves the API key to its owner, applies a per-key limit of 60 requests per minute, loads that owner's active policy, applies deterministic fail-closed checks, and persists a decision receipt. Responses are `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`. An `ALLOW` is not a signature or transaction execution authorization; no wallet is connected and this endpoint never moves funds.

Supported inspection is currently limited to transfers and token approvals. Swaps and arbitrary contract calls are blocked as unsupported until their semantics can be decoded and verified.

**Security:** The Edge Function uses Supabase's server-only secret key internally. It is never sent to the browser or committed to this repository. API keys are not user passwords; store them in a trusted backend secret manager and revoke them if exposed. The Developer API currently enforces a per-key limit of 60 requests per minute. This is a prototype limit, not a complete production abuse-prevention system. There is no transaction execution.


## Agent chat prototype

The authenticated `/wallet` workspace connects a NEAR Testnet wallet using `@hot-labs/near-connect` (NEAR Connect). It requests testnet-capable wallets, does not collect private keys or recovery phrases, and reads the connected public account ID. The separate transfer flow performs policy-bound authorization and, after explicit owner confirmation in the wallet, signs and broadcasts the approved Testnet transfer. The wallet remains responsible for holding keys and approving the transaction.

The authenticated `/agent` workspace provides a constrained natural-language command interface. The current parser supports only commands in this format:

`Send 0.001 NEAR to confirmwithmandate.testnet`

It converts the amount into NEAR atomic units and submits the structured proposal to the authenticated `/api/inspect` route, which loads the signed-in owner's active policy and stores a decision receipt. Unsupported or ambiguous commands are not guessed. This first interface uses a deterministic command parser, not an LLM. The separate `/wallet` page connects a NEAR Testnet wallet and reads its public account ID. Wallet connection alone does not sign, broadcast, or move funds; the dedicated transfer journey handles those steps only after policy checks and explicit wallet confirmation.

The dashboard links to the chat workspace. The external Developer API remains intended for trusted server-side agent integrations and must not be called with a secret key from browser code.


## NEAR Testnet wallet connection

The authenticated `/wallet` page uses `@hot-labs/near-connect` configured for **NEAR Testnet only**. It lets the user select a compatible wallet, connects without requesting a transaction, reads the public account ID, and supports disconnecting. Wallet keys and recovery phrases remain inside the wallet; MANDATE does not request or store them.

**Current boundary:** the wallet connection screen itself is connection-only. The separate Testnet transfer journey binds the authorization to the exact network, signer, receiver, transfer action, and amount; checks the active policy; requires explicit owner confirmation in the wallet; and verifies the resulting finalized transaction before recording success. The execution path is Testnet-only and is not a mainnet payment system.


## First successful NEAR Testnet payment proof

The project operator reported a successful end-to-end Testnet transfer with the following details:

- **Network:** NEAR Testnet
- **Amount:** 0.001 NEAR
- **Recipient:** `confirmwithmandate.testnet`
- **Transaction hash:** `3J2DLMZ2mWq3W8aBfCz5NzGdxkjDU5GD3ut5H6wzfkw1`

This is the first recorded successful MANDATE transfer milestone. The transaction hash is retained as the reference for the demo; it is not a mainnet payment or evidence of production financial readiness.
