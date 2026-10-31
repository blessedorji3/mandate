# MANDATE

**Intelligence with boundaries.**

An independent authorization and security layer for autonomous AI financial agents.

MANDATE inspects proposed financial actions, evaluates them against owner-defined policies, and returns an allow, block, or require-approval decision before execution.

## Current status

- Deterministic authorization engine with fail-closed validation.
- Demo Attack Lab with simulated proposals; no wallet or funds are connected.
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
- The current inspection route uses a clearly labelled demo policy; it is not yet loading a user's saved policy.

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

The endpoint resolves the API key to its owner, loads that owner's active policy, applies deterministic fail-closed checks, and persists a decision receipt. Responses are `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`. An `ALLOW` is not a signature or transaction execution authorization; no wallet is connected and this endpoint never moves funds.

Supported inspection is currently limited to transfers and token approvals. Swaps and arbitrary contract calls are blocked as unsupported until their semantics can be decoded and verified.

**Security:** The Edge Function uses Supabase's server-only secret key internally. It is never sent to the browser or committed to this repository. API keys are not user passwords; store them in a trusted backend secret manager and revoke them if exposed. This prototype does not yet include production rate limiting, usage quotas, or transaction execution.
