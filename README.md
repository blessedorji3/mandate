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
