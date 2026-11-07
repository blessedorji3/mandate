-- Decision receipts are authorization evidence consumed by wallet transfer
-- RPCs. They must only be written by trusted server-side service-role code.
-- Owner-scoped RLS alone is not sufficient: a browser owner could otherwise
-- forge an ALLOW receipt and counterpartyRisk payload for their own account.
revoke insert on table public.authorization_decisions from anon, authenticated;

drop policy if exists "Users can insert their own authorization decisions"
  on public.authorization_decisions;
