-- Phase 2 counterparty review evidence. Only reviewed, reviewer-attributed
-- confirmations can become BLOCK signals.
create schema if not exists mandate_private;

create table if not exists mandate_private.counterparty_blocklist (
  id uuid primary key default gen_random_uuid(),
  network text not null check (network in ('testnet', 'mainnet')),
  account_id text not null check (
    account_id ~ '^[a-z0-9]+([-_][a-z0-9]+)*(\.[a-z0-9]+([-_][a-z0-9]+)*)*$'
    and length(account_id) between 2 and 64
  ),
  status text not null default 'pending' check (status in ('pending', 'confirmed', 'rejected')),
  reason text not null check (length(trim(reason)) between 8 and 500),
  evidence_ref text not null check (length(trim(evidence_ref)) between 8 and 2048),
  evidence_sha256 text check (evidence_sha256 is null or evidence_sha256 ~ '^[0-9a-f]{64}$'),
  source_type text not null check (source_type in ('chain_tx', 'explorer', 'security_advisory', 'other')),
  reporter_owner_id uuid references auth.users(id) on delete set null,
  reviewer_owner_id uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint counterparty_blocklist_review_state check (
    (status = 'confirmed' and reviewer_owner_id is not null and reviewed_at is not null)
    or status <> 'confirmed'
  )
);

create index if not exists counterparty_blocklist_lookup_idx
  on mandate_private.counterparty_blocklist(network, account_id, status);

alter table mandate_private.counterparty_blocklist enable row level security;
revoke all on mandate_private.counterparty_blocklist from public, anon, authenticated;
grant select, insert, update on mandate_private.counterparty_blocklist to service_role;

create or replace function public.lookup_counterparty_blocklist(
  p_network text,
  p_account_id text
)
returns table (status text, evidence_ref text, reason text, reviewed_at timestamptz, reviewer_owner_id uuid)
language plpgsql
security definer
set search_path = pg_catalog, mandate_private
as $$
begin
  if p_network is null or p_network not in ('testnet', 'mainnet')
     or p_account_id is null or length(p_account_id) < 2
     or length(p_account_id) > 64 or p_account_id !~ '^[a-z0-9._-]+$' then
    raise exception 'Invalid counterparty lookup';
  end if;

  return query
    select b.status, b.evidence_ref, b.reason, b.reviewed_at, b.reviewer_owner_id
    from mandate_private.counterparty_blocklist b
    where b.network = p_network and b.account_id = p_account_id and b.status = 'confirmed'
    order by b.reviewed_at desc limit 1;
  if found then return; end if;

  return query
    select b.status, b.evidence_ref, b.reason, b.reviewed_at, b.reviewer_owner_id
    from mandate_private.counterparty_blocklist b
    where b.network = p_network and b.account_id = p_account_id and b.status = 'pending'
    order by b.created_at desc limit 1;
end;
$$;

revoke all on function public.lookup_counterparty_blocklist(text, text) from public, anon, authenticated;
grant execute on function public.lookup_counterparty_blocklist(text, text) to service_role;
