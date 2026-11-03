-- Evidence-backed shared blocklist. Reports default to pending; only an
-- explicitly reviewed record may be used as a BLOCK signal.
create table if not exists mandate_private.counterparty_blocklist (
 id uuid primary key default gen_random_uuid(),
 network text not null check(network in ('testnet','mainnet')),
 account_id text not null check(account_id ~ '^[a-z0-9._-]{2,64}([.][a-z0-9._-]{2,64})*$'),
 status text not null default 'pending' check(status in ('pending','confirmed','rejected')),
 reason text not null check(length(trim(reason)) between 8 and 500),
 evidence_ref text not null check(length(trim(evidence_ref)) between 8 and 2048),
 evidence_sha256 text check(evidence_sha256 is null or evidence_sha256 ~ '^[0-9a-f]{64}$'),
 source_type text not null check(source_type in ('chain_tx','explorer','security_advisory','other')),
 reporter_owner_id uuid references auth.users(id) on delete set null,
 reviewer_owner_id uuid references auth.users(id) on delete set null,
 reviewed_at timestamptz,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 constraint counterparty_blocklist_review_state check(
  (status='confirmed' and reviewer_owner_id is not null and reviewed_at is not null) or status<>'confirmed'
 )
);
create index if not exists counterparty_blocklist_lookup_idx on mandate_private.counterparty_blocklist(network,account_id,status);
alter table mandate_private.counterparty_blocklist enable row level security;
revoke all on mandate_private.counterparty_blocklist from public,anon,authenticated;
grant select,insert,update on mandate_private.counterparty_blocklist to service_role;


-- Internal lookup is exposed only through a service-role-only RPC. The private
-- schema itself remains unavailable through the public Data API.
create or replace function public.lookup_counterparty_blocklist(
  p_network text,
  p_account_id text
)
returns table(
  status text,
  evidence_ref text,
  reason text,
  reviewed_at timestamptz,
  reviewer_owner_id uuid
)
language plpgsql
security definer
set search_path = pg_catalog, mandate_private
as $$
begin
  if p_network is null or p_network not in ('testnet', 'mainnet')
     or p_account_id is null
     or length(p_account_id) < 2
     or length(p_account_id) > 64
     or p_account_id !~ '^[a-z0-9._-]+$' then
    raise exception 'Invalid counterparty lookup';
  end if;

  return query
    select b.status, b.evidence_ref, b.reason, b.reviewed_at, b.reviewer_owner_id
    from mandate_private.counterparty_blocklist b
    where b.network = p_network
      and b.account_id = p_account_id
      and b.status = 'confirmed'
    order by b.reviewed_at desc
    limit 1;

  if found then return; end if;

  return query
    select b.status, b.evidence_ref, b.reason, b.reviewed_at, b.reviewer_owner_id
    from mandate_private.counterparty_blocklist b
    where b.network = p_network
      and b.account_id = p_account_id
      and b.status = 'pending'
    order by b.created_at desc
    limit 1;
end;
$$;

revoke all on function public.lookup_counterparty_blocklist(text, text) from public, anon, authenticated;
grant execute on function public.lookup_counterparty_blocklist(text, text) to service_role;


-- Bind final one-time consumption to the exact inspected proposal. This closes
-- the legacy path where a client could pair a valid receipt with another
-- proposal reference when asking the server to consume it.
create or replace function public.consume_near_transfer_authorization_v3(
  p_owner_id uuid,
  p_token_hash text,
  p_signer_account_id text,
  p_network text,
  p_receiver_id text,
  p_asset text,
  p_amount_atomic text,
  p_action_type text,
  p_action_digest text,
  p_proposal_id text
) returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare r mandate_private.near_transfer_receipts%rowtype;
begin
  if p_owner_id is null
     or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_action_digest !~ '^[0-9a-f]{64}$'
     or p_proposal_id is null
     or p_proposal_id !~ '^[a-zA-Z0-9_-]{1,128}$' then
    return false;
  end if;

  select * into r
  from mandate_private.near_transfer_receipts
  where owner_id = p_owner_id
    and token_hash = decode(p_token_hash, 'hex')
    and proposal_id = p_proposal_id
    and consumed_at is null
    and expires_at > now()
    and signer_account_id = p_signer_account_id
    and network = p_network
    and receiver_id = p_receiver_id
    and asset = p_asset
    and amount_atomic = p_amount_atomic
    and action_type = p_action_type
    and action_digest = p_action_digest
  for update;

  if not found then return false; end if;

  if not exists (
    select 1 from public.security_policies p
    where p.id = r.policy_id
      and p.owner_id = p_owner_id
      and p.active = true
      and p.version = r.policy_version
      and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric
      and p.require_approval_for_all_actions = false
  ) then return false; end if;

  update mandate_private.near_transfer_receipts
  set consumed_at = now()
  where id = r.id
    and owner_id = p_owner_id
    and proposal_id = p_proposal_id
    and consumed_at is null;
  return found;
end;
$$;

revoke all on function public.consume_near_transfer_authorization_v3(uuid,text,text,text,text,text,text,text,text,text) from public, anon, authenticated;
grant execute on function public.consume_near_transfer_authorization_v3(uuid,text,text,text,text,text,text,text,text,text) to service_role;
