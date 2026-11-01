create schema if not exists mandate_private;
revoke all on schema mandate_private from public, anon, authenticated;

create table if not exists mandate_private.near_transfer_challenges (
  id uuid primary key,
  owner_id uuid not null,
  nonce_hex text not null unique check (nonce_hex ~ '^[0-9a-f]{64}$'),
  message text not null,
  signer_account_id text not null,
  policy_id uuid not null,
  policy_version integer not null,
  proposal_id text not null,
  network text not null check (network = 'testnet'),
  receiver_id text not null check (receiver_id = 'confirmwithmandate.testnet'),
  asset text not null check (asset = 'NEAR'),
  amount_atomic text not null check (amount_atomic = '1000000000000000000000'),
  action_type text not null check (action_type = 'transfer'),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists mandate_private.near_transfer_receipts (
  id uuid primary key,
  owner_id uuid not null,
  token_hash bytea not null unique,
  signer_account_id text not null,
  policy_id uuid not null,
  policy_version integer not null,
  proposal_id text not null,
  network text not null check (network = 'testnet'),
  receiver_id text not null check (receiver_id = 'confirmwithmandate.testnet'),
  asset text not null check (asset = 'NEAR'),
  amount_atomic text not null check (amount_atomic = '1000000000000000000000'),
  action_type text not null check (action_type = 'transfer'),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

alter table mandate_private.near_transfer_challenges enable row level security;
alter table mandate_private.near_transfer_receipts enable row level security;
revoke all on all tables in schema mandate_private from public, anon, authenticated;

create or replace function public.create_near_transfer_challenge(
  p_id uuid, p_nonce_hex text, p_message text, p_signer_account_id text,
  p_policy_id uuid, p_policy_version integer, p_proposal_id text
) returns uuid
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private, auth
as $$
declare v_policy public.security_policies%rowtype;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_nonce_hex !~ '^[0-9a-f]{64}$' or length(p_message) > 2048
     or p_signer_account_id !~ '^[a-z0-9._-]+\.testnet$'
     or p_proposal_id !~ '^[a-zA-Z0-9_-]{1,128}$' then
    raise exception 'Invalid challenge data';
  end if;
  select * into v_policy from public.security_policies
   where id = p_policy_id and owner_id = auth.uid() and active = true limit 1;
  if not found or v_policy.version <> p_policy_version then
    raise exception 'Policy changed or inactive';
  end if;
  if not ('transfer' = any(v_policy.allowed_action_types))
     or not ('confirmwithmandate.testnet' = any(v_policy.allowed_recipients))
     or v_policy.max_amount_atomic::numeric < 1000000000000000000000::numeric
     or v_policy.require_approval_for_all_actions then
    raise exception 'Current policy does not permit this transfer';
  end if;
  insert into mandate_private.near_transfer_challenges
    (id, owner_id, nonce_hex, message, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type, expires_at)
  values
    (p_id, auth.uid(), p_nonce_hex, p_message, p_signer_account_id, p_policy_id, p_policy_version,
     p_proposal_id, 'testnet', 'confirmwithmandate.testnet', 'NEAR',
     '1000000000000000000000', 'transfer', now() + interval '3 minutes');
  return p_id;
end;
$$;

create or replace function public.get_near_transfer_challenge(p_id uuid)
returns table(id uuid, nonce_hex text, message text, signer_account_id text, expires_at timestamptz)
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private, auth
as $$
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  return query select c.id, c.nonce_hex, c.message, c.signer_account_id, c.expires_at
    from mandate_private.near_transfer_challenges c
    where c.id = p_id and c.owner_id = auth.uid()
      and c.consumed_at is null and c.expires_at > now();
end;
$$;

create or replace function public.finalize_near_transfer_challenge(p_id uuid, p_token_hash text)
returns boolean
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private, auth
as $$
declare c mandate_private.near_transfer_challenges%rowtype;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_token_hash !~ '^[0-9a-f]{64}$' then raise exception 'Invalid receipt hash'; end if;
  select * into c from mandate_private.near_transfer_challenges
   where id = p_id and owner_id = auth.uid() and consumed_at is null
     and expires_at > now() for update;
  if not found then return false; end if;
  if not exists (select 1 from public.security_policies p
    where p.id = c.policy_id and p.owner_id = auth.uid() and p.active = true
      and p.version = c.policy_version and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric
      and p.require_approval_for_all_actions = false) then return false; end if;
  update mandate_private.near_transfer_challenges set consumed_at = now()
    where id = c.id and consumed_at is null;
  if not found then return false; end if;
  insert into mandate_private.near_transfer_receipts
    (id, owner_id, token_hash, signer_account_id, policy_id, policy_version, proposal_id,
     network, receiver_id, asset, amount_atomic, action_type, expires_at)
  values (gen_random_uuid(), auth.uid(), decode(p_token_hash, 'hex'), c.signer_account_id,
    c.policy_id, c.policy_version, c.proposal_id, c.network, c.receiver_id, c.asset,
    c.amount_atomic, c.action_type, least(c.expires_at, now() + interval '90 seconds'));
  return true;
end;
$$;

create or replace function public.consume_near_transfer_authorization(
  p_token_hash text, p_signer_account_id text, p_network text,
  p_receiver_id text, p_asset text, p_amount_atomic text, p_action_type text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private, auth
as $$
declare r mandate_private.near_transfer_receipts%rowtype;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_token_hash !~ '^[0-9a-f]{64}$' then return false; end if;
  select * into r from mandate_private.near_transfer_receipts
   where owner_id = auth.uid() and token_hash = decode(p_token_hash, 'hex')
     and consumed_at is null and expires_at > now()
     and signer_account_id = p_signer_account_id and network = p_network
     and receiver_id = p_receiver_id and asset = p_asset
     and amount_atomic = p_amount_atomic and action_type = p_action_type
   for update;
  if not found then return false; end if;
  if not exists (select 1 from public.security_policies p
    where p.id = r.policy_id and p.owner_id = auth.uid()
      and p.active = true and p.version = r.policy_version) then return false; end if;
  update mandate_private.near_transfer_receipts set consumed_at = now()
    where id = r.id and consumed_at is null;
  return found;
end;
$$;

revoke all on function public.create_near_transfer_challenge(uuid,text,text,text,uuid,integer,text) from public, anon, authenticated;
revoke all on function public.get_near_transfer_challenge(uuid) from public, anon, authenticated;
revoke all on function public.finalize_near_transfer_challenge(uuid,text) from public, anon, authenticated;
revoke all on function public.consume_near_transfer_authorization(text,text,text,text,text,text,text) from public, anon, authenticated;
