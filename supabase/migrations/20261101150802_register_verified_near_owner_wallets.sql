-- Registered and verified NEAR Testnet wallets are bound to authenticated MANDATE owners.
-- Registration challenges are short-lived, owner-bound, one-time, and completed only
-- after the Edge Function verifies the NEP-413 signature and FullAccess key on-chain.

create table if not exists mandate_private.near_owner_wallets (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  account_id text not null unique check (account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'),
  public_key text not null check (public_key ~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'),
  verified_at timestamptz not null default now(),
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  unique(owner_id, account_id)
);
create index if not exists near_owner_wallets_owner_active_idx
  on mandate_private.near_owner_wallets(owner_id, account_id) where revoked_at is null;
create table if not exists mandate_private.near_wallet_registration_challenges (
  id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  account_id text not null check (account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'),
  nonce_hex text not null unique check (nonce_hex ~ '^[0-9a-f]{64}$'),
  message text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists near_wallet_registration_challenges_owner_created_idx
  on mandate_private.near_wallet_registration_challenges(owner_id, created_at desc);
alter table mandate_private.near_owner_wallets enable row level security;
alter table mandate_private.near_wallet_registration_challenges enable row level security;
revoke all on mandate_private.near_owner_wallets, mandate_private.near_wallet_registration_challenges from public, anon, authenticated;

create or replace function public.create_near_wallet_registration_challenge_v1(
 p_owner_id uuid,p_id uuid,p_account_id text,p_nonce_hex text,p_message text
) returns uuid language plpgsql security definer
set search_path=pg_catalog,public,mandate_private as $$
declare v_count integer;
begin
 if p_owner_id is null or p_id is null or p_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
   or p_nonce_hex !~ '^[0-9a-f]{64}$' or length(p_message)>2048 then
   raise exception 'Invalid wallet registration challenge'; end if;
 select count(*) into v_count from mandate_private.near_wallet_registration_challenges
  where owner_id=p_owner_id and created_at>now()-interval '5 minutes';
 if v_count>=5 then raise exception 'Wallet registration rate limit exceeded'; end if;
 if exists(select 1 from mandate_private.near_owner_wallets
  where account_id=p_account_id and revoked_at is null and owner_id<>p_owner_id) then
  raise exception 'This NEAR account is already registered to another MANDATE owner'; end if;
 insert into mandate_private.near_wallet_registration_challenges(id,owner_id,account_id,nonce_hex,message,expires_at)
 values(p_id,p_owner_id,p_account_id,p_nonce_hex,p_message,now()+interval '5 minutes');
 return p_id;
end $$;

create or replace function public.get_near_wallet_registration_challenge_v1(p_owner_id uuid,p_id uuid)
returns table(id uuid,account_id text,nonce_hex text,message text,expires_at timestamptz)
language sql security definer set search_path=pg_catalog,public,mandate_private as $$
 select c.id,c.account_id,c.nonce_hex,c.message,c.expires_at
 from mandate_private.near_wallet_registration_challenges c
 where c.id=p_id and c.owner_id=p_owner_id and c.consumed_at is null and c.expires_at>now()
$$;

create or replace function public.complete_near_wallet_registration_v1(p_owner_id uuid,p_id uuid,p_public_key text)
returns boolean language plpgsql security definer
set search_path=pg_catalog,public,mandate_private as $$
declare c mandate_private.near_wallet_registration_challenges%rowtype;
begin
 if p_owner_id is null or p_public_key !~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$' then return false; end if;
 select * into c from mandate_private.near_wallet_registration_challenges
  where id=p_id and owner_id=p_owner_id and consumed_at is null and expires_at>now() for update;
 if not found then return false; end if;
 update mandate_private.near_wallet_registration_challenges set consumed_at=now()
  where id=c.id and owner_id=p_owner_id and consumed_at is null;
 if not found then return false; end if;
 insert into mandate_private.near_owner_wallets(owner_id,account_id,public_key,verified_at,revoked_at)
 values(p_owner_id,c.account_id,p_public_key,now(),null)
 on conflict(owner_id,account_id) do update
 set public_key=excluded.public_key,verified_at=now(),revoked_at=null;
 return true;
exception when unique_violation then
 raise exception 'This NEAR account is already registered to another MANDATE owner';
end $$;

create or replace function public.get_near_owner_wallet_v1(p_owner_id uuid,p_account_id text)
returns table(account_id text,public_key text,verified_at timestamptz)
language sql security definer set search_path=pg_catalog,public,mandate_private as $$
 select w.account_id,w.public_key,w.verified_at from mandate_private.near_owner_wallets w
 where w.owner_id=p_owner_id and w.account_id=p_account_id and w.revoked_at is null limit 1
$$;

create or replace function public.create_near_transfer_challenge_v2(
 p_owner_id uuid,p_id uuid,p_nonce_hex text,p_message text,p_signer_account_id text,
 p_policy_id uuid,p_policy_version integer,p_proposal_id text,p_action_digest text
) returns uuid language plpgsql security definer
set search_path=pg_catalog,public,mandate_private as $$
declare v_policy public.security_policies%rowtype; v_recent_count integer;
begin
 if p_owner_id is null or p_nonce_hex !~ '^[0-9a-f]{64}$' or p_action_digest !~ '^[0-9a-f]{64}$'
  or length(p_message)>2048 or p_signer_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
  or p_proposal_id !~ '^[a-zA-Z0-9_-]{1,128}$' then raise exception 'Invalid challenge data'; end if;
 if not exists(select 1 from mandate_private.near_owner_wallets w
  where w.owner_id=p_owner_id and w.account_id=p_signer_account_id and w.revoked_at is null) then
  raise exception 'Register and verify this NEAR wallet for your MANDATE account before authorizing transfers'; end if;
 select count(*) into v_recent_count from mandate_private.near_transfer_challenges
  where owner_id=p_owner_id and created_at>now()-interval '5 minutes';
 if v_recent_count>=10 then raise exception 'Transfer challenge rate limit exceeded'; end if;
 if exists(select 1 from mandate_private.near_transfer_receipts r
  where r.owner_id=p_owner_id and r.proposal_id=p_proposal_id) then
  raise exception 'This proposal already has a consumed authorization. Inspect an new proposal before attempting another transfer'; end if;
 select * into v_policy from public.security_policies
  where id=p_policy_id and owner_id=p_owner_id and active=true limit 1;
 if not found or v_policy.version<>p_policy_version then raise exception 'Policy changed or inactive'; end if;
 if not ('transfer'=any(v_policy.allowed_action_types))
  or not ('confirmwithmandate.testnet'=any(v_policy.allowed_recipients))
  or v_policy.max_amount_atomic::numeric<1000000000000000000000::numeric then
  raise exception 'Current policy does not permit this transfer'; end if;
 insert into mandate_private.near_transfer_challenges
 (id,owner_id,nonce_hex,message,signer_account_id,policy_id,policy_version,proposal_id,
 network,receiver_id,asset,amount_atomic,action_type,action_digest,expires_at)
 values(p_id,p_owner_id,p_nonce_hex,p_message,p_signer_account_id,p_policy_id,p_policy_version,p_proposal_id,
 'testnet','confirmwithmandate.testnet','NEAR','1000000000000000000000','transfer',p_action_digest,now()+interval '3 minutes');
 return p_id;
end $$;

create or replace function public.consume_near_transfer_authorization_v2(
 p_owner_id uuid,p_token_hash text,p_signer_account_id text,p_network text,p_receiver_id text,
 p_asset text,p_amount_atomic text,p_action_type text,p_action_digest text
) returns boolean language plpgsql security definer
set search_path=pg_catalog,public,mandate_private as $$
declare r mandate_private.near_transfer_receipts%rowtype;
begin
 if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$' or p_action_digest !~ '^[0-9a-f]{64}$' then return false; end if;
 select * into r from mandate_private.near_transfer_receipts
 where owner_id=p_owner_id and token_hash=decode(p_token_hash,'hex') and consumed_at is null and expires_at>now()
 and signer_account_id=p_signer_account_id and network=p_network and receiver_id=p_receiver_id
 and asset=p_asset and amount_atomic=p_amount_atomic and action_type=p_action_type and action_digest=p_action_digest
 for update;
 if not found then return false; end if;
 if not exists(select 1 from mandate_private.near_owner_wallets w
  where w.owner_id=p_owner_id and w.account_id=p_signer_account_id and w.revoked_at is null)
  or not exists(select 1 from public.security_policies p where p.id=r.policy_id and p.owner_id=p_owner_id
  and p.active=true and p.version=r.policy_version and 'transfer'=any(p.allowed_action_types)
  and 'confirmwithmandate.testnet'=any(p.allowed_recipients)
  and p.max_amount_atomic::numeric>=1000000000000000000000::numeric) then return false; end if;
 update mandate_private.near_transfer_receipts set consumed_at=now()
  where id=r.id and owner_id=p_owner_id and consumed_at is null;
 return found;
end $$;

revoke all on function public.create_near_wallet_registration_challenge_v1(uuid,uuid,text,text,text) from public,anon,authenticated;
revoke all on function public.get_near_wallet_registration_challenge_v1(uuid,uuid) from public,anon,authenticated;
revoke all on function public.complete_near_wallet_registration_v1(uuid,uuid,text) from public,anon,authenticated;
revoke all on function public.get_near_owner_wallet_v1(uuid,text) from public,anon,authenticated;
revoke all on function public.create_near_transfer_challenge_v2(uuid,uuid,text,text,text,uuid,integer,text,text) from public,anon,authenticated;
revoke all on function public.consume_near_transfer_authorization_v2(uuid,text,text,text,text,text,text,text,text) from public,anon,authenticated;
grant execute on function public.create_near_wallet_registration_challenge_v1(uuid,uuid,text,text,text) to service_role;
grant execute on function public.get_near_wallet_registration_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.complete_near_wallet_registration_v1(uuid,uuid,text) to service_role;
grant execute on function public.get_near_owner_wallet_v1(uuid,text) to service_role;
grant execute on function public.create_near_transfer_challenge_v2(uuid,uuid,text,text,text,uuid,integer,text,text) to service_role;
grant execute on function public.consume_near_transfer_authorization_v2(uuid,text,text,text,text,text,text,text,text) to service_role;
