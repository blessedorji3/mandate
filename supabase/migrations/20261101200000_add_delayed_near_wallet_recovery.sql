-- Delayed, independent-factor NEAR wallet recovery.
-- A recovery request freezes all financial authorization for 24 hours.
-- Replacement is finalized only after a second fresh NEP-413 proof from the new wallet.

create table if not exists mandate_private.near_wallet_recovery_requests (
  id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  new_account_id text not null check (new_account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'),
  new_public_key text not null check (new_public_key ~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'),
  status text not null default 'pending' check (status in ('pending','completed','cancelled')),
  started_at timestamptz not null default now(),
  available_at timestamptz not null default (now() + interval '24 hours'),
  completed_at timestamptz,
  cancelled_at timestamptz,
  constraint near_wallet_recovery_request_terminal_state check (
    (status = 'pending' and completed_at is null and cancelled_at is null)
    or (status = 'completed' and completed_at is not null and cancelled_at is null)
    or (status = 'cancelled' and cancelled_at is not null and completed_at is null)
  )
);

create unique index if not exists near_wallet_recovery_one_pending_per_owner_idx
  on mandate_private.near_wallet_recovery_requests(owner_id) where status = 'pending';
create index if not exists near_wallet_recovery_requests_owner_started_idx
  on mandate_private.near_wallet_recovery_requests(owner_id, started_at desc);

create table if not exists mandate_private.near_wallet_recovery_action_challenges (
  id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  request_id uuid not null,
  action text not null check (action in ('start','finalize')),
  account_id text not null check (account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'),
  public_key text not null check (public_key ~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'),
  nonce_hex text not null check (nonce_hex ~ '^[0-9a-f]{64}$'),
  message text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists near_wallet_recovery_action_challenges_owner_idx
  on mandate_private.near_wallet_recovery_action_challenges(owner_id, created_at desc);


create table if not exists mandate_private.near_wallet_recovery_events (
  id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  request_id uuid not null,
  event_type text not null check (event_type in ('started','cancelled','completed')),
  account_id text not null,
  created_at timestamptz not null default now()
);
create index if not exists near_wallet_recovery_events_owner_created_idx
  on mandate_private.near_wallet_recovery_events(owner_id,created_at desc);
alter table mandate_private.near_wallet_recovery_events enable row level security;
revoke all on mandate_private.near_wallet_recovery_events from public,anon,authenticated;
grant all on mandate_private.near_wallet_recovery_events to service_role;
grant usage,select on sequence mandate_private.near_wallet_recovery_events_id_seq to service_role;

create table if not exists mandate_private.near_wallet_recovery_code_attempts (
  id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  attempted_at timestamptz not null default now()
);
create index if not exists near_wallet_recovery_code_attempts_owner_time_idx
  on mandate_private.near_wallet_recovery_code_attempts(owner_id, attempted_at desc);

alter table mandate_private.near_wallet_recovery_requests enable row level security;
alter table mandate_private.near_wallet_recovery_action_challenges enable row level security;
alter table mandate_private.near_wallet_recovery_code_attempts enable row level security;
revoke all on mandate_private.near_wallet_recovery_requests from public, anon, authenticated;
revoke all on mandate_private.near_wallet_recovery_action_challenges from public, anon, authenticated;
revoke all on mandate_private.near_wallet_recovery_code_attempts from public, anon, authenticated;
grant all on mandate_private.near_wallet_recovery_requests to service_role;
grant all on mandate_private.near_wallet_recovery_action_challenges to service_role;
grant all on mandate_private.near_wallet_recovery_code_attempts to service_role;
grant usage, select on sequence mandate_private.near_wallet_recovery_code_attempts_id_seq to service_role;

create or replace function public.get_near_wallet_recovery_lifecycle_v1(p_owner_id uuid)
returns table (
  code_established boolean,
  code_consumed boolean,
  has_wallet_history boolean,
  active_wallet_account_id text,
  request_id uuid,
  request_status text,
  new_account_id text,
  started_at timestamptz,
  available_at timestamptz,
  seconds_remaining bigint
)
language sql security definer
set search_path = pg_catalog, public, mandate_private
as $$
  select
    exists(select 1 from mandate_private.near_wallet_recovery_credentials c where c.owner_id=p_owner_id),
    exists(select 1 from mandate_private.near_wallet_recovery_credentials c where c.owner_id=p_owner_id and c.consumed_at is not null),
    exists(select 1 from mandate_private.near_owner_wallets w where w.owner_id=p_owner_id),
    (select w.account_id from mandate_private.near_owner_wallets w where w.owner_id=p_owner_id and w.revoked_at is null order by w.verified_at desc limit 1),
    r.id, r.status, r.new_account_id, r.started_at, r.available_at,
    case when r.status='pending' then greatest(0,ceil(extract(epoch from (r.available_at-now())))::bigint) else 0 end
  from (select 1) seed
  left join lateral (
    select * from mandate_private.near_wallet_recovery_requests
    where owner_id=p_owner_id order by started_at desc limit 1
  ) r on true;
$$;

create or replace function public.create_near_wallet_recovery_action_challenge_v1(
 p_owner_id uuid,p_id uuid,p_request_id uuid,p_action text,
 p_account_id text,p_public_key text,p_nonce_hex text,p_message text
) returns uuid language plpgsql security definer
set search_path=pg_catalog,public,mandate_private as $$
declare
 v_request mandate_private.near_wallet_recovery_requests%rowtype;
 v_recent_count integer;
begin
 if p_owner_id is null or p_id is null or p_request_id is null
  or p_action not in ('start','finalize')
  or p_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
  or p_public_key !~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'
  or p_nonce_hex !~ '^[0-9a-f]{64}$' or length(p_message)>2048 then
  raise exception 'Invalid wallet recovery challenge';
 end if;
 perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text,0));
 select count(*) into v_recent_count from mandate_private.near_wallet_recovery_action_challenges
  where owner_id=p_owner_id and created_at>now()-interval '1 hour';
 if v_recent_count>=5 then raise exception 'Wallet recovery challenge rate limit exceeded'; end if;

 if p_action='start' then
  if not exists(select 1 from mandate_private.near_wallet_recovery_credentials
   where owner_id=p_owner_id and consumed_at is null) then
   raise exception 'An active independent MANDATE recovery code is required';
  end if;
  if not exists(select 1 from mandate_private.near_owner_wallets where owner_id=p_owner_id) then
   raise exception 'Wallet recovery is available only for accounts with wallet history';
  end if;
  if exists(select 1 from mandate_private.near_wallet_recovery_requests
   where owner_id=p_owner_id and status='pending') then
   raise exception 'A wallet recovery request is already pending';
  end if;
  if exists(select 1 from mandate_private.near_owner_wallets
   where account_id=p_account_id and revoked_at is null and owner_id<>p_owner_id) then
   raise exception 'The replacement NEAR wallet is already active under another MANDATE account';
  end if;
 else
  select * into v_request from mandate_private.near_wallet_recovery_requests
   where id=p_request_id and owner_id=p_owner_id and status='pending' for update;
  if not found or v_request.available_at>now() then
   raise exception 'Recovery is not ready for finalization';
  end if;
  if v_request.new_account_id<>p_account_id or v_request.new_public_key<>p_public_key then
   raise exception 'The finalization wallet does not match the pending recovery request';
  end if;
 end if;

 insert into mandate_private.near_wallet_recovery_action_challenges
  (id,owner_id,request_id,action,account_id,public_key,nonce_hex,message,expires_at)
 values(p_id,p_owner_id,p_request_id,p_action,p_account_id,p_public_key,p_nonce_hex,p_message,now()+interval '5 minutes');
 return p_id;
end;
$$;











-- Freeze policy authorization at the database boundary while recovery is pending.






-- Also guard the transaction-recording endpoint; recovery start invalidates existing receipts.












-- Freeze policy authorization at the database boundary while recovery is pending.






-- Also guard the transaction-recording endpoint; recovery start invalidates existing receipts.












-- Freeze policy authorization at the database boundary while recovery is pending.






-- Also guard the transaction-recording endpoint; recovery start invalidates existing receipts.

create or replace function public.get_near_wallet_recovery_action_challenge_v1(p_owner_id uuid,p_id uuid)
returns table(id uuid,request_id uuid,action text,account_id text,public_key text,nonce_hex text,message text,expires_at timestamptz)
language sql security definer
set search_path = pg_catalog, public, mandate_private
as $$
  select c.id,c.request_id,c.action,c.account_id,c.public_key,c.nonce_hex,c.message,c.expires_at
  from mandate_private.near_wallet_recovery_action_challenges c
  where c.id=p_id and c.owner_id=p_owner_id and c.consumed_at is null and c.expires_at>now()
  limit 1;
$$;









-- Freeze policy authorization at the database boundary while recovery is pending.
create or replace function public.create_near_transfer_challenge_v2(
 p_owner_id uuid,p_id uuid,p_nonce_hex text,p_message text,p_signer_account_id text,
 p_policy_id uuid,p_policy_version integer,p_proposal_id text,p_action_digest text
) returns uuid language plpgsql security definer
set search_path=pg_catalog,public,mandate_private as $$
declare v_policy public.security_policies%rowtype; v_recent_count integer;
begin
 if p_owner_id is null or p_nonce_hex !~ '^[0-9a-f]{64}$'
   or p_action_digest !~ '^[0-9a-f]{64}$' or length(p_message)>2048
   or p_signer_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
   or p_proposal_id !~ '^[a-zA-Z0-9_-]{1,128}$' then
   raise exception 'Invalid challenge data';
 end if;
 perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text,0));
 if exists(select 1 from mandate_private.near_wallet_recovery_requests
   where owner_id=p_owner_id and status='pending') then
   raise exception 'Financial authorizations are frozen while wallet recovery is pending';
 end if;
 if not exists(select 1 from mandate_private.near_owner_wallets
   where owner_id=p_owner_id and account_id=p_signer_account_id and revoked_at is null) then
   raise exception 'The signing wallet is not the active MANDATE sender wallet';
 end if;
 select count(*) into v_recent_count from mandate_private.near_transfer_challenges
  where owner_id=p_owner_id and created_at>now()-interval '5 minutes';
 if v_recent_count>=10 then raise exception 'Transfer challenge rate limit exceeded'; end if;
 if exists(select 1 from mandate_private.near_transfer_receipts
   where owner_id=p_owner_id and proposal_id=p_proposal_id) then
   raise exception 'This proposal already has a consumed authorization';
 end if;
 select * into v_policy from public.security_policies
  where id=p_policy_id and owner_id=p_owner_id and active=true limit 1;
 if not found or v_policy.version<>p_policy_version then raise exception 'Policy changed or inactive'; end if;
 if not ('transfer'=any(v_policy.allowed_action_types))
  or not ('confirmwithmandate.testnet'=any(v_policy.allowed_recipients))
  or v_policy.max_amount_atomic::numeric<1000000000000000000000::numeric then
  raise exception 'Current policy does not permit this transfer';
 end if;
 insert into mandate_private.near_transfer_challenges
  (id,owner_id,nonce_hex,message,signer_account_id,policy_id,policy_version,proposal_id,
   network,receiver_id,asset,amount_atomic,action_type,action_digest,expires_at)
 values(p_id,p_owner_id,p_nonce_hex,p_message,p_signer_account_id,p_policy_id,p_policy_version,
   p_proposal_id,'testnet','confirmwithmandate.testnet','NEAR',
   '1000000000000000000000','transfer',p_action_digest,now()+interval '3 minutes');
 return p_id;
end $$;

create or replace function public.finalize_near_transfer_challenge_v2(p_owner_id uuid,p_id uuid,p_token_hash text)
returns boolean language plpgsql security definer
set search_path=pg_catalog,public,mandate_private as $$
declare c mandate_private.near_transfer_challenges%rowtype;
begin
 if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$' then return false; end if;
 perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text,0));
 if exists(select 1 from mandate_private.near_wallet_recovery_requests
   where owner_id=p_owner_id and status='pending') then return false; end if;
 select * into c from mandate_private.near_transfer_challenges
  where id=p_id and owner_id=p_owner_id and consumed_at is null and expires_at>now() for update;
 if not found then return false; end if;
 if not exists(select 1 from mandate_private.near_owner_wallets
   where owner_id=p_owner_id and account_id=c.signer_account_id and revoked_at is null) then return false; end if;
 if not exists(select 1 from public.security_policies p where p.id=c.policy_id and p.owner_id=p_owner_id
   and p.active=true and p.version=c.policy_version and 'transfer'=any(p.allowed_action_types)
   and 'confirmwithmandate.testnet'=any(p.allowed_recipients)
   and p.max_amount_atomic::numeric>=1000000000000000000000::numeric) then return false; end if;
 update mandate_private.near_transfer_challenges set consumed_at=now() where id=c.id and consumed_at is null;
 if not found then return false; end if;
 insert into mandate_private.near_transfer_receipts
  (id,owner_id,token_hash,signer_account_id,policy_id,policy_version,proposal_id,network,
   receiver_id,asset,amount_atomic,action_type,action_digest,expires_at)
 values(gen_random_uuid(),p_owner_id,decode(p_token_hash,'hex'),c.signer_account_id,c.policy_id,
   c.policy_version,c.proposal_id,c.network,c.receiver_id,c.asset,c.amount_atomic,c.action_type,
   c.action_digest,least(c.expires_at,now()+interval '90 seconds'));
 return true;
end $$;

create or replace function public.consume_near_transfer_authorization_v2(
 p_owner_id uuid,p_token_hash text,p_signer_account_id text,p_network text,p_receiver_id text,
 p_asset text,p_amount_atomic text,p_action_type text,p_action_digest text
) returns boolean language plpgsql security definer
set search_path=pg_catalog,public,mandate_private as $$
declare r mandate_private.near_transfer_receipts%rowtype;
begin
 if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$'
  or p_action_digest !~ '^[0-9a-f]{64}$' then return false; end if;
 perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text,0));
 if exists(select 1 from mandate_private.near_wallet_recovery_requests
   where owner_id=p_owner_id and status='pending') then return false; end if;
 select * into r from mandate_private.near_transfer_receipts
  where owner_id=p_owner_id and token_hash=decode(p_token_hash,'hex')
   and consumed_at is null and expires_at>now() and signer_account_id=p_signer_account_id
   and network=p_network and receiver_id=p_receiver_id and asset=p_asset
   and amount_atomic=p_amount_atomic and action_type=p_action_type
   and action_digest=p_action_digest for update;
 if not found then return false; end if;
 if not exists(select 1 from mandate_private.near_owner_wallets w
   where w.owner_id=p_owner_id and w.account_id=p_signer_account_id and w.revoked_at is null)
  or not exists(select 1 from public.security_policies p where p.id=r.policy_id
   and p.owner_id=p_owner_id and p.active=true and p.version=r.policy_version
   and 'transfer'=any(p.allowed_action_types)
   and 'confirmwithmandate.testnet'=any(p.allowed_recipients)
   and p.max_amount_atomic::numeric>=1000000000000000000000::numeric) then return false; end if;
 update mandate_private.near_transfer_receipts set consumed_at=now()
  where id=r.id and owner_id=p_owner_id and consumed_at is null;
 return found;
end $$;

-- Also guard the transaction-recording endpoint; recovery start invalidates existing receipts.
create or replace function public.bind_near_transfer_transaction_v1(
 p_owner_id uuid,p_token_hash text,p_signer_account_id text,p_transaction_hash text,
 p_transaction_timestamp_ns text
) returns boolean language plpgsql security definer
set search_path=pg_catalog,public,mandate_private as $$
declare v_transaction_time timestamptz;
begin
 if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$'
  or p_signer_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
  or p_transaction_hash !~ '^[1-9A-HJ-NP-Za-km-z]{43,44}$'
  or p_transaction_timestamp_ns !~ '^[0-9]{1,30}$' then return false; end if;
 perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text,0));
 if exists(select 1 from mandate_private.near_wallet_recovery_requests
   where owner_id=p_owner_id and status='pending') then return false; end if;
 v_transaction_time:=to_timestamp((p_transaction_timestamp_ns::numeric/1000000000)::double precision);
 update mandate_private.near_transfer_receipts r
  set transaction_hash=p_transaction_hash,verified_at=now()
  where r.owner_id=p_owner_id and r.token_hash=decode(p_token_hash,'hex')
   and r.signer_account_id=p_signer_account_id and r.network='testnet'
   and r.receiver_id='confirmwithmandate.testnet' and r.asset='NEAR'
   and r.amount_atomic='1000000000000000000000' and r.action_type='transfer'
   and r.consumed_at is not null and r.consumed_at>now()-interval '10 minutes'
   and v_transaction_time>r.consumed_at and v_transaction_time<now()+interval '1 minute'
   and r.expires_at>r.consumed_at
   and (r.transaction_hash is null or r.transaction_hash=p_transaction_hash)
   and exists(select 1 from mandate_private.near_owner_wallets w
     where w.owner_id=p_owner_id and w.account_id=p_signer_account_id and w.revoked_at is null)
   and exists(select 1 from public.security_policies p where p.id=r.policy_id
     and p.owner_id=p_owner_id and p.active=true and p.version=r.policy_version
     and 'transfer'=any(p.allowed_action_types)
     and 'confirmwithmandate.testnet'=any(p.allowed_recipients)
     and p.max_amount_atomic::numeric>=1000000000000000000000::numeric);
 return found;
end $$;


-- Canonical final definitions for lifecycle operations (keep audit writes in the same transaction).
create or replace function public.start_near_wallet_recovery_v1(
 p_owner_id uuid,p_id uuid,p_code_hash_hex text
) returns boolean language plpgsql security definer
set search_path=pg_catalog,public,mandate_private as $$
declare
 c mandate_private.near_wallet_recovery_action_challenges%rowtype;
 v_code_hash bytea;
 v_attempts integer;
begin
 if p_owner_id is null or p_code_hash_hex !~ '^[0-9a-f]{64}$' then return false; end if;
 perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text,0));
 delete from mandate_private.near_wallet_recovery_code_attempts where attempted_at<now()-interval '24 hours';
 select count(*) into v_attempts from mandate_private.near_wallet_recovery_code_attempts
  where owner_id=p_owner_id and attempted_at>now()-interval '1 hour';
 if v_attempts>=5 then return false; end if;
 select code_hash into v_code_hash from mandate_private.near_wallet_recovery_credentials
  where owner_id=p_owner_id and consumed_at is null for update;
 insert into mandate_private.near_wallet_recovery_code_attempts(owner_id) values(p_owner_id);
 if v_code_hash is null or v_code_hash<>decode(p_code_hash_hex,'hex') then return false; end if;
 select * into c from mandate_private.near_wallet_recovery_action_challenges
  where id=p_id and owner_id=p_owner_id and action='start' and consumed_at is null and expires_at>now()
  for update;
 if not found then return false; end if;
 if exists(select 1 from mandate_private.near_wallet_recovery_requests where owner_id=p_owner_id and status='pending') then return false; end if;
 insert into mandate_private.near_wallet_recovery_requests(id,owner_id,new_account_id,new_public_key,status,started_at,available_at)
  values(c.request_id,p_owner_id,c.account_id,c.public_key,'pending',now(),now()+interval '24 hours');
 update mandate_private.near_wallet_recovery_action_challenges set consumed_at=now() where id=c.id;
 insert into mandate_private.near_wallet_recovery_events(owner_id,request_id,event_type,account_id)
  values(p_owner_id,c.request_id,'started',c.account_id);
 update mandate_private.near_transfer_challenges set consumed_at=now()
  where owner_id=p_owner_id and consumed_at is null;
 update mandate_private.near_transfer_receipts set consumed_at=now()
  where owner_id=p_owner_id and consumed_at is null;
 return true;
end $$;

create or replace function public.cancel_near_wallet_recovery_v1(
 p_owner_id uuid,p_request_id uuid,p_code_hash_hex text
) returns boolean language plpgsql security definer
set search_path=pg_catalog,public,mandate_private as $$
declare v_code_hash bytea; v_attempts integer;
begin
 if p_owner_id is null or p_code_hash_hex !~ '^[0-9a-f]{64}$' then return false; end if;
 perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text,0));
 select count(*) into v_attempts from mandate_private.near_wallet_recovery_code_attempts
  where owner_id=p_owner_id and attempted_at>now()-interval '1 hour';
 if v_attempts>=5 then return false; end if;
 select code_hash into v_code_hash from mandate_private.near_wallet_recovery_credentials
  where owner_id=p_owner_id and consumed_at is null for update;
 insert into mandate_private.near_wallet_recovery_code_attempts(owner_id) values(p_owner_id);
 if v_code_hash is null or v_code_hash<>decode(p_code_hash_hex,'hex') then return false; end if;
 update mandate_private.near_wallet_recovery_requests set status='cancelled',cancelled_at=now()
  where id=p_request_id and owner_id=p_owner_id and status='pending';
 if not found then return false; end if;
 insert into mandate_private.near_wallet_recovery_events(owner_id,request_id,event_type,account_id)
  select owner_id,id,'cancelled',new_account_id from mandate_private.near_wallet_recovery_requests
  where id=p_request_id and owner_id=p_owner_id;
 return true;
end $$;

create or replace function public.finalize_near_wallet_recovery_v1(
 p_owner_id uuid,p_id uuid,p_new_code_hash_hex text
) returns boolean language plpgsql security definer
set search_path=pg_catalog,public,mandate_private as $$
declare
 c mandate_private.near_wallet_recovery_action_challenges%rowtype;
 r mandate_private.near_wallet_recovery_requests%rowtype;
begin
 if p_owner_id is null or p_new_code_hash_hex !~ '^[0-9a-f]{64}$' then return false; end if;
 perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text,0));
 select * into c from mandate_private.near_wallet_recovery_action_challenges
  where id=p_id and owner_id=p_owner_id and action='finalize' and consumed_at is null and expires_at>now() for update;
 if not found then return false; end if;
 select * into r from mandate_private.near_wallet_recovery_requests
  where id=c.request_id and owner_id=p_owner_id and status='pending' for update;
 if not found or r.available_at>now() or r.new_account_id<>c.account_id or r.new_public_key<>c.public_key then return false; end if;
 if exists(select 1 from mandate_private.near_owner_wallets where account_id=r.new_account_id and revoked_at is null and owner_id<>p_owner_id) then
  raise exception 'Replacement NEAR wallet is now active under another MANDATE account';
 end if;
 update mandate_private.near_owner_wallets set revoked_at=now() where owner_id=p_owner_id and revoked_at is null;
 insert into mandate_private.near_owner_wallets(owner_id,account_id,public_key,verified_at,revoked_at)
  values(p_owner_id,r.new_account_id,r.new_public_key,now(),null)
  on conflict(owner_id,account_id) do update set public_key=excluded.public_key,verified_at=now(),revoked_at=null;
 update mandate_private.near_wallet_recovery_requests set status='completed',completed_at=now()
  where id=r.id and status='pending';
 insert into mandate_private.near_wallet_recovery_events(owner_id,request_id,event_type,account_id)
  values(p_owner_id,r.id,'completed',r.new_account_id);
 update mandate_private.near_wallet_recovery_action_challenges set consumed_at=now() where id=c.id and consumed_at is null;
 update mandate_private.near_wallet_recovery_credentials
  set code_hash=decode(p_new_code_hash_hex,'hex'),consumed_at=null,rotated_at=now()
  where owner_id=p_owner_id and consumed_at is null;
 if not found then raise exception 'Active recovery credential disappeared during finalization'; end if;
 update mandate_private.near_wallet_registration_challenges set consumed_at=now() where owner_id=p_owner_id and consumed_at is null;
 update mandate_private.near_transfer_challenges set consumed_at=now() where owner_id=p_owner_id and consumed_at is null;
 update mandate_private.near_transfer_receipts set consumed_at=now() where owner_id=p_owner_id and consumed_at is null;
 return true;
end $$;


revoke all on function public.get_near_wallet_recovery_lifecycle_v1(uuid) from public,anon,authenticated;
revoke all on function public.create_near_wallet_recovery_action_challenge_v1(uuid,uuid,uuid,text,text,text,text,text) from public,anon,authenticated;
revoke all on function public.get_near_wallet_recovery_action_challenge_v1(uuid,uuid) from public,anon,authenticated;
revoke all on function public.start_near_wallet_recovery_v1(uuid,uuid,text) from public,anon,authenticated;
revoke all on function public.cancel_near_wallet_recovery_v1(uuid,uuid,text) from public,anon,authenticated;
revoke all on function public.finalize_near_wallet_recovery_v1(uuid,uuid,text) from public,anon,authenticated;
grant execute on function public.get_near_wallet_recovery_lifecycle_v1(uuid) to service_role;
grant execute on function public.create_near_wallet_recovery_action_challenge_v1(uuid,uuid,uuid,text,text,text,text,text) to service_role;
grant execute on function public.get_near_wallet_recovery_action_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.start_near_wallet_recovery_v1(uuid,uuid,text) to service_role;
grant execute on function public.cancel_near_wallet_recovery_v1(uuid,uuid,text) to service_role;
grant execute on function public.finalize_near_wallet_recovery_v1(uuid,uuid,text) to service_role;
