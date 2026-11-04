-- MANDATE multi-wallet ownership model.
-- Forward-only migration: preserve registered wallet history and global owner binding,
-- while allowing one authenticated MANDATE owner to link multiple NEAR Testnet wallets.

begin;

-- A MANDATE account may now have several active, independently verified wallets.
-- Keep the unique account_id constraint: a NEAR account remains bound to one MANDATE
-- owner, including after revocation, so it cannot be claimed by a different account.
drop index if exists mandate_private.near_owner_wallets_one_active_per_owner_idx;

create table if not exists mandate_private.near_wallet_events (
  id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  account_id text not null check (account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'),
  event_type text not null check (event_type in ('linked','relinked','revoked','recovered')),
  actor_account_id text check (
    actor_account_id is null or actor_account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'
  ),
  created_at timestamptz not null default now()
);
create index if not exists near_wallet_events_owner_created_idx
  on mandate_private.near_wallet_events(owner_id, created_at desc);
alter table mandate_private.near_wallet_events enable row level security;
revoke all on mandate_private.near_wallet_events from public, anon, authenticated;
grant all on mandate_private.near_wallet_events to service_role;
grant usage, select on sequence mandate_private.near_wallet_events_id_seq to service_role;

create table if not exists mandate_private.near_wallet_revocation_challenges (
  id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  target_account_id text not null check (target_account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'),
  signer_account_id text not null check (signer_account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'),
  signer_public_key text not null check (signer_public_key ~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'),
  nonce_hex text not null unique check (nonce_hex ~ '^[0-9a-f]{64}$'),
  message text not null check (length(message) between 1 and 2048),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  constraint near_wallet_revocation_challenge_distinct_wallets
    check (target_account_id <> signer_account_id)
);
create index if not exists near_wallet_revocation_challenges_owner_created_idx
  on mandate_private.near_wallet_revocation_challenges(owner_id, created_at desc);
alter table mandate_private.near_wallet_revocation_challenges enable row level security;
revoke all on mandate_private.near_wallet_revocation_challenges from public, anon, authenticated;
grant all on mandate_private.near_wallet_revocation_challenges to service_role;

-- Replace the former "no wallet history" rule with verified multi-wallet registration.
-- A wallet may be re-linked only to its original MANDATE owner; it can never migrate
-- to another owner account after it has been recorded.
create or replace function public.create_near_wallet_registration_challenge_v1(
  p_owner_id uuid, p_id uuid, p_account_id text, p_nonce_hex text, p_message text
) returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare
  v_count integer;
begin
  if p_owner_id is null or p_id is null
     or p_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
     or p_nonce_hex !~ '^[0-9a-f]{64}$'
     or length(p_message) not between 1 and 2048 then
    raise exception 'Invalid wallet registration challenge';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then
    raise exception 'Wallet registration is unavailable while 24-hour recovery is pending';
  end if;

  select count(*) into v_count
  from mandate_private.near_wallet_registration_challenges
  where owner_id = p_owner_id
    and created_at > now() - interval '5 minutes';
  if v_count >= 5 then
    raise exception 'Wallet registration rate limit exceeded';
  end if;

  if exists (
    select 1
    from mandate_private.near_owner_wallets
    where account_id = p_account_id
      and owner_id <> p_owner_id
  ) then
    raise exception 'This NEAR account is permanently associated with another MANDATE account';
  end if;

  insert into mandate_private.near_wallet_registration_challenges
    (id, owner_id, account_id, nonce_hex, message, expires_at)
  values
    (p_id, p_owner_id, p_account_id, p_nonce_hex, p_message, now() + interval '5 minutes');

  return p_id;
end;
$$;

create or replace function public.complete_near_wallet_registration_v1(
  p_owner_id uuid, p_id uuid, p_public_key text
) returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare
  c mandate_private.near_wallet_registration_challenges%rowtype;
  v_existing boolean;
begin
  if p_owner_id is null
     or p_public_key !~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$' then
    return false;
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then
    raise exception 'Wallet registration is unavailable while 24-hour recovery is pending';
  end if;

  select * into c
  from mandate_private.near_wallet_registration_challenges
  where id = p_id
    and owner_id = p_owner_id
    and consumed_at is null
    and expires_at > now()
  for update;

  if not found then
    return false;
  end if;

  if exists (
    select 1
    from mandate_private.near_owner_wallets
    where account_id = c.account_id
      and owner_id <> p_owner_id
  ) then
    raise exception 'This NEAR account is permanently associated with another MANDATE account';
  end if;

  select exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = c.account_id
  ) into v_existing;

  update mandate_private.near_wallet_registration_challenges
  set consumed_at = now()
  where id = c.id and owner_id = p_owner_id and consumed_at is null;
  if not found then
    return false;
  end if;

  insert into mandate_private.near_owner_wallets
    (owner_id, account_id, public_key, verified_at, revoked_at)
  values
    (p_owner_id, c.account_id, p_public_key, now(), null)
  on conflict (owner_id, account_id) do update
    set public_key = excluded.public_key,
        verified_at = now(),
        revoked_at = null;

  insert into mandate_private.near_wallet_events(owner_id, account_id, event_type)
  values (p_owner_id, c.account_id, case when v_existing then 'relinked' else 'linked' end);

  return true;
exception
  when unique_violation then
    raise exception 'This NEAR account is already associated with another MANDATE account';
end;
$$;

-- Return the complete owner-scoped wallet inventory, including revoked history.
create or replace function public.list_near_owner_wallets_v1(p_owner_id uuid)
returns table (
  account_id text,
  public_key text,
  verified_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz
)
language sql
security definer
set search_path = pg_catalog, public, mandate_private
as $$
  select w.account_id, w.public_key, w.verified_at, w.revoked_at, w.created_at
  from mandate_private.near_owner_wallets w
  where w.owner_id = p_owner_id
  order by (w.revoked_at is null) desc, w.verified_at desc, w.created_at desc;
$$;

-- A wallet can be removed from MANDATE only when a different active linked wallet
-- authorizes the revocation. The last active wallet must use the existing 24-hour
-- independent-factor recovery process instead.
create or replace function public.create_near_wallet_revoke_challenge_v1(
  p_owner_id uuid,
  p_id uuid,
  p_target_account_id text,
  p_signer_account_id text,
  p_signer_public_key text,
  p_nonce_hex text,
  p_message text
) returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare
  v_active_count integer;
  v_recent_count integer;
begin
  if p_owner_id is null or p_id is null
     or p_target_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
     or p_signer_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
     or p_target_account_id = p_signer_account_id
     or p_signer_public_key !~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'
     or p_nonce_hex !~ '^[0-9a-f]{64}$'
     or length(p_message) not between 1 and 2048 then
    raise exception 'Invalid wallet revocation challenge';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then
    raise exception 'Wallet changes are unavailable while 24-hour recovery is pending';
  end if;

  select count(*) into v_active_count
  from mandate_private.near_owner_wallets
  where owner_id = p_owner_id and revoked_at is null;
  if v_active_count < 2 then
    raise exception 'The last active MANDATE wallet can only be replaced through 24-hour recovery';
  end if;

  if not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id
      and account_id = p_target_account_id
      and revoked_at is null
  ) then
    raise exception 'The wallet selected for revocation is not active on this MANDATE account';
  end if;

  if not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id
      and account_id = p_signer_account_id
      and public_key = p_signer_public_key
      and revoked_at is null
  ) then
    raise exception 'The authorizing wallet is not an active verified wallet on this MANDATE account';
  end if;

  select count(*) into v_recent_count
  from mandate_private.near_wallet_revocation_challenges
  where owner_id = p_owner_id
    and created_at > now() - interval '5 minutes';
  if v_recent_count >= 5 then
    raise exception 'Wallet revocation rate limit exceeded';
  end if;

  insert into mandate_private.near_wallet_revocation_challenges
    (id, owner_id, target_account_id, signer_account_id, signer_public_key,
     nonce_hex, message, expires_at)
  values
    (p_id, p_owner_id, p_target_account_id, p_signer_account_id, p_signer_public_key,
     p_nonce_hex, p_message, now() + interval '5 minutes');

  return p_id;
end;
$$;

create or replace function public.get_near_wallet_revoke_challenge_v1(
  p_owner_id uuid, p_id uuid
)
returns table (
  id uuid,
  target_account_id text,
  signer_account_id text,
  signer_public_key text,
  nonce_hex text,
  message text,
  expires_at timestamptz
)
language sql
security definer
set search_path = pg_catalog, public, mandate_private
as $$
  select c.id, c.target_account_id, c.signer_account_id, c.signer_public_key,
         c.nonce_hex, c.message, c.expires_at
  from mandate_private.near_wallet_revocation_challenges c
  where c.owner_id = p_owner_id
    and c.id = p_id
    and c.consumed_at is null
    and c.expires_at > now()
  limit 1;
$$;

create or replace function public.complete_near_wallet_revoke_v1(
  p_owner_id uuid, p_id uuid
) returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare
  c mandate_private.near_wallet_revocation_challenges%rowtype;
  v_active_count integer;
begin
  if p_owner_id is null or p_id is null then
    return false;
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  select * into c
  from mandate_private.near_wallet_revocation_challenges
  where id = p_id
    and owner_id = p_owner_id
    and consumed_at is null
    and expires_at > now()
  for update;

  if not found then
    return false;
  end if;

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then
    return false;
  end if;

  select count(*) into v_active_count
  from mandate_private.near_owner_wallets
  where owner_id = p_owner_id and revoked_at is null;
  if v_active_count < 2 then
    return false;
  end if;

  if not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id
      and account_id = c.target_account_id
      and revoked_at is null
  ) or not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id
      and account_id = c.signer_account_id
      and public_key = c.signer_public_key
      and revoked_at is null
  ) then
    return false;
  end if;

  update mandate_private.near_wallet_revocation_challenges
  set consumed_at = now()
  where id = c.id and owner_id = p_owner_id and consumed_at is null;
  if not found then
    return false;
  end if;

  update mandate_private.near_owner_wallets
  set revoked_at = now()
  where owner_id = p_owner_id
    and account_id = c.target_account_id
    and revoked_at is null;
  if not found then
    return false;
  end if;

  -- A revoked signer can no longer consume any outstanding MANDATE transfer grant.
  update mandate_private.near_transfer_challenges
  set consumed_at = now()
  where owner_id = p_owner_id
    and signer_account_id = c.target_account_id
    and consumed_at is null;

  update mandate_private.near_transfer_receipts
  set consumed_at = now()
  where owner_id = p_owner_id
    and signer_account_id = c.target_account_id
    and consumed_at is null;

  insert into mandate_private.near_wallet_events
    (owner_id, account_id, event_type, actor_account_id)
  values (p_owner_id, c.target_account_id, 'revoked', c.signer_account_id);

  return true;
end;
$$;

-- Preserve the emergency full-account recovery flow, but do not permit a currently
-- linked wallet to be selected as its own replacement. A wallet reserved to another
-- owner remains unavailable even if that previous record was revoked.
create or replace function public.create_near_wallet_recovery_action_challenge_v1(
  p_owner_id uuid, p_id uuid, p_request_id uuid, p_action text,
  p_account_id text, p_public_key text, p_nonce_hex text, p_message text
) returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare
  v_request mandate_private.near_wallet_recovery_requests%rowtype;
  v_recent_count integer;
begin
  if p_owner_id is null or p_id is null or p_request_id is null
     or p_action not in ('start','finalize')
     or p_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
     or p_public_key !~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'
     or p_nonce_hex !~ '^[0-9a-f]{64}$'
     or length(p_message) not between 1 and 2048 then
    raise exception 'Invalid wallet recovery challenge';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  select count(*) into v_recent_count
  from mandate_private.near_wallet_recovery_action_challenges
  where owner_id = p_owner_id
    and created_at > now() - interval '1 hour';
  if v_recent_count >= 5 then
    raise exception 'Wallet recovery challenge rate limit exceeded';
  end if;

  if p_action = 'start' then
    if not exists (
      select 1 from mandate_private.near_wallet_recovery_credentials
      where owner_id = p_owner_id and consumed_at is null
    ) then
      raise exception 'An active independent MANDATE recovery code is required';
    end if;

    if not exists (
      select 1 from mandate_private.near_owner_wallets where owner_id = p_owner_id
    ) then
      raise exception 'Wallet recovery is available only for accounts with wallet history';
    end if;

    if exists (
      select 1 from mandate_private.near_wallet_recovery_requests
      where owner_id = p_owner_id and status = 'pending'
    ) then
      raise exception 'A wallet recovery request is already pending';
    end if;

    if exists (
      select 1 from mandate_private.near_owner_wallets
      where account_id = p_account_id and owner_id <> p_owner_id
    ) then
      raise exception 'The replacement NEAR wallet is already active under another MANDATE account';
    end if;

    if exists (
      select 1 from mandate_private.near_owner_wallets
      where owner_id = p_owner_id
        and account_id = p_account_id
        and revoked_at is null
    ) then
      raise exception 'Choose a new or previously revoked wallet, not a wallet already active on this MANDATE account';
    end if;
  else
    select * into v_request
    from mandate_private.near_wallet_recovery_requests
    where id = p_request_id
      and owner_id = p_owner_id
      and status = 'pending'
    for update;

    if not found or v_request.available_at > now() then
      raise exception 'Recovery is not ready for finalization';
    end if;

    if v_request.new_account_id <> p_account_id
       or v_request.new_public_key <> p_public_key then
      raise exception 'The finalization wallet does not match the pending recovery request';
    end if;
  end if;

  insert into mandate_private.near_wallet_recovery_action_challenges
    (id, owner_id, request_id, action, account_id, public_key, nonce_hex, message, expires_at)
  values
    (p_id, p_owner_id, p_request_id, p_action, p_account_id, p_public_key,
     p_nonce_hex, p_message, now() + interval '5 minutes');

  return p_id;
end;
$$;

-- A successful 24-hour recovery replaces the whole MANDATE wallet set.
-- Record the batch of revocations and the new replacement in the wallet event log.
create or replace function public.finalize_near_wallet_recovery_v1(
  p_owner_id uuid, p_id uuid, p_new_code_hash_hex text
) returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, mandate_private
as $fn$
declare
  c mandate_private.near_wallet_recovery_action_challenges%rowtype;
  r mandate_private.near_wallet_recovery_requests%rowtype;
begin
  if p_owner_id is null or p_new_code_hash_hex !~ '^[0-9a-f]{64}$' then
    return false;
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  select * into c
  from mandate_private.near_wallet_recovery_action_challenges
  where id = p_id and owner_id = p_owner_id
    and action = 'finalize' and consumed_at is null and expires_at > now()
  for update;
  if not found then
    return false;
  end if;

  select * into r
  from mandate_private.near_wallet_recovery_requests
  where id = c.request_id and owner_id = p_owner_id and status = 'pending'
  for update;
  if not found or r.available_at > now()
     or r.new_account_id <> c.account_id or r.new_public_key <> c.public_key then
    return false;
  end if;

  -- Preserve the lifetime owner binding, including revoked history.
  if exists (
    select 1 from mandate_private.near_owner_wallets
    where account_id = r.new_account_id and owner_id <> p_owner_id
  ) then
    raise exception 'Replacement NEAR wallet belongs to another MANDATE account';
  end if;

  if exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = r.new_account_id and revoked_at is null
  ) then
    raise exception 'Replacement NEAR wallet is already active on this MANDATE account';
  end if;

  insert into mandate_private.near_wallet_events(owner_id, account_id, event_type, actor_account_id)
  select p_owner_id, w.account_id, 'revoked', r.new_account_id
  from mandate_private.near_owner_wallets w
  where w.owner_id = p_owner_id and w.revoked_at is null;

  update mandate_private.near_owner_wallets
  set revoked_at = now()
  where owner_id = p_owner_id and revoked_at is null;

  insert into mandate_private.near_owner_wallets
    (owner_id, account_id, public_key, verified_at, revoked_at)
  values
    (p_owner_id, r.new_account_id, r.new_public_key, now(), null)
  on conflict (owner_id, account_id) do update
    set public_key = excluded.public_key,
        verified_at = now(),
        revoked_at = null;

  insert into mandate_private.near_wallet_events(owner_id, account_id, event_type, actor_account_id)
  values (p_owner_id, r.new_account_id, 'recovered', r.new_account_id);

  update mandate_private.near_wallet_recovery_requests
  set status = 'completed', completed_at = now()
  where id = r.id and status = 'pending';
  if not found then
    raise exception 'Wallet recovery request changed during finalization';
  end if;

  insert into mandate_private.near_wallet_recovery_events(owner_id, request_id, event_type, account_id)
  values (p_owner_id, r.id, 'completed', r.new_account_id);

  update mandate_private.near_wallet_recovery_action_challenges
  set consumed_at = now()
  where owner_id = p_owner_id and consumed_at is null;

  update mandate_private.near_wallet_revocation_challenges
  set consumed_at = now()
  where owner_id = p_owner_id and consumed_at is null;

  update mandate_private.near_wallet_recovery_credentials
  set code_hash = decode(p_new_code_hash_hex, 'hex'),
      consumed_at = null,
      rotated_at = now()
  where owner_id = p_owner_id and consumed_at is null;
  if not found then
    raise exception 'Active recovery credential disappeared during finalization';
  end if;

  update mandate_private.near_wallet_registration_challenges
  set consumed_at = now()
  where owner_id = p_owner_id and consumed_at is null;

  update mandate_private.near_transfer_challenges
  set consumed_at = now()
  where owner_id = p_owner_id and consumed_at is null;

  update mandate_private.near_transfer_receipts
  set consumed_at = now()
  where owner_id = p_owner_id and consumed_at is null;

  return true;
end;
$fn$;

-- These routines are called only by the authenticated Edge Function with service role.
revoke all on function public.create_near_wallet_registration_challenge_v1(uuid,uuid,text,text,text) from public, anon, authenticated;
revoke all on function public.complete_near_wallet_registration_v1(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.list_near_owner_wallets_v1(uuid) from public, anon, authenticated;
revoke all on function public.create_near_wallet_revoke_challenge_v1(uuid,uuid,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.get_near_wallet_revoke_challenge_v1(uuid,uuid) from public, anon, authenticated;
revoke all on function public.complete_near_wallet_revoke_v1(uuid,uuid) from public, anon, authenticated;
revoke all on function public.create_near_wallet_recovery_action_challenge_v1(uuid,uuid,uuid,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.finalize_near_wallet_recovery_v1(uuid,uuid,text) from public, anon, authenticated;

grant execute on function public.create_near_wallet_registration_challenge_v1(uuid,uuid,text,text,text) to service_role;
grant execute on function public.complete_near_wallet_registration_v1(uuid,uuid,text) to service_role;
grant execute on function public.list_near_owner_wallets_v1(uuid) to service_role;
grant execute on function public.create_near_wallet_revoke_challenge_v1(uuid,uuid,text,text,text,text,text) to service_role;
grant execute on function public.get_near_wallet_revoke_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.complete_near_wallet_revoke_v1(uuid,uuid) to service_role;
grant execute on function public.create_near_wallet_recovery_action_challenge_v1(uuid,uuid,uuid,text,text,text,text,text) to service_role;
grant execute on function public.finalize_near_wallet_recovery_v1(uuid,uuid,text) to service_role;

commit;
