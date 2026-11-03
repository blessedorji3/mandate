-- Wallet-authorized recovery-code reset. This rotates only the recovery verifier;
-- it never changes wallet registration or starts the delayed wallet-recovery flow.

create table if not exists mandate_private.near_wallet_recovery_reset_challenges (
  id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  account_id text not null check (account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'),
  public_key text not null check (public_key ~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'),
  nonce_hex text not null check (nonce_hex ~ '^[0-9a-f]{64}$'),
  message text not null,
  callback_url text not null check (callback_url ~ '^https://[^[:space:]]+ timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists near_wallet_recovery_reset_challenges_owner_created_idx
  on mandate_private.near_wallet_recovery_reset_challenges(owner_id, created_at desc);

alter table mandate_private.near_wallet_recovery_reset_challenges enable row level security;
revoke all on mandate_private.near_wallet_recovery_reset_challenges from public, anon, authenticated;
grant all on mandate_private.near_wallet_recovery_reset_challenges to service_role;

create or replace function public.create_near_wallet_recovery_reset_challenge_v1(
  p_owner_id uuid, p_id uuid, p_account_id text, p_public_key text,
  p_nonce_hex text, p_message text, p_callback_url text
) returns uuid
language plpgsql security definer
set search_path = pg_catalog, mandate_private
as $$
declare v_recent_count integer;
begin
  if p_owner_id is null or p_id is null
    or p_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
    or p_public_key !~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'
    or p_nonce_hex !~ '^[0-9a-f]{64}$'
    or length(p_message) > 2048
    or p_callback_url !~ '^https://[^[:space:]]+
    raise exception 'Invalid recovery-code reset challenge';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  if not exists (
    select 1 from mandate_private.near_wallet_recovery_credentials
    where owner_id = p_owner_id and consumed_at is null
  ) then
    raise exception 'An active recovery code is required to reset it';
  end if;

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then
    raise exception 'Recovery-code reset is unavailable while wallet recovery is pending';
  end if;

  if not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = p_account_id
      and public_key = p_public_key and revoked_at is null
  ) then
    raise exception 'The signing wallet is not the active registered MANDATE wallet';
  end if;

  select count(*) into v_recent_count
  from mandate_private.near_wallet_recovery_reset_challenges
  where owner_id = p_owner_id and created_at > now() - interval '1 hour';
  if v_recent_count >= 3 then
    raise exception 'Recovery-code reset rate limit exceeded';
  end if;

  update mandate_private.near_wallet_recovery_reset_challenges
    set consumed_at = now()
    where owner_id = p_owner_id and consumed_at is null;

  insert into mandate_private.near_wallet_recovery_reset_challenges
    (id, owner_id, account_id, public_key, nonce_hex, message, callback_url, expires_at)
  values
    (p_id, p_owner_id, p_account_id, p_public_key, p_nonce_hex, p_message, p_callback_url, now() + interval '5 minutes');

  return p_id;
end;
$$;

create or replace function public.get_near_wallet_recovery_reset_challenge_v1(
  p_owner_id uuid, p_id uuid
) returns table(
  id uuid, account_id text, public_key text, nonce_hex text, message text, callback_url text, expires_at timestamptz
)
language sql security definer
set search_path = pg_catalog, mandate_private
as $$
  select c.id, c.account_id, c.public_key, c.nonce_hex, c.message, c.callback_url, c.expires_at
  from mandate_private.near_wallet_recovery_reset_challenges c
  where c.owner_id = p_owner_id and c.id = p_id
    and c.consumed_at is null and c.expires_at > now()
  limit 1;
$$;

create or replace function public.complete_near_wallet_recovery_reset_v1(
  p_owner_id uuid, p_id uuid, p_code_hash_hex text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, mandate_private
as $$
declare c mandate_private.near_wallet_recovery_reset_challenges%rowtype;
begin
  if p_owner_id is null or p_code_hash_hex !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  select * into c
  from mandate_private.near_wallet_recovery_reset_challenges
  where id = p_id and owner_id = p_owner_id
    and consumed_at is null and expires_at > now()
  for update;
  if not found then return false; end if;

  if not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = c.account_id
      and public_key = c.public_key and revoked_at is null
  ) then return false; end if;

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then return false; end if;

  update mandate_private.near_wallet_recovery_credentials
    set code_hash = decode(p_code_hash_hex, 'hex'), rotated_at = now()
    where owner_id = p_owner_id and consumed_at is null;
  if not found then return false; end if;

  update mandate_private.near_wallet_recovery_reset_challenges
    set consumed_at = now()
    where owner_id = p_owner_id and consumed_at is null;

  update mandate_private.near_wallet_recovery_setup_challenges
    set consumed_at = now()
    where owner_id = p_owner_id and consumed_at is null;

  return true;
end;
$$;

revoke all on function public.create_near_wallet_recovery_reset_challenge_v1(uuid,uuid,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.get_near_wallet_recovery_reset_challenge_v1(uuid,uuid) from public, anon, authenticated;
revoke all on function public.complete_near_wallet_recovery_reset_v1(uuid,uuid,text) from public, anon, authenticated;
grant execute on function public.create_near_wallet_recovery_reset_challenge_v1(uuid,uuid,text,text,text,text) to service_role;
grant execute on function public.get_near_wallet_recovery_reset_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.complete_near_wallet_recovery_reset_v1(uuid,uuid,text) to service_role;
 and length(callback_url) <= 2048),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists near_wallet_recovery_reset_challenges_owner_created_idx
  on mandate_private.near_wallet_recovery_reset_challenges(owner_id, created_at desc);

alter table mandate_private.near_wallet_recovery_reset_challenges enable row level security;
revoke all on mandate_private.near_wallet_recovery_reset_challenges from public, anon, authenticated;
grant all on mandate_private.near_wallet_recovery_reset_challenges to service_role;

create or replace function public.create_near_wallet_recovery_reset_challenge_v1(
  p_owner_id uuid, p_id uuid, p_account_id text, p_public_key text,
  p_nonce_hex text, p_message text
) returns uuid
language plpgsql security definer
set search_path = pg_catalog, mandate_private
as $$
declare v_recent_count integer;
begin
  if p_owner_id is null or p_id is null
    or p_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
    or p_public_key !~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'
    or p_nonce_hex !~ '^[0-9a-f]{64}$'
    or length(p_message) > 2048 then
    raise exception 'Invalid recovery-code reset challenge';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  if not exists (
    select 1 from mandate_private.near_wallet_recovery_credentials
    where owner_id = p_owner_id and consumed_at is null
  ) then
    raise exception 'An active recovery code is required to reset it';
  end if;

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then
    raise exception 'Recovery-code reset is unavailable while wallet recovery is pending';
  end if;

  if not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = p_account_id
      and public_key = p_public_key and revoked_at is null
  ) then
    raise exception 'The signing wallet is not the active registered MANDATE wallet';
  end if;

  select count(*) into v_recent_count
  from mandate_private.near_wallet_recovery_reset_challenges
  where owner_id = p_owner_id and created_at > now() - interval '1 hour';
  if v_recent_count >= 3 then
    raise exception 'Recovery-code reset rate limit exceeded';
  end if;

  update mandate_private.near_wallet_recovery_reset_challenges
    set consumed_at = now()
    where owner_id = p_owner_id and consumed_at is null;

  insert into mandate_private.near_wallet_recovery_reset_challenges
    (id, owner_id, account_id, public_key, nonce_hex, message, expires_at)
  values
    (p_id, p_owner_id, p_account_id, p_public_key, p_nonce_hex, p_message, now() + interval '5 minutes');

  return p_id;
end;
$$;

create or replace function public.get_near_wallet_recovery_reset_challenge_v1(
  p_owner_id uuid, p_id uuid
) returns table(
  id uuid, account_id text, public_key text, nonce_hex text, message text, expires_at timestamptz
)
language sql security definer
set search_path = pg_catalog, mandate_private
as $$
  select c.id, c.account_id, c.public_key, c.nonce_hex, c.message, c.expires_at
  from mandate_private.near_wallet_recovery_reset_challenges c
  where c.owner_id = p_owner_id and c.id = p_id
    and c.consumed_at is null and c.expires_at > now()
  limit 1;
$$;

create or replace function public.complete_near_wallet_recovery_reset_v1(
  p_owner_id uuid, p_id uuid, p_code_hash_hex text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, mandate_private
as $$
declare c mandate_private.near_wallet_recovery_reset_challenges%rowtype;
begin
  if p_owner_id is null or p_code_hash_hex !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  select * into c
  from mandate_private.near_wallet_recovery_reset_challenges
  where id = p_id and owner_id = p_owner_id
    and consumed_at is null and expires_at > now()
  for update;
  if not found then return false; end if;

  if not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = c.account_id
      and public_key = c.public_key and revoked_at is null
  ) then return false; end if;

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then return false; end if;

  update mandate_private.near_wallet_recovery_credentials
    set code_hash = decode(p_code_hash_hex, 'hex'), rotated_at = now()
    where owner_id = p_owner_id and consumed_at is null;
  if not found then return false; end if;

  update mandate_private.near_wallet_recovery_reset_challenges
    set consumed_at = now()
    where owner_id = p_owner_id and consumed_at is null;

  update mandate_private.near_wallet_recovery_setup_challenges
    set consumed_at = now()
    where owner_id = p_owner_id and consumed_at is null;

  return true;
end;
$$;

revoke all on function public.create_near_wallet_recovery_reset_challenge_v1(uuid,uuid,text,text,text,text) from public, anon, authenticated;
revoke all on function public.get_near_wallet_recovery_reset_challenge_v1(uuid,uuid) from public, anon, authenticated;
revoke all on function public.complete_near_wallet_recovery_reset_v1(uuid,uuid,text) from public, anon, authenticated;
grant execute on function public.create_near_wallet_recovery_reset_challenge_v1(uuid,uuid,text,text,text,text) to service_role;
grant execute on function public.get_near_wallet_recovery_reset_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.complete_near_wallet_recovery_reset_v1(uuid,uuid,text) to service_role;
 or length(p_callback_url) > 2048 then
    raise exception 'Invalid recovery-code reset challenge';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  if not exists (
    select 1 from mandate_private.near_wallet_recovery_credentials
    where owner_id = p_owner_id and consumed_at is null
  ) then
    raise exception 'An active recovery code is required to reset it';
  end if;

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then
    raise exception 'Recovery-code reset is unavailable while wallet recovery is pending';
  end if;

  if not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = p_account_id
      and public_key = p_public_key and revoked_at is null
  ) then
    raise exception 'The signing wallet is not the active registered MANDATE wallet';
  end if;

  select count(*) into v_recent_count
  from mandate_private.near_wallet_recovery_reset_challenges
  where owner_id = p_owner_id and created_at > now() - interval '1 hour';
  if v_recent_count >= 3 then
    raise exception 'Recovery-code reset rate limit exceeded';
  end if;

  update mandate_private.near_wallet_recovery_reset_challenges
    set consumed_at = now()
    where owner_id = p_owner_id and consumed_at is null;

  insert into mandate_private.near_wallet_recovery_reset_challenges
    (id, owner_id, account_id, public_key, nonce_hex, message, expires_at)
  values
    (p_id, p_owner_id, p_account_id, p_public_key, p_nonce_hex, p_message, now() + interval '5 minutes');

  return p_id;
end;
$$;

create or replace function public.get_near_wallet_recovery_reset_challenge_v1(
  p_owner_id uuid, p_id uuid
) returns table(
  id uuid, account_id text, public_key text, nonce_hex text, message text, expires_at timestamptz
)
language sql security definer
set search_path = pg_catalog, mandate_private
as $$
  select c.id, c.account_id, c.public_key, c.nonce_hex, c.message, c.expires_at
  from mandate_private.near_wallet_recovery_reset_challenges c
  where c.owner_id = p_owner_id and c.id = p_id
    and c.consumed_at is null and c.expires_at > now()
  limit 1;
$$;

create or replace function public.complete_near_wallet_recovery_reset_v1(
  p_owner_id uuid, p_id uuid, p_code_hash_hex text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, mandate_private
as $$
declare c mandate_private.near_wallet_recovery_reset_challenges%rowtype;
begin
  if p_owner_id is null or p_code_hash_hex !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  select * into c
  from mandate_private.near_wallet_recovery_reset_challenges
  where id = p_id and owner_id = p_owner_id
    and consumed_at is null and expires_at > now()
  for update;
  if not found then return false; end if;

  if not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = c.account_id
      and public_key = c.public_key and revoked_at is null
  ) then return false; end if;

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then return false; end if;

  update mandate_private.near_wallet_recovery_credentials
    set code_hash = decode(p_code_hash_hex, 'hex'), rotated_at = now()
    where owner_id = p_owner_id and consumed_at is null;
  if not found then return false; end if;

  update mandate_private.near_wallet_recovery_reset_challenges
    set consumed_at = now()
    where owner_id = p_owner_id and consumed_at is null;

  update mandate_private.near_wallet_recovery_setup_challenges
    set consumed_at = now()
    where owner_id = p_owner_id and consumed_at is null;

  return true;
end;
$$;

revoke all on function public.create_near_wallet_recovery_reset_challenge_v1(uuid,uuid,text,text,text,text) from public, anon, authenticated;
revoke all on function public.get_near_wallet_recovery_reset_challenge_v1(uuid,uuid) from public, anon, authenticated;
revoke all on function public.complete_near_wallet_recovery_reset_v1(uuid,uuid,text) from public, anon, authenticated;
grant execute on function public.create_near_wallet_recovery_reset_challenge_v1(uuid,uuid,text,text,text,text) to service_role;
grant execute on function public.get_near_wallet_recovery_reset_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.complete_near_wallet_recovery_reset_v1(uuid,uuid,text) to service_role;
 and length(callback_url) <= 2048),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists near_wallet_recovery_reset_challenges_owner_created_idx
  on mandate_private.near_wallet_recovery_reset_challenges(owner_id, created_at desc);

alter table mandate_private.near_wallet_recovery_reset_challenges enable row level security;
revoke all on mandate_private.near_wallet_recovery_reset_challenges from public, anon, authenticated;
grant all on mandate_private.near_wallet_recovery_reset_challenges to service_role;

create or replace function public.create_near_wallet_recovery_reset_challenge_v1(
  p_owner_id uuid, p_id uuid, p_account_id text, p_public_key text,
  p_nonce_hex text, p_message text
) returns uuid
language plpgsql security definer
set search_path = pg_catalog, mandate_private
as $$
declare v_recent_count integer;
begin
  if p_owner_id is null or p_id is null
    or p_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
    or p_public_key !~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'
    or p_nonce_hex !~ '^[0-9a-f]{64}$'
    or length(p_message) > 2048 then
    raise exception 'Invalid recovery-code reset challenge';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  if not exists (
    select 1 from mandate_private.near_wallet_recovery_credentials
    where owner_id = p_owner_id and consumed_at is null
  ) then
    raise exception 'An active recovery code is required to reset it';
  end if;

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then
    raise exception 'Recovery-code reset is unavailable while wallet recovery is pending';
  end if;

  if not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = p_account_id
      and public_key = p_public_key and revoked_at is null
  ) then
    raise exception 'The signing wallet is not the active registered MANDATE wallet';
  end if;

  select count(*) into v_recent_count
  from mandate_private.near_wallet_recovery_reset_challenges
  where owner_id = p_owner_id and created_at > now() - interval '1 hour';
  if v_recent_count >= 3 then
    raise exception 'Recovery-code reset rate limit exceeded';
  end if;

  update mandate_private.near_wallet_recovery_reset_challenges
    set consumed_at = now()
    where owner_id = p_owner_id and consumed_at is null;

  insert into mandate_private.near_wallet_recovery_reset_challenges
    (id, owner_id, account_id, public_key, nonce_hex, message, expires_at)
  values
    (p_id, p_owner_id, p_account_id, p_public_key, p_nonce_hex, p_message, now() + interval '5 minutes');

  return p_id;
end;
$$;

create or replace function public.get_near_wallet_recovery_reset_challenge_v1(
  p_owner_id uuid, p_id uuid
) returns table(
  id uuid, account_id text, public_key text, nonce_hex text, message text, expires_at timestamptz
)
language sql security definer
set search_path = pg_catalog, mandate_private
as $$
  select c.id, c.account_id, c.public_key, c.nonce_hex, c.message, c.expires_at
  from mandate_private.near_wallet_recovery_reset_challenges c
  where c.owner_id = p_owner_id and c.id = p_id
    and c.consumed_at is null and c.expires_at > now()
  limit 1;
$$;

create or replace function public.complete_near_wallet_recovery_reset_v1(
  p_owner_id uuid, p_id uuid, p_code_hash_hex text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, mandate_private
as $$
declare c mandate_private.near_wallet_recovery_reset_challenges%rowtype;
begin
  if p_owner_id is null or p_code_hash_hex !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  select * into c
  from mandate_private.near_wallet_recovery_reset_challenges
  where id = p_id and owner_id = p_owner_id
    and consumed_at is null and expires_at > now()
  for update;
  if not found then return false; end if;

  if not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = c.account_id
      and public_key = c.public_key and revoked_at is null
  ) then return false; end if;

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then return false; end if;

  update mandate_private.near_wallet_recovery_credentials
    set code_hash = decode(p_code_hash_hex, 'hex'), rotated_at = now()
    where owner_id = p_owner_id and consumed_at is null;
  if not found then return false; end if;

  update mandate_private.near_wallet_recovery_reset_challenges
    set consumed_at = now()
    where owner_id = p_owner_id and consumed_at is null;

  update mandate_private.near_wallet_recovery_setup_challenges
    set consumed_at = now()
    where owner_id = p_owner_id and consumed_at is null;

  return true;
end;
$$;

revoke all on function public.create_near_wallet_recovery_reset_challenge_v1(uuid,uuid,text,text,text,text) from public, anon, authenticated;
revoke all on function public.get_near_wallet_recovery_reset_challenge_v1(uuid,uuid) from public, anon, authenticated;
revoke all on function public.complete_near_wallet_recovery_reset_v1(uuid,uuid,text) from public, anon, authenticated;
grant execute on function public.create_near_wallet_recovery_reset_challenge_v1(uuid,uuid,text,text,text,text) to service_role;
grant execute on function public.get_near_wallet_recovery_reset_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.complete_near_wallet_recovery_reset_v1(uuid,uuid,text) to service_role;
