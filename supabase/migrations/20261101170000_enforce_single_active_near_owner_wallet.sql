-- Enforce one active NEAR sender wallet per MANDATE owner.
-- Historical/revoked wallet rows remain intact. Replacing an active wallet must
-- use the dedicated recovery process; normal registration cannot replace it.

do $$
begin
  if exists (
    select 1
    from mandate_private.near_owner_wallets
    where revoked_at is null
    group by owner_id
    having count(*) > 1
  ) then
    raise exception 'Cannot enforce one active NEAR wallet: duplicate active owner registrations exist';
  end if;
end;
$$;

create unique index if not exists near_owner_wallets_one_active_per_owner_idx
  on mandate_private.near_owner_wallets(owner_id)
  where revoked_at is null;

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
     or length(p_message) > 2048 then
    raise exception 'Invalid wallet registration challenge';
  end if;

  -- Serialize registrations for this owner. The partial unique index below is
  -- the final database-level guard even if another code path is introduced.
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  select count(*) into v_count
  from mandate_private.near_wallet_registration_challenges
  where owner_id = p_owner_id
    and created_at > now() - interval '5 minutes';

  if v_count >= 5 then
    raise exception 'Wallet registration rate limit exceeded';
  end if;

  -- A normal registration is permitted only for an owner with no wallet history.
  -- Even a fully revoked wallet must be replaced through independent-factor recovery.
  if exists (
    select 1
    from mandate_private.near_owner_wallets
    where owner_id = p_owner_id
  ) then
    raise exception 'This MANDATE account has previous NEAR wallet history. Complete the official independent-factor wallet recovery process before registering a replacement.';
  end if;

  if exists (
    select 1
    from mandate_private.near_owner_wallets
    where account_id = p_account_id
      and revoked_at is null
      and owner_id <> p_owner_id
  ) then
    raise exception 'This NEAR account is already registered to another MANDATE owner';
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
begin
  if p_owner_id is null
     or p_public_key !~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$' then
    return false;
  end if;

  -- This lock closes the race between two previously-created challenges.
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

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

  -- Re-check at completion: an older challenge must not bypass a wallet
  -- registration or revocation/recovery event that happened after challenge creation.
  if exists (
    select 1
    from mandate_private.near_owner_wallets
    where owner_id = p_owner_id
  ) then
    raise exception 'This MANDATE account has previous NEAR wallet history. Complete the official independent-factor wallet recovery process before registering a replacement.';
  end if;

  update mandate_private.near_wallet_registration_challenges
  set consumed_at = now()
  where id = c.id
    and owner_id = p_owner_id
    and consumed_at is null;

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

  return true;
exception
  when unique_violation then
    raise exception 'A NEAR sender wallet is already active for this MANDATE account, or this NEAR account belongs to another MANDATE owner';
end;
$$;

-- CREATE OR REPLACE preserves the existing service_role-only EXECUTE grants.
