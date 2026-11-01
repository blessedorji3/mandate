-- Store one independent, single-use MANDATE recovery-code verifier per owner.
-- Plaintext codes are generated and returned once by the authenticated Edge Function.
-- No wallet replacement is enabled by this migration.

create table if not exists mandate_private.near_wallet_recovery_credentials (
  owner_id uuid primary key references auth.users(id) on delete cascade,
  code_hash bytea not null,
  created_at timestamptz not null default now(),
  consumed_at timestamptz,
  rotated_at timestamptz,
  constraint near_wallet_recovery_code_hash_length check (octet_length(code_hash) = 32)
);

create unique index if not exists near_wallet_recovery_credentials_hash_uidx
  on mandate_private.near_wallet_recovery_credentials(code_hash);

create table if not exists mandate_private.near_wallet_recovery_setup_challenges (
  id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  historical_account_id text,
  nonce_hex text not null check (nonce_hex ~ '^[0-9a-f]{64}$'),
  message text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists near_wallet_recovery_setup_challenges_owner_created_idx
  on mandate_private.near_wallet_recovery_setup_challenges(owner_id, created_at desc);

alter table mandate_private.near_wallet_recovery_credentials enable row level security;
alter table mandate_private.near_wallet_recovery_setup_challenges enable row level security;
revoke all on mandate_private.near_wallet_recovery_credentials from public, anon, authenticated;
revoke all on mandate_private.near_wallet_recovery_setup_challenges from public, anon, authenticated;
grant all on mandate_private.near_wallet_recovery_credentials to service_role;
grant all on mandate_private.near_wallet_recovery_setup_challenges to service_role;

create or replace function public.create_near_wallet_recovery_setup_challenge_v1(
  p_owner_id uuid,
  p_id uuid,
  p_historical_account_id text,
  p_nonce_hex text,
  p_message text
) returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public, mandate_private, auth
as $$
declare
  v_has_history boolean;
  v_recent_count integer;
begin
  if p_owner_id is null or p_id is null
     or p_nonce_hex !~ '^[0-9a-f]{64}$'
     or length(p_message) > 2048
     or (p_historical_account_id is not null
         and p_historical_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$') then
    raise exception 'Invalid recovery setup challenge';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  if exists (
    select 1 from mandate_private.near_wallet_recovery_credentials
    where owner_id = p_owner_id
  ) then
    raise exception 'A MANDATE recovery code is already established for this account';
  end if;

  select exists (
    select 1 from mandate_private.near_owner_wallets where owner_id = p_owner_id
  ) into v_has_history;

  if v_has_history and (
    p_historical_account_id is null
    or not exists (
      select 1 from mandate_private.near_owner_wallets
      where owner_id = p_owner_id and account_id = p_historical_account_id
    )
  ) then
    raise exception 'A previously registered wallet must be selected to establish recovery for this existing account';
  end if;

  select count(*) into v_recent_count
  from mandate_private.near_wallet_recovery_setup_challenges
  where owner_id = p_owner_id and created_at > now() - interval '1 hour';
  if v_recent_count >= 5 then
    raise exception 'Recovery setup rate limit exceeded';
  end if;

  insert into mandate_private.near_wallet_recovery_setup_challenges
    (id, owner_id, historical_account_id, nonce_hex, message, expires_at)
  values
    (p_id, p_owner_id, p_historical_account_id, p_nonce_hex, p_message, now() + interval '5 minutes');

  return p_id;
end;
$$;

create or replace function public.get_near_wallet_recovery_setup_challenge_v1(
  p_owner_id uuid,
  p_id uuid
) returns table(
  id uuid,
  historical_account_id text,
  nonce_hex text,
  message text,
  expires_at timestamptz
)
language sql
security definer
set search_path = pg_catalog, public, mandate_private
as $$
  select c.id, c.historical_account_id, c.nonce_hex, c.message, c.expires_at
  from mandate_private.near_wallet_recovery_setup_challenges c
  where c.owner_id = p_owner_id
    and c.id = p_id
    and c.consumed_at is null
    and c.expires_at > now()
  limit 1;
$$;

create or replace function public.complete_near_wallet_recovery_setup_v1(
  p_owner_id uuid,
  p_id uuid,
  p_code_hash_hex text,
  p_verified_historical_account_id text default null
) returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, mandate_private, auth
as $$
declare
  c mandate_private.near_wallet_recovery_setup_challenges%rowtype;
  v_has_history boolean;
begin
  if p_owner_id is null or p_code_hash_hex !~ '^[0-9a-f]{64}$' then
    return false;
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  select * into c
  from mandate_private.near_wallet_recovery_setup_challenges
  where id = p_id and owner_id = p_owner_id
    and consumed_at is null and expires_at > now()
  for update;

  if not found then return false; end if;

  select exists (
    select 1 from mandate_private.near_owner_wallets where owner_id = p_owner_id
  ) into v_has_history;

  if v_has_history and (
    c.historical_account_id is null
    or p_verified_historical_account_id is distinct from c.historical_account_id
    or not exists (
      select 1 from mandate_private.near_owner_wallets
      where owner_id = p_owner_id and account_id = c.historical_account_id
    )
  ) then
    raise exception 'Verified historical wallet proof is required';
  end if;

  if not v_has_history and (
    c.historical_account_id is not null
    or p_verified_historical_account_id is not null
  ) then
    raise exception 'Unexpected historical wallet proof';
  end if;

  update mandate_private.near_wallet_recovery_setup_challenges
  set consumed_at = now()
  where id = c.id and owner_id = p_owner_id and consumed_at is null;
  if not found then return false; end if;

  insert into mandate_private.near_wallet_recovery_credentials(owner_id, code_hash)
  values (p_owner_id, decode(p_code_hash_hex, 'hex'));

  return true;
exception
  when unique_violation then
    raise exception 'A recovery code is already established or this code has already been used';
end;
$$;

revoke all on function public.create_near_wallet_recovery_setup_challenge_v1(uuid,uuid,text,text,text) from public, anon, authenticated;
revoke all on function public.get_near_wallet_recovery_setup_challenge_v1(uuid,uuid) from public, anon, authenticated;
revoke all on function public.complete_near_wallet_recovery_setup_v1(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.create_near_wallet_recovery_setup_challenge_v1(uuid,uuid,text,text,text) to service_role;
grant execute on function public.get_near_wallet_recovery_setup_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.complete_near_wallet_recovery_setup_v1(uuid,uuid,text,text) to service_role;
