-- Store one independent, single-use MANDATE recovery-code verifier per owner.
-- Plaintext recovery codes are generated and shown only by the authenticated Edge Function.
-- This migration intentionally does not implement or enable wallet replacement.

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

alter table mandate_private.near_wallet_recovery_credentials enable row level security;
revoke all on mandate_private.near_wallet_recovery_credentials from public, anon, authenticated;
grant all on mandate_private.near_wallet_recovery_credentials to service_role;

create or replace function public.create_near_wallet_recovery_credential_v1(
  p_owner_id uuid,
  p_code_hash_hex text,
  p_verified_historical_account_id text default null
) returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, mandate_private, auth
as $$
declare
  v_has_wallet_history boolean;
begin
  if p_owner_id is null or p_code_hash_hex !~ '^[0-9a-f]{64}$' then
    return false;
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  select exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id
  ) into v_has_wallet_history;

  -- Legacy accounts may establish their first recovery factor only after the
  -- Edge Function verifies a fresh NEP-413 signature from one of their
  -- previously registered wallets (including a revoked historical wallet).
  if v_has_wallet_history and (
    p_verified_historical_account_id is null
    or not exists (
      select 1 from mandate_private.near_owner_wallets
      where owner_id = p_owner_id
        and account_id = p_verified_historical_account_id
    )
  ) then
    raise exception 'Historical wallet proof is required to establish recovery for this account';
  end if;

  insert into mandate_private.near_wallet_recovery_credentials(owner_id, code_hash)
  values (p_owner_id, decode(p_code_hash_hex, 'hex'));

  return true;
exception
  when unique_violation then
    raise exception 'A recovery code is already established or this code has already been used';
end;
$$;

revoke all on function public.create_near_wallet_recovery_credential_v1(uuid,text,text) from public, anon, authenticated;
grant execute on function public.create_near_wallet_recovery_credential_v1(uuid,text,text) to service_role;
