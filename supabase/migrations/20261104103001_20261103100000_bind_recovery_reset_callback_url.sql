-- Bind an explicit, trusted NEP-413 callback URL to each recovery-code reset challenge.
alter table mandate_private.near_wallet_recovery_reset_challenges
  add column if not exists callback_url text;

-- Existing rows cannot be used for verification after this change; they are short-lived.
update mandate_private.near_wallet_recovery_reset_challenges
  set consumed_at = coalesce(consumed_at, now()),
      callback_url = 'https://invalidated-challenge.mandate.invalid'
  where callback_url is null;

alter table mandate_private.near_wallet_recovery_reset_challenges
  alter column callback_url set not null;

alter table mandate_private.near_wallet_recovery_reset_challenges
  add constraint near_wallet_recovery_reset_callback_url_check
  check (callback_url ~ '^https://[^[:space:]]+$' and length(callback_url) <= 2048);

drop function if exists public.create_near_wallet_recovery_reset_challenge_v1(uuid,uuid,text,text,text,text);
drop function if exists public.get_near_wallet_recovery_reset_challenge_v1(uuid,uuid);

create function public.create_near_wallet_recovery_reset_challenge_v1(
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
    or p_callback_url !~ '^https://[^[:space:]]+$'
    or length(p_callback_url) > 2048 then
    raise exception 'Invalid recovery-code reset challenge';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));

  if not exists (
    select 1 from mandate_private.near_wallet_recovery_credentials
    where owner_id = p_owner_id and consumed_at is null
  ) then raise exception 'An active recovery code is required to reset it'; end if;

  if exists (
    select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending'
  ) then raise exception 'Recovery-code reset is unavailable while wallet recovery is pending'; end if;

  if not exists (
    select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = p_account_id
      and public_key = p_public_key and revoked_at is null
  ) then raise exception 'The signing wallet is not the active registered MANDATE wallet'; end if;

  select count(*) into v_recent_count
  from mandate_private.near_wallet_recovery_reset_challenges
  where owner_id = p_owner_id and created_at > now() - interval '1 hour';
  if v_recent_count >= 3 then raise exception 'Recovery-code reset rate limit exceeded'; end if;

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

create function public.get_near_wallet_recovery_reset_challenge_v1(
  p_owner_id uuid, p_id uuid
) returns table(
  id uuid, account_id text, public_key text, nonce_hex text, message text,
  callback_url text, expires_at timestamptz
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

revoke all on function public.create_near_wallet_recovery_reset_challenge_v1(uuid,uuid,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.get_near_wallet_recovery_reset_challenge_v1(uuid,uuid) from public, anon, authenticated;
grant execute on function public.create_near_wallet_recovery_reset_challenge_v1(uuid,uuid,text,text,text,text,text) to service_role;
grant execute on function public.get_near_wallet_recovery_reset_challenge_v1(uuid,uuid) to service_role;
