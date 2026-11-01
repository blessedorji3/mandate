create unique index if not exists near_transfer_receipts_owner_proposal_uidx
  on mandate_private.near_transfer_receipts (owner_id, proposal_id);

create or replace function public.create_near_transfer_challenge_v2(
  p_owner_id uuid,
  p_id uuid,
  p_nonce_hex text,
  p_message text,
  p_signer_account_id text,
  p_policy_id uuid,
  p_policy_version integer,
  p_proposal_id text,
  p_action_digest text
)
returns uuid
language plpgsql
security definer
set search_path to 'pg_catalog', 'public', 'mandate_private'
as $function$
declare
  v_policy public.security_policies%rowtype;
  v_recent_count integer;
begin
  if p_owner_id is null or p_nonce_hex !~ '^[0-9a-f]{64}$'
     or p_action_digest !~ '^[0-9a-f]{64}$'
     or length(p_message) > 2048
     or p_signer_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
     or p_proposal_id !~ '^[a-zA-Z0-9_-]{1,128}$' then
    raise exception 'Invalid challenge data';
  end if;

  select count(*) into v_recent_count
    from mandate_private.near_transfer_challenges
    where owner_id = p_owner_id and created_at > now() - interval '5 minutes';
  if v_recent_count >= 10 then raise exception 'Transfer challenge rate limit exceeded'; end if;

  if exists (
    select 1 from mandate_private.near_transfer_receipts r
    where r.owner_id = p_owner_id and r.proposal_id = p_proposal_id
  ) then
    raise exception 'This proposal already has a consumed authorization. Inspect a new proposal before attempting another transfer.';
  end if;

  select * into v_policy from public.security_policies
   where id = p_policy_id and owner_id = p_owner_id and active = true limit 1;
  if not found or v_policy.version <> p_policy_version then
    raise exception 'Policy changed or inactive';
  end if;
  if not ('transfer' = any(v_policy.allowed_action_types))
     or not ('confirmwithmandate.testnet' = any(v_policy.allowed_recipients))
     or v_policy.max_amount_atomic::numeric < 1000000000000000000000::numeric then
    raise exception 'Current policy does not permit this transfer';
  end if;

  insert into mandate_private.near_transfer_challenges
    (id, owner_id, nonce_hex, message, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type,
     action_digest, expires_at)
  values
    (p_id, p_owner_id, p_nonce_hex, p_message, p_signer_account_id,
     p_policy_id, p_policy_version, p_proposal_id, 'testnet',
     'confirmwithmandate.testnet', 'NEAR', '1000000000000000000000',
     'transfer', p_action_digest, now() + interval '3 minutes');
  return p_id;
end;
$function$;

revoke all on function public.create_near_transfer_challenge_v2(uuid, uuid, text, text, text, uuid, integer, text, text) from public, anon, authenticated;
grant execute on function public.create_near_transfer_challenge_v2(uuid, uuid, text, text, text, uuid, integer, text, text) to service_role;
