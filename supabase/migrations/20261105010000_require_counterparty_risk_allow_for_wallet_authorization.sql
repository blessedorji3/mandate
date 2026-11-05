-- The wallet execution boundary independently enforces counterparty risk.
-- The Edge Function must also re-assess live evidence before each transition;
-- these database predicates prevent receipts without an ALLOW risk result.
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

  if not exists (
    select 1 from public.authorization_decisions d
    where d.owner_id = p_owner_id
      and d.proposal_id = p_proposal_id
      and d.proposal->'counterpartyRisk'->>'outcome' = 'ALLOW'
  ) then
    raise exception 'Proposal counterparty risk is not ALLOW';
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

create or replace function public.finalize_near_transfer_challenge_v2(
  p_owner_id uuid, p_id uuid, p_token_hash text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare c mandate_private.near_transfer_challenges%rowtype;
begin
  if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$' then return false; end if;
  select * into c from mandate_private.near_transfer_challenges
   where id = p_id and owner_id = p_owner_id and consumed_at is null
     and expires_at > now() for update;
  if not found then return false; end if;
  if not exists (
    select 1 from public.security_policies p
    where p.id = c.policy_id and p.owner_id = p_owner_id
      and p.active = true and p.version = c.policy_version
      and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric
      and p.require_approval_for_all_actions = false
  ) then return false; end if;
  if not exists (
    select 1 from public.authorization_decisions d
    where d.owner_id = p_owner_id
      and d.proposal_id = c.proposal_id
      and d.proposal->'counterpartyRisk'->>'outcome' = 'ALLOW'
  ) then return false; end if;
  update mandate_private.near_transfer_challenges
    set consumed_at = now()
    where id = c.id and owner_id = p_owner_id and consumed_at is null;
  if not found then return false; end if;
  insert into mandate_private.near_transfer_receipts
    (id, owner_id, token_hash, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type,
     action_digest, expires_at)
  values
    (gen_random_uuid(), p_owner_id, decode(p_token_hash, 'hex'),
     c.signer_account_id, c.policy_id, c.policy_version, c.proposal_id,
     c.network, c.receiver_id, c.asset, c.amount_atomic, c.action_type,
     c.action_digest, least(c.expires_at, now() + interval '90 seconds'));
  return true;
end;
$$;

create or replace function public.consume_near_transfer_authorization_v2(
  p_owner_id uuid, p_token_hash text, p_signer_account_id text,
  p_network text, p_receiver_id text, p_asset text,
  p_amount_atomic text, p_action_type text, p_action_digest text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare r mandate_private.near_transfer_receipts%rowtype;
begin
  if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_action_digest !~ '^[0-9a-f]{64}$' then return false; end if;
  select * into r from mandate_private.near_transfer_receipts
   where owner_id = p_owner_id and token_hash = decode(p_token_hash, 'hex')
     and consumed_at is null and expires_at > now()
     and signer_account_id = p_signer_account_id
     and network = p_network and receiver_id = p_receiver_id
     and asset = p_asset and amount_atomic = p_amount_atomic
     and action_type = p_action_type and action_digest = p_action_digest
   for update;
  if not found then return false; end if;
  if not exists (
    select 1 from public.security_policies p
    where p.id = r.policy_id and p.owner_id = p_owner_id
      and p.active = true and p.version = r.policy_version
      and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric
      and p.require_approval_for_all_actions = false
  ) then return false; end if;
  if not exists (
    select 1 from public.authorization_decisions d
    where d.owner_id = p_owner_id
      and d.proposal_id = r.proposal_id
      and d.proposal->'counterpartyRisk'->>'outcome' = 'ALLOW'
  ) then return false; end if;
  update mandate_private.near_transfer_receipts
    set consumed_at = now()
    where id = r.id and owner_id = p_owner_id and consumed_at is null;
  return found;
end;
$$;
