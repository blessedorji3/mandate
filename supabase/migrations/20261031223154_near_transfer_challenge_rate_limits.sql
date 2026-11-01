alter table mandate_private.near_transfer_challenges
  add column if not exists signature_attempts integer not null default 0
  check (signature_attempts >= 0 and signature_attempts <= 3);

create index if not exists near_transfer_challenges_owner_created_idx
  on mandate_private.near_transfer_challenges(owner_id, created_at desc);

create or replace function public.create_near_transfer_challenge_v2(
  p_owner_id uuid, p_id uuid, p_nonce_hex text, p_message text,
  p_signer_account_id text, p_policy_id uuid, p_policy_version integer,
  p_proposal_id text, p_action_digest text
) returns uuid
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare v_policy public.security_policies%rowtype; v_recent_count integer;
begin
  if p_owner_id is null or p_nonce_hex !~ '^[0-9a-f]{64}$'
     or p_action_digest !~ '^[0-9a-f]{64}$'
     or length(p_message) > 2048
     or p_signer_account_id !~ '^[a-z0-9._-]{2,64}\.testnet$'
     or p_proposal_id !~ '^[a-zA-Z0-9_-]{1,128}$' then
    raise exception 'Invalid challenge data';
  end if;
  select count(*) into v_recent_count
    from mandate_private.near_transfer_challenges
    where owner_id = p_owner_id and created_at > now() - interval '5 minutes';
  if v_recent_count >= 10 then raise exception 'Transfer challenge rate limit exceeded'; end if;
  select * into v_policy from public.security_policies
   where id = p_policy_id and owner_id = p_owner_id and active = true limit 1;
  if not found or v_policy.version <> p_policy_version then
    raise exception 'Policy changed or inactive';
  end if;
  if not ('transfer' = any(v_policy.allowed_action_types))
     or not ('confirmwithmandate.testnet' = any(v_policy.allowed_recipients))
     or v_policy.max_amount_atomic::numeric < 1000000000000000000000::numeric
     or v_policy.require_approval_for_all_actions then
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
$$;

create or replace function public.get_near_transfer_challenge_v2(
  p_owner_id uuid, p_id uuid
) returns table(
  id uuid, nonce_hex text, message text, signer_account_id text,
  policy_id uuid, policy_version integer, proposal_id text, network text,
  receiver_id text, asset text, amount_atomic text, action_type text,
  action_digest text, expires_at timestamptz
)
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private
as $$
begin
  return query
  update mandate_private.near_transfer_challenges c
    set signature_attempts = c.signature_attempts + 1
    where c.id = p_id and c.owner_id = p_owner_id
      and c.consumed_at is null and c.expires_at > now()
      and c.signature_attempts < 3
  returning c.id, c.nonce_hex, c.message, c.signer_account_id,
    c.policy_id, c.policy_version, c.proposal_id, c.network,
    c.receiver_id, c.asset, c.amount_atomic, c.action_type,
    c.action_digest, c.expires_at;
end;
$$;

revoke all on function public.create_near_transfer_challenge_v2(uuid,uuid,text,text,text,uuid,integer,text,text) from public, anon, authenticated;
revoke all on function public.get_near_transfer_challenge_v2(uuid,uuid) from public, anon, authenticated;
grant execute on function public.create_near_transfer_challenge_v2(uuid,uuid,text,text,text,uuid,integer,text,text) to service_role;
grant execute on function public.get_near_transfer_challenge_v2(uuid,uuid) to service_role;
