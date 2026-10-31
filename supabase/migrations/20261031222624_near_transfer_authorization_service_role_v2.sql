alter table mandate_private.near_transfer_challenges
  add column if not exists action_digest text not null default repeat('0', 64);
alter table mandate_private.near_transfer_receipts
  add column if not exists action_digest text not null default repeat('0', 64);

alter table mandate_private.near_transfer_challenges
  add constraint near_transfer_challenges_action_digest_check
  check (action_digest ~ '^[0-9a-f]{64}$');
alter table mandate_private.near_transfer_receipts
  add constraint near_transfer_receipts_action_digest_check
  check (action_digest ~ '^[0-9a-f]{64}$');

grant usage on schema mandate_private to service_role;
grant select, insert, update on mandate_private.near_transfer_challenges to service_role;
grant select, insert, update on mandate_private.near_transfer_receipts to service_role;

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
  update mandate_private.near_transfer_receipts
    set consumed_at = now()
    where id = r.id and owner_id = p_owner_id and consumed_at is null;
  return found;
end;
$$;

revoke all on function public.finalize_near_transfer_challenge_v2(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.consume_near_transfer_authorization_v2(uuid,text,text,text,text,text,text,text,text) from public, anon, authenticated;
grant execute on function public.finalize_near_transfer_challenge_v2(uuid,uuid,text) to service_role;
grant execute on function public.consume_near_transfer_authorization_v2(uuid,text,text,text,text,text,text,text,text) to service_role;

revoke all on function public.create_near_transfer_challenge(uuid,text,text,text,uuid,integer,text) from service_role;
revoke all on function public.get_near_transfer_challenge(uuid) from service_role;
revoke all on function public.finalize_near_transfer_challenge(uuid,text) from service_role;
revoke all on function public.consume_near_transfer_authorization(text,text,text,text,text,text,text) from service_role;
