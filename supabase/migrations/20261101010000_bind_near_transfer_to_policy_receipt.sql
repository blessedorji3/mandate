-- Bind a finalized NEAR Testnet transaction to the exact one-time MANDATE receipt.
alter table mandate_private.near_transfer_receipts
  add column if not exists transaction_hash text,
  add column if not exists verified_at timestamptz;

create unique index if not exists near_transfer_receipts_transaction_hash_unique
  on mandate_private.near_transfer_receipts (transaction_hash)
  where transaction_hash is not null;

alter table mandate_private.near_transfer_receipts
  add constraint near_transfer_receipts_transaction_hash_check
  check (transaction_hash is null or transaction_hash ~ '^[1-9A-HJ-NP-Za-km-z]{43,44}$');

create or replace function public.bind_near_transfer_transaction_v1(
  p_owner_id uuid,
  p_token_hash text,
  p_signer_account_id text,
  p_transaction_hash text
) returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, mandate_private
as $$
begin
  if p_owner_id is null
     or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_signer_account_id !~ '^[a-z0-9._-]{2,64}\\.testnet$'
     or p_transaction_hash !~ '^[1-9A-HJ-NP-Za-km-z]{43,44}$' then
    return false;
  end if;

  update mandate_private.near_transfer_receipts r
     set transaction_hash = p_transaction_hash,
         verified_at = now()
   where r.owner_id = p_owner_id
     and r.token_hash = decode(p_token_hash, 'hex')
     and r.signer_account_id = p_signer_account_id
     and r.network = 'testnet'
     and r.receiver_id = 'confirmwithmandate.testnet'
     and r.asset = 'NEAR'
     and r.amount_atomic = '1000000000000000000000'
     and r.action_type = 'transfer'
     and r.consumed_at is not null
     and r.consumed_at > now() - interval '10 minutes'
     and r.expires_at > r.consumed_at
     and r.transaction_hash is null
     and exists (
       select 1
         from public.security_policies p
        where p.id = r.policy_id
          and p.owner_id = p_owner_id
          and p.active = true
          and p.version = r.policy_version
          and 'transfer' = any(p.allowed_action_types)
          and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
          and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric
          and p.require_approval_for_all_actions = false
     );

  return found;
end;
$$;

revoke all on function public.bind_near_transfer_transaction_v1(uuid,text,text,text)
  from public, anon, authenticated;
grant execute on function public.bind_near_transfer_transaction_v1(uuid,text,text,text)
  to service_role;

-- Decision history must only be written by trusted server-side services.
drop policy if exists "Users can insert their own authorization decisions"
  on public.authorization_decisions;
revoke insert on public.authorization_decisions from anon, authenticated;
