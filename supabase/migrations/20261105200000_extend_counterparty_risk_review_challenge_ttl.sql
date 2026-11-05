-- Align the stored one-time owner risk-review challenge with the five-minute
-- acknowledgement window presented by the MANDATE UI. All proposal, policy,
-- owner-wallet, blocklist, nonce, and replay checks remain unchanged.
create or replace function public.create_counterparty_risk_review_challenge_v1(
  p_owner_id uuid, p_id uuid, p_proposal_id text, p_policy_id uuid,
  p_policy_version integer, p_target_account_id text, p_risk_fingerprint text,
  p_signer_account_id text, p_signer_public_key text, p_nonce_hex text, p_message text
) returns uuid
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare v_recent_count integer;
begin
  if p_owner_id is null or p_id is null or p_proposal_id is null
     or p_policy_version is null or p_risk_fingerprint is null
     or p_target_account_id is null or p_signer_account_id is null
     or p_signer_public_key is null or p_nonce_hex is null or p_message is null
     or p_proposal_id !~ '^[a-zA-Z0-9_-]{1,128}$'
     or p_policy_version < 1
     or p_target_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
     or p_risk_fingerprint !~ '^[0-9a-f]{64}$'
     or p_signer_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet$'
     or p_signer_public_key !~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'
     or p_nonce_hex !~ '^[0-9a-f]{64}$'
     or length(p_message) not between 1 and 2048 then
    raise exception 'Invalid counterparty risk review challenge';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));
  if exists (
    select 1 from mandate_private.counterparty_blocklist b
    where b.network = 'testnet'
      and b.account_id = 'confirmwithmandate.testnet'
      and b.status = 'confirmed'
  ) then
    raise exception 'Counterparty risk BLOCK cannot be overridden by owner review';
  end if;
  if exists (select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending') then
    raise exception 'Risk review is unavailable while wallet recovery is pending';
  end if;
  if not exists (select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = p_signer_account_id
      and public_key = p_signer_public_key and revoked_at is null) then
    raise exception 'Risk review signer is not an active verified owner wallet';
  end if;
  if not exists (select 1 from public.security_policies p
    where p.id = p_policy_id and p.owner_id = p_owner_id
      and p.active = true and p.version = p_policy_version) then
    raise exception 'Policy changed or inactive';
  end if;
  if not exists (
    select 1 from public.authorization_decisions d
    where d.owner_id = p_owner_id and d.proposal_id = p_proposal_id
      and d.policy_id = p_policy_id and d.policy_version = p_policy_version
      and d.outcome = 'REQUIRE_APPROVAL'
      and d.proposal->>'id' = p_proposal_id
      and d.proposal->>'target' = p_target_account_id
      and d.proposal->>'network' = 'testnet'
      and d.proposal->'counterpartyRisk'->>'outcome' = 'WARN'
      and d.proposal->>'counterpartyRiskFingerprint' = p_risk_fingerprint
  ) then
    raise exception 'Only the exact inspected WARN proposal can be reviewed';
  end if;

  select count(*) into v_recent_count
  from mandate_private.counterparty_risk_review_challenges
  where owner_id = p_owner_id and created_at > now() - interval '5 minutes';
  if v_recent_count >= 5 then raise exception 'Counterparty risk review rate limit exceeded'; end if;

  insert into mandate_private.counterparty_risk_review_challenges
    (id, owner_id, proposal_id, policy_id, policy_version, target_account_id,
     risk_fingerprint, signer_account_id, signer_public_key, nonce_hex, message, expires_at)
  values
    (p_id, p_owner_id, p_proposal_id, p_policy_id, p_policy_version, p_target_account_id,
     p_risk_fingerprint, p_signer_account_id, p_signer_public_key, p_nonce_hex, p_message,
     now() + interval '5 minutes');
  return p_id;
end;
$$;

-- Preserve the existing service-role-only execution boundary.
revoke all on function public.create_counterparty_risk_review_challenge_v1(uuid,uuid,text,uuid,integer,text,text,text,text,text,text) from public, anon, authenticated;
grant execute on function public.create_counterparty_risk_review_challenge_v1(uuid,uuid,text,uuid,integer,text,text,text,text,text,text) to service_role;
