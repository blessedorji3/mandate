-- Proposal-bound, signed owner acknowledgements for counterparty WARN results.
create table if not exists mandate_private.counterparty_risk_review_challenges (
  id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  proposal_id text not null,
  policy_id uuid not null references public.security_policies(id) on delete cascade,
  policy_version integer not null check (policy_version > 0),
  target_account_id text not null check (target_account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'),
  risk_fingerprint text not null check (risk_fingerprint ~ '^[0-9a-f]{64}$'),
  signer_account_id text not null check (signer_account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'),
  signer_public_key text not null check (signer_public_key ~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'),
  nonce_hex text not null unique check (nonce_hex ~ '^[0-9a-f]{64}$'),
  message text not null check (length(message) between 1 and 2048),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists mandate_private.counterparty_risk_reviews (
  id uuid primary key default gen_random_uuid(),
  challenge_id uuid not null unique references mandate_private.counterparty_risk_review_challenges(id) on delete restrict,
  owner_id uuid not null references auth.users(id) on delete cascade,
  proposal_id text not null,
  policy_id uuid not null references public.security_policies(id) on delete restrict,
  policy_version integer not null check (policy_version > 0),
  target_account_id text not null check (target_account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'),
  risk_fingerprint text not null check (risk_fingerprint ~ '^[0-9a-f]{64}$'),
  signer_account_id text not null check (signer_account_id ~ '^[a-z0-9._-]{2,64}[.]testnet$'),
  signer_public_key text not null check (signer_public_key ~ '^ed25519:[1-9A-HJ-NP-Za-km-z]{40,50}$'),
  wallet_signature text not null check (length(wallet_signature) between 1 and 512),
  reviewed_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz
);

create index if not exists counterparty_risk_review_challenges_owner_created_idx
  on mandate_private.counterparty_risk_review_challenges(owner_id, created_at desc);
create index if not exists counterparty_risk_reviews_binding_idx
  on mandate_private.counterparty_risk_reviews(owner_id, proposal_id, risk_fingerprint, expires_at);

alter table mandate_private.counterparty_risk_review_challenges enable row level security;
alter table mandate_private.counterparty_risk_reviews enable row level security;
revoke all on mandate_private.counterparty_risk_review_challenges from public, anon, authenticated;
revoke all on mandate_private.counterparty_risk_reviews from public, anon, authenticated;
grant select, insert, update on mandate_private.counterparty_risk_review_challenges to service_role;
grant select, insert, update on mandate_private.counterparty_risk_reviews to service_role;

alter table mandate_private.near_transfer_challenges
  add column if not exists risk_review_id uuid references mandate_private.counterparty_risk_reviews(id) on delete restrict;
alter table mandate_private.near_transfer_receipts
  add column if not exists risk_review_id uuid references mandate_private.counterparty_risk_reviews(id) on delete restrict;

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
     now() + interval '3 minutes');
  return p_id;
end;
$$;

create or replace function public.get_counterparty_risk_review_challenge_v1(
  p_owner_id uuid, p_id uuid
) returns table (
  id uuid, proposal_id text, policy_id uuid, policy_version integer,
  target_account_id text, risk_fingerprint text, signer_account_id text,
  signer_public_key text, nonce_hex text, message text, expires_at timestamptz
)
language sql security definer
set search_path = pg_catalog, public, mandate_private
as $$
  select c.id, c.proposal_id, c.policy_id, c.policy_version, c.target_account_id,
         c.risk_fingerprint, c.signer_account_id, c.signer_public_key,
         c.nonce_hex, c.message, c.expires_at
  from mandate_private.counterparty_risk_review_challenges c
  where c.owner_id = p_owner_id and c.id = p_id
    and c.consumed_at is null and c.expires_at > now()
  limit 1;
$$;

create or replace function public.complete_counterparty_risk_review_v1(
  p_owner_id uuid, p_id uuid, p_wallet_signature text
) returns uuid
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare
  c mandate_private.counterparty_risk_review_challenges%rowtype;
  v_review_id uuid;
begin
  if p_owner_id is null or p_id is null or p_wallet_signature is null
     or length(p_wallet_signature) not between 1 and 512 then return null; end if;

  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));
  if exists (
    select 1 from mandate_private.counterparty_blocklist b
    where b.network = 'testnet'
      and b.account_id = 'confirmwithmandate.testnet'
      and b.status = 'confirmed'
  ) then
    return false;
  end if;
  if exists (select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending') then
    raise exception 'Risk review is unavailable while wallet recovery is pending';
  end if;

  select * into c from mandate_private.counterparty_risk_review_challenges
  where id = p_id and owner_id = p_owner_id
    and consumed_at is null and expires_at > now()
  for update;
  if not found then return null; end if;

  if not exists (select 1 from public.security_policies p
    where p.id = c.policy_id and p.owner_id = p_owner_id
      and p.active = true and p.version = c.policy_version)
    or not exists (select 1 from mandate_private.near_owner_wallets w
      where w.owner_id = p_owner_id and w.account_id = c.signer_account_id
        and w.public_key = c.signer_public_key and w.revoked_at is null)
    or not exists (
      select 1 from public.authorization_decisions d
      where d.owner_id = p_owner_id and d.proposal_id = c.proposal_id
        and d.policy_id = c.policy_id and d.policy_version = c.policy_version
        and d.outcome = 'REQUIRE_APPROVAL'
        and d.proposal->'counterpartyRisk'->>'outcome' = 'WARN'
        and d.proposal->>'counterpartyRiskFingerprint' = c.risk_fingerprint
        and d.proposal->>'target' = c.target_account_id
    ) then
    return null;
  end if;

  update mandate_private.counterparty_risk_review_challenges
  set consumed_at = now()
  where id = c.id and owner_id = p_owner_id and consumed_at is null;
  if not found then return null; end if;

  insert into mandate_private.counterparty_risk_reviews
    (challenge_id, owner_id, proposal_id, policy_id, policy_version, target_account_id,
     risk_fingerprint, signer_account_id, signer_public_key, wallet_signature, reviewed_at, expires_at)
  values
    (c.id, p_owner_id, c.proposal_id, c.policy_id, c.policy_version, c.target_account_id,
     c.risk_fingerprint, c.signer_account_id, c.signer_public_key, p_wallet_signature, now(),
     now() + interval '5 minutes')
  returning id into v_review_id;
  return v_review_id;
end;
$$;

create or replace function public.create_near_transfer_challenge_v2(
  p_owner_id uuid, p_id uuid, p_nonce_hex text, p_message text,
  p_signer_account_id text, p_policy_id uuid, p_policy_version integer,
  p_proposal_id text, p_action_digest text
) returns uuid
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare
  v_policy public.security_policies%rowtype;
  v_recent_count integer;
  v_risk_outcome text;
  v_risk_fingerprint text;
  v_review mandate_private.counterparty_risk_reviews%rowtype;
begin
  if p_owner_id is null or p_id is null or p_nonce_hex is null
     or p_message is null or p_signer_account_id is null
     or p_policy_id is null or p_policy_version is null
     or p_proposal_id is null or p_action_digest is null
     or p_nonce_hex !~ '^[0-9a-f]{64}
    raise exception 'Invalid challenge data';
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
    raise exception 'Financial authorizations are frozen while wallet recovery is pending';
  end if;
  if not exists (select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = p_signer_account_id and revoked_at is null) then
    raise exception 'The signing wallet is not the active MANDATE sender wallet';
  end if;

  select count(*) into v_recent_count from mandate_private.near_transfer_challenges
  where owner_id = p_owner_id and created_at > now() - interval '5 minutes';
  if v_recent_count >= 10 then raise exception 'Transfer challenge rate limit exceeded'; end if;
  if exists (select 1 from mandate_private.near_transfer_receipts
    where owner_id = p_owner_id and proposal_id = p_proposal_id) then
    raise exception 'This proposal already has a consumed authorization. Inspect a new proposal before attempting another transfer.';
  end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = p_proposal_id
    and d.policy_id = p_policy_id and d.policy_version = p_policy_version
    and d.proposal->>'id' = p_proposal_id
    and d.proposal->>'target' = 'confirmwithmandate.testnet'
    and d.proposal->>'network' = 'testnet'
    and d.outcome in ('ALLOW', 'REQUIRE_APPROVAL');
  if coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then
    raise exception 'Counterparty risk BLOCK or missing evidence cannot be authorized';
  end if;

  if v_risk_outcome = 'WARN' then
    select * into v_review from mandate_private.counterparty_risk_reviews
    where owner_id = p_owner_id and proposal_id = p_proposal_id
      and policy_id = p_policy_id and policy_version = p_policy_version
      and target_account_id = 'confirmwithmandate.testnet'
      and risk_fingerprint = v_risk_fingerprint
      and signer_account_id = p_signer_account_id
      and consumed_at is null and expires_at > now()
    order by reviewed_at desc limit 1
    for update;
    if not found then raise exception 'A current signed owner risk review is required'; end if;
    update mandate_private.counterparty_risk_reviews
      set consumed_at = now()
      where id = v_review.id and consumed_at is null;
    if not found then raise exception 'Owner risk review has already been used'; end if;
  else
    v_review.id := null;
  end if;

  select * into v_policy from public.security_policies
  where id = p_policy_id and owner_id = p_owner_id and active = true limit 1;
  if not found or v_policy.version <> p_policy_version then raise exception 'Policy changed or inactive'; end if;
  if not ('transfer' = any(v_policy.allowed_action_types))
     or not ('confirmwithmandate.testnet' = any(v_policy.allowed_recipients))
     or v_policy.max_amount_atomic::numeric < 1000000000000000000000::numeric then
    raise exception 'Current policy does not permit this transfer';
  end if;

  insert into mandate_private.near_transfer_challenges
    (id, owner_id, nonce_hex, message, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type,
     action_digest, risk_review_id, expires_at)
  values
    (p_id, p_owner_id, p_nonce_hex, p_message, p_signer_account_id, p_policy_id,
     p_policy_version, p_proposal_id, 'testnet', 'confirmwithmandate.testnet',
     'NEAR', '1000000000000000000000', 'transfer', p_action_digest,
     v_review.id, now() + interval '3 minutes');
  return p_id;
end;
$$;

create or replace function public.finalize_near_transfer_challenge_v2(
  p_owner_id uuid, p_id uuid, p_token_hash text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare
  c mandate_private.near_transfer_challenges%rowtype;
  v_risk_outcome text;
  v_risk_fingerprint text;
begin
  if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));
  if exists (
    select 1 from mandate_private.counterparty_blocklist b
    where b.network = 'testnet'
      and b.account_id = 'confirmwithmandate.testnet'
      and b.status = 'confirmed'
  ) then
    return false;
  end if;
  if exists (select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending') then return false; end if;

  select * into c from mandate_private.near_transfer_challenges
  where id = p_id and owner_id = p_owner_id and consumed_at is null and expires_at > now()
  for update;
  if not found then return false; end if;
  if not exists (select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = c.signer_account_id and revoked_at is null) then
    return false;
  end if;
  if not exists (select 1 from public.security_policies p
    where p.id = c.policy_id and p.owner_id = p_owner_id and p.active = true
      and p.version = c.policy_version and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric) then return false; end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = c.proposal_id
    and d.policy_id = c.policy_id and d.policy_version = c.policy_version;
  if v_risk_outcome = 'BLOCK' or coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then return false; end if;
  if v_risk_outcome = 'WARN' and (
    c.risk_review_id is null or not exists (
      select 1 from mandate_private.counterparty_risk_reviews r
      where r.id = c.risk_review_id and r.owner_id = p_owner_id
        and r.proposal_id = c.proposal_id and r.policy_id = c.policy_id
        and r.policy_version = c.policy_version and r.risk_fingerprint = v_risk_fingerprint
        and r.signer_account_id = c.signer_account_id
        and r.consumed_at is not null and r.expires_at > now()
    )
  ) then return false; end if;
  if v_risk_outcome = 'ALLOW' and c.risk_review_id is not null then return false; end if;

  update mandate_private.near_transfer_challenges set consumed_at = now()
  where id = c.id and owner_id = p_owner_id and consumed_at is null;
  if not found then return false; end if;

  insert into mandate_private.near_transfer_receipts
    (id, owner_id, token_hash, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type,
     action_digest, risk_review_id, expires_at)
  values
    (gen_random_uuid(), p_owner_id, decode(p_token_hash, 'hex'), c.signer_account_id,
     c.policy_id, c.policy_version, c.proposal_id, c.network, c.receiver_id,
     c.asset, c.amount_atomic, c.action_type, c.action_digest, c.risk_review_id,
     least(c.expires_at, now() + interval '90 seconds'));
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
declare
  r mandate_private.near_transfer_receipts%rowtype;
  v_risk_outcome text;
  v_risk_fingerprint text;
begin
  if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_action_digest !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));
  if exists (
    select 1 from mandate_private.counterparty_blocklist b
    where b.network = 'testnet'
      and b.account_id = 'confirmwithmandate.testnet'
      and b.status = 'confirmed'
  ) then
    return false;
  end if;
  if exists (select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending') then return false; end if;

  select * into r from mandate_private.near_transfer_receipts
  where owner_id = p_owner_id and token_hash = decode(p_token_hash, 'hex')
    and invalidated_at is null and consumed_at is null and expires_at > now()
    and signer_account_id = p_signer_account_id and network = p_network
    and receiver_id = p_receiver_id and asset = p_asset
    and amount_atomic = p_amount_atomic and action_type = p_action_type
    and action_digest = p_action_digest
  for update;
  if not found then return false; end if;
  if not exists (select 1 from mandate_private.near_owner_wallets w
    where w.owner_id = p_owner_id and w.account_id = p_signer_account_id and w.revoked_at is null)
    or not exists (select 1 from public.security_policies p
    where p.id = r.policy_id and p.owner_id = p_owner_id and p.active = true
      and p.version = r.policy_version and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric) then
    return false;
  end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = r.proposal_id
    and d.policy_id = r.policy_id and d.policy_version = r.policy_version;
  if v_risk_outcome = 'BLOCK' or coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then return false; end if;
  if v_risk_outcome = 'WARN' and (
    r.risk_review_id is null or not exists (
      select 1 from mandate_private.counterparty_risk_reviews rr
      where rr.id = r.risk_review_id and rr.owner_id = p_owner_id
        and rr.proposal_id = r.proposal_id and rr.policy_id = r.policy_id
        and rr.policy_version = r.policy_version and rr.risk_fingerprint = v_risk_fingerprint
        and rr.signer_account_id = r.signer_account_id
        and rr.consumed_at is not null and rr.expires_at > now()
    )
  ) then return false; end if;
  if v_risk_outcome = 'ALLOW' and r.risk_review_id is not null then return false; end if;

  update mandate_private.near_transfer_receipts
  set consumed_at = now()
  where id = r.id and owner_id = p_owner_id and consumed_at is null and invalidated_at is null;
  return found;
end;
$$;

create or replace function public.get_near_transfer_risk_binding_v1(
  p_owner_id uuid, p_token_hash text
) returns table (proposal_id text, policy_id uuid, policy_version integer, proposal jsonb)
language sql security definer
set search_path = pg_catalog, public, mandate_private
as $$
  select d.proposal_id, d.policy_id, d.policy_version, d.proposal
  from mandate_private.near_transfer_receipts r
  join public.authorization_decisions d
    on d.owner_id = r.owner_id and d.proposal_id = r.proposal_id
   and d.policy_id = r.policy_id and d.policy_version = r.policy_version
  where r.owner_id = p_owner_id and r.token_hash = decode(p_token_hash, 'hex')
    and r.invalidated_at is null and r.expires_at > now()
  limit 1;
$$;

revoke all on function public.create_counterparty_risk_review_challenge_v1(uuid,uuid,text,uuid,integer,text,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.get_counterparty_risk_review_challenge_v1(uuid,uuid) from public, anon, authenticated;
revoke all on function public.complete_counterparty_risk_review_v1(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.get_near_transfer_risk_binding_v1(uuid,text) from public, anon, authenticated;
grant execute on function public.create_counterparty_risk_review_challenge_v1(uuid,uuid,text,uuid,integer,text,text,text,text,text,text) to service_role;
grant execute on function public.get_counterparty_risk_review_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.complete_counterparty_risk_review_v1(uuid,uuid,text) to service_role;
grant execute on function public.get_near_transfer_risk_binding_v1(uuid,text) to service_role;

     or p_action_digest !~ '^[0-9a-f]{64}
    raise exception 'Invalid challenge data';
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
    raise exception 'Financial authorizations are frozen while wallet recovery is pending';
  end if;
  if not exists (select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = p_signer_account_id and revoked_at is null) then
    raise exception 'The signing wallet is not the active MANDATE sender wallet';
  end if;

  select count(*) into v_recent_count from mandate_private.near_transfer_challenges
  where owner_id = p_owner_id and created_at > now() - interval '5 minutes';
  if v_recent_count >= 10 then raise exception 'Transfer challenge rate limit exceeded'; end if;
  if exists (select 1 from mandate_private.near_transfer_receipts
    where owner_id = p_owner_id and proposal_id = p_proposal_id) then
    raise exception 'This proposal already has a consumed authorization. Inspect a new proposal before attempting another transfer.';
  end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = p_proposal_id
    and d.policy_id = p_policy_id and d.policy_version = p_policy_version
    and d.proposal->>'id' = p_proposal_id
    and d.proposal->>'target' = 'confirmwithmandate.testnet'
    and d.proposal->>'network' = 'testnet'
    and d.outcome in ('ALLOW', 'REQUIRE_APPROVAL');
  if coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then
    raise exception 'Counterparty risk BLOCK or missing evidence cannot be authorized';
  end if;

  if v_risk_outcome = 'WARN' then
    select * into v_review from mandate_private.counterparty_risk_reviews
    where owner_id = p_owner_id and proposal_id = p_proposal_id
      and policy_id = p_policy_id and policy_version = p_policy_version
      and target_account_id = 'confirmwithmandate.testnet'
      and risk_fingerprint = v_risk_fingerprint
      and signer_account_id = p_signer_account_id
      and consumed_at is null and expires_at > now()
    order by reviewed_at desc limit 1
    for update;
    if not found then raise exception 'A current signed owner risk review is required'; end if;
    update mandate_private.counterparty_risk_reviews
      set consumed_at = now()
      where id = v_review.id and consumed_at is null;
    if not found then raise exception 'Owner risk review has already been used'; end if;
  else
    v_review.id := null;
  end if;

  select * into v_policy from public.security_policies
  where id = p_policy_id and owner_id = p_owner_id and active = true limit 1;
  if not found or v_policy.version <> p_policy_version then raise exception 'Policy changed or inactive'; end if;
  if not ('transfer' = any(v_policy.allowed_action_types))
     or not ('confirmwithmandate.testnet' = any(v_policy.allowed_recipients))
     or v_policy.max_amount_atomic::numeric < 1000000000000000000000::numeric then
    raise exception 'Current policy does not permit this transfer';
  end if;

  insert into mandate_private.near_transfer_challenges
    (id, owner_id, nonce_hex, message, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type,
     action_digest, risk_review_id, expires_at)
  values
    (p_id, p_owner_id, p_nonce_hex, p_message, p_signer_account_id, p_policy_id,
     p_policy_version, p_proposal_id, 'testnet', 'confirmwithmandate.testnet',
     'NEAR', '1000000000000000000000', 'transfer', p_action_digest,
     v_review.id, now() + interval '3 minutes');
  return p_id;
end;
$$;

create or replace function public.finalize_near_transfer_challenge_v2(
  p_owner_id uuid, p_id uuid, p_token_hash text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare
  c mandate_private.near_transfer_challenges%rowtype;
  v_risk_outcome text;
  v_risk_fingerprint text;
begin
  if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));
  if exists (
    select 1 from mandate_private.counterparty_blocklist b
    where b.network = 'testnet'
      and b.account_id = 'confirmwithmandate.testnet'
      and b.status = 'confirmed'
  ) then
    return false;
  end if;
  if exists (select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending') then return false; end if;

  select * into c from mandate_private.near_transfer_challenges
  where id = p_id and owner_id = p_owner_id and consumed_at is null and expires_at > now()
  for update;
  if not found then return false; end if;
  if not exists (select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = c.signer_account_id and revoked_at is null) then
    return false;
  end if;
  if not exists (select 1 from public.security_policies p
    where p.id = c.policy_id and p.owner_id = p_owner_id and p.active = true
      and p.version = c.policy_version and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric) then return false; end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = c.proposal_id
    and d.policy_id = c.policy_id and d.policy_version = c.policy_version;
  if v_risk_outcome = 'BLOCK' or coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then return false; end if;
  if v_risk_outcome = 'WARN' and (
    c.risk_review_id is null or not exists (
      select 1 from mandate_private.counterparty_risk_reviews r
      where r.id = c.risk_review_id and r.owner_id = p_owner_id
        and r.proposal_id = c.proposal_id and r.policy_id = c.policy_id
        and r.policy_version = c.policy_version and r.risk_fingerprint = v_risk_fingerprint
        and r.signer_account_id = c.signer_account_id
        and r.consumed_at is not null and r.expires_at > now()
    )
  ) then return false; end if;
  if v_risk_outcome = 'ALLOW' and c.risk_review_id is not null then return false; end if;

  update mandate_private.near_transfer_challenges set consumed_at = now()
  where id = c.id and owner_id = p_owner_id and consumed_at is null;
  if not found then return false; end if;

  insert into mandate_private.near_transfer_receipts
    (id, owner_id, token_hash, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type,
     action_digest, risk_review_id, expires_at)
  values
    (gen_random_uuid(), p_owner_id, decode(p_token_hash, 'hex'), c.signer_account_id,
     c.policy_id, c.policy_version, c.proposal_id, c.network, c.receiver_id,
     c.asset, c.amount_atomic, c.action_type, c.action_digest, c.risk_review_id,
     least(c.expires_at, now() + interval '90 seconds'));
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
declare
  r mandate_private.near_transfer_receipts%rowtype;
  v_risk_outcome text;
  v_risk_fingerprint text;
begin
  if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_action_digest !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));
  if exists (
    select 1 from mandate_private.counterparty_blocklist b
    where b.network = 'testnet'
      and b.account_id = 'confirmwithmandate.testnet'
      and b.status = 'confirmed'
  ) then
    return false;
  end if;
  if exists (select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending') then return false; end if;

  select * into r from mandate_private.near_transfer_receipts
  where owner_id = p_owner_id and token_hash = decode(p_token_hash, 'hex')
    and invalidated_at is null and consumed_at is null and expires_at > now()
    and signer_account_id = p_signer_account_id and network = p_network
    and receiver_id = p_receiver_id and asset = p_asset
    and amount_atomic = p_amount_atomic and action_type = p_action_type
    and action_digest = p_action_digest
  for update;
  if not found then return false; end if;
  if not exists (select 1 from mandate_private.near_owner_wallets w
    where w.owner_id = p_owner_id and w.account_id = p_signer_account_id and w.revoked_at is null)
    or not exists (select 1 from public.security_policies p
    where p.id = r.policy_id and p.owner_id = p_owner_id and p.active = true
      and p.version = r.policy_version and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric) then
    return false;
  end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = r.proposal_id
    and d.policy_id = r.policy_id and d.policy_version = r.policy_version;
  if v_risk_outcome = 'BLOCK' or coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then return false; end if;
  if v_risk_outcome = 'WARN' and (
    r.risk_review_id is null or not exists (
      select 1 from mandate_private.counterparty_risk_reviews rr
      where rr.id = r.risk_review_id and rr.owner_id = p_owner_id
        and rr.proposal_id = r.proposal_id and rr.policy_id = r.policy_id
        and rr.policy_version = r.policy_version and rr.risk_fingerprint = v_risk_fingerprint
        and rr.signer_account_id = r.signer_account_id
        and rr.consumed_at is not null and rr.expires_at > now()
    )
  ) then return false; end if;
  if v_risk_outcome = 'ALLOW' and r.risk_review_id is not null then return false; end if;

  update mandate_private.near_transfer_receipts
  set consumed_at = now()
  where id = r.id and owner_id = p_owner_id and consumed_at is null and invalidated_at is null;
  return found;
end;
$$;

create or replace function public.get_near_transfer_risk_binding_v1(
  p_owner_id uuid, p_token_hash text
) returns table (proposal_id text, policy_id uuid, policy_version integer, proposal jsonb)
language sql security definer
set search_path = pg_catalog, public, mandate_private
as $$
  select d.proposal_id, d.policy_id, d.policy_version, d.proposal
  from mandate_private.near_transfer_receipts r
  join public.authorization_decisions d
    on d.owner_id = r.owner_id and d.proposal_id = r.proposal_id
   and d.policy_id = r.policy_id and d.policy_version = r.policy_version
  where r.owner_id = p_owner_id and r.token_hash = decode(p_token_hash, 'hex')
    and r.invalidated_at is null and r.expires_at > now()
  limit 1;
$$;

revoke all on function public.create_counterparty_risk_review_challenge_v1(uuid,uuid,text,uuid,integer,text,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.get_counterparty_risk_review_challenge_v1(uuid,uuid) from public, anon, authenticated;
revoke all on function public.complete_counterparty_risk_review_v1(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.get_near_transfer_risk_binding_v1(uuid,text) from public, anon, authenticated;
grant execute on function public.create_counterparty_risk_review_challenge_v1(uuid,uuid,text,uuid,integer,text,text,text,text,text,text) to service_role;
grant execute on function public.get_counterparty_risk_review_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.complete_counterparty_risk_review_v1(uuid,uuid,text) to service_role;
grant execute on function public.get_near_transfer_risk_binding_v1(uuid,text) to service_role;
 or length(p_message) > 2048
     or p_signer_account_id !~ '^[a-z0-9._-]{2,64}[.]testnet
    raise exception 'Invalid challenge data';
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
    raise exception 'Financial authorizations are frozen while wallet recovery is pending';
  end if;
  if not exists (select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = p_signer_account_id and revoked_at is null) then
    raise exception 'The signing wallet is not the active MANDATE sender wallet';
  end if;

  select count(*) into v_recent_count from mandate_private.near_transfer_challenges
  where owner_id = p_owner_id and created_at > now() - interval '5 minutes';
  if v_recent_count >= 10 then raise exception 'Transfer challenge rate limit exceeded'; end if;
  if exists (select 1 from mandate_private.near_transfer_receipts
    where owner_id = p_owner_id and proposal_id = p_proposal_id) then
    raise exception 'This proposal already has a consumed authorization. Inspect a new proposal before attempting another transfer.';
  end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = p_proposal_id
    and d.policy_id = p_policy_id and d.policy_version = p_policy_version
    and d.proposal->>'id' = p_proposal_id
    and d.proposal->>'target' = 'confirmwithmandate.testnet'
    and d.proposal->>'network' = 'testnet'
    and d.outcome in ('ALLOW', 'REQUIRE_APPROVAL');
  if coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then
    raise exception 'Counterparty risk BLOCK or missing evidence cannot be authorized';
  end if;

  if v_risk_outcome = 'WARN' then
    select * into v_review from mandate_private.counterparty_risk_reviews
    where owner_id = p_owner_id and proposal_id = p_proposal_id
      and policy_id = p_policy_id and policy_version = p_policy_version
      and target_account_id = 'confirmwithmandate.testnet'
      and risk_fingerprint = v_risk_fingerprint
      and signer_account_id = p_signer_account_id
      and consumed_at is null and expires_at > now()
    order by reviewed_at desc limit 1
    for update;
    if not found then raise exception 'A current signed owner risk review is required'; end if;
    update mandate_private.counterparty_risk_reviews
      set consumed_at = now()
      where id = v_review.id and consumed_at is null;
    if not found then raise exception 'Owner risk review has already been used'; end if;
  else
    v_review.id := null;
  end if;

  select * into v_policy from public.security_policies
  where id = p_policy_id and owner_id = p_owner_id and active = true limit 1;
  if not found or v_policy.version <> p_policy_version then raise exception 'Policy changed or inactive'; end if;
  if not ('transfer' = any(v_policy.allowed_action_types))
     or not ('confirmwithmandate.testnet' = any(v_policy.allowed_recipients))
     or v_policy.max_amount_atomic::numeric < 1000000000000000000000::numeric then
    raise exception 'Current policy does not permit this transfer';
  end if;

  insert into mandate_private.near_transfer_challenges
    (id, owner_id, nonce_hex, message, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type,
     action_digest, risk_review_id, expires_at)
  values
    (p_id, p_owner_id, p_nonce_hex, p_message, p_signer_account_id, p_policy_id,
     p_policy_version, p_proposal_id, 'testnet', 'confirmwithmandate.testnet',
     'NEAR', '1000000000000000000000', 'transfer', p_action_digest,
     v_review.id, now() + interval '3 minutes');
  return p_id;
end;
$$;

create or replace function public.finalize_near_transfer_challenge_v2(
  p_owner_id uuid, p_id uuid, p_token_hash text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare
  c mandate_private.near_transfer_challenges%rowtype;
  v_risk_outcome text;
  v_risk_fingerprint text;
begin
  if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));
  if exists (
    select 1 from mandate_private.counterparty_blocklist b
    where b.network = 'testnet'
      and b.account_id = 'confirmwithmandate.testnet'
      and b.status = 'confirmed'
  ) then
    return false;
  end if;
  if exists (select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending') then return false; end if;

  select * into c from mandate_private.near_transfer_challenges
  where id = p_id and owner_id = p_owner_id and consumed_at is null and expires_at > now()
  for update;
  if not found then return false; end if;
  if not exists (select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = c.signer_account_id and revoked_at is null) then
    return false;
  end if;
  if not exists (select 1 from public.security_policies p
    where p.id = c.policy_id and p.owner_id = p_owner_id and p.active = true
      and p.version = c.policy_version and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric) then return false; end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = c.proposal_id
    and d.policy_id = c.policy_id and d.policy_version = c.policy_version;
  if v_risk_outcome = 'BLOCK' or coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then return false; end if;
  if v_risk_outcome = 'WARN' and (
    c.risk_review_id is null or not exists (
      select 1 from mandate_private.counterparty_risk_reviews r
      where r.id = c.risk_review_id and r.owner_id = p_owner_id
        and r.proposal_id = c.proposal_id and r.policy_id = c.policy_id
        and r.policy_version = c.policy_version and r.risk_fingerprint = v_risk_fingerprint
        and r.signer_account_id = c.signer_account_id
        and r.consumed_at is not null and r.expires_at > now()
    )
  ) then return false; end if;
  if v_risk_outcome = 'ALLOW' and c.risk_review_id is not null then return false; end if;

  update mandate_private.near_transfer_challenges set consumed_at = now()
  where id = c.id and owner_id = p_owner_id and consumed_at is null;
  if not found then return false; end if;

  insert into mandate_private.near_transfer_receipts
    (id, owner_id, token_hash, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type,
     action_digest, risk_review_id, expires_at)
  values
    (gen_random_uuid(), p_owner_id, decode(p_token_hash, 'hex'), c.signer_account_id,
     c.policy_id, c.policy_version, c.proposal_id, c.network, c.receiver_id,
     c.asset, c.amount_atomic, c.action_type, c.action_digest, c.risk_review_id,
     least(c.expires_at, now() + interval '90 seconds'));
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
declare
  r mandate_private.near_transfer_receipts%rowtype;
  v_risk_outcome text;
  v_risk_fingerprint text;
begin
  if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_action_digest !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));
  if exists (
    select 1 from mandate_private.counterparty_blocklist b
    where b.network = 'testnet'
      and b.account_id = 'confirmwithmandate.testnet'
      and b.status = 'confirmed'
  ) then
    return false;
  end if;
  if exists (select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending') then return false; end if;

  select * into r from mandate_private.near_transfer_receipts
  where owner_id = p_owner_id and token_hash = decode(p_token_hash, 'hex')
    and invalidated_at is null and consumed_at is null and expires_at > now()
    and signer_account_id = p_signer_account_id and network = p_network
    and receiver_id = p_receiver_id and asset = p_asset
    and amount_atomic = p_amount_atomic and action_type = p_action_type
    and action_digest = p_action_digest
  for update;
  if not found then return false; end if;
  if not exists (select 1 from mandate_private.near_owner_wallets w
    where w.owner_id = p_owner_id and w.account_id = p_signer_account_id and w.revoked_at is null)
    or not exists (select 1 from public.security_policies p
    where p.id = r.policy_id and p.owner_id = p_owner_id and p.active = true
      and p.version = r.policy_version and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric) then
    return false;
  end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = r.proposal_id
    and d.policy_id = r.policy_id and d.policy_version = r.policy_version;
  if v_risk_outcome = 'BLOCK' or coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then return false; end if;
  if v_risk_outcome = 'WARN' and (
    r.risk_review_id is null or not exists (
      select 1 from mandate_private.counterparty_risk_reviews rr
      where rr.id = r.risk_review_id and rr.owner_id = p_owner_id
        and rr.proposal_id = r.proposal_id and rr.policy_id = r.policy_id
        and rr.policy_version = r.policy_version and rr.risk_fingerprint = v_risk_fingerprint
        and rr.signer_account_id = r.signer_account_id
        and rr.consumed_at is not null and rr.expires_at > now()
    )
  ) then return false; end if;
  if v_risk_outcome = 'ALLOW' and r.risk_review_id is not null then return false; end if;

  update mandate_private.near_transfer_receipts
  set consumed_at = now()
  where id = r.id and owner_id = p_owner_id and consumed_at is null and invalidated_at is null;
  return found;
end;
$$;

create or replace function public.get_near_transfer_risk_binding_v1(
  p_owner_id uuid, p_token_hash text
) returns table (proposal_id text, policy_id uuid, policy_version integer, proposal jsonb)
language sql security definer
set search_path = pg_catalog, public, mandate_private
as $$
  select d.proposal_id, d.policy_id, d.policy_version, d.proposal
  from mandate_private.near_transfer_receipts r
  join public.authorization_decisions d
    on d.owner_id = r.owner_id and d.proposal_id = r.proposal_id
   and d.policy_id = r.policy_id and d.policy_version = r.policy_version
  where r.owner_id = p_owner_id and r.token_hash = decode(p_token_hash, 'hex')
    and r.invalidated_at is null and r.expires_at > now()
  limit 1;
$$;

revoke all on function public.create_counterparty_risk_review_challenge_v1(uuid,uuid,text,uuid,integer,text,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.get_counterparty_risk_review_challenge_v1(uuid,uuid) from public, anon, authenticated;
revoke all on function public.complete_counterparty_risk_review_v1(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.get_near_transfer_risk_binding_v1(uuid,text) from public, anon, authenticated;
grant execute on function public.create_counterparty_risk_review_challenge_v1(uuid,uuid,text,uuid,integer,text,text,text,text,text,text) to service_role;
grant execute on function public.get_counterparty_risk_review_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.complete_counterparty_risk_review_v1(uuid,uuid,text) to service_role;
grant execute on function public.get_near_transfer_risk_binding_v1(uuid,text) to service_role;

     or p_proposal_id !~ '^[a-zA-Z0-9_-]{1,128}
    raise exception 'Invalid challenge data';
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
    raise exception 'Financial authorizations are frozen while wallet recovery is pending';
  end if;
  if not exists (select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = p_signer_account_id and revoked_at is null) then
    raise exception 'The signing wallet is not the active MANDATE sender wallet';
  end if;

  select count(*) into v_recent_count from mandate_private.near_transfer_challenges
  where owner_id = p_owner_id and created_at > now() - interval '5 minutes';
  if v_recent_count >= 10 then raise exception 'Transfer challenge rate limit exceeded'; end if;
  if exists (select 1 from mandate_private.near_transfer_receipts
    where owner_id = p_owner_id and proposal_id = p_proposal_id) then
    raise exception 'This proposal already has a consumed authorization. Inspect a new proposal before attempting another transfer.';
  end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = p_proposal_id
    and d.policy_id = p_policy_id and d.policy_version = p_policy_version
    and d.proposal->>'id' = p_proposal_id
    and d.proposal->>'target' = 'confirmwithmandate.testnet'
    and d.proposal->>'network' = 'testnet'
    and d.outcome in ('ALLOW', 'REQUIRE_APPROVAL');
  if coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then
    raise exception 'Counterparty risk BLOCK or missing evidence cannot be authorized';
  end if;

  if v_risk_outcome = 'WARN' then
    select * into v_review from mandate_private.counterparty_risk_reviews
    where owner_id = p_owner_id and proposal_id = p_proposal_id
      and policy_id = p_policy_id and policy_version = p_policy_version
      and target_account_id = 'confirmwithmandate.testnet'
      and risk_fingerprint = v_risk_fingerprint
      and signer_account_id = p_signer_account_id
      and consumed_at is null and expires_at > now()
    order by reviewed_at desc limit 1
    for update;
    if not found then raise exception 'A current signed owner risk review is required'; end if;
    update mandate_private.counterparty_risk_reviews
      set consumed_at = now()
      where id = v_review.id and consumed_at is null;
    if not found then raise exception 'Owner risk review has already been used'; end if;
  else
    v_review.id := null;
  end if;

  select * into v_policy from public.security_policies
  where id = p_policy_id and owner_id = p_owner_id and active = true limit 1;
  if not found or v_policy.version <> p_policy_version then raise exception 'Policy changed or inactive'; end if;
  if not ('transfer' = any(v_policy.allowed_action_types))
     or not ('confirmwithmandate.testnet' = any(v_policy.allowed_recipients))
     or v_policy.max_amount_atomic::numeric < 1000000000000000000000::numeric then
    raise exception 'Current policy does not permit this transfer';
  end if;

  insert into mandate_private.near_transfer_challenges
    (id, owner_id, nonce_hex, message, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type,
     action_digest, risk_review_id, expires_at)
  values
    (p_id, p_owner_id, p_nonce_hex, p_message, p_signer_account_id, p_policy_id,
     p_policy_version, p_proposal_id, 'testnet', 'confirmwithmandate.testnet',
     'NEAR', '1000000000000000000000', 'transfer', p_action_digest,
     v_review.id, now() + interval '3 minutes');
  return p_id;
end;
$$;

create or replace function public.finalize_near_transfer_challenge_v2(
  p_owner_id uuid, p_id uuid, p_token_hash text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare
  c mandate_private.near_transfer_challenges%rowtype;
  v_risk_outcome text;
  v_risk_fingerprint text;
begin
  if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));
  if exists (
    select 1 from mandate_private.counterparty_blocklist b
    where b.network = 'testnet'
      and b.account_id = 'confirmwithmandate.testnet'
      and b.status = 'confirmed'
  ) then
    return false;
  end if;
  if exists (select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending') then return false; end if;

  select * into c from mandate_private.near_transfer_challenges
  where id = p_id and owner_id = p_owner_id and consumed_at is null and expires_at > now()
  for update;
  if not found then return false; end if;
  if not exists (select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = c.signer_account_id and revoked_at is null) then
    return false;
  end if;
  if not exists (select 1 from public.security_policies p
    where p.id = c.policy_id and p.owner_id = p_owner_id and p.active = true
      and p.version = c.policy_version and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric) then return false; end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = c.proposal_id
    and d.policy_id = c.policy_id and d.policy_version = c.policy_version;
  if v_risk_outcome = 'BLOCK' or coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then return false; end if;
  if v_risk_outcome = 'WARN' and (
    c.risk_review_id is null or not exists (
      select 1 from mandate_private.counterparty_risk_reviews r
      where r.id = c.risk_review_id and r.owner_id = p_owner_id
        and r.proposal_id = c.proposal_id and r.policy_id = c.policy_id
        and r.policy_version = c.policy_version and r.risk_fingerprint = v_risk_fingerprint
        and r.signer_account_id = c.signer_account_id
        and r.consumed_at is not null and r.expires_at > now()
    )
  ) then return false; end if;
  if v_risk_outcome = 'ALLOW' and c.risk_review_id is not null then return false; end if;

  update mandate_private.near_transfer_challenges set consumed_at = now()
  where id = c.id and owner_id = p_owner_id and consumed_at is null;
  if not found then return false; end if;

  insert into mandate_private.near_transfer_receipts
    (id, owner_id, token_hash, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type,
     action_digest, risk_review_id, expires_at)
  values
    (gen_random_uuid(), p_owner_id, decode(p_token_hash, 'hex'), c.signer_account_id,
     c.policy_id, c.policy_version, c.proposal_id, c.network, c.receiver_id,
     c.asset, c.amount_atomic, c.action_type, c.action_digest, c.risk_review_id,
     least(c.expires_at, now() + interval '90 seconds'));
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
declare
  r mandate_private.near_transfer_receipts%rowtype;
  v_risk_outcome text;
  v_risk_fingerprint text;
begin
  if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_action_digest !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));
  if exists (
    select 1 from mandate_private.counterparty_blocklist b
    where b.network = 'testnet'
      and b.account_id = 'confirmwithmandate.testnet'
      and b.status = 'confirmed'
  ) then
    return false;
  end if;
  if exists (select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending') then return false; end if;

  select * into r from mandate_private.near_transfer_receipts
  where owner_id = p_owner_id and token_hash = decode(p_token_hash, 'hex')
    and invalidated_at is null and consumed_at is null and expires_at > now()
    and signer_account_id = p_signer_account_id and network = p_network
    and receiver_id = p_receiver_id and asset = p_asset
    and amount_atomic = p_amount_atomic and action_type = p_action_type
    and action_digest = p_action_digest
  for update;
  if not found then return false; end if;
  if not exists (select 1 from mandate_private.near_owner_wallets w
    where w.owner_id = p_owner_id and w.account_id = p_signer_account_id and w.revoked_at is null)
    or not exists (select 1 from public.security_policies p
    where p.id = r.policy_id and p.owner_id = p_owner_id and p.active = true
      and p.version = r.policy_version and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric) then
    return false;
  end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = r.proposal_id
    and d.policy_id = r.policy_id and d.policy_version = r.policy_version;
  if v_risk_outcome = 'BLOCK' or coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then return false; end if;
  if v_risk_outcome = 'WARN' and (
    r.risk_review_id is null or not exists (
      select 1 from mandate_private.counterparty_risk_reviews rr
      where rr.id = r.risk_review_id and rr.owner_id = p_owner_id
        and rr.proposal_id = r.proposal_id and rr.policy_id = r.policy_id
        and rr.policy_version = r.policy_version and rr.risk_fingerprint = v_risk_fingerprint
        and rr.signer_account_id = r.signer_account_id
        and rr.consumed_at is not null and rr.expires_at > now()
    )
  ) then return false; end if;
  if v_risk_outcome = 'ALLOW' and r.risk_review_id is not null then return false; end if;

  update mandate_private.near_transfer_receipts
  set consumed_at = now()
  where id = r.id and owner_id = p_owner_id and consumed_at is null and invalidated_at is null;
  return found;
end;
$$;

create or replace function public.get_near_transfer_risk_binding_v1(
  p_owner_id uuid, p_token_hash text
) returns table (proposal_id text, policy_id uuid, policy_version integer, proposal jsonb)
language sql security definer
set search_path = pg_catalog, public, mandate_private
as $$
  select d.proposal_id, d.policy_id, d.policy_version, d.proposal
  from mandate_private.near_transfer_receipts r
  join public.authorization_decisions d
    on d.owner_id = r.owner_id and d.proposal_id = r.proposal_id
   and d.policy_id = r.policy_id and d.policy_version = r.policy_version
  where r.owner_id = p_owner_id and r.token_hash = decode(p_token_hash, 'hex')
    and r.invalidated_at is null and r.expires_at > now()
  limit 1;
$$;

revoke all on function public.create_counterparty_risk_review_challenge_v1(uuid,uuid,text,uuid,integer,text,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.get_counterparty_risk_review_challenge_v1(uuid,uuid) from public, anon, authenticated;
revoke all on function public.complete_counterparty_risk_review_v1(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.get_near_transfer_risk_binding_v1(uuid,text) from public, anon, authenticated;
grant execute on function public.create_counterparty_risk_review_challenge_v1(uuid,uuid,text,uuid,integer,text,text,text,text,text,text) to service_role;
grant execute on function public.get_counterparty_risk_review_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.complete_counterparty_risk_review_v1(uuid,uuid,text) to service_role;
grant execute on function public.get_near_transfer_risk_binding_v1(uuid,text) to service_role;
 then
    raise exception 'Invalid challenge data';
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
    raise exception 'Financial authorizations are frozen while wallet recovery is pending';
  end if;
  if not exists (select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = p_signer_account_id and revoked_at is null) then
    raise exception 'The signing wallet is not the active MANDATE sender wallet';
  end if;

  select count(*) into v_recent_count from mandate_private.near_transfer_challenges
  where owner_id = p_owner_id and created_at > now() - interval '5 minutes';
  if v_recent_count >= 10 then raise exception 'Transfer challenge rate limit exceeded'; end if;
  if exists (select 1 from mandate_private.near_transfer_receipts
    where owner_id = p_owner_id and proposal_id = p_proposal_id) then
    raise exception 'This proposal already has a consumed authorization. Inspect a new proposal before attempting another transfer.';
  end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = p_proposal_id
    and d.policy_id = p_policy_id and d.policy_version = p_policy_version
    and d.proposal->>'id' = p_proposal_id
    and d.proposal->>'target' = 'confirmwithmandate.testnet'
    and d.proposal->>'network' = 'testnet'
    and d.outcome in ('ALLOW', 'REQUIRE_APPROVAL');
  if coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then
    raise exception 'Counterparty risk BLOCK or missing evidence cannot be authorized';
  end if;

  if v_risk_outcome = 'WARN' then
    select * into v_review from mandate_private.counterparty_risk_reviews
    where owner_id = p_owner_id and proposal_id = p_proposal_id
      and policy_id = p_policy_id and policy_version = p_policy_version
      and target_account_id = 'confirmwithmandate.testnet'
      and risk_fingerprint = v_risk_fingerprint
      and signer_account_id = p_signer_account_id
      and consumed_at is null and expires_at > now()
    order by reviewed_at desc limit 1
    for update;
    if not found then raise exception 'A current signed owner risk review is required'; end if;
    update mandate_private.counterparty_risk_reviews
      set consumed_at = now()
      where id = v_review.id and consumed_at is null;
    if not found then raise exception 'Owner risk review has already been used'; end if;
  else
    v_review.id := null;
  end if;

  select * into v_policy from public.security_policies
  where id = p_policy_id and owner_id = p_owner_id and active = true limit 1;
  if not found or v_policy.version <> p_policy_version then raise exception 'Policy changed or inactive'; end if;
  if not ('transfer' = any(v_policy.allowed_action_types))
     or not ('confirmwithmandate.testnet' = any(v_policy.allowed_recipients))
     or v_policy.max_amount_atomic::numeric < 1000000000000000000000::numeric then
    raise exception 'Current policy does not permit this transfer';
  end if;

  insert into mandate_private.near_transfer_challenges
    (id, owner_id, nonce_hex, message, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type,
     action_digest, risk_review_id, expires_at)
  values
    (p_id, p_owner_id, p_nonce_hex, p_message, p_signer_account_id, p_policy_id,
     p_policy_version, p_proposal_id, 'testnet', 'confirmwithmandate.testnet',
     'NEAR', '1000000000000000000000', 'transfer', p_action_digest,
     v_review.id, now() + interval '3 minutes');
  return p_id;
end;
$$;

create or replace function public.finalize_near_transfer_challenge_v2(
  p_owner_id uuid, p_id uuid, p_token_hash text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, public, mandate_private
as $$
declare
  c mandate_private.near_transfer_challenges%rowtype;
  v_risk_outcome text;
  v_risk_fingerprint text;
begin
  if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));
  if exists (
    select 1 from mandate_private.counterparty_blocklist b
    where b.network = 'testnet'
      and b.account_id = 'confirmwithmandate.testnet'
      and b.status = 'confirmed'
  ) then
    return false;
  end if;
  if exists (select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending') then return false; end if;

  select * into c from mandate_private.near_transfer_challenges
  where id = p_id and owner_id = p_owner_id and consumed_at is null and expires_at > now()
  for update;
  if not found then return false; end if;
  if not exists (select 1 from mandate_private.near_owner_wallets
    where owner_id = p_owner_id and account_id = c.signer_account_id and revoked_at is null) then
    return false;
  end if;
  if not exists (select 1 from public.security_policies p
    where p.id = c.policy_id and p.owner_id = p_owner_id and p.active = true
      and p.version = c.policy_version and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric) then return false; end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = c.proposal_id
    and d.policy_id = c.policy_id and d.policy_version = c.policy_version;
  if v_risk_outcome = 'BLOCK' or coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then return false; end if;
  if v_risk_outcome = 'WARN' and (
    c.risk_review_id is null or not exists (
      select 1 from mandate_private.counterparty_risk_reviews r
      where r.id = c.risk_review_id and r.owner_id = p_owner_id
        and r.proposal_id = c.proposal_id and r.policy_id = c.policy_id
        and r.policy_version = c.policy_version and r.risk_fingerprint = v_risk_fingerprint
        and r.signer_account_id = c.signer_account_id
        and r.consumed_at is not null and r.expires_at > now()
    )
  ) then return false; end if;
  if v_risk_outcome = 'ALLOW' and c.risk_review_id is not null then return false; end if;

  update mandate_private.near_transfer_challenges set consumed_at = now()
  where id = c.id and owner_id = p_owner_id and consumed_at is null;
  if not found then return false; end if;

  insert into mandate_private.near_transfer_receipts
    (id, owner_id, token_hash, signer_account_id, policy_id, policy_version,
     proposal_id, network, receiver_id, asset, amount_atomic, action_type,
     action_digest, risk_review_id, expires_at)
  values
    (gen_random_uuid(), p_owner_id, decode(p_token_hash, 'hex'), c.signer_account_id,
     c.policy_id, c.policy_version, c.proposal_id, c.network, c.receiver_id,
     c.asset, c.amount_atomic, c.action_type, c.action_digest, c.risk_review_id,
     least(c.expires_at, now() + interval '90 seconds'));
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
declare
  r mandate_private.near_transfer_receipts%rowtype;
  v_risk_outcome text;
  v_risk_fingerprint text;
begin
  if p_owner_id is null or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_action_digest !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_owner_id::text, 0));
  if exists (
    select 1 from mandate_private.counterparty_blocklist b
    where b.network = 'testnet'
      and b.account_id = 'confirmwithmandate.testnet'
      and b.status = 'confirmed'
  ) then
    return false;
  end if;
  if exists (select 1 from mandate_private.near_wallet_recovery_requests
    where owner_id = p_owner_id and status = 'pending') then return false; end if;

  select * into r from mandate_private.near_transfer_receipts
  where owner_id = p_owner_id and token_hash = decode(p_token_hash, 'hex')
    and invalidated_at is null and consumed_at is null and expires_at > now()
    and signer_account_id = p_signer_account_id and network = p_network
    and receiver_id = p_receiver_id and asset = p_asset
    and amount_atomic = p_amount_atomic and action_type = p_action_type
    and action_digest = p_action_digest
  for update;
  if not found then return false; end if;
  if not exists (select 1 from mandate_private.near_owner_wallets w
    where w.owner_id = p_owner_id and w.account_id = p_signer_account_id and w.revoked_at is null)
    or not exists (select 1 from public.security_policies p
    where p.id = r.policy_id and p.owner_id = p_owner_id and p.active = true
      and p.version = r.policy_version and 'transfer' = any(p.allowed_action_types)
      and 'confirmwithmandate.testnet' = any(p.allowed_recipients)
      and p.max_amount_atomic::numeric >= 1000000000000000000000::numeric) then
    return false;
  end if;

  select d.proposal->'counterpartyRisk'->>'outcome',
         d.proposal->>'counterpartyRiskFingerprint'
    into v_risk_outcome, v_risk_fingerprint
  from public.authorization_decisions d
  where d.owner_id = p_owner_id and d.proposal_id = r.proposal_id
    and d.policy_id = r.policy_id and d.policy_version = r.policy_version;
  if v_risk_outcome = 'BLOCK' or coalesce(v_risk_outcome, '') not in ('ALLOW', 'WARN') then return false; end if;
  if v_risk_outcome = 'WARN' and (
    r.risk_review_id is null or not exists (
      select 1 from mandate_private.counterparty_risk_reviews rr
      where rr.id = r.risk_review_id and rr.owner_id = p_owner_id
        and rr.proposal_id = r.proposal_id and rr.policy_id = r.policy_id
        and rr.policy_version = r.policy_version and rr.risk_fingerprint = v_risk_fingerprint
        and rr.signer_account_id = r.signer_account_id
        and rr.consumed_at is not null and rr.expires_at > now()
    )
  ) then return false; end if;
  if v_risk_outcome = 'ALLOW' and r.risk_review_id is not null then return false; end if;

  update mandate_private.near_transfer_receipts
  set consumed_at = now()
  where id = r.id and owner_id = p_owner_id and consumed_at is null and invalidated_at is null;
  return found;
end;
$$;

create or replace function public.get_near_transfer_risk_binding_v1(
  p_owner_id uuid, p_token_hash text
) returns table (proposal_id text, policy_id uuid, policy_version integer, proposal jsonb)
language sql security definer
set search_path = pg_catalog, public, mandate_private
as $$
  select d.proposal_id, d.policy_id, d.policy_version, d.proposal
  from mandate_private.near_transfer_receipts r
  join public.authorization_decisions d
    on d.owner_id = r.owner_id and d.proposal_id = r.proposal_id
   and d.policy_id = r.policy_id and d.policy_version = r.policy_version
  where r.owner_id = p_owner_id and r.token_hash = decode(p_token_hash, 'hex')
    and r.invalidated_at is null and r.expires_at > now()
  limit 1;
$$;

revoke all on function public.create_counterparty_risk_review_challenge_v1(uuid,uuid,text,uuid,integer,text,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.get_counterparty_risk_review_challenge_v1(uuid,uuid) from public, anon, authenticated;
revoke all on function public.complete_counterparty_risk_review_v1(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.get_near_transfer_risk_binding_v1(uuid,text) from public, anon, authenticated;
grant execute on function public.create_counterparty_risk_review_challenge_v1(uuid,uuid,text,uuid,integer,text,text,text,text,text,text) to service_role;
grant execute on function public.get_counterparty_risk_review_challenge_v1(uuid,uuid) to service_role;
grant execute on function public.complete_counterparty_risk_review_v1(uuid,uuid,text) to service_role;
grant execute on function public.get_near_transfer_risk_binding_v1(uuid,text) to service_role;
