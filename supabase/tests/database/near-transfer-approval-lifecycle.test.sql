begin;
select no_plan();

-- This regression exercises the service-role database lifecycle after the
-- Edge Function has verified the owner's NEP-413 transfer-approval signature.
-- The active policy intentionally requires approval for every action.
insert into auth.users (id, aud, role, email, created_at, updated_at)
values (
  '51000000-0000-4000-8000-000000000001',
  'authenticated',
  'authenticated',
  'approval-lifecycle-owner@example.test',
  now(),
  now()
);

insert into mandate_private.near_owner_wallets
  (owner_id, account_id, public_key, verified_at, revoked_at)
values (
  '51000000-0000-4000-8000-000000000001',
  'approval-owner.testnet',
  'ed25519:' || repeat('6', 44),
  now(),
  null
);

insert into public.security_policies
  (id, owner_id, name, version, active, max_amount_atomic, allowed_recipients,
   allowed_action_types, require_approval_for_token_approvals, require_approval_for_all_actions)
values (
  '52000000-0000-4000-8000-000000000001',
  '51000000-0000-4000-8000-000000000001',
  'Approval required lifecycle policy',
  1,
  true,
  '1000000000000000000000',
  array['confirmwithmandate.testnet']::text[],
  array['transfer']::text[],
  true,
  true
);

insert into public.authorization_decisions
  (id, owner_id, policy_id, policy_version, proposal_id, agent_id, action_type,
   outcome, reason, proposal)
values (
  '53000000-0000-4000-8000-000000000001',
  '51000000-0000-4000-8000-000000000001',
  '52000000-0000-4000-8000-000000000001',
  1,
  'approval-required-proposal-1',
  'approval-lifecycle-test',
  'transfer',
  'REQUIRE_APPROVAL',
  'OWNER_APPROVAL_REQUIRED',
  jsonb_build_object(
    'id', 'approval-required-proposal-1',
    'agentId', 'approval-lifecycle-test',
    'actionType', 'transfer',
    'asset', 'NEAR',
    'amountAtomic', '1000000000000000000000',
    'target', 'confirmwithmandate.testnet',
    'network', 'testnet',
    'counterpartyRisk', jsonb_build_object(
      'outcome', 'ALLOW',
      'reasons', jsonb_build_array('Required risk evidence verified')
    ),
    'counterpartyRiskFingerprint', repeat('a', 64)
  )
);

select ok(
  (select require_approval_for_all_actions
   from public.security_policies
   where id = '52000000-0000-4000-8000-000000000001'),
  'fixture policy genuinely requires owner approval for every action'
);

select is(
  public.create_near_transfer_challenge_v2(
    '51000000-0000-4000-8000-000000000001',
    '54000000-0000-4000-8000-000000000001',
    repeat('b', 64),
    'MANDATE transfer approval for this exact proposal',
    'approval-owner.testnet',
    '52000000-0000-4000-8000-000000000001',
    1,
    'approval-required-proposal-1',
    repeat('e', 64)
  ),
  '54000000-0000-4000-8000-000000000001'::uuid,
  'approval-required policy can create the proposal-bound owner-signature challenge'
);

select is(
  public.finalize_near_transfer_challenge_v2(
    '51000000-0000-4000-8000-000000000001',
    '54000000-0000-4000-8000-000000000001',
    repeat('c', 64)
  ),
  true,
  'verified owner-signature boundary can finalize the challenge into a short-lived receipt'
);

select is(
  public.consume_near_transfer_authorization_v2(
    '51000000-0000-4000-8000-000000000001',
    repeat('c', 64),
    'approval-owner.testnet',
    'testnet',
    'confirmwithmandate.testnet',
    'NEAR',
    '1000000000000000000000',
    'transfer',
    repeat('e', 64)
  ),
  true,
  'approval-required policy receipt can be consumed only for the exact transfer binding'
);

select is(
  public.bind_near_transfer_transaction_v1(
    '51000000-0000-4000-8000-000000000001',
    repeat('c', 64),
    'approval-owner.testnet',
    repeat('1', 44),
    floor(extract(epoch from clock_timestamp() + interval '10 seconds') * 1000000000)::text
  ),
  true,
  'finalized Testnet transaction binds successfully after owner approval was required'
);

select is(
  (select transaction_hash
   from mandate_private.near_transfer_receipts
   where owner_id = '51000000-0000-4000-8000-000000000001'
     and token_hash = decode(repeat('c', 64), 'hex')),
  repeat('1', 44),
  'the verified transaction hash is retained on the exact consumed receipt'
);

select ok(
  (select verified_at is not null
   from mandate_private.near_transfer_receipts
   where owner_id = '51000000-0000-4000-8000-000000000001'
     and token_hash = decode(repeat('c', 64), 'hex')),
  'successful binding records a verification timestamp'
);

select is(
  public.bind_near_transfer_transaction_v1(
    '51000000-0000-4000-8000-000000000001',
    repeat('c', 64),
    'approval-owner.testnet',
    repeat('2', 44),
    floor(extract(epoch from clock_timestamp() + interval '10 seconds') * 1000000000)::text
  ),
  false,
  'a consumed receipt cannot be rebound to a different transaction hash'
);

select * from finish();
rollback;
