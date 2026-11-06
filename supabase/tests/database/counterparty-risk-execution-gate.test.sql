begin;
select no_plan();

insert into auth.users (id, aud, role, email, created_at, updated_at)
values ('31000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'risk-gate-owner@example.test', now(), now());

insert into mandate_private.near_owner_wallets
  (owner_id, account_id, public_key, verified_at, revoked_at)
values
  ('31000000-0000-4000-8000-000000000001',
   'owner-wallet.testnet',
   'ed25519:' || repeat('3',44),
   now(), null);

insert into public.security_policies
  (id, owner_id, name, version, active, max_amount_atomic, allowed_recipients, allowed_action_types,
   require_approval_for_token_approvals, require_approval_for_all_actions)
values
  ('32000000-0000-4000-8000-000000000001',
   '31000000-0000-4000-8000-000000000001',
   'Phase 2 risk gate', 1, true, '1000000000000000000000',
   array['confirmwithmandate.testnet']::text[], array['transfer']::text[], true, false);

insert into public.authorization_decisions
  (id, owner_id, policy_id, policy_version, proposal_id, agent_id, action_type, outcome, reason, proposal)
values
  ('33000000-0000-4000-8000-000000000001',
   '31000000-0000-4000-8000-000000000001',
   '32000000-0000-4000-8000-000000000001', 1, 'risk-warn-proposal',
   'phase2-test', 'transfer', 'REQUIRE_APPROVAL', 'COUNTERPARTY_RISK_REVIEW_REQUIRED',
   '{"id":"risk-warn-proposal","network":"testnet","target":"confirmwithmandate.testnet","counterpartyRisk":{"outcome":"WARN"}}'::jsonb),
  ('33000000-0000-4000-8000-000000000002',
   '31000000-0000-4000-8000-000000000001',
   '32000000-0000-4000-8000-000000000001', 1, 'risk-allow-proposal',
   'phase2-test', 'transfer', 'ALLOW', 'POLICY_CHECKS_PASSED',
   '{"id":"risk-allow-proposal","network":"testnet","target":"confirmwithmandate.testnet","counterpartyRisk":{"outcome":"ALLOW"}}'::jsonb);

select throws_ok(
  $$select public.create_near_transfer_challenge_v2(
    '31000000-0000-4000-8000-000000000001',
    '34000000-0000-4000-8000-000000000001',
    repeat('a',64), 'test challenge', 'owner-wallet.testnet',
    '32000000-0000-4000-8000-000000000001', 1,
    'risk-warn-proposal', repeat('b',64)
  )$$,
  'P0001',
  'A current signed owner risk review is required',
  'database refuses a challenge for a WARN proposal without a signed owner review'
);

select is(
  public.create_near_transfer_challenge_v2(
    '31000000-0000-4000-8000-000000000001',
    '34000000-0000-4000-8000-000000000002',
    repeat('c',64), 'test challenge', 'owner-wallet.testnet',
    '32000000-0000-4000-8000-000000000001', 1,
    'risk-allow-proposal', repeat('b',64)
  ),
  '34000000-0000-4000-8000-000000000002'::uuid,
  'database creates a challenge only for an ALLOW risk proposal'
);

select is(
  public.finalize_near_transfer_challenge_v2(
    '31000000-0000-4000-8000-000000000001',
    '34000000-0000-4000-8000-000000000002',
    repeat('d',64)
  ),
  true,
  'database finalizes a receipt only for the ALLOW risk proposal'
);

update public.authorization_decisions
set proposal = jsonb_set(proposal, '{counterpartyRisk,outcome}', '"WARN"'::jsonb)
where proposal_id = 'risk-allow-proposal'
  and owner_id = '31000000-0000-4000-8000-000000000001';

select is(
  public.consume_near_transfer_authorization_v2(
    '31000000-0000-4000-8000-000000000001', repeat('d',64),
    'owner-wallet.testnet', 'testnet', 'confirmwithmandate.testnet',
    'NEAR', '1000000000000000000000', 'transfer', repeat('b',64)
  ),
  false,
  'database refuses receipt consumption if the recorded risk no longer says ALLOW'
);

update public.authorization_decisions
set proposal = jsonb_set(proposal, '{counterpartyRisk,outcome}', '"ALLOW"'::jsonb)
where proposal_id = 'risk-allow-proposal'
  and owner_id = '31000000-0000-4000-8000-000000000001';

select is(
  public.consume_near_transfer_authorization_v2(
    '31000000-0000-4000-8000-000000000001', repeat('d',64),
    'owner-wallet.testnet', 'testnet', 'confirmwithmandate.testnet',
    'NEAR', '1000000000000000000000', 'transfer', repeat('b',64)
  ),
  true,
  'database consumes the one-time receipt while its risk record remains ALLOW'
);

select * from finish();
rollback;
