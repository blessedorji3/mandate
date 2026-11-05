begin;
select no_plan();

insert into auth.users (id, aud, role, email, created_at, updated_at)
values
  ('41000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'risk-review-owner@example.test', now(), now()),
  ('41000000-0000-4000-8000-000000000002', 'authenticated', 'authenticated', 'risk-review-other@example.test', now(), now());

insert into mandate_private.near_owner_wallets
  (owner_id, account_id, public_key, verified_at, revoked_at)
values
  ('41000000-0000-4000-8000-000000000001',
   'review-owner.testnet', 'ed25519:' || repeat('4',44), now(), null);

insert into public.security_policies
  (id, owner_id, name, version, active, max_amount_atomic, allowed_recipients,
   allowed_action_types, require_approval_for_token_approvals, require_approval_for_all_actions)
values
  ('42000000-0000-4000-8000-000000000001',
   '41000000-0000-4000-8000-000000000001',
   'Risk review test policy', 1, true, '1000000000000000000000',
   array['confirmwithmandate.testnet']::text[], array['transfer']::text[], true, true);

insert into public.authorization_decisions
  (id, owner_id, policy_id, policy_version, proposal_id, agent_id, action_type, outcome, reason, proposal)
values
  ('43000000-0000-4000-8000-000000000001',
   '41000000-0000-4000-8000-000000000001',
   '42000000-0000-4000-8000-000000000001', 1, 'review-warn-proposal',
   'phase2-test', 'transfer', 'REQUIRE_APPROVAL', 'COUNTERPARTY_RISK_REVIEW_REQUIRED',
   '{"id":"review-warn-proposal","network":"testnet","target":"confirmwithmandate.testnet","counterpartyRisk":{"outcome":"WARN","reasons":["Account history incomplete"]},"counterpartyRiskFingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'::jsonb),
  ('43000000-0000-4000-8000-000000000002',
   '41000000-0000-4000-8000-000000000001',
   '42000000-0000-4000-8000-000000000001', 1, 'review-block-proposal',
   'phase2-test', 'transfer', 'BLOCK', 'COUNTERPARTY_RISK_BLOCKED',
   '{"id":"review-block-proposal","network":"testnet","target":"confirmwithmandate.testnet","counterpartyRisk":{"outcome":"BLOCK","reasons":["Confirmed malicious counterparty"]},"counterpartyRiskFingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'::jsonb);

select ok(
  (select relrowsecurity from pg_class where oid = 'mandate_private.counterparty_risk_reviews'::regclass)
  and (select relrowsecurity from pg_class where oid = 'mandate_private.counterparty_risk_review_challenges'::regclass),
  'risk review challenge and approval records have RLS enabled'
);
select ok(
  not has_table_privilege('authenticated', 'mandate_private.counterparty_risk_reviews', 'SELECT')
  and not has_table_privilege('anon', 'mandate_private.counterparty_risk_reviews', 'SELECT')
  and has_table_privilege('service_role', 'mandate_private.counterparty_risk_reviews', 'SELECT'),
  'only trusted service-role code can read risk review records'
);

select throws_ok(
  $$select public.create_counterparty_risk_review_challenge_v1(
    '41000000-0000-4000-8000-000000000001',
    '44000000-0000-4000-8000-000000000001',
    'review-block-proposal',
    '42000000-0000-4000-8000-000000000001',
    1,
    'confirmwithmandate.testnet',
    repeat('b',64),
    'review-owner.testnet',
    'ed25519:' || repeat('4',44),
    repeat('a',64),
    'blocked reports cannot be acknowledged'
  )$$,
  'P0001',
  'Only the exact inspected WARN proposal can be reviewed',
  'BLOCK has no owner-review challenge path'
);

select is(
  public.create_counterparty_risk_review_challenge_v1(
    '41000000-0000-4000-8000-000000000001',
    '44000000-0000-4000-8000-000000000002',
    'review-warn-proposal',
    '42000000-0000-4000-8000-000000000001',
    1,
    'confirmwithmandate.testnet',
    repeat('a',64),
    'review-owner.testnet',
    'ed25519:' || repeat('4',44),
    repeat('c',64),
    'I acknowledge the WARN risk for this proposal only'
  ),
  '44000000-0000-4000-8000-000000000002'::uuid,
  'owner review challenge is bound to the exact WARN proposal and fingerprint'
);

select ok(
  (select count(*) = 1
   from public.get_counterparty_risk_review_challenge_v1(
     '41000000-0000-4000-8000-000000000001',
     '44000000-0000-4000-8000-000000000002'
   )),
  'review challenge can be retrieved only for its authenticated owner'
);

select ok(
  public.complete_counterparty_risk_review_v1(
    '41000000-0000-4000-8000-000000000001',
    '44000000-0000-4000-8000-000000000002',
    'ed25519-signature-proof-from-edge'
  ) is not null,
  'verified owner review creates a short-lived approval record'
);
select is(
  public.complete_counterparty_risk_review_v1(
    '41000000-0000-4000-8000-000000000001',
    '44000000-0000-4000-8000-000000000002',
    'ed25519-signature-proof-from-edge'
  ),
  null,
  'review challenge cannot be completed twice'
);
select is(
  (select outcome from public.authorization_decisions
   where owner_id = '41000000-0000-4000-8000-000000000001'
     and proposal_id = 'review-warn-proposal'),
  'REQUIRE_APPROVAL',
  'owner review does not rewrite the original decision'
);
select is(
  (select proposal->'counterpartyRisk'->>'outcome' from public.authorization_decisions
   where owner_id = '41000000-0000-4000-8000-000000000001'
     and proposal_id = 'review-warn-proposal'),
  'WARN',
  'owner review does not change the evaluator outcome'
);

-- A relink can keep the same account ID while changing its public key.
-- The old key's acknowledgement must not authorize the new key.
update mandate_private.near_owner_wallets
set public_key = 'ed25519:' || repeat('5',44)
where owner_id = '41000000-0000-4000-8000-000000000001'
  and account_id = 'review-owner.testnet';

select throws_ok(
  $$select public.create_near_transfer_challenge_v2(
    '41000000-0000-4000-8000-000000000001',
    '45000000-0000-4000-8000-000000000004',
    repeat('c',64), 'changed-key transfer attempt',
    'review-owner.testnet',
    '42000000-0000-4000-8000-000000000001',
    1,
    'review-warn-proposal',
    repeat('d',64)
  )$$,
  'P0001',
  'A current signed owner risk review is required',
  'a WARN acknowledgement from a previous wallet key cannot authorize a relinked key'
);

update mandate_private.near_owner_wallets
set public_key = 'ed25519:' || repeat('4',44)
where owner_id = '41000000-0000-4000-8000-000000000001'
  and account_id = 'review-owner.testnet';

select is(
  public.create_near_transfer_challenge_v2(
    '41000000-0000-4000-8000-000000000001',
    '45000000-0000-4000-8000-000000000001',
    repeat('d',64), 'test transaction authorization',
    'review-owner.testnet',
    '42000000-0000-4000-8000-000000000001',
    1,
    'review-warn-proposal',
    repeat('e',64)
  ),
  '45000000-0000-4000-8000-000000000001'::uuid,
  'WARN can create a wallet challenge only after matching signed owner review'
);

select is(
  (select wallet_signature from mandate_private.counterparty_risk_reviews
   where owner_id = '41000000-0000-4000-8000-000000000001'
     and proposal_id = 'review-warn-proposal'),
  'ed25519-signature-proof-from-edge',
  'the review record retains the verified wallet signature for audit'
);

select ok(
  (select consumed_at is not null
   from mandate_private.counterparty_risk_reviews
   where owner_id = '41000000-0000-4000-8000-000000000001'
     and proposal_id = 'review-warn-proposal'),
  'owner review is consumed when bound to the one-time wallet challenge'
);

update mandate_private.near_owner_wallets
set public_key = 'ed25519:' || repeat('5',44)
where owner_id = '41000000-0000-4000-8000-000000000001'
  and account_id = 'review-owner.testnet';

select is(
  public.finalize_near_transfer_challenge_v2(
    '41000000-0000-4000-8000-000000000001',
    '45000000-0000-4000-8000-000000000001',
    repeat('f',64)
  ),
  false,
  'finalization rejects a review signed by a key that is no longer registered'
);

update mandate_private.near_owner_wallets
set public_key = 'ed25519:' || repeat('4',44)
where owner_id = '41000000-0000-4000-8000-000000000001'
  and account_id = 'review-owner.testnet';

select is(
  public.finalize_near_transfer_challenge_v2(
    '41000000-0000-4000-8000-000000000001',
    '45000000-0000-4000-8000-000000000001',
    repeat('f',64)
  ),
  true,
  'reviewed WARN challenge can finalize into a short-lived authorization receipt'
);

update mandate_private.near_owner_wallets
set public_key = 'ed25519:' || repeat('5',44)
where owner_id = '41000000-0000-4000-8000-000000000001'
  and account_id = 'review-owner.testnet';

select is(
  public.consume_near_transfer_authorization_v2(
    '41000000-0000-4000-8000-000000000001',
    repeat('f',64),
    'review-owner.testnet',
    'testnet',
    'confirmwithmandate.testnet',
    'NEAR',
    '1000000000000000000000',
    'transfer',
    repeat('e',64)
  ),
  false,
  'receipt consumption rejects a review signed by a key that is no longer registered'
);

update mandate_private.near_owner_wallets
set public_key = 'ed25519:' || repeat('4',44)
where owner_id = '41000000-0000-4000-8000-000000000001'
  and account_id = 'review-owner.testnet';

update public.authorization_decisions
set proposal = jsonb_set(proposal, '{counterpartyRisk,outcome}', '"BLOCK"'::jsonb)
where owner_id = '41000000-0000-4000-8000-000000000001'
  and proposal_id = 'review-warn-proposal';

select is(
  public.consume_near_transfer_authorization_v2(
    '41000000-0000-4000-8000-000000000001',
    repeat('f',64),
    'review-owner.testnet',
    'testnet',
    'confirmwithmandate.testnet',
    'NEAR',
    '1000000000000000000000',
    'transfer',
    repeat('e',64)
  ),
  false,
  'a later BLOCK cannot be overridden by the previous owner WARN acknowledgement'
);

select throws_ok(
  $$select public.create_near_transfer_challenge_v2(
    '41000000-0000-4000-8000-000000000001',
    '45000000-0000-4000-8000-000000000002',
    repeat('1',64), 'blocked proposal attempt',
    'review-owner.testnet',
    '42000000-0000-4000-8000-000000000001',
    1,
    'review-block-proposal',
    repeat('2',64)
  )$$,
  'P0001',
  'Counterparty risk BLOCK or missing evidence cannot be authorized',
  'BLOCK cannot create a challenge even if review flow exists'
);


-- A fresh reviewed blocklist confirmation is terminal even if an owner previously
-- acknowledged a WARN fingerprint for the same proposal.
update public.authorization_decisions
set proposal = jsonb_set(proposal, '{counterpartyRisk,outcome}', '"WARN"'::jsonb)
where owner_id = '41000000-0000-4000-8000-000000000001'
  and proposal_id = 'review-warn-proposal';

select is(
  public.create_counterparty_risk_review_challenge_v1(
    '41000000-0000-4000-8000-000000000001',
    '44000000-0000-4000-8000-000000000003',
    'review-warn-proposal',
    '42000000-0000-4000-8000-000000000001',
    1,
    'confirmwithmandate.testnet',
    repeat('a',64),
    'review-owner.testnet',
    'ed25519:' || repeat('4',44),
    repeat('5',64),
    'I acknowledge this warning for this proposal only'
  ),
  '44000000-0000-4000-8000-000000000003'::uuid,
  'a fresh WARN review challenge can be created before blocklist confirmation'
);

insert into mandate_private.counterparty_blocklist
  (id, network, account_id, status, reason, evidence_ref, source_type,
   reporter_owner_id, reviewer_owner_id, reviewed_at)
values
  ('46000000-0000-4000-8000-000000000001',
   'testnet', 'confirmwithmandate.testnet', 'confirmed',
   'Confirmed malicious counterparty', 'https://evidence.example/confirmed/review',
   'security_advisory',
   '41000000-0000-4000-8000-000000000001',
   '41000000-0000-4000-8000-000000000002',
   now());

select is(
  public.complete_counterparty_risk_review_v1(
    '41000000-0000-4000-8000-000000000001',
    '44000000-0000-4000-8000-000000000003',
    'must-not-be-recorded'
  ),
  null,
  'a confirmed blocklist entry prevents completion of an outstanding WARN review'
);

select is(
  public.consume_near_transfer_authorization_v2(
    '41000000-0000-4000-8000-000000000001',
    repeat('f',64),
    'review-owner.testnet',
    'testnet',
    'confirmwithmandate.testnet',
    'NEAR',
    '1000000000000000000000',
    'transfer',
    repeat('e',64)
  ),
  false,
  'a newly confirmed blocklist report invalidates an earlier WARN review at receipt consumption'
);

select throws_ok(
  $$select public.create_near_transfer_challenge_v2(
    '41000000-0000-4000-8000-000000000001',
    '45000000-0000-4000-8000-000000000003',
    repeat('3',64), 'new attempt after blocklist confirmation',
    'review-owner.testnet',
    '42000000-0000-4000-8000-000000000001',
    1,
    'review-warn-proposal',
    repeat('4',64)
  )$$,
  'P0001',
  'Counterparty risk BLOCK cannot be overridden by owner review',
  'a fresh confirmed blocklist entry prevents new challenge creation despite a prior WARN acknowledgement'
);

select * from finish();
rollback;
