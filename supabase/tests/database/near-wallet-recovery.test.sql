begin;
select no_plan();

-- All fixtures are transaction-scoped and use synthetic local-only users.
insert into auth.users (id, aud, role, email, created_at, updated_at)
values
 ('10000000-0000-4000-8000-000000000001','authenticated','authenticated','recovery-a@example.test',now(),now()),
 ('10000000-0000-4000-8000-000000000002','authenticated','authenticated','recovery-b@example.test',now(),now());

select ok(
  (select relrowsecurity from pg_class where oid='mandate_private.near_wallet_recovery_credentials'::regclass),
  'recovery credentials table has RLS enabled'
);
select ok(
  (select relrowsecurity from pg_class where oid='mandate_private.near_wallet_recovery_requests'::regclass),
  'recovery requests table has RLS enabled'
);
select ok(
  not has_function_privilege('anon','public.start_near_wallet_recovery_v1(uuid,uuid,text)','EXECUTE'),
  'anonymous role cannot execute recovery start RPC'
);
select ok(
  has_function_privilege('service_role','public.start_near_wallet_recovery_v1(uuid,uuid,text)','EXECUTE'),
  'service role can execute recovery start RPC'
);

-- Owner A: establish an independent recovery code and register the first wallet.
select is(
  public.create_near_wallet_recovery_setup_challenge_v1(
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    null,
    repeat('a',64),
    'local recovery setup proof'
  ),
  '20000000-0000-4000-8000-000000000001'::uuid,
  'recovery setup challenge is created for a new owner'
);
select is(
  public.complete_near_wallet_recovery_setup_v1(
    '10000000-0000-4000-8000-000000000001',
    '20000000-0000-4000-8000-000000000001',
    repeat('1',64),
    null
  ),
  true,
  'new owner can establish an independent recovery-code verifier'
);
select is(
  (select encode(code_hash,'hex') from mandate_private.near_wallet_recovery_credentials
   where owner_id='10000000-0000-4000-8000-000000000001'),
  repeat('1',64),
  'only the recovery-code hash is stored'
);
select is(
  public.create_near_wallet_registration_challenge_v1(
    '10000000-0000-4000-8000-000000000001',
    '30000000-0000-4000-8000-000000000001',
    'old-wallet-a.testnet',
    repeat('b',64),
    'local initial wallet registration'
  ),
  '30000000-0000-4000-8000-000000000001'::uuid,
  'initial wallet registration challenge is created after recovery setup'
);
select is(
  public.complete_near_wallet_registration_v1(
    '10000000-0000-4000-8000-000000000001',
    '30000000-0000-4000-8000-000000000001',
    'ed25519:' || repeat('1',44)
  ),
  true,
  'initial wallet registration succeeds'
);

-- Owner B cannot read owner A's recovery challenge.
select is(
  (select count(*)::integer
   from public.get_near_wallet_recovery_action_challenge_v1(
     '10000000-0000-4000-8000-000000000002',
     '40000000-0000-4000-8000-000000000001'
   )),
  0,
  'recovery challenge lookup is owner-bound'
);

-- Seed an outstanding receipt to prove recovery start invalidates old authorization.
insert into mandate_private.near_transfer_receipts (
 id,owner_id,token_hash,signer_account_id,policy_id,policy_version,proposal_id,
 network,receiver_id,asset,amount_atomic,action_type,action_digest,expires_at
) values (
 '50000000-0000-4000-8000-000000000001',
 '10000000-0000-4000-8000-000000000001',
 decode(repeat('c',64),'hex'),
 'old-wallet-a.testnet',
 '60000000-0000-4000-8000-000000000001',
 1,'recovery-before-existing-receipt',
 'testnet','confirmwithmandate.testnet','NEAR',
 '1000000000000000000000','transfer',repeat('d',64),now()+interval '2 minutes'
);

select is(
  public.create_near_wallet_recovery_action_challenge_v1(
    '10000000-0000-4000-8000-000000000001',
    '40000000-0000-4000-8000-000000000001',
    '70000000-0000-4000-8000-000000000001',
    'start',
    'new-wallet-a.testnet',
    'ed25519:' || repeat('2',44),
    repeat('e',64),
    'local start recovery proof'
  ),
  '40000000-0000-4000-8000-000000000001'::uuid,
  'replacement-wallet start challenge is created'
);
select is(
  public.start_near_wallet_recovery_v1(
    '10000000-0000-4000-8000-000000000001',
    '40000000-0000-4000-8000-000000000001',
    repeat('9',64)
  ),
  false,
  'incorrect recovery code cannot start wallet replacement'
);
select is(
  public.start_near_wallet_recovery_v1(
    '10000000-0000-4000-8000-000000000001',
    '40000000-0000-4000-8000-000000000001',
    repeat('1',64)
  ),
  true,
  'correct independent recovery code starts wallet replacement'
);
select is(
  public.start_near_wallet_recovery_v1(
    '10000000-0000-4000-8000-000000000001',
    '40000000-0000-4000-8000-000000000001',
    repeat('1',64)
  ),
  false,
  'start challenge cannot be replayed'
);
select is(
  (select request_status from public.get_near_wallet_recovery_lifecycle_v1(
    '10000000-0000-4000-8000-000000000001'
  )),
  'pending',
  'recovery lifecycle reports a pending request'
);
select ok(
  (select available_at >= started_at + interval '24 hours'
   from mandate_private.near_wallet_recovery_requests
   where id='70000000-0000-4000-8000-000000000001'),
  'replacement cannot become available before the 24-hour delay'
);
select throws_ok(
  $$select public.create_near_transfer_challenge_v2(
    '10000000-0000-4000-8000-000000000001',
    '80000000-0000-4000-8000-000000000001',
    repeat('f',64),'blocked while recovering','old-wallet-a.testnet',
    '60000000-0000-4000-8000-000000000001',1,'blocked-proposal',repeat('a',64)
  )$$,
  'P0001',
  'Financial authorizations are frozen while wallet recovery is pending',
  'database rejects new transfer challenges during pending recovery'
);
select is(
  public.consume_near_transfer_authorization_v2(
    '10000000-0000-4000-8000-000000000001',repeat('c',64),
    'old-wallet-a.testnet','testnet','confirmwithmandate.testnet','NEAR',
    '1000000000000000000000','transfer',repeat('d',64)
  ),
  false,
  'an existing transfer receipt cannot be consumed during pending recovery'
);
select is(
  public.bind_near_transfer_transaction_v1(
    '10000000-0000-4000-8000-000000000001',repeat('c',64),
    'old-wallet-a.testnet',repeat('1',44),'999999999999999999999999999'
  ),
  false,
  'transaction binding is blocked during pending recovery'
);
select ok(
  (select consumed_at is not null from mandate_private.near_transfer_receipts
   where id='50000000-0000-4000-8000-000000000001'),
  'recovery start invalidates outstanding transfer receipts'
);
select throws_ok(
  $$select public.create_near_wallet_recovery_action_challenge_v1(
    '10000000-0000-4000-8000-000000000001',
    '40000000-0000-4000-8000-000000000002',
    '70000000-0000-4000-8000-000000000001',
    'finalize','new-wallet-a.testnet','ed25519:' || repeat('2',44),
    repeat('f',64),'too early to finalize'
  )$$,
  'P0001',
  'Recovery is not ready for finalization',
  'finalization challenge is denied before the 24-hour delay'
);

-- Move only the synthetic local fixture clock forward; no production data or clock is touched.
update mandate_private.near_wallet_recovery_requests
set available_at=now()-interval '1 minute'
where id='70000000-0000-4000-8000-000000000001';

select is(
  public.create_near_wallet_recovery_action_challenge_v1(
    '10000000-0000-4000-8000-000000000001',
    '40000000-0000-4000-8000-000000000003',
    '70000000-0000-4000-8000-000000000001',
    'finalize',
    'new-wallet-a.testnet',
    'ed25519:' || repeat('2',44),
    repeat('b',64),
    'local finalization proof'
  ),
  '40000000-0000-4000-8000-000000000003'::uuid,
  'finalization challenge is created after the delay elapses'
);
select is(
  public.finalize_near_wallet_recovery_v1(
    '10000000-0000-4000-8000-000000000001',
    '40000000-0000-4000-8000-000000000003',
    repeat('2',64)
  ),
  true,
  'wallet replacement finalizes with a fresh matching challenge'
);
select ok(
  (select revoked_at is not null from mandate_private.near_owner_wallets
   where owner_id='10000000-0000-4000-8000-000000000001'
     and account_id='old-wallet-a.testnet'),
  'old wallet is revoked after successful replacement'
);
select ok(
  (select revoked_at is null from mandate_private.near_owner_wallets
   where owner_id='10000000-0000-4000-8000-000000000001'
     and account_id='new-wallet-a.testnet'),
  'replacement wallet becomes the active wallet'
);
select is(
  (select status from mandate_private.near_wallet_recovery_requests
   where id='70000000-0000-4000-8000-000000000001'),
  'completed',
  'recovery request reaches completed terminal state'
);
select is(
  (select encode(code_hash,'hex') from mandate_private.near_wallet_recovery_credentials
   where owner_id='10000000-0000-4000-8000-000000000001'),
  repeat('2',64),
  'recovery credential is rotated to the new verifier'
);
select ok(
  (select rotated_at is not null and consumed_at is null
   from mandate_private.near_wallet_recovery_credentials
   where owner_id='10000000-0000-4000-8000-000000000001'),
  'rotated recovery credential is active and marked rotated'
);
select is(
  public.finalize_near_wallet_recovery_v1(
    '10000000-0000-4000-8000-000000000001',
    '40000000-0000-4000-8000-000000000003',
    repeat('3',64)
  ),
  false,
  'finalization challenge cannot be replayed'
);

-- Owner B exercises the explicit cancellation path.
select public.create_near_wallet_recovery_setup_challenge_v1(
 '10000000-0000-4000-8000-000000000002',
 '20000000-0000-4000-8000-000000000002',null,repeat('c',64),'owner B setup'
);
select is(
 public.complete_near_wallet_recovery_setup_v1(
  '10000000-0000-4000-8000-000000000002',
  '20000000-0000-4000-8000-000000000002',repeat('4',64),null
 ),
 true,'second owner can independently establish recovery'
);
select public.create_near_wallet_registration_challenge_v1(
 '10000000-0000-4000-8000-000000000002',
 '30000000-0000-4000-8000-000000000002',
 'old-wallet-b.testnet',repeat('d',64),'owner B wallet registration'
);
select is(
 public.complete_near_wallet_registration_v1(
  '10000000-0000-4000-8000-000000000002',
  '30000000-0000-4000-8000-000000000002',
  'ed25519:' || repeat('3',44)
 ),
 true,'second owner registers an independent wallet'
);
select public.create_near_wallet_recovery_action_challenge_v1(
 '10000000-0000-4000-8000-000000000002',
 '40000000-0000-4000-8000-000000000004',
 '70000000-0000-4000-8000-000000000002',
 'start','new-wallet-b.testnet','ed25519:' || repeat('4',44),
 repeat('e',64),'owner B start proof'
);
-- An active wallet belonging to a different MANDATE owner cannot be selected as a replacement.
select throws_ok(
 $$select public.create_near_wallet_recovery_action_challenge_v1(
  '10000000-0000-4000-8000-000000000001',
  '40000000-0000-4000-8000-000000000005',
  '70000000-0000-4000-8000-000000000005',
  'start','old-wallet-b.testnet','ed25519:' || repeat('3',44),
  repeat('f',64),'attempt to substitute another owner wallet'
 )$$,
 'P0001',
 'The replacement NEAR wallet is already active under another MANDATE account',
 'replacement wallet already active for another owner is rejected'
);

-- Expired challenge rows are not returned to the Edge Function verifier.
insert into mandate_private.near_wallet_recovery_action_challenges
 (id,owner_id,request_id,action,account_id,public_key,nonce_hex,message,expires_at)
 values(
  '40000000-0000-4000-8000-000000000006',
  '10000000-0000-4000-8000-000000000002',
  '70000000-0000-4000-8000-000000000006',
  'start','new-wallet-b.testnet','ed25519:' || repeat('4',44),
  repeat('a',64),'expired local recovery challenge',now()-interval '1 second'
 );
select is(
 (select count(*)::integer from public.get_near_wallet_recovery_action_challenge_v1(
  '10000000-0000-4000-8000-000000000002',
  '40000000-0000-4000-8000-000000000006'
 )),
 0,
 'expired recovery challenge cannot be retrieved for signature verification'
);

select is(
 public.start_near_wallet_recovery_v1(
  '10000000-0000-4000-8000-000000000002',
  '40000000-0000-4000-8000-000000000004',repeat('4',64)
 ),
 true,'second owner can start recovery'
);
select is(
 public.cancel_near_wallet_recovery_v1(
  '10000000-0000-4000-8000-000000000002',
  '70000000-0000-4000-8000-000000000002',repeat('9',64)
 ),
 false,'incorrect recovery code cannot cancel a pending request'
);
select is(
 public.cancel_near_wallet_recovery_v1(
  '10000000-0000-4000-8000-000000000002',
  '70000000-0000-4000-8000-000000000002',repeat('4',64)
 ),
 true,'correct recovery code can cancel a pending request'
);
select is(
 (select request_status from public.get_near_wallet_recovery_lifecycle_v1(
  '10000000-0000-4000-8000-000000000002'
 )),
 'cancelled','cancelled request is no longer pending'
);
select ok(
 (select revoked_at is null from mandate_private.near_owner_wallets
  where owner_id='10000000-0000-4000-8000-000000000002'
    and account_id='old-wallet-b.testnet'),
 'cancellation preserves the existing active wallet'
);

select * from finish();
rollback;
