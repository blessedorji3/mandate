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
select ok(
  not has_function_privilege('authenticated','public.start_near_wallet_recovery_v1(uuid,uuid,text)','EXECUTE'),
  'authenticated users cannot execute recovery start RPC directly'
);
select ok(
  not has_table_privilege('authenticated','mandate_private.near_wallet_recovery_requests','SELECT')
  and not has_table_privilege('authenticated','mandate_private.near_wallet_recovery_action_challenges','SELECT')
  and not has_table_privilege('authenticated','mandate_private.near_wallet_recovery_credentials','SELECT'),
  'authenticated users cannot directly read private recovery records'
);
select ok(
  has_table_privilege('service_role','mandate_private.near_wallet_recovery_requests','SELECT')
  and has_table_privilege('service_role','mandate_private.near_wallet_recovery_action_challenges','SELECT')
  and has_table_privilege('service_role','mandate_private.near_wallet_recovery_credentials','SELECT'),
  'service role retains access required by the Edge Function'
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

-- Recovery-code reset is authorized by the active wallet and rotates only its verifier.
select ok(
  (select relrowsecurity from pg_class where oid='mandate_private.near_wallet_recovery_reset_challenges'::regclass),
  'recovery reset challenge table has RLS enabled'
);
select ok(
  not has_table_privilege('authenticated','mandate_private.near_wallet_recovery_reset_challenges','SELECT')
  and not has_function_privilege('authenticated','public.complete_near_wallet_recovery_reset_v1(uuid,uuid,text)','EXECUTE')
  and has_function_privilege('service_role','public.complete_near_wallet_recovery_reset_v1(uuid,uuid,text)','EXECUTE'),
  'only service role can access recovery reset records and RPCs'
);
select is(
  public.create_near_wallet_recovery_reset_challenge_v1(
    '10000000-0000-4000-8000-000000000001',
    '90000000-0000-4000-8000-000000000001',
    'new-wallet-a.testnet',
    'ed25519:' || repeat('2',44),
    repeat('a',64),
    'local recovery-code reset proof',
    'https://mandate-snowy.vercel.app'
  ),
  '90000000-0000-4000-8000-000000000001'::uuid,
  'active registered wallet can create a recovery-code reset challenge'
);
select throws_ok(
  $$select public.create_near_wallet_recovery_reset_challenge_v1(
    '10000000-0000-4000-8000-000000000001',
    '90000000-0000-4000-8000-000000000009',
    'old-wallet-a.testnet',
    'ed25519:' || repeat('1',44),
    repeat('9',64),
    'revoked wallet reset attempt',
    'https://mandate-snowy.vercel.app'
  )$$,
  'P0001',
  'The signing wallet is not the active registered MANDATE wallet',
  'revoked historical wallet cannot create a recovery-code reset challenge'
);
select is(
  (select callback_url from public.get_near_wallet_recovery_reset_challenge_v1(
    '10000000-0000-4000-8000-000000000001',
    '90000000-0000-4000-8000-000000000001'
  )),
  'https://mandate-snowy.vercel.app',
  'recovery reset challenge stores the exact callback URL'
);
select is(
  (select count(*)::integer from public.get_near_wallet_recovery_reset_challenge_v1(
    '10000000-0000-4000-8000-000000000002',
    '90000000-0000-4000-8000-000000000001'
  )),
  0,
  'recovery reset challenge lookup is owner-bound'
);
select is(
  public.complete_near_wallet_recovery_reset_v1(
    '10000000-0000-4000-8000-000000000001',
    '90000000-0000-4000-8000-000000000001',
    repeat('3',64)
  ),
  true,
  'valid active-wallet challenge atomically resets the recovery verifier'
);
select is(
  (select encode(code_hash,'hex') from mandate_private.near_wallet_recovery_credentials
   where owner_id='10000000-0000-4000-8000-000000000001'),
  repeat('3',64),
  'recovery reset stores only the new verifier hash'
);
select is(
  public.complete_near_wallet_recovery_reset_v1(
    '10000000-0000-4000-8000-000000000001',
    '90000000-0000-4000-8000-000000000001',
    repeat('4',64)
  ),
  false,
  'recovery reset challenge cannot be replayed'
);
select is(
  (select count(*)::integer from public.get_near_wallet_recovery_reset_challenge_v1(
    '10000000-0000-4000-8000-000000000001',
    '90000000-0000-4000-8000-000000000001'
  )),
  0,
  'successful reset invalidates the challenge against later reuse'
);
select ok(
  not exists (
    select 1 from information_schema.columns
    where table_schema='mandate_private'
      and table_name='near_wallet_recovery_credentials'
      and column_name in ('recovery_code','plaintext_code','code')
  ),
  'recovery credential schema has no plaintext recovery-code column'
);
select ok(
  (select account_id='new-wallet-a.testnet' and revoked_at is null
   from mandate_private.near_owner_wallets
   where owner_id='10000000-0000-4000-8000-000000000001' and revoked_at is null),
  'recovery-code reset leaves the active registered wallet unchanged'
);
select ok(
  (select request_status is distinct from 'pending'
   from public.get_near_wallet_recovery_lifecycle_v1('10000000-0000-4000-8000-000000000001')),
  'recovery-code reset does not start a 24-hour wallet recovery request'
);
select ok(
  (select rotated_at is not null and consumed_at is null
   from mandate_private.near_wallet_recovery_credentials
   where owner_id='10000000-0000-4000-8000-000000000001'),
  'reset credential remains active and is marked rotated'
);
select is(
  public.complete_near_wallet_recovery_reset_v1(
    '10000000-0000-4000-8000-000000000002',
    '90000000-0000-4000-8000-000000000001',
    repeat('4',64)
  ),
  false,
  'another MANDATE owner cannot complete this reset challenge'
);
select public.create_near_wallet_recovery_reset_challenge_v1(
  '10000000-0000-4000-8000-000000000001',
  '90000000-0000-4000-8000-000000000002',
  'new-wallet-a.testnet','ed25519:' || repeat('2',44),
  repeat('b',64),'second reset rate-limit fixture', 'https://mandate-snowy.vercel.app'
);
select public.create_near_wallet_recovery_reset_challenge_v1(
  '10000000-0000-4000-8000-000000000001',
  '90000000-0000-4000-8000-000000000003',
  'new-wallet-a.testnet','ed25519:' || repeat('2',44),
  repeat('c',64),'third reset rate-limit fixture', 'https://mandate-snowy.vercel.app'
);
select throws_ok(
  $$select public.create_near_wallet_recovery_reset_challenge_v1(
    '10000000-0000-4000-8000-000000000001',
    '90000000-0000-4000-8000-000000000004',
    'new-wallet-a.testnet','ed25519:' || repeat('2',44),
    repeat('d',64),'fourth reset rate-limit fixture', 'https://mandate-snowy.vercel.app'
  )$$,
  'P0001',
  'Recovery-code reset rate limit exceeded',
  'fourth recovery-code reset challenge within one hour is rejected'
);
insert into mandate_private.near_wallet_recovery_reset_challenges
  (id,owner_id,account_id,public_key,nonce_hex,message,callback_url,expires_at)
values (
  '90000000-0000-4000-8000-000000000005',
  '10000000-0000-4000-8000-000000000001',
  'new-wallet-a.testnet','ed25519:' || repeat('2',44),
  repeat('e',64),'expired reset challenge','https://mandate-snowy.vercel.app',now()-interval '1 second'
);
select is(
  (select count(*)::integer from public.get_near_wallet_recovery_reset_challenge_v1(
    '10000000-0000-4000-8000-000000000001',
    '90000000-0000-4000-8000-000000000005'
  )),
  0,
  'expired recovery-code reset challenge cannot be retrieved'
);
select is(
  public.complete_near_wallet_recovery_reset_v1(
    '10000000-0000-4000-8000-000000000001',
    '90000000-0000-4000-8000-000000000005',
    repeat('5',64)
  ),
  false,
  'expired recovery-code reset challenge cannot rotate the verifier'
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
select throws_ok(
 $$select public.create_near_wallet_recovery_reset_challenge_v1(
  '10000000-0000-4000-8000-000000000002',
  '90000000-0000-4000-8000-000000000006',
  'old-wallet-b.testnet','ed25519:' || repeat('3',44),
  repeat('f',64),'reset during pending wallet recovery', 'https://mandate-snowy.vercel.app'
 )$$,
 'P0001',
 'Recovery-code reset is unavailable while wallet recovery is pending',
 'recovery-code reset is blocked during a pending 24-hour wallet recovery'
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

-- Recovery-code verification is rate limited across both start and cancellation attempts.
select is(
 public.cancel_near_wallet_recovery_v1(
  '10000000-0000-4000-8000-000000000002',
  '70000000-0000-4000-8000-000000000002',repeat('9',64)
 ),
 false,'fifth recovery-code attempt is recorded and rejected'
);
select is(
 public.cancel_near_wallet_recovery_v1(
  '10000000-0000-4000-8000-000000000002',
  '70000000-0000-4000-8000-000000000002',repeat('4',64)
 ),
 false,'sixth recovery-code attempt is rate-limited even with the correct code'
);

-- Recovery challenge creation is limited to five challenges per owner per hour.
select public.create_near_wallet_recovery_action_challenge_v1(
 '10000000-0000-4000-8000-000000000002',
 gen_random_uuid(),'70000000-0000-4000-8000-000000000099',
 'start','new-wallet-b.testnet','ed25519:' || repeat('4',44),
 repeat('b',64),'rate-limit fixture one'
);
select public.create_near_wallet_recovery_action_challenge_v1(
 '10000000-0000-4000-8000-000000000002',
 gen_random_uuid(),'70000000-0000-4000-8000-000000000099',
 'start','new-wallet-b.testnet','ed25519:' || repeat('4',44),
 repeat('c',64),'rate-limit fixture two'
);
select public.create_near_wallet_recovery_action_challenge_v1(
 '10000000-0000-4000-8000-000000000002',
 gen_random_uuid(),'70000000-0000-4000-8000-000000000099',
 'start','new-wallet-b.testnet','ed25519:' || repeat('4',44),
 repeat('d',64),'rate-limit fixture three'
);
select throws_ok(
 $$select public.create_near_wallet_recovery_action_challenge_v1(
  '10000000-0000-4000-8000-000000000002',
  gen_random_uuid(),'70000000-0000-4000-8000-000000000099',
  'start','new-wallet-b.testnet','ed25519:' || repeat('4',44),
  repeat('f',64),'rate-limit fixture five'
 )$$,
 'P0001',
 'Wallet recovery challenge rate limit exceeded',
 'sixth recovery challenge within one hour is rejected'
);

select * from finish();
rollback;
