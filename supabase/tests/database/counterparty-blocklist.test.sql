begin;
select no_plan();

insert into auth.users (id, aud, role, email, created_at, updated_at)
values
 ('11000000-0000-4000-8000-000000000001','authenticated','authenticated','blocklist-reporter@example.test',now(),now()),
 ('11000000-0000-4000-8000-000000000002','authenticated','authenticated','blocklist-reviewer@example.test',now(),now());

select ok(
  (select relrowsecurity from pg_class where oid='mandate_private.counterparty_blocklist'::regclass),
  'shared counterparty blocklist has RLS enabled'
);
select ok(
  not has_table_privilege('anon','mandate_private.counterparty_blocklist','SELECT')
  and not has_table_privilege('authenticated','mandate_private.counterparty_blocklist','SELECT'),
  'anonymous and authenticated roles cannot directly read private blocklist records'
);
select ok(
  has_table_privilege('service_role','mandate_private.counterparty_blocklist','SELECT')
  and has_table_privilege('service_role','mandate_private.counterparty_blocklist','INSERT')
  and has_table_privilege('service_role','mandate_private.counterparty_blocklist','UPDATE'),
  'service role has only the required blocklist data access'
);
select ok(
  not has_function_privilege('anon','public.lookup_counterparty_blocklist(text,text)','EXECUTE')
  and not has_function_privilege('authenticated','public.lookup_counterparty_blocklist(text,text)','EXECUTE')
  and has_function_privilege('service_role','public.lookup_counterparty_blocklist(text,text)','EXECUTE')
  and not has_function_privilege('anon','public.consume_near_transfer_authorization_v3(uuid,text,text,text,text,text,text,text,text,text)','EXECUTE')
  and has_function_privilege('service_role','public.consume_near_transfer_authorization_v3(uuid,text,text,text,text,text,text,text,text,text)','EXECUTE'),
  'private blocklist lookup RPC is callable only by service role'
);

insert into mandate_private.counterparty_blocklist
 (id,network,account_id,status,reason,evidence_ref,source_type,reporter_owner_id,reviewer_owner_id,reviewed_at)
values
 ('12000000-0000-4000-8000-000000000001','testnet','pending-bad.testnet','pending',
  'Suspicious destination report','https://evidence.example/pending/1','explorer',
  '11000000-0000-4000-8000-000000000001',null,null),
 ('12000000-0000-4000-8000-000000000002','testnet','confirmed-bad.testnet','confirmed',
  'Confirmed malicious drain','https://evidence.example/confirmed/1','chain_tx',
  '11000000-0000-4000-8000-000000000001','11000000-0000-4000-8000-000000000002',now()),
 ('12000000-0000-4000-8000-000000000003','testnet','rejected-bad.testnet','rejected',
  'Report reviewed and rejected','https://evidence.example/rejected/1','other',
  '11000000-0000-4000-8000-000000000001',null,null);

select is(
  (select status from public.lookup_counterparty_blocklist('testnet','confirmed-bad.testnet')),
  'confirmed',
  'lookup returns a reviewed confirmed record'
);
select is(
  (select reviewer_owner_id from public.lookup_counterparty_blocklist('testnet','confirmed-bad.testnet')),
  '11000000-0000-4000-8000-000000000002'::uuid,
  'confirmed record retains reviewer attribution'
);
select is(
  (select status from public.lookup_counterparty_blocklist('testnet','pending-bad.testnet')),
  'pending',
  'pending reports are returned as pending and are not promoted to confirmed'
);
select is(
  (select count(*)::integer from public.lookup_counterparty_blocklist('testnet','rejected-bad.testnet')),
  0,
  'rejected reports are not returned as block signals'
);
select throws_ok(
  $$select * from public.lookup_counterparty_blocklist(null,'valid.testnet')$$,
  'P0001',
  'Invalid counterparty lookup',
  'lookup rejects a missing network'
);


insert into public.security_policies
 (id,owner_id,version,active,max_amount_atomic,allowed_recipients,allowed_action_types,
  require_approval_for_all_actions)
values
 ('13000000-0000-4000-8000-000000000001',
  '11000000-0000-4000-8000-000000000001',
  1,true,
  '1000000000000000000000',
  array['confirmwithmandate.testnet']::text[],
  array['transfer']::text[],false);

insert into mandate_private.near_transfer_receipts
 (id,owner_id,token_hash,signer_account_id,policy_id,policy_version,proposal_id,
  network,receiver_id,asset,amount_atomic,action_type,action_digest,expires_at)
values
 ('14000000-0000-4000-8000-000000000001',
  '11000000-0000-4000-8000-000000000001',
  decode(repeat('a',64),'hex'),
  'owner-wallet.testnet',
  '13000000-0000-4000-8000-000000000001',1,'inspected-proposal-1',
  'testnet','confirmwithmandate.testnet','NEAR',
  '1000000000000000000000','transfer',repeat('b',64),now()+interval '2 minutes');

select is(
  public.consume_near_transfer_authorization_v3(
    '11000000-0000-4000-8000-000000000001',repeat('a',64),
    'owner-wallet.testnet','testnet','confirmwithmandate.testnet','NEAR',
    '1000000000000000000000','transfer',repeat('b',64),'different-proposal'
  ),
  false,
  'receipt cannot be consumed using a different proposal reference'
);
select is(
  public.consume_near_transfer_authorization_v3(
    '11000000-0000-4000-8000-000000000001',repeat('a',64),
    'owner-wallet.testnet','testnet','confirmwithmandate.testnet','NEAR',
    '1000000000000000000000','transfer',repeat('b',64),'inspected-proposal-1'
  ),
  true,
  'receipt can be consumed only with its exact inspected proposal reference'
);

select * from finish();
rollback;
