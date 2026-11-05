begin;
select no_plan();

insert into auth.users (id, aud, role, email, created_at, updated_at)
values
  ('21000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'phase2-reporter@example.test', now(), now()),
  ('21000000-0000-4000-8000-000000000002', 'authenticated', 'authenticated', 'phase2-reviewer@example.test', now(), now());

select ok(
  (select relrowsecurity from pg_class where oid = 'mandate_private.counterparty_blocklist'::regclass),
  'counterparty blocklist has RLS enabled'
);
select ok(
  not has_table_privilege('anon', 'mandate_private.counterparty_blocklist', 'SELECT')
  and not has_table_privilege('authenticated', 'mandate_private.counterparty_blocklist', 'SELECT'),
  'anon and authenticated roles cannot read the private blocklist directly'
);
select ok(
  has_table_privilege('service_role', 'mandate_private.counterparty_blocklist', 'SELECT')
  and not has_table_privilege('service_role', 'mandate_private.counterparty_blocklist', 'INSERT')
  and not has_table_privilege('service_role', 'mandate_private.counterparty_blocklist', 'UPDATE')
  and not has_table_privilege('service_role', 'mandate_private.counterparty_blocklist', 'DELETE'),
  'service role can read evidence but all report changes must use the audited RPC path'
);
select ok(
  not has_function_privilege('anon', 'public.lookup_counterparty_blocklist(text,text)', 'EXECUTE')
  and not has_function_privilege('authenticated', 'public.lookup_counterparty_blocklist(text,text)', 'EXECUTE')
  and has_function_privilege('service_role', 'public.lookup_counterparty_blocklist(text,text)', 'EXECUTE'),
  'lookup RPC is executable only by service role'
);

insert into mandate_private.counterparty_blocklist
  (id, network, account_id, status, reason, evidence_ref, source_type, reporter_owner_id, reviewer_owner_id, reviewed_at)
values
  ('22000000-0000-4000-8000-000000000001', 'testnet', 'pending-bad.testnet', 'pending',
   'Unreviewed risk report', 'https://evidence.example/pending/1', 'explorer',
   '21000000-0000-4000-8000-000000000001', null, null),
  ('22000000-0000-4000-8000-000000000002', 'testnet', 'confirmed-bad.testnet', 'confirmed',
   'Confirmed malicious counterparty', 'https://evidence.example/confirmed/1', 'chain_tx',
   '21000000-0000-4000-8000-000000000001', '21000000-0000-4000-8000-000000000002', now()),
  ('22000000-0000-4000-8000-000000000003', 'testnet', 'rejected-bad.testnet', 'rejected',
   'Report reviewed and rejected', 'https://evidence.example/rejected/1', 'other',
   '21000000-0000-4000-8000-000000000001', null, null);

select is(
  (select status from public.lookup_counterparty_blocklist('testnet', 'confirmed-bad.testnet')),
  'confirmed',
  'lookup returns a confirmed record'
);
select is(
  (select reviewer_owner_id from public.lookup_counterparty_blocklist('testnet', 'confirmed-bad.testnet')),
  '21000000-0000-4000-8000-000000000002'::uuid,
  'confirmed lookup preserves reviewer identity'
);
select is(
  (select status from public.lookup_counterparty_blocklist('testnet', 'pending-bad.testnet')),
  'pending',
  'unreviewed reports remain pending'
);
select is(
  (select count(*)::integer from public.lookup_counterparty_blocklist('testnet', 'rejected-bad.testnet')),
  0,
  'rejected reports are not returned as block signals'
);
select throws_ok(
  $$select * from public.lookup_counterparty_blocklist(null, 'alice.testnet')$$,
  'P0001',
  'Invalid counterparty lookup',
  'lookup rejects an invalid network'
);

select * from finish();
rollback;
