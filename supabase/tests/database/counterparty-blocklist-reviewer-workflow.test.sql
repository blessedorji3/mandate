begin;
select no_plan();

insert into auth.users (id, aud, role, email, created_at, updated_at)
values
  ('61000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'blocklist-admin@example.test', now(), now()),
  ('61000000-0000-4000-8000-000000000002', 'authenticated', 'authenticated', 'blocklist-reviewer@example.test', now(), now()),
  ('61000000-0000-4000-8000-000000000003', 'authenticated', 'authenticated', 'blocklist-reporter@example.test', now(), now()),
  ('61000000-0000-4000-8000-000000000004', 'authenticated', 'authenticated', 'blocklist-outsider@example.test', now(), now());

insert into mandate_private.counterparty_blocklist_reviewer_roles
  (owner_id, role, is_active, grant_reason)
values
  ('61000000-0000-4000-8000-000000000001', 'admin', true, 'Initial isolated test administrator'),
  ('61000000-0000-4000-8000-000000000002', 'reviewer', true, 'Initial isolated test reviewer');

select ok(
  (select relrowsecurity from pg_class where oid = 'mandate_private.counterparty_blocklist_reviewer_roles'::regclass)
  and (select relrowsecurity from pg_class where oid = 'mandate_private.counterparty_blocklist_audit'::regclass),
  'reviewer assignments and audit records have RLS enabled'
);
select ok(
  not has_table_privilege('anon', 'mandate_private.counterparty_blocklist_audit', 'SELECT')
  and not has_table_privilege('authenticated', 'mandate_private.counterparty_blocklist_audit', 'SELECT')
  and not has_table_privilege('service_role', 'mandate_private.counterparty_blocklist_audit', 'UPDATE')
  and not has_table_privilege('service_role', 'mandate_private.counterparty_blocklist_audit', 'DELETE'),
  'audit records cannot be directly read or mutated by client and service roles'
);
select ok(
  not has_table_privilege('service_role', 'mandate_private.counterparty_blocklist', 'INSERT')
  and not has_table_privilege('service_role', 'mandate_private.counterparty_blocklist', 'UPDATE')
  and has_table_privilege('service_role', 'mandate_private.counterparty_blocklist', 'SELECT'),
  'service role can read evidence but cannot bypass audited report RPCs'
);

select throws_ok(
  $$select public.provision_counterparty_blocklist_reviewer_v1(
    '61000000-0000-4000-8000-000000000004',
    '61000000-0000-4000-8000-000000000003',
    'grant', 'Unauthorized role assignment'
  )$$,
  'P0001',
  'Active blocklist administrator role is required',
  'ordinary users cannot provision reviewers'
);

select throws_ok(
  $$select public.list_counterparty_blocklist_review_queue_v1(
    '61000000-0000-4000-8000-000000000004'
  )$$,
  'P0001',
  'Active blocklist reviewer role is required',
  'ordinary users cannot read the review queue'
);

select throws_ok(
  $$select public.review_counterparty_blocklist_report_v1(
    '61000000-0000-4000-8000-000000000004',
    '62000000-0000-4000-8000-000000000001',
    'confirmed', 'Unauthorized confirmation attempt'
  )$$,
  'P0001',
  'Active blocklist reviewer role is required',
  'ordinary users cannot confirm a report'
);

select is(
  public.provision_counterparty_blocklist_reviewer_v1(
    '61000000-0000-4000-8000-000000000001',
    '61000000-0000-4000-8000-000000000003',
    'grant', 'Assigned after verifying reviewer identity'
  ),
  (select id from mandate_private.counterparty_blocklist_reviewer_roles
    where owner_id = '61000000-0000-4000-8000-000000000003'),
  'administrator can provision a reviewer assignment'
);

select ok(
  (select count(*) = 1 from mandate_private.counterparty_blocklist_audit
    where action = 'reviewer_granted'
      and actor_owner_id = '61000000-0000-4000-8000-000000000001'
      and subject_owner_id = '61000000-0000-4000-8000-000000000003'
      and before_state is null and after_state->>'role' = 'reviewer'),
  'reviewer grant creates an attributable audit event with state snapshots'
);

select throws_ok(
  $$select public.provision_counterparty_blocklist_reviewer_v1(
    '61000000-0000-4000-8000-000000000001',
    '61000000-0000-4000-8000-000000000001',
    'grant', 'Self-provisioning attempt'
  )$$,
  'P0001',
  'Invalid reviewer provisioning request',
  'administrators cannot provision themselves as reviewers'
);

select ok(
  public.submit_counterparty_blocklist_report_v1(
    '61000000-0000-4000-8000-000000000003',
    'testnet', 'reported.testnet', 'Suspicious deployment activity',
    'https://evidence.example/report/one', null, 'explorer'
  ) is not null,
  'authenticated reporter can submit a pending evidence report'
);

select throws_ok(
  $sql$select public.review_counterparty_blocklist_report_v1(
    '61000000-0000-4000-8000-000000000003',
    (select id from mandate_private.counterparty_blocklist where account_id = 'reported.testnet' limit 1),
    'confirmed', 'Self review is forbidden'
  )$sql$,
  'P0001',
  'Reporters cannot review their own counterparty reports',
  'reporter cannot review their own submitted evidence'
);

select throws_ok(
  $sql$select public.review_counterparty_blocklist_report_v1(
    '61000000-0000-4000-8000-000000000004',
    (select id from mandate_private.counterparty_blocklist where account_id = 'reported.testnet' limit 1),
    'confirmed', 'Unprovisioned account cannot decide'
  )$sql$,
  'P0001',
  'Active blocklist reviewer role is required',
  'unprovisioned account cannot review a report'
);

select is(
  public.review_counterparty_blocklist_report_v1(
    '61000000-0000-4000-8000-000000000002',
    (select id from mandate_private.counterparty_blocklist where account_id = 'reported.testnet' limit 1),
    'confirmed', 'Verified evidence supports this report'
  ),
  true,
  'a separate active reviewer can confirm a pending report'
);

select ok(
  (select status = 'confirmed'
   from mandate_private.counterparty_blocklist
   where account_id = 'reported.testnet')
  and (select count(*) = 1
       from mandate_private.counterparty_blocklist_audit
       where action = 'report_confirmed'
         and actor_owner_id = '61000000-0000-4000-8000-000000000002'
         and report_id = (select id from mandate_private.counterparty_blocklist where account_id = 'reported.testnet')),
  'confirmed decision updates the report and appends attributable audit snapshots'
);

select throws_ok(
  $sql$update mandate_private.counterparty_blocklist_audit
    set reason = 'tampered audit record'
    where action = 'report_confirmed'$sql$,
  'P0001',
  'Counterparty blocklist audit records are append-only',
  'audit records reject updates'
);

select throws_ok(
  $sql$delete from mandate_private.counterparty_blocklist_audit
    where action = 'report_confirmed'$sql$,
  'P0001',
  'Counterparty blocklist audit records are append-only',
  'audit records reject deletes'
);

select is(
  public.provision_counterparty_blocklist_reviewer_v1(
    '61000000-0000-4000-8000-000000000001',
    '61000000-0000-4000-8000-000000000002',
    'revoke', 'Reviewer access removed after rotation'
  ),
  (select id from mandate_private.counterparty_blocklist_reviewer_roles
    where owner_id = '61000000-0000-4000-8000-000000000002'),
  'administrator can revoke a reviewer assignment'
);

select throws_ok(
  $sql$select public.list_counterparty_blocklist_review_queue_v1(
    '61000000-0000-4000-8000-000000000002'
  )$sql$,
  'P0001',
  'Active blocklist reviewer role is required',
  'revoked reviewer loses queue access'
);

select throws_ok(
  $sql$select public.list_counterparty_blocklist_audit_v1(
    '61000000-0000-4000-8000-000000000003', 100
  )$sql$,
  'P0001',
  'Active blocklist administrator role is required',
  'non-admin users cannot read global audit history'
);

select ok(
  exists (select 1 from mandate_private.counterparty_blocklist_audit
    where action = 'reviewer_revoked'
      and actor_owner_id = '61000000-0000-4000-8000-000000000001'
      and subject_owner_id = '61000000-0000-4000-8000-000000000002'),
  'reviewer revocation is retained in immutable audit history'
);

select * from finish();
rollback;
