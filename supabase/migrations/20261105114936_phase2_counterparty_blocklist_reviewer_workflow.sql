-- Audited, role-gated shared counterparty blocklist workflow.
-- Role membership is private and managed only through service-role RPCs.
-- The first administrator is bootstrapped once by a project database owner;
-- see docs/phase-2-inspection-api-integration.md.

create table if not exists mandate_private.counterparty_blocklist_reviewer_roles (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null unique references auth.users(id) on delete restrict,
  role text not null check (role in ('admin', 'reviewer')),
  is_active boolean not null default true,
  granted_by uuid references auth.users(id) on delete set null,
  grant_reason text not null check (length(trim(grant_reason)) between 8 and 500),
  granted_at timestamptz not null default now(),
  revoked_by uuid references auth.users(id) on delete set null,
  revoked_at timestamptz,
  revocation_reason text,
  constraint counterparty_reviewer_revocation_shape check (
    (is_active and revoked_at is null and revoked_by is null and revocation_reason is null)
    or
    (not is_active and revoked_at is not null and revocation_reason is not null
      and length(trim(revocation_reason)) between 8 and 500)
  )
);

create table if not exists mandate_private.counterparty_blocklist_audit (
  id uuid primary key default gen_random_uuid(),
  actor_owner_id uuid references auth.users(id) on delete set null,
  subject_owner_id uuid references auth.users(id) on delete set null,
  report_id uuid references mandate_private.counterparty_blocklist(id) on delete set null,
  action text not null check (action in (
    'admin_bootstrapped',
    'reviewer_granted',
    'reviewer_revoked',
    'report_submitted',
    'report_confirmed',
    'report_rejected'
  )),
  reason text not null check (length(trim(reason)) between 1 and 1000),
  before_state jsonb,
  after_state jsonb,
  created_at timestamptz not null default now()
);

create index if not exists counterparty_blocklist_roles_active_idx
  on mandate_private.counterparty_blocklist_reviewer_roles(role, is_active, owner_id);
create index if not exists counterparty_blocklist_audit_report_idx
  on mandate_private.counterparty_blocklist_audit(report_id, created_at desc);
create index if not exists counterparty_blocklist_audit_actor_idx
  on mandate_private.counterparty_blocklist_audit(actor_owner_id, created_at desc);

alter table mandate_private.counterparty_blocklist_reviewer_roles enable row level security;
alter table mandate_private.counterparty_blocklist_audit enable row level security;
revoke all on mandate_private.counterparty_blocklist_reviewer_roles from public, anon, authenticated, service_role;
revoke all on mandate_private.counterparty_blocklist_audit from public, anon, authenticated, service_role;
revoke all on mandate_private.counterparty_blocklist from public, anon, authenticated, service_role;

alter table mandate_private.counterparty_blocklist
  add column if not exists reviewer_note text;

create or replace function mandate_private.reject_counterparty_blocklist_audit_mutation()
returns trigger
language plpgsql
set search_path = pg_catalog, mandate_private
as $$
begin
  raise exception 'Counterparty blocklist audit records are append-only';
end;
$$;

drop trigger if exists counterparty_blocklist_audit_immutable on mandate_private.counterparty_blocklist_audit;
create trigger counterparty_blocklist_audit_immutable
before update or delete on mandate_private.counterparty_blocklist_audit
for each row execute function mandate_private.reject_counterparty_blocklist_audit_mutation();

-- The lookup now returns the stable report ID as part of evidence.
drop function if exists public.lookup_counterparty_blocklist(text, text);
create function public.lookup_counterparty_blocklist(
  p_network text,
  p_account_id text
)
returns table (
  id uuid,
  status text,
  evidence_ref text,
  reason text,
  reviewed_at timestamptz,
  reviewer_owner_id uuid
)
language plpgsql
security definer
set search_path = pg_catalog, mandate_private
as $$
begin
  if p_network is null or p_network not in ('testnet', 'mainnet')
     or p_account_id is null or length(p_account_id) < 2
     or length(p_account_id) > 64 or p_account_id !~ '^[a-z0-9._-]+$' then
    raise exception 'Invalid counterparty lookup';
  end if;

  return query
    select b.id, b.status, b.evidence_ref, b.reason, b.reviewed_at, b.reviewer_owner_id
    from mandate_private.counterparty_blocklist b
    where b.network = p_network and b.account_id = p_account_id and b.status = 'confirmed'
    order by b.reviewed_at desc, b.created_at desc limit 1;
  if found then return; end if;

  return query
    select b.id, b.status, b.evidence_ref, b.reason, b.reviewed_at, b.reviewer_owner_id
    from mandate_private.counterparty_blocklist b
    where b.network = p_network and b.account_id = p_account_id and b.status = 'pending'
    order by b.created_at desc limit 1;
end;
$$;

create or replace function public.submit_counterparty_blocklist_report_v1(
  p_reporter_owner_id uuid,
  p_network text,
  p_account_id text,
  p_reason text,
  p_evidence_ref text,
  p_evidence_sha256 text,
  p_source_type text
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, mandate_private
as $$
declare
  v_report mandate_private.counterparty_blocklist%rowtype;
  v_recent_count integer;
begin
  if p_reporter_owner_id is null
     or p_network is distinct from 'testnet'
     or p_account_id is null or length(p_account_id) not between 2 and 64
     or p_account_id !~ '^[a-z0-9]+([-_][a-z0-9]+)*(\.[a-z0-9]+([-_][a-z0-9]+)*)*$'
     or p_reason is null or length(trim(p_reason)) not between 8 and 500
     or p_evidence_ref is null or length(trim(p_evidence_ref)) not between 8 and 2048
     or p_source_type is null or p_source_type not in ('chain_tx', 'explorer', 'security_advisory', 'other')
     or (p_evidence_sha256 is not null and p_evidence_sha256 !~ '^[0-9a-f]{64}$') then
    raise exception 'Invalid counterparty report';
  end if;
  if not exists (select 1 from auth.users u where u.id = p_reporter_owner_id) then
    raise exception 'Report owner does not exist';
  end if;

  select count(*)::integer into v_recent_count
  from mandate_private.counterparty_blocklist b
  where b.reporter_owner_id = p_reporter_owner_id
    and b.created_at > now() - interval '1 hour';
  if v_recent_count >= 10 then raise exception 'Counterparty report submission limit exceeded'; end if;

  insert into mandate_private.counterparty_blocklist
    (network, account_id, status, reason, evidence_ref, evidence_sha256,
     source_type, reporter_owner_id)
  values
    (p_network, p_account_id, 'pending', trim(p_reason), trim(p_evidence_ref),
     p_evidence_sha256, p_source_type, p_reporter_owner_id)
  returning * into v_report;

  insert into mandate_private.counterparty_blocklist_audit
    (actor_owner_id, subject_owner_id, report_id, action, reason, before_state, after_state)
  values
    (p_reporter_owner_id, p_reporter_owner_id, v_report.id, 'report_submitted',
     'Reporter submitted evidence for independent review.', null, to_jsonb(v_report));

  return v_report.id;
end;
$$;

create or replace function public.provision_counterparty_blocklist_reviewer_v1(
  p_actor_owner_id uuid,
  p_subject_owner_id uuid,
  p_action text,
  p_reason text
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, mandate_private
as $$
declare
  v_actor mandate_private.counterparty_blocklist_reviewer_roles%rowtype;
  v_role mandate_private.counterparty_blocklist_reviewer_roles%rowtype;
  v_before jsonb;
begin
  if p_actor_owner_id is null or p_subject_owner_id is null
     or p_actor_owner_id = p_subject_owner_id
     or p_action is null or p_action not in ('grant', 'revoke')
     or p_reason is null or length(trim(p_reason)) not between 8 and 500 then
    raise exception 'Invalid reviewer provisioning request';
  end if;

  select * into v_actor
  from mandate_private.counterparty_blocklist_reviewer_roles r
  where r.owner_id = p_actor_owner_id and r.role = 'admin' and r.is_active
  for update;
  if not found then raise exception 'Active blocklist administrator role is required'; end if;

  if not exists (select 1 from auth.users u where u.id = p_subject_owner_id) then
    raise exception 'Reviewer account does not exist';
  end if;

  select * into v_role
  from mandate_private.counterparty_blocklist_reviewer_roles r
  where r.owner_id = p_subject_owner_id
  for update;
  if found then v_before := to_jsonb(v_role); end if;

  if v_role.id is not null and v_role.role = 'admin' then
    raise exception 'Administrator roles cannot be altered through reviewer provisioning';
  end if;

  if p_action = 'grant' then
    if v_role.id is not null and v_role.is_active then
      raise exception 'Account already has an active blocklist role';
    end if;
    if v_role.id is null then
      insert into mandate_private.counterparty_blocklist_reviewer_roles
        (owner_id, role, is_active, granted_by, grant_reason)
      values (p_subject_owner_id, 'reviewer', true, p_actor_owner_id, trim(p_reason))
      returning * into v_role;
    else
      update mandate_private.counterparty_blocklist_reviewer_roles
      set role = 'reviewer', is_active = true, granted_by = p_actor_owner_id,
          grant_reason = trim(p_reason), granted_at = now(),
          revoked_by = null, revoked_at = null, revocation_reason = null
      where id = v_role.id
      returning * into v_role;
    end if;
    insert into mandate_private.counterparty_blocklist_audit
      (actor_owner_id, subject_owner_id, action, reason, before_state, after_state)
    values
      (p_actor_owner_id, p_subject_owner_id, 'reviewer_granted', trim(p_reason),
       v_before, to_jsonb(v_role));
  else
    if v_role.id is null or not v_role.is_active or v_role.role <> 'reviewer' then
      raise exception 'Active reviewer assignment was not found';
    end if;
    update mandate_private.counterparty_blocklist_reviewer_roles
    set is_active = false, revoked_by = p_actor_owner_id, revoked_at = now(),
        revocation_reason = trim(p_reason)
    where id = v_role.id
    returning * into v_role;
    insert into mandate_private.counterparty_blocklist_audit
      (actor_owner_id, subject_owner_id, action, reason, before_state, after_state)
    values
      (p_actor_owner_id, p_subject_owner_id, 'reviewer_revoked', trim(p_reason),
       v_before, to_jsonb(v_role));
  end if;
  return v_role.id;
end;
$$;

create or replace function public.list_counterparty_blocklist_review_queue_v1(
  p_actor_owner_id uuid
)
returns table (
  id uuid, network text, account_id text, status text, reason text,
  evidence_ref text, evidence_sha256 text, source_type text,
  reporter_owner_id uuid, created_at timestamptz
)
language plpgsql
security definer
set search_path = pg_catalog, mandate_private
as $$
begin
  if not exists (
    select 1 from mandate_private.counterparty_blocklist_reviewer_roles r
    where r.owner_id = p_actor_owner_id and r.is_active and r.role in ('admin', 'reviewer')
  ) then raise exception 'Active blocklist reviewer role is required'; end if;

  return query
    select b.id, b.network, b.account_id, b.status, b.reason,
           b.evidence_ref, b.evidence_sha256, b.source_type,
           b.reporter_owner_id, b.created_at
    from mandate_private.counterparty_blocklist b
    where b.status = 'pending'
    order by b.created_at asc;
end;
$$;

create or replace function public.review_counterparty_blocklist_report_v1(
  p_reviewer_owner_id uuid,
  p_report_id uuid,
  p_decision text,
  p_review_note text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, mandate_private
as $$
declare
  v_actor mandate_private.counterparty_blocklist_reviewer_roles%rowtype;
  v_report mandate_private.counterparty_blocklist%rowtype;
  v_before jsonb;
  v_action text;
begin
  if p_reviewer_owner_id is null or p_report_id is null
     or p_decision is null or p_decision not in ('confirmed', 'rejected')
     or p_review_note is null or length(trim(p_review_note)) not between 8 and 500 then
    raise exception 'Invalid counterparty review decision';
  end if;

  select * into v_actor
  from mandate_private.counterparty_blocklist_reviewer_roles r
  where r.owner_id = p_reviewer_owner_id and r.is_active and r.role in ('admin', 'reviewer')
  for update;
  if not found then raise exception 'Active blocklist reviewer role is required'; end if;

  select * into v_report
  from mandate_private.counterparty_blocklist b
  where b.id = p_report_id
  for update;
  if not found or v_report.status <> 'pending' then
    raise exception 'Only a pending counterparty report can be reviewed';
  end if;
  if v_report.reporter_owner_id = p_reviewer_owner_id then
    raise exception 'Reporters cannot review their own counterparty reports';
  end if;

  v_before := to_jsonb(v_report);
  update mandate_private.counterparty_blocklist
  set status = p_decision, reviewer_owner_id = p_reviewer_owner_id,
      reviewed_at = now(), reviewer_note = trim(p_review_note), updated_at = now()
  where id = p_report_id
  returning * into v_report;
  v_action := case when p_decision = 'confirmed' then 'report_confirmed' else 'report_rejected' end;

  insert into mandate_private.counterparty_blocklist_audit
    (actor_owner_id, subject_owner_id, report_id, action, reason, before_state, after_state)
  values
    (p_reviewer_owner_id, v_report.reporter_owner_id, v_report.id, v_action,
     trim(p_review_note), v_before, to_jsonb(v_report));
  return true;
end;
$$;

create or replace function public.list_counterparty_blocklist_audit_v1(
  p_actor_owner_id uuid,
  p_limit integer default 100
)
returns table (
  id uuid, actor_owner_id uuid, subject_owner_id uuid, report_id uuid,
  action text, reason text, before_state jsonb, after_state jsonb, created_at timestamptz
)
language plpgsql
security definer
set search_path = pg_catalog, mandate_private
as $$
begin
  if p_limit is null or p_limit not between 1 and 200 then raise exception 'Invalid audit page size'; end if;
  if not exists (
    select 1 from mandate_private.counterparty_blocklist_reviewer_roles r
    where r.owner_id = p_actor_owner_id and r.is_active and r.role = 'admin'
  ) then raise exception 'Active blocklist administrator role is required'; end if;

  return query
    select a.id, a.actor_owner_id, a.subject_owner_id, a.report_id,
           a.action, a.reason, a.before_state, a.after_state, a.created_at
    from mandate_private.counterparty_blocklist_audit a
    order by a.created_at desc, a.id desc
    limit p_limit;
end;
$$;

revoke all on function public.lookup_counterparty_blocklist(text, text) from public, anon, authenticated;
revoke all on function public.submit_counterparty_blocklist_report_v1(uuid, text, text, text, text, text, text) from public, anon, authenticated;
revoke all on function public.provision_counterparty_blocklist_reviewer_v1(uuid, uuid, text, text) from public, anon, authenticated;
revoke all on function public.list_counterparty_blocklist_review_queue_v1(uuid) from public, anon, authenticated;
revoke all on function public.review_counterparty_blocklist_report_v1(uuid, uuid, text, text) from public, anon, authenticated;
revoke all on function public.list_counterparty_blocklist_audit_v1(uuid, integer) from public, anon, authenticated;
grant execute on function public.lookup_counterparty_blocklist(text, text) to service_role;
grant execute on function public.submit_counterparty_blocklist_report_v1(uuid, text, text, text, text, text, text) to service_role;
grant execute on function public.provision_counterparty_blocklist_reviewer_v1(uuid, uuid, text, text) to service_role;
grant execute on function public.list_counterparty_blocklist_review_queue_v1(uuid) to service_role;
grant execute on function public.review_counterparty_blocklist_report_v1(uuid, uuid, text, text) to service_role;
grant execute on function public.list_counterparty_blocklist_audit_v1(uuid, integer) to service_role;
