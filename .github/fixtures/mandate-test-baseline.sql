-- TEST ONLY: minimal pre-existing application schema needed to replay this PR's
-- migrations in a disposable local Supabase stack. This fixture is copied into
-- the migrations directory by .github/scripts/run-recovery-db-tests.sh and is
-- never applied to a linked or hosted Supabase project.
create table public.security_policies (
  id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  active boolean not null default true,
  version integer not null default 1,
  allowed_action_types text[] not null default '{}',
  allowed_recipients text[] not null default '{}',
  max_amount_atomic text not null default '0',
  require_approval_for_all_actions boolean not null default false
);
alter table public.security_policies enable row level security;
revoke all on public.security_policies from public, anon, authenticated;
grant select, insert, update, delete on public.security_policies to service_role;
