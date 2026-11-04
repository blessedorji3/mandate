create table public.security_policies (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (length(trim(name)) between 1 and 100),
  version integer not null default 1 check (version > 0),
  active boolean not null default true,
  max_amount_atomic text not null check (max_amount_atomic ~ '^[1-9][0-9]*$'),
  allowed_recipients text[] not null default '{}',
  allowed_action_types text[] not null default array['transfer']::text[],
  require_approval_for_token_approvals boolean not null default true,
  require_approval_for_all_actions boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint security_policies_action_types_check
    check (allowed_action_types <@ array['transfer','token_approval','swap','contract_call']::text[])
);

create index security_policies_owner_id_idx on public.security_policies(owner_id);

alter table public.security_policies enable row level security;

create policy "Owners can view their own policies"
on public.security_policies for select to authenticated
using ((select auth.uid()) = owner_id);

create policy "Owners can create their own policies"
on public.security_policies for insert to authenticated
with check ((select auth.uid()) = owner_id);

create policy "Owners can update their own policies"
on public.security_policies for update to authenticated
using ((select auth.uid()) = owner_id)
with check ((select auth.uid()) = owner_id);

create policy "Owners can delete their own policies"
on public.security_policies for delete to authenticated
using ((select auth.uid()) = owner_id);

grant select, insert, update, delete on public.security_policies to authenticated;
revoke all on public.security_policies from anon;

create table public.authorization_decisions (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  policy_id uuid references public.security_policies(id) on delete set null,
  policy_version integer not null check (policy_version >= 0),
  proposal_id text not null,
  agent_id text not null,
  action_type text not null check (action_type in ('transfer','token_approval','swap','contract_call')),
  outcome text not null check (outcome in ('ALLOW','BLOCK','REQUIRE_APPROVAL')),
  reason text not null,
  proposal jsonb not null,
  created_at timestamptz not null default now()
);

create index authorization_decisions_owner_created_idx
on public.authorization_decisions(owner_id, created_at desc);

alter table public.authorization_decisions enable row level security;

create policy "Owners can view their own decision history"
on public.authorization_decisions for select to authenticated
using ((select auth.uid()) = owner_id);

grant select on public.authorization_decisions to authenticated;
revoke all on public.authorization_decisions from anon;
revoke insert, update, delete on public.authorization_decisions from authenticated, anon;
