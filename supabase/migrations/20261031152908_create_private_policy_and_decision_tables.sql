-- Reconstructed migration baseline from the deployed Supabase catalog.
-- This restores the original application tables that predate the NEAR transfer
-- migrations, so a clean local replay has the same starting schema as production.

create table public.security_policies (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  version integer not null default 1 check (version > 0),
  active boolean not null default true,
  max_amount_atomic text not null check (max_amount_atomic ~ '^[1-9][0-9]*$'),
  allowed_recipients text[] not null default '{}'::text[],
  allowed_action_types text[] not null default array['transfer']::text[],
  require_approval_for_token_approvals boolean not null default true,
  require_approval_for_all_actions boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint security_policies_name_check
    check (length(trim(name)) between 1 and 100),
  constraint security_policies_action_types_check
    check (allowed_action_types <@ array['transfer','token_approval','swap','contract_call']::text[])
);
create index security_policies_owner_id_idx on public.security_policies(owner_id);
alter table public.security_policies enable row level security;

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

create table public.api_keys (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 80),
  key_prefix text not null,
  key_hash text not null unique,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);
create index api_keys_owner_created_idx on public.api_keys(owner_id, created_at desc);
alter table public.api_keys enable row level security;

create table public.api_key_rate_limits (
  key_id uuid not null references public.api_keys(id) on delete cascade,
  window_start timestamptz not null,
  request_count integer not null default 0 check (request_count >= 0),
  primary key (key_id, window_start)
);
alter table public.api_key_rate_limits enable row level security;

create policy "Owners can create their own policies"
  on public.security_policies for insert to authenticated
  with check ((select auth.uid()) = owner_id);
create policy "Owners can delete their own policies"
  on public.security_policies for delete to authenticated
  using ((select auth.uid()) = owner_id);
create policy "Owners can update their own policies"
  on public.security_policies for update to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);
create policy "Owners can view their own policies"
  on public.security_policies for select to authenticated
  using ((select auth.uid()) = owner_id);

create policy "Owners can create their own API keys"
  on public.api_keys for insert to authenticated
  with check ((select auth.uid()) = owner_id);
create policy "Owners can revoke their own API keys"
  on public.api_keys for update to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);
create policy "Owners can view their own API keys"
  on public.api_keys for select to authenticated
  using ((select auth.uid()) = owner_id);

create policy "Owners can view their own decision history"
  on public.authorization_decisions for select to authenticated
  using ((select auth.uid()) = owner_id);

create policy "No direct client access to API rate limits"
  on public.api_key_rate_limits for all to anon, authenticated
  using (false) with check (false);

create or replace function public.consume_api_key_quota(
  p_key_id uuid, p_limit integer default 60
) returns boolean
language plpgsql
set search_path = ''
as $$
declare
  v_count integer;
  v_window timestamptz := date_trunc('minute', now());
begin
  if p_limit < 1 or p_limit > 1000 then return false; end if;
  delete from public.api_key_rate_limits
    where window_start < now() - interval '1 day';
  insert into public.api_key_rate_limits(key_id, window_start, request_count)
    values (p_key_id, v_window, 1)
    on conflict (key_id, window_start)
    do update set request_count = public.api_key_rate_limits.request_count + 1
    returning request_count into v_count;
  return v_count <= p_limit;
end;
$$;
