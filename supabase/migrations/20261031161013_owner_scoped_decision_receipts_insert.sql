grant insert on table public.authorization_decisions to authenticated;
drop policy if exists "Users can insert their own authorization decisions" on public.authorization_decisions;
create policy "Users can insert their own authorization decisions"
on public.authorization_decisions
for insert
to authenticated
with check (owner_id = (select auth.uid()));
