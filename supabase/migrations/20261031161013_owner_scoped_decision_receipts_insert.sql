-- Authorization decision receipts may only be inserted for the signed-in owner.
create policy "Users can insert their own authorization decisions"
  on public.authorization_decisions for insert to authenticated
  with check (owner_id = (select auth.uid()));
