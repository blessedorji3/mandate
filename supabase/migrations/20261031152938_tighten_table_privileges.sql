revoke all privileges on table public.security_policies from anon, authenticated;
revoke all privileges on table public.authorization_decisions from anon, authenticated;
grant select, insert, update, delete on table public.security_policies to authenticated;
grant select on table public.authorization_decisions to authenticated;
