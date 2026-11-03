-- Browser roles receive only the privileges required by owner-scoped RLS.
revoke all on public.security_policies, public.authorization_decisions,
  public.api_keys, public.api_key_rate_limits from public, anon, authenticated;

grant select, insert, update, delete on public.security_policies to authenticated;
grant select, insert on public.authorization_decisions to authenticated;
grant select, insert, update on public.api_keys to authenticated;

grant all on public.security_policies, public.authorization_decisions,
  public.api_keys, public.api_key_rate_limits to service_role;

revoke all on function public.consume_api_key_quota(uuid, integer)
  from public, anon, authenticated;
grant execute on function public.consume_api_key_quota(uuid, integer) to service_role;
