-- These RPCs are deliberately dormant until the authenticated server routes
-- verify NEP-413 signatures and use a trusted server-side database client.
-- Do not expose SECURITY DEFINER functions to browser roles.
revoke all on function public.create_near_transfer_challenge(uuid,text,text,text,uuid,integer,text) from public, anon, authenticated;
revoke all on function public.get_near_transfer_challenge(uuid) from public, anon, authenticated;
revoke all on function public.finalize_near_transfer_challenge(uuid,text) from public, anon, authenticated;
revoke all on function public.consume_near_transfer_authorization(text,text,text,text,text,text,text) from public, anon, authenticated;
