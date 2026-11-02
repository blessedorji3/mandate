#!/usr/bin/env bash
set -euo pipefail

# Runs only against the disposable local Supabase database started by
# run-recovery-db-tests.sh. Never reads or uses linked-project credentials.
eval "$(supabase status -o env)"
: "${DB_URL:?Supabase local DB_URL was not provided}"

owner="10000000-0000-4000-8000-000000000099"
request_a="70000000-0000-4000-8000-000000000091"
request_b="70000000-0000-4000-8000-000000000092"
challenge_a="40000000-0000-4000-8000-000000000091"
challenge_b="40000000-0000-4000-8000-000000000092"
code_hash="$(printf '1%.0s' {1..64})"
public_key="ed25519:11111111111111111111111111111111111111111111"
nonce_a="$(printf 'a%.0s' {1..64})"
nonce_b="$(printf 'b%.0s' {1..64})"
tmp="$(mktemp -d)"
cleanup() {
  psql "$DB_URL" -v ON_ERROR_STOP=1 -q <<SQL
delete from mandate_private.near_wallet_recovery_events where owner_id='$owner';
delete from mandate_private.near_wallet_recovery_action_challenges where owner_id='$owner';
delete from mandate_private.near_wallet_recovery_requests where owner_id='$owner';
delete from mandate_private.near_wallet_recovery_credentials where owner_id='$owner';
delete from mandate_private.near_owner_wallets where owner_id='$owner';
delete from auth.users where id='$owner';
SQL
  rm -rf "$tmp"
}
trap cleanup EXIT

# Committed synthetic fixtures are visible to both independent sessions.
psql "$DB_URL" -v ON_ERROR_STOP=1 -q <<SQL
insert into auth.users (id,aud,role,email,created_at,updated_at)
values ('$owner','authenticated','authenticated','recovery-concurrency@example.test',now(),now());
insert into mandate_private.near_wallet_recovery_credentials(owner_id,code_hash)
values ('$owner',decode('$code_hash','hex'));
insert into mandate_private.near_owner_wallets(owner_id,account_id,public_key)
values ('$owner','old-concurrency-wallet.testnet','$public_key');
insert into mandate_private.near_wallet_recovery_action_challenges
 (id,owner_id,request_id,action,account_id,public_key,nonce_hex,message,expires_at)
values
 ('$challenge_a','$owner','$request_a','start','new-concurrency-a.testnet','$public_key','$nonce_a','concurrency proof A',now()+interval '5 minutes'),
 ('$challenge_b','$owner','$request_b','start','new-concurrency-b.testnet','$public_key','$nonce_b','concurrency proof B',now()+interval '5 minutes');
SQL

# Session A deliberately holds the exact owner-scoped advisory lock before
# invoking the RPC. Session B starts concurrently and must wait, then observe
# A's committed pending request. The calls use separate psql processes.
psql "$DB_URL" -v ON_ERROR_STOP=1 -Atq >"$tmp/a" <<SQL &
begin;
select pg_advisory_xact_lock(hashtextextended('$owner'::text,0));
select pg_sleep(2);
select public.start_near_wallet_recovery_v1('$owner','$challenge_a','$code_hash');
commit;
SQL
pid_a=$!

sleep 0.25
psql "$DB_URL" -v ON_ERROR_STOP=1 -Atq >"$tmp/b" <<SQL &
select public.start_near_wallet_recovery_v1('$owner','$challenge_b','$code_hash');
SQL
pid_b=$!

wait "$pid_a"
wait "$pid_b"

result_a="$(grep -E '^(t|f)$' "$tmp/a" | tail -n1 || true)"
result_b="$(grep -E '^(t|f)$' "$tmp/b" | tail -n1 || true)"
successes=0
[[ "$result_a" == "t" ]] && successes=$((successes+1))
[[ "$result_b" == "t" ]] && successes=$((successes+1))
if [[ "$successes" -ne 1 ]]; then
  echo "Expected exactly one successful recovery start; session A='$result_a', session B='$result_b'" >&2
  cat "$tmp/a" "$tmp/b" >&2
  exit 1
fi

pending="$(psql "$DB_URL" -v ON_ERROR_STOP=1 -Atq -c "select count(*) from mandate_private.near_wallet_recovery_requests where owner_id='$owner' and status='pending'")"
if [[ "$pending" != "1" ]]; then
  echo "Expected exactly one pending recovery request, found '$pending'" >&2
  exit 1
fi

echo "PASS: two independent PostgreSQL sessions raced; exactly one recovery start succeeded and exactly one pending request exists."
