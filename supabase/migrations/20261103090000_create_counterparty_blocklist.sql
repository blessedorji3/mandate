-- Evidence-backed shared blocklist. Reports default to pending; only an
-- explicitly reviewed record may be used as a BLOCK signal.
create table if not exists mandate_private.counterparty_blocklist (
 id uuid primary key default gen_random_uuid(),
 network text not null check(network in ('testnet','mainnet')),
 account_id text not null check(account_id ~ '^[a-z0-9._-]{2,64}([.][a-z0-9._-]{2,64})*$'),
 status text not null default 'pending' check(status in ('pending','confirmed','rejected')),
 reason text not null check(length(trim(reason)) between 8 and 500),
 evidence_ref text not null check(length(trim(evidence_ref)) between 8 and 2048),
 evidence_sha256 text check(evidence_sha256 is null or evidence_sha256 ~ '^[0-9a-f]{64}$'),
 source_type text not null check(source_type in ('chain_tx','explorer','security_advisory','other')),
 reporter_owner_id uuid references auth.users(id) on delete set null,
 reviewer_owner_id uuid references auth.users(id) on delete set null,
 reviewed_at timestamptz,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 constraint counterparty_blocklist_review_state check(
  (status='confirmed' and reviewer_owner_id is not null and reviewed_at is not null) or status<>'confirmed'
 )
);
create index if not exists counterparty_blocklist_lookup_idx on mandate_private.counterparty_blocklist(network,account_id,status);
alter table mandate_private.counterparty_blocklist enable row level security;
revoke all on mandate_private.counterparty_blocklist from public,anon,authenticated;
grant select,insert,update on mandate_private.counterparty_blocklist to service_role;
