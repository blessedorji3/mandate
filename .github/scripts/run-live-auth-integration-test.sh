#!/usr/bin/env bash
set -euo pipefail

# This script is called only after the disposable local Supabase stack has
# started. It never reads linked-project credentials or calls hosted Supabase.
eval "$(supabase status -o env)"
: "${API_URL:?Supabase local API_URL was not provided}"
: "${ANON_KEY:?Supabase local ANON_KEY was not provided}"
: "${SERVICE_ROLE_KEY:?Supabase local SERVICE_ROLE_KEY was not provided}"

export SUPABASE_URL="$API_URL"
export SUPABASE_ANON_KEY="$ANON_KEY"
export SUPABASE_SERVICE_ROLE_KEY="$SERVICE_ROLE_KEY"

deno test --no-check --node-modules-dir=auto --allow-env --allow-net \
  supabase/functions/near-transfer-authorization/live-auth-integration.test.ts
