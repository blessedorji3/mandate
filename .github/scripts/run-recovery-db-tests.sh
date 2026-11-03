#!/usr/bin/env bash
set -euo pipefail

# Always replay the complete tracked migration history into a disposable local
# Supabase stack. No linked-project credentials or hosted database are used.
cleanup() {
  supabase stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

supabase start
bash .github/scripts/run-live-auth-integration-test.sh
supabase test db
bash .github/scripts/run-recovery-concurrency-test.sh
