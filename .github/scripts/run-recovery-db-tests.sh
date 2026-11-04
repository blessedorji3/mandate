#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  supabase stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Replay the tracked production migration history against a disposable local stack.
supabase start

bash .github/scripts/run-live-auth-integration-test.sh
supabase test db
bash .github/scripts/run-recovery-concurrency-test.sh
