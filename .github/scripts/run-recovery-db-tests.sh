#!/usr/bin/env bash
set -euo pipefail

fixture="supabase/tests/fixtures/mandate-test-baseline.sql"
temporary_migration="supabase/migrations/20261001000000_test_only_baseline.sql"

if [[ ! -f "$fixture" ]]; then
  echo "Missing test-only schema fixture: $fixture" >&2
  exit 1
fi
if [[ -e "$temporary_migration" ]]; then
  echo "Refusing to overwrite an existing migration: $temporary_migration" >&2
  exit 1
fi

cleanup() {
  rm -f "$temporary_migration"
  supabase stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

# This migration exists only while the disposable local stack is being tested.
# The trap removes it even when startup or tests fail.
cp "$fixture" "$temporary_migration"
supabase start
supabase test db
