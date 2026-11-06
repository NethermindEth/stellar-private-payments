#!/usr/bin/env bash
# One chain/deployment/server; each cargo invocation creates a fresh browser/OPFS.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
cases=(
  e2e_smoke_client_construction
  e2e_foreign_derivation_signature_is_refused
  e2e_seed_deposit_creates_spendable_notes
  e2e_deposit_halts_at_signing
  e2e_transfer_halts_at_signing
  e2e_withdraw_halts_at_signing
  e2e_session_account_setup_and_sync
)
# --fresh-localnet retains the old lifecycle for cold baseline measurements.
mode="${1:-}"
if [[ "$mode" != --cases && "$mode" != --fresh-localnet ]]; then
  exec bash "$ROOT/integration-tests-web/run.sh" bash "$0" --cases "$@"
fi
shift
if [[ "${1:-}" == --reverse ]]; then
  reversed=()
  for ((i=${#cases[@]}-1; i>=0; i--)); do reversed+=("${cases[i]}"); done
  cases=("${reversed[@]}")
elif [[ $# -gt 0 ]]; then
  # Explicit case selection supports standalone isolation checks.
  cases=("$@")
fi
for test_name in "${cases[@]}"; do
  if [[ "$mode" == --cases ]]; then export E2E_SKIP_LOCALNET=1; fi
  bash "$ROOT/integration-tests-web/run.sh" \
    cargo test --target wasm32-unknown-unknown \
    --manifest-path integration-tests-web/Cargo.toml \
    "$test_name" -- --include-ignored
done
