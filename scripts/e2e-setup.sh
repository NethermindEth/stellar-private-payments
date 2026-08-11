#!/usr/bin/env bash
# One-command setup for all E2E test suites.
#
# - Provisions the four testnet accounts (A/B for the SDK suite, C/D for the
#   Freighter suite) and writes deployments/testnet/.e2e-accounts.env.
# - Builds the circuit artifacts the pre-signing SDK tests need.
# - Prepares the Freighter profile snapshot for the real-browser suite.
#
# Does NOT run the tests themselves — it prints the commands to run them.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

need() { command -v "$1" >/dev/null 2>&1 || { echo "e2e-setup: missing '$1'" >&2; exit 1; }; }
step() { echo "==> $*" >&2; }

need bash
need cargo
need node
need npm

step "Provisioning testnet accounts (idempotent)"
bash "$REPO_ROOT/deployments/scripts/e2e-accounts-setup.sh"

step "Building circuit artifacts for the pre-signing SDK tests"
cargo build -p circuits
cargo build -p circuits --release

step "Setting up the Freighter profile snapshot (idempotent)"
bash "$REPO_ROOT/e2e-freighter/scripts/setup.sh"

cat <<'EOF'

E2E setup complete.

Run the pre-signing SDK tests:

  export E2E_STATIC_ORIGIN=http://127.0.0.1:8099
  set -a; . deployments/testnet/.e2e-accounts.env; set +a
  bash sdk/web/scripts/e2e-browser-test.sh \
    cargo test --target wasm32-unknown-unknown -p stellar-private-payments-sdk-web \
    -- --include-ignored

Run the real-browser Freighter tests:

  bash e2e-freighter/scripts/run-all.sh

Run a single Freighter test:

  bash e2e-freighter/scripts/run-e2e.sh e2e-freighter/tests/01-connect.mjs

The env file is sourced automatically by the Freighter scripts. The SDK test
command above sources it explicitly because the variables are read at compile
time via option_env!.

EOF
