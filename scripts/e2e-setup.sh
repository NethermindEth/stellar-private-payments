#!/usr/bin/env bash
# One-command setup for all E2E test suites.
#
# Delegates all provisioning to scripts/e2e-preflight.sh --fix — the single
# source of truth for what "e2e setup" means: the testnet accounts, the
# compiled circuit artifacts, the sdk/web dist, and the Freighter
# node_modules + vendored extension. The one thing --fix cannot do is the
# one-time headed Freighter onboarding; when that remains outstanding, the
# preflight's own report already names the exact command to run — this
# script surfaces that rather than inventing its own wording.
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

step "Running the unified e2e preflight in --fix mode"
PREFLIGHT_EXIT=0
bash "$REPO_ROOT/scripts/e2e-preflight.sh" --fix --suite all || PREFLIGHT_EXIT=$?
if [ "$PREFLIGHT_EXIT" -ne 0 ]; then
  step "preflight could not heal everything — see its report above for the exact remaining command (expected for the one-time headed Freighter onboarding)"
fi

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

exit "$PREFLIGHT_EXIT"
