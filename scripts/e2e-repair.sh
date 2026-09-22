#!/usr/bin/env bash
# Salvage an e2e setup that stopped working after a redeploy.
#
# Usage: e2e-repair.sh [--profile] [--dry-run]
#
#   --profile    Also rebuild the Freighter profile snapshot (HEADED, ~2min)
#   --dry-run    Print the steps without running them
#
# The failure this repairs: contracts get redeployed, and everything anchored
# to the old ones goes stale at once — in ways that surface far from the
# cause. The accounts still verify as funded but not as registered; the CLI
# keeps testing the previous deployment; the wallet DB accumulates pools that
# no longer exist. Each is a different script with a different flag, and the
# error you actually see (a failed preflight check, or a test dying on a
# balance that should be there) names none of them.
#
# Order matters and is not arbitrary:
#
#   1. Rebuild spp FIRST. cli/src/config/mod.rs embeds deployments.json at
#      COMPILE time via include_str!, so a stale binary talks to the previous
#      deployment no matter what the file on disk says. Every later step uses
#      this binary, so rebuilding it after them would invalidate their work.
#   2. Re-register the accounts. A redeploy mints a new public-key registry;
#      the keypairs and funding are fine, the registration is in a contract
#      nothing points at. --reregister repairs that in place. NOT --force,
#      which would regenerate the keypairs and abandon four funded accounts.
#   3. Prune the wallet DB of contract generations no deployments.json names.
#   4. Re-run the preflight to confirm, rather than declaring success.
#
# The Freighter profile snapshot is NOT rebuilt by default: it is headed,
# takes a couple of minutes, and the wallet inside it survives a redeploy
# untouched (the imported account C keeps its address). Pass --profile if the
# app state baked into the profile is itself suspect.

set -euo pipefail

die() { echo "e2e-repair.sh: $*" >&2; exit 1; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$*" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WITH_PROFILE=0
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --profile) WITH_PROFILE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,36p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) die "unknown argument '$1'" ;;
  esac
done

cd "$REPO_ROOT"

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "    $*" >&2
    return 0
  fi
  "$@"
}

step "1/4  rebuilding the spp CLI (it embeds deployments.json at compile time)"
run cargo build --release -p stellar-private-payments-cli

step "2/4  re-registering the test accounts against the current deployment"
run bash deployments/scripts/e2e-accounts-setup.sh --reregister

step "3/4  pruning wallet-DB state for contracts no deployments.json names"
run bash scripts/e2e-cleanup.sh --apply

if [ "$WITH_PROFILE" -eq 1 ]; then
  step "4/5  rebuilding the Freighter profile snapshot (headed)"
  run bash e2e-freighter/scripts/setup.sh --force
fi

step "$( [ "$WITH_PROFILE" -eq 1 ] && echo '5/5' || echo '4/4' )  verifying with the preflight"
# The preflight's browser.app_url check requires APP_URL, and repairing a
# deployment has nothing to do with where the app is served — without this the
# run always ends on a MISSING for a variable the test targets set themselves.
# Point it at the URL `make freighter-smoke` serves on. The check asserts the
# URL is well-formed and local; it does not probe it, so nothing needs to be
# listening while the repair runs.
export APP_URL="${APP_URL:-http://localhost:8000}"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "    bash scripts/e2e-preflight.sh --check --suite freighter" >&2
  exit 0
fi
if bash scripts/e2e-preflight.sh --check --suite freighter; then
  step "repaired — the suite should run again (make freighter-smoke)"
else
  # A surviving failure is reported, not swallowed: the preflight names the
  # specific check, which is a better starting point than this script guessing.
  die "the preflight still reports failures above — those need handling individually"
fi
