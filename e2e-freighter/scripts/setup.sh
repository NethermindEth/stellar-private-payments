#!/usr/bin/env bash
# One-command first-time setup for the real-Freighter e2e suite.
#
# Chains the four steps that used to be run by hand: npm deps, Freighter
# profile provisioning, the one-time headed onboarding completion, and the
# profile snapshot. Idempotent: if a working snapshot already exists, it
# verifies it and exits without redoing anything (use --force to rebuild).
#
# Usage: setup.sh [--force]

set -euo pipefail

die() { echo "setup.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
step() { echo "==> $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SNAPSHOT="$PKG_ROOT/profile-snapshot.tar.gz"
FORCE=0

usage() {
  cat >&2 <<'USAGE'
Usage: setup.sh [--force]

First-time setup for the e2e-freighter suite, in one command:

  1. npm ci (skipped when node_modules exists)
  2. provision the Freighter profile (pinned extension, test account,
     testnet, sidebar mode) — scripts/setup-freighter-profile.mjs
  3. complete the app's onboarding wizard once, HEADED (it can stall
     under headless rendering) — scripts/complete-onboarding.mjs
  4. snapshot the result — scripts/snapshot-profile.sh
  5. verify a restored copy works — scripts/verify-onboarded.mjs

Idempotent: with a good existing snapshot it verifies and exits. The env
file (deployments/testnet/.e2e-accounts.env) is self-sourced by all of
these; create it first with deployments/scripts/e2e-accounts-setup.sh.

  --force   Rebuild the profile and snapshot even if one verifies fine.
USAGE
}

case "${1:-}" in
  --force) FORCE=1 ;;
  -h|--help) usage; exit 0 ;;
  "") ;;
  *) usage; die "unknown argument '$1'" ;;
esac

need node
need npm

if [ -d "$PKG_ROOT/node_modules" ]; then
  step "node_modules present; skipping npm ci"
else
  step "installing npm dependencies"
  npm ci --prefix "$PKG_ROOT"
fi

if [ "$FORCE" -eq 0 ] && [ -s "$SNAPSHOT" ]; then
  step "snapshot exists; verifying instead of rebuilding (use --force to rebuild)"
  node "$SCRIPT_DIR/verify-onboarded.mjs"
  step "setup already complete — snapshot verified"
  exit 0
fi

# The wizard completion drives a headed browser; it cannot run headless.
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
  die "no display available: the onboarding step must run headed (run on a machine with a desktop session)"
fi

step "provisioning the Freighter profile"
node "$SCRIPT_DIR/setup-freighter-profile.mjs"

step "completing the app's onboarding wizard (headed)"
node "$SCRIPT_DIR/complete-onboarding.mjs"

step "snapshotting the profile"
bash "$SCRIPT_DIR/snapshot-profile.sh"

step "verifying a restored copy"
node "$SCRIPT_DIR/verify-onboarded.mjs"

step "setup complete — run the suite with: bash $SCRIPT_DIR/run-all.sh"
