#!/usr/bin/env bash
# Bring the Freighter e2e prerequisites into existence, but only the ones
# that are actually missing. A no-op on an already-set-up checkout.
#
# Usage: e2e-ensure-setup.sh
#
#   E2E_SKIP_SETUP=1   Skip entirely and let the preflight report what is missing
#
# No account provisioning here: e2e-freighter creates its own ephemeral
# account per test run, so the only prerequisite is the account-agnostic
# Freighter profile snapshot, plus node_modules and the vendored extension.
#
# Gating is a cheap filesystem check, not setup.sh's own idempotency — its
# no-op path still restores the snapshot and launches a browser, several
# seconds not worth paying on every `make freighter-smoke`.
#
# Deliberately no REPAIR here: a snapshot that exists but no longer works
# needs `bash e2e-freighter/scripts/setup.sh --force`, not silent
# reprovisioning on every failure mid test run.

set -euo pipefail

die() { echo "e2e-ensure-setup.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ -n "${E2E_SKIP_SETUP:-}" ]; then
  step "E2E_SKIP_SETUP is set — skipping the setup check"
  exit 0
fi

PKG="e2e-freighter"
SNAPSHOT="$PKG/profile-snapshot.tar.gz"

MISSING=()
[ -d "$PKG/node_modules" ] || MISSING+=("node_modules")
[ -d "$PKG/vendor/freighter" ] || MISSING+=("vendored extension")
[ -s "$SNAPSHOT" ] || MISSING+=("profile snapshot")

if [ ${#MISSING[@]} -eq 0 ]; then
  step "profile: snapshot, extension and node_modules all present"
else
  step "profile: missing ${MISSING[*]} — running e2e-freighter/scripts/setup.sh"
  # Provisioning drives a real browser window. Say so before it happens,
  # rather than letting provision.sh die on a missing display several steps in.
  if [ ! -s "$SNAPSHOT" ] && [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    die "building the profile snapshot needs a display (it completes Freighter's own onboarding headed). Run under a desktop session, or wrap this in xvfb-run."
  fi
  # setup.sh needs a served app (even its verify-only path connects to it),
  # so route through serve-and-run.sh for the same start/stop/reuse logic
  # and local-network startup a real test run gets.
  bash "$PKG/scripts/serve-and-run.sh" -- bash "$PKG/scripts/setup.sh"
fi

step "setup check complete"
