#!/usr/bin/env bash
# Bring the Freighter e2e prerequisites into existence, but only the ones
# that are actually missing. A no-op on an already-set-up checkout.
#
# Usage: e2e-ensure-setup.sh
#
#   E2E_SKIP_SETUP=1   Skip entirely and let the preflight report what is missing
#
# Gating is by cheap filesystem checks, NOT by calling the setup scripts and
# letting their idempotency sort it out. Both scripts are idempotent, but
# their no-op paths are expensive: e2e-accounts-setup.sh verifies four
# accounts over RPC, and e2e-freighter/scripts/setup.sh validates the profile
# snapshot by restoring it and launching a browser against it. Paying that on
# every `make freighter-smoke` would be several seconds to a minute of
# nothing. A stat is free, so the expensive path runs only when a piece is
# genuinely absent.
#
# This deliberately does not attempt REPAIR. Missing and broken are different
# problems: a snapshot that exists but no longer works, or accounts registered
# against a superseded deployment, are what scripts/e2e-repair.sh is for. A
# target that silently reprovisioned on every failure would turn a two-minute
# headed rebuild into a surprise in the middle of a test run.

set -euo pipefail

die() { echo "e2e-ensure-setup.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ -n "${E2E_SKIP_SETUP:-}" ]; then
  step "E2E_SKIP_SETUP is set — skipping the setup check"
  exit 0
fi

ENV_FILE="deployments/testnet/.e2e-accounts.env"
PKG="e2e-freighter"
SNAPSHOT="$PKG/profile-snapshot.tar.gz"

# --- accounts -------------------------------------------------------------
if [ -s "$ENV_FILE" ]; then
  step "accounts: $ENV_FILE present"
else
  step "accounts: $ENV_FILE missing — provisioning four testnet accounts"
  bash deployments/scripts/e2e-accounts-setup.sh
fi

# --- profile, extension, node_modules -------------------------------------
# setup.sh covers all three (npm ci, fetch the pinned extension, provision and
# snapshot the profile), and skips whichever of them is already done, so one
# invocation is enough no matter which piece is the missing one.
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
    die "building the profile snapshot needs a display (it completes the wallet and app onboarding headed). Run under a desktop session, or wrap this in xvfb-run."
  fi
  # setup.sh needs a served app regardless of which piece was missing:
  # provision.mjs completes the APP's onboarding wizard (navigates to
  # APP_URL), and even the snapshot-already-exists verify path calls
  # connectApp(), which needs one too. Routed through serve-and-run.sh
  # rather than duplicated here, so the same start/stop/reuse-if-already-
  # running logic applies as it does for an actual test run.
  bash "$PKG/scripts/serve-and-run.sh" -- bash "$PKG/scripts/setup.sh"
fi

step "setup check complete"
