#!/usr/bin/env bash
# One-command first-time setup for the real-Freighter e2e suite.
#
# Delegates to the consolidated provision.sh, which handles the full
# provisioning, snapshot, and verification pipeline.
#
# Usage: setup.sh [--force] [--add-account]

set -euo pipefail

die() { echo "setup.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PKG_ROOT/.." && pwd)"
E2E_ENV_FILE="$REPO_ROOT/deployments/testnet/.e2e-accounts.env"

case "${1:-}" in
  --force|--add-account|"") ;;
  -h|--help)
    cat >&2 <<'USAGE'
Usage: setup.sh [--force] [--add-account]

First-time setup for the e2e-freighter suite, in one command:

  1. npm ci (skipped when node_modules exists)
  2. fetch the pinned Freighter extension (if not cached)
  3. provision the Freighter profile (extension, test account, sidebar mode)
  4. complete app onboarding, migrate storage to SQLite3MC, and enroll Freighter unlock, HEADED
  5. snapshot the result
  6. verify a restored copy works

Idempotent: with a good existing snapshot it verifies and exits.

Prerequisite: run deployments/scripts/e2e-accounts-setup.sh first. It writes
the generated E2E_FREIGHTER_PASSWORD to the git-ignored account env file;
you do not need to export or choose a password manually.

  --force        Rebuild the profile and snapshot even if one verifies fine.
  --add-account  Also import account B (E2E_ACCOUNT_D_SECRET).
USAGE
    exit 0 ;;
  *) die "unknown argument '$1'" ;;
esac

if [ -z "${E2E_FREIGHTER_PASSWORD:-}" ] &&
   { [ ! -f "$E2E_ENV_FILE" ] || ! grep -q '^E2E_FREIGHTER_PASSWORD=.' "$E2E_ENV_FILE"; }; then
  die "test-account env file has no E2E_FREIGHTER_PASSWORD. Run 'bash deployments/scripts/e2e-accounts-setup.sh' from the repo root first; it generates and saves the test password automatically."
fi

# A direct setup invocation needs the checked-out app running for onboarding.
# The wrapper starts it, or reuses an existing local server, and passes APP_URL
# to this script. CI already enters through that wrapper and skips this branch.
if [ -z "${APP_URL:-}" ]; then
  step "starting the checked-out app for Freighter profile setup"
  exec bash "$SCRIPT_DIR/serve-and-run.sh" -- bash "$SCRIPT_DIR/setup.sh" "$@"
fi

# Provisioning imports Playwright through src/runner.mjs, so dependencies must
# be installed before running it.
if [ ! -d "$PKG_ROOT/node_modules" ]; then
  step "installing e2e-freighter npm dependencies: npm ci"
  ( cd "$PKG_ROOT" && npm ci )
fi

# Step 2, same story: vendor/freighter is git-ignored (third-party build
# output), so a fresh checkout has no extension at all until this runs.
# Without it, runner.mjs's --load-extension points at a directory with no
# valid manifest, Chromium never derives the pinned extension id, and
# provisioning fails navigating to chrome-extension://<id>/... with
# ERR_BLOCKED_BY_CLIENT — a failure that looks like a browser/launch
# problem but is actually just a missing fetch step. fetch-extension.sh is
# itself idempotent (skips cleanly if the pinned version is already
# vendored), so this is safe to run unconditionally.
step "ensuring the pinned Freighter extension is vendored"
bash "$SCRIPT_DIR/fetch-extension.sh"

case "${1:-}" in
  --force) exec bash "$SCRIPT_DIR/provision.sh" --force ;;
  --add-account) exec bash "$SCRIPT_DIR/provision.sh" --add-account ;;
  *)
    step "running the consolidated provision pipeline"
    exec bash "$SCRIPT_DIR/provision.sh" ;;
esac
