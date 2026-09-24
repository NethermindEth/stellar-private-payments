#!/usr/bin/env bash
# One-command first-time setup for the real-Freighter e2e suite.
#
# Delegates to the consolidated provision.sh, which handles the full
# provisioning, snapshot, and verification pipeline.
#
# Usage: setup.sh [--force]

set -euo pipefail

die() { echo "setup.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PKG_ROOT/.." && pwd)"

case "${1:-}" in
  --force|"") ;;
  -h|--help)
    cat >&2 <<'USAGE'
Usage: setup.sh [--force]

First-time setup for the e2e-freighter suite, in one command:

  1. npm ci (skipped when node_modules exists)
  2. fetch the pinned Freighter extension (if not cached)
  3. provision the Freighter profile (extension, accounts C and D, sidebar mode)
  4. complete the app's onboarding wizard once, HEADED
  5. snapshot the result
  6. verify a restored copy works

Idempotent: with a good existing snapshot it verifies and exits.

  --force        Rebuild the profile and snapshot even if one verifies fine.
USAGE
    exit 0 ;;
  *) die "unknown argument '$1'" ;;
esac

# A server left running across branch switches can serve an older dist/ while
# APP_URL still points to it. Reject that before provision.sh clears a working
# Freighter profile and drives the wrong storage/onboarding flow.
# Asset names do not change between builds (Trunk.toml sets filehash = false),
# so compare contents: the app code, SDK and storage worker must match this
# checkout's build byte for byte.
[ -n "${APP_URL:-}" ] || die "APP_URL is not set; build and serve this checkout first."
curl -fsS -o /dev/null "$APP_URL" \
  || die "APP_URL=$APP_URL is not serving the app; build and serve this checkout first."
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1
}
DIST="$REPO_ROOT/${DIST_DIR:-dist}"
for asset in \
  js/ui.js \
  js/stellar-private-payments/dist/stellar_private_payments_web_bg.wasm \
  js/stellar-private-payments/dist/workers/storage-worker-module_bg.wasm
do
  [ -f "$DIST/$asset" ] || die "$DIST/$asset is missing; build and serve this checkout first."
  served="$(curl -fsS "${APP_URL%/}/$asset" | sha256)" \
    || die "APP_URL=$APP_URL does not serve $asset; build and serve this checkout first."
  [ "$served" = "$(sha256 < "$DIST/$asset")" ] \
    || die "APP_URL=$APP_URL serves a different $asset than $DIST. Rebuild and serve this branch before provisioning."
done

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
  *)
    step "running the consolidated provision pipeline"
    exec bash "$SCRIPT_DIR/provision.sh" ;;
esac
