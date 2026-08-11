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

case "${1:-}" in
  --force) exec bash "$SCRIPT_DIR/provision.sh" --force ;;
  --add-account) exec bash "$SCRIPT_DIR/provision.sh" --add-account ;;
  -h|--help)
    cat >&2 <<'USAGE'
Usage: setup.sh [--force] [--add-account]

First-time setup for the e2e-freighter suite, in one command:

  1. npm ci (skipped when node_modules exists)
  2. fetch the pinned Freighter extension (if not cached)
  3. provision the Freighter profile (extension, test account, sidebar mode)
  4. complete the app's onboarding wizard once, HEADED
  5. snapshot the result
  6. verify a restored copy works

Idempotent: with a good existing snapshot it verifies and exits.

  --force        Rebuild the profile and snapshot even if one verifies fine.
  --add-account  Also import account B (E2E_ACCOUNT_D_SECRET).
USAGE
    exit 0 ;;
  "") ;;  # default: run provision with existing snapshot check
  *) die "unknown argument '$1'" ;;
esac

step "running the consolidated provision pipeline"
bash "$SCRIPT_DIR/provision.sh"