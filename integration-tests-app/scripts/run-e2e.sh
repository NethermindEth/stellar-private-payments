#!/usr/bin/env bash
# Orchestrate one e2e run: restore a fresh Freighter profile from the
# snapshot into a temp dir, run src/runner.mjs against it, then clean up.
#
# Usage: run-e2e.sh TEST_FILE

set -euo pipefail

die() { echo "run-e2e.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
step() { echo "==> $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TEST_FILE=""

usage() {
  cat >&2 <<'USAGE'
Usage: run-e2e.sh [OPTIONS] TEST_FILE

Restores a fresh Freighter profile from the snapshot (scripts/provision.sh
--restore) into a temp dir, runs src/runner.mjs against it with the given
TEST_FILE (a module exporting an async run({ context, page, ... }) function)
— then removes the temp profile dir.

Options:
  -h, --help     Show this help

Environment:
  APPROVE=auto|human    auto clicks through Freighter approvals by text;
                        human waits for you to act (the demo path)
  HEADFUL=1             Run Chrome headed instead of headless
  APP_URL                App URL to connect to (required; no default)
  E2E_FREIGHTER_PASSWORD Freighter unlock password (default: a fixed
                        constant — see src/env.mjs)

Examples:
  npm run demo                 # HEADFUL=1 APPROVE=human
  npm run ci                    # APPROVE=auto, headless
  scripts/run-e2e.sh tests/deposit.mjs
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) TEST_FILE="$1"; shift ;;
  esac
done

if [ -z "$TEST_FILE" ]; then
  usage
  die "need a TEST_FILE"
fi

# Provision the Freighter profile if node_modules/extension/snapshot are
# missing (E2E_SKIP_SETUP=1 bypasses this).
if [ "${E2E_SKIP_SETUP:-}" != "1" ]; then
  MISSING=()
  [ -d "$PKG_ROOT/node_modules" ] || MISSING+=("node_modules")
  [ -d "$PKG_ROOT/vendor/freighter" ] || MISSING+=("vendored extension")
  [ -s "$PKG_ROOT/profile-snapshot.tar.gz" ] || MISSING+=("profile snapshot")
  if [ ${#MISSING[@]} -gt 0 ]; then
    step "profile: missing ${MISSING[*]} — running integration-tests-app/scripts/setup.sh"
    bash "$PKG_ROOT/scripts/setup.sh" || die "profile setup failed"
  fi
fi

need node
need bash

step "preparing profile"
USER_DATA_DIR="$(bash "$SCRIPT_DIR/provision.sh" --restore)"
TMP_ROOT="$(dirname "$USER_DATA_DIR")"

cleanup() { rm -rf "$TMP_ROOT"; }
trap cleanup EXIT

export E2E_CHROME_USER_DATA_DIR="$USER_DATA_DIR"

step "running $TEST_FILE"
node "$PKG_ROOT/src/runner.mjs" "$TEST_FILE"
