#!/usr/bin/env bash
# Orchestrate one e2e run: restore a fresh Freighter profile from the
# snapshot into a temp dir, run src/runner.mjs against it, then clean up.
#
# Usage: run-e2e.sh [--smoke] [TEST_FILE]

set -euo pipefail

die() { echo "run-e2e.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
step() { echo "==> $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PKG_ROOT/.." && pwd)"

# Config comes from the provisioned env file when the variables are not
# already exported, so a bare invocation works from any interactive shell
# (the file is git-ignored and mode 600; explicit environment wins).
E2E_ENV_FILE="$REPO_ROOT/deployments/testnet/.e2e-accounts.env"
if [ -z "${E2E_FREIGHTER_PASSWORD:-}" ] && [ -f "$E2E_ENV_FILE" ]; then
  set -a; . "$E2E_ENV_FILE"; set +a
fi

# Colorized output on an interactive terminal only (CI logs stay plain).
# Tests print consistent tokens: "OK:" on success, "FAILED" on failure.
if [ -t 1 ]; then
  C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_RESET=$'\033[0m'
else
  C_GREEN=""; C_RED=""; C_RESET=""
fi
colorize() {
  sed -uE "s/OK:/${C_GREEN}OK:${C_RESET}/g; s/FAILED/${C_RED}FAILED${C_RESET}/g"
}

SMOKE=0
TEST_FILE=""

usage() {
  cat >&2 <<'USAGE'
Usage: run-e2e.sh [OPTIONS] [TEST_FILE]

# Restores a fresh Freighter profile from the snapshot (scripts/provision.sh --restore)
into a temp dir, runs src/runner.mjs against it — either --smoke (reach a
connected state against the app, no test logic) or a given TEST_FILE (a
module exporting an async run({ context, page, ... }) function) — then
removes the temp profile dir.

Options:
  --smoke        Run only the smoke check
  -h, --help     Show this help

Environment:
  APPROVE=auto|human    auto clicks through Freighter approvals by text;
                        human waits for you to act (the demo path)
  HEADFUL=1             Run Chrome headed instead of headless
  APP_URL                App URL to connect to (required; no default)
  E2E_FREIGHTER_PASSWORD, E2E_ACCOUNT_C_SECRET, E2E_ACCOUNT_C_ADDRESS
                        Sourced from deployments/testnet/.e2e-accounts.env

Examples:
  npm run demo                 # HEADFUL=1 APPROVE=human
  npm run ci                    # APPROVE=auto, headless
  scripts/run-e2e.sh --smoke
  scripts/run-e2e.sh tests/deposit.mjs
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --smoke) SMOKE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) TEST_FILE="$1"; shift ;;
  esac
done

if [ "$SMOKE" -ne 1 ] && [ -z "$TEST_FILE" ]; then
  usage
  die "need --smoke or a TEST_FILE"
fi

# Skipped when a parent run-all.sh already ran it once for the whole suite
# (E2E_PREFLIGHT_DONE), or when E2E_SKIP_PREFLIGHT=1 bypasses it entirely.
# On failure, abort with the preflight's own report already printed.
if [ "${E2E_SKIP_PREFLIGHT:-}" != "1" ] && [ "${E2E_PREFLIGHT_DONE:-}" != "1" ]; then
  bash "$REPO_ROOT/scripts/e2e-preflight.sh" --check --suite freighter || exit 1
fi

need node
need bash

step "preparing profile"
PROFILE_SUBDIR="$(bash "$SCRIPT_DIR/provision.sh" --restore)"
USER_DATA_DIR="$(dirname "$PROFILE_SUBDIR")"
TMP_ROOT="$(dirname "$USER_DATA_DIR")"

cleanup() { rm -rf "$TMP_ROOT"; }
trap cleanup EXIT

export E2E_CHROME_USER_DATA_DIR="$USER_DATA_DIR"

if [ "$SMOKE" -eq 1 ]; then
  step "running smoke check"
  node "$PKG_ROOT/src/runner.mjs" --smoke
else
  step "running $TEST_FILE"
  node "$PKG_ROOT/src/runner.mjs" "$TEST_FILE"
fi
