#!/usr/bin/env bash
# Run the real-Freighter e2e suite (or a given subset) end to end: one
# scripts/run-e2e.sh invocation per test, so each test gets a fresh
# profile restore exactly as it was verified. Prints a per-test summary
# at the end and exits nonzero if any test failed.
#
# Usage: run-all.sh [TEST_FILE ...]   (default: every tests/*.mjs in order)

set -uo pipefail

die() { echo "run-all.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat >&2 <<'USAGE'
Usage: run-all.sh [TEST_FILE ...]

Runs the suite one test at a time through scripts/run-e2e.sh (fresh
profile restore per test), then prints a pass/fail summary. Exits 0 only
if every test passed — a failure never stops the remaining tests, so the
summary always names everything that broke, not just the first.

With no arguments, runs every tests/*.mjs in filename order. Any
arguments are taken as the subset to run (paths from the repo root or the
e2e-freighter directory).

Environment: same as run-e2e.sh (APPROVE, HEADFUL, APP_URL, the sourced
deployments/testnet/.e2e-accounts.env).

Examples:
  scripts/run-all.sh                          # whole suite
  scripts/run-all.sh tests/01-connect.mjs     # one test
  npm run ci                                   # = APPROVE=auto run-all.sh
USAGE
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
need bash
need node

tests=()
if [ $# -gt 0 ]; then
  tests=("$@")
else
  for f in "$PKG_ROOT"/tests/*.mjs; do
    [ -e "$f" ] && tests+=("$f")
  done
fi
[ ${#tests[@]} -gt 0 ] || die "no test files found"

passed=0
failed=0
failed_names=()

for t in "${tests[@]}"; do
  step "running $t"
  if bash "$SCRIPT_DIR/run-e2e.sh" "$t"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    failed_names+=("$t")
  fi
done

echo
step "suite summary: $passed passed, $failed failed (${#tests[@]} total)"
for t in ${failed_names[@]+"${failed_names[@]}"}; do
  echo "  FAILED: $t"
done

[ "$failed" -eq 0 ]
