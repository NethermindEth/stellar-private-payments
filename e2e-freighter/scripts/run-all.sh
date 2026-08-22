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
REPO_ROOT="$(cd "$PKG_ROOT/.." && pwd)"

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

Environment: same as run-e2e.sh (APPROVE, HEADFUL, APP_URL, E2E_LOG_LEVEL,
the sourced deployments/testnet/.e2e-accounts.env).

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

# Run once before the loop — run-e2e.sh (invoked once per test below) skips
# its own preflight via E2E_PREFLIGHT_DONE, so this is not repeated
# per-test. E2E_SKIP_PREFLIGHT=1 bypasses it entirely. On failure, abort
# with the preflight's own report already printed — no extra wrapping.
if [ "${E2E_SKIP_PREFLIGHT:-}" != "1" ]; then
  bash "$REPO_ROOT/scripts/e2e-preflight.sh" --check --suite freighter || exit 1
  export E2E_PREFLIGHT_DONE=1
  echo >&2
  echo '--- e2e suite ---' >&2
fi

# Colorized results on an interactive terminal only (CI logs stay plain).
if [ -t 1 ]; then
  C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_RESET=$'\033[0m'
else
  C_GREEN=""; C_RED=""; C_RESET=""
fi

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
    echo "  ${C_GREEN}PASS${C_RESET}: $t"
  else
    failed=$((failed + 1))
    failed_names+=("$t")
    echo "  ${C_RED}FAIL${C_RESET}: $t"
  fi
done

echo
if [ "$failed" -eq 0 ]; then
  step "suite summary: ${C_GREEN}$passed passed${C_RESET}, $failed failed (${#tests[@]} total)"
else
  step "suite summary: $passed passed, ${C_RED}$failed failed${C_RESET} (${#tests[@]} total)"
fi
for t in ${failed_names[@]+"${failed_names[@]}"}; do
  echo "  ${C_RED}FAILED${C_RESET}: $t"
done

if [ "$failed" -gt 0 ]; then
  echo
  echo "Run this next (headed, with human approvals):"
  for t in ${failed_names[@]+"${failed_names[@]}"}; do
    echo "  HEADFUL=1 APPROVE=human bash scripts/run-e2e.sh $t"
  done
fi

[ "$failed" -eq 0 ]
