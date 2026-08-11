#!/usr/bin/env bash
# scripts/e2e-preflight-selftest.sh
#
# Regression test for scripts/e2e-preflight.sh: hermetic fault injection
# proving the preflight actually detects breakage rather than always
# printing green. Uses ONLY the contract's path-override env vars
# (E2E_ENV_FILE, E2E_SNAPSHOT_FILE, E2E_VENDOR_DIR, E2E_CIRCUITS_OUT_DIR,
# E2E_SDK_DIST_DIR, E2E_CHROMIUM_PATH, E2E_PROFILE_TMPDIR) pointed at
# nonexistent or mktemp -d temp paths — it never moves, renames or deletes
# any real repo file. Never invokes --fix, never touches the network, and
# never launches a browser.
#
# Usage: scripts/e2e-preflight-selftest.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PREFLIGHT="$REPO_ROOT/scripts/e2e-preflight.sh"

FAILURES=0
CHECKS_RUN=0

fail() {
  FAILURES=$((FAILURES + 1))
  echo "FAIL: $*" >&2
}

count() {
  CHECKS_RUN=$((CHECKS_RUN + 1))
}

TMP_ROOT="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Invocation + assertion helpers
# ---------------------------------------------------------------------------

# Runs the preflight, capturing stderr (ERR) and exit code (STATUS).
# COMBINED holds stdout+stderr for the secret-leak sweep.
run_preflight() {
  local stderr_file
  stderr_file="$(mktemp)"
  # Skip network checks in the selftest — we never need real RPC
  OUT="$(E2E_SKIP_NETWORK_CHECKS=1 bash "$PREFLIGHT" "$@" 2>"$stderr_file")"
  STATUS=$?
  ERR="$(cat "$stderr_file")"
  rm -f "$stderr_file"
  COMBINED="$OUT
$ERR"
}

# Assert that the preflight's stderr contains a given check id with MISSING status
assert_missing() {
  local id="$1"
  count
  if ! printf '%s' "$ERR" | grep -q "^MISSING  $id "; then
    fail "$id: expected MISSING status in stderr"
    echo "--- stderr ($id) ---" >&2
    printf '%s\n' "$ERR" >&2
  fi
}

# Assert that the preflight's stderr contains a given check id with ok status
assert_ok() {
  local id="$1"
  count
  if ! printf '%s' "$ERR" | grep -q "^ok: $id "; then
    fail "$id: expected OK status in stderr"
    echo "--- stderr ($id) ---" >&2
    printf '%s\n' "$ERR" >&2
  fi
}

# Assert that a check id does NOT appear in stderr at all
assert_absent() {
  local id="$1"
  count
  if printf '%s' "$ERR" | grep -q "$id"; then
    fail "$id: expected to be absent from output, but found it"
  fi
}

# Assert a specific remediation string in stderr for a check id
assert_remediation() {
  local id="$1" pattern="$2"
  count
  if ! printf '%s' "$ERR" | grep -q "fix: .*$pattern"; then
    fail "$id: expected remediation pattern '$pattern' in stderr"
    echo "--- stderr ($id) ---" >&2
    printf '%s\n' "$ERR" >&2
  fi
}

# Assert no remediation with the given pattern (used for negative assertions)
assert_no_remediation() {
  local id="$1" pattern="$2"
  count
  if printf '%s' "$ERR" | grep -q "fix: .*$pattern"; then
    fail "$id: found unexpected remediation pattern '$pattern' in stderr"
  fi
}

assert_exit() {
  local label="$1" want="$2" got="$3"
  count
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
  fi
}

assert_no_secret_pattern() {
  local combined="$1" label="$2"
  count
  if printf '%s' "$combined" | grep -qE 'S[A-Z2-7]{55}'; then
    fail "$label: output matches the Stellar secret-key pattern"
  fi
}

assert_not_contains() {
  local combined="$1" needle="$2" label="$3"
  count
  if printf '%s' "$combined" | grep -qF "$needle"; then
    fail "$label: dummy secret value leaked verbatim into output"
  fi
}

# ---------------------------------------------------------------------------
# Suite-exclusivity check lists
# ---------------------------------------------------------------------------
SDK_ONLY_IDS="tool.cargo tool.rust-toolchain tool.wasm32-target tool.wasm-bindgen-cli tool.chromedriver env.pool.matches_deployments env.compiletime.exported artifact.circuits.debug artifact.circuits.release artifact.circuit_keys artifact.sdk_dist.workers artifact.sdk_dist.circuits artifact.sdk_dist.freshness"
FREIGHTER_ONLY_IDS="tool.tar tool.unzip tool.chromium tool.trunk tool.xvfb freighter.node_modules freighter.playwright freighter.ffmpeg freighter.extension.pinned freighter.snapshot.exists freighter.snapshot.integrity freighter.onboarding browser.chromium.resolved browser.profile_tmpdir browser.display browser.app_url"

# ---------------------------------------------------------------------------
# Test A: env.file.* / env.vars.required / env.compiletime.exported fault
# (E2E_ENV_FILE -> nonexistent). Also covers suite exclusivity for --suite sdk.
# ---------------------------------------------------------------------------
export CI=1
export E2E_ENV_FILE="$TMP_ROOT/no-such.env"
run_preflight --check --suite sdk
assert_missing env.file.exists
assert_missing env.file.mode
assert_missing env.file.gitignored
assert_missing env.vars.required
assert_missing env.compiletime.exported
assert_exit "env.file.* fault" 1 "$STATUS"
for id in $FREIGHTER_ONLY_IDS; do assert_absent "$id"; done
unset E2E_ENV_FILE

# ---------------------------------------------------------------------------
# Test B: freighter.extension.pinned fault (E2E_VENDOR_DIR -> nonexistent).
# Also covers suite exclusivity for --suite freighter.
# ---------------------------------------------------------------------------
export E2E_VENDOR_DIR="$TMP_ROOT/no-vendor"
run_preflight --check --suite freighter
assert_missing freighter.extension.pinned
assert_exit "freighter.extension.pinned fault" 1 "$STATUS"
for id in $SDK_ONLY_IDS; do assert_absent "$id"; done
unset E2E_VENDOR_DIR

# ---------------------------------------------------------------------------
# Test C: freighter.snapshot.* fault (E2E_SNAPSHOT_FILE -> nonexistent),
# CI simulated -> expect the xvfb-run remediation form, exactly once.
# ---------------------------------------------------------------------------
export CI=1
export E2E_SNAPSHOT_FILE="$TMP_ROOT/no-snapshot-ci.tar.gz"
run_preflight --check --suite freighter
assert_missing freighter.snapshot.exists
assert_missing freighter.snapshot.integrity
assert_missing freighter.onboarding
assert_exit "freighter.snapshot.* fault (CI)" 1 "$STATUS"
assert_remediation freighter.snapshot.exists "xvfb-run -a bash e2e-freighter/scripts/setup.sh"
assert_remediation freighter.snapshot.integrity "xvfb-run -a bash e2e-freighter/scripts/setup.sh"
unset E2E_SNAPSHOT_FILE

# ---------------------------------------------------------------------------
# Test D: same fault, desktop simulated (no CI, DISPLAY set) -> expect the
# plain remediation form, exactly once.
# ---------------------------------------------------------------------------
unset CI GITHUB_ACTIONS
export DISPLAY=":0"
export E2E_SNAPSHOT_FILE="$TMP_ROOT/no-snapshot-desktop.tar.gz"
run_preflight --check --suite freighter
assert_missing freighter.onboarding
assert_exit "freighter.snapshot.* fault (desktop)" 1 "$STATUS"
assert_remediation freighter.onboarding "bash e2e-freighter/scripts/setup.sh"
assert_no_remediation freighter.onboarding "xvfb-run"
unset E2E_SNAPSHOT_FILE
export CI=1

# ---------------------------------------------------------------------------
# Test E: artifact.* fault (E2E_CIRCUITS_OUT_DIR, E2E_SDK_DIST_DIR ->
# nonexistent).
# ---------------------------------------------------------------------------
export E2E_CIRCUITS_OUT_DIR="$TMP_ROOT/no-circuits"
export E2E_SDK_DIST_DIR="$TMP_ROOT/no-dist"
run_preflight --check --suite sdk
assert_missing artifact.circuits.debug
assert_missing artifact.circuits.release
assert_missing artifact.sdk_dist.workers
assert_missing artifact.sdk_dist.circuits
assert_exit "artifact.* fault" 1 "$STATUS"
unset E2E_CIRCUITS_OUT_DIR E2E_SDK_DIST_DIR

# ---------------------------------------------------------------------------
# Test F: tool.chromium / browser.chromium.resolved fault
# (E2E_CHROMIUM_PATH -> nonexistent).
# ---------------------------------------------------------------------------
export E2E_CHROMIUM_PATH="$TMP_ROOT/no-chromium"
run_preflight --check --suite freighter
assert_missing tool.chromium
assert_missing browser.chromium.resolved
assert_exit "chromium fault" 1 "$STATUS"
unset E2E_CHROMIUM_PATH

# ---------------------------------------------------------------------------
# Test G: browser.profile_tmpdir fault (E2E_PROFILE_TMPDIR -> a path whose
# PARENT does not exist either, so it is neither writable nor creatable).
# ---------------------------------------------------------------------------
export E2E_PROFILE_TMPDIR="$TMP_ROOT/no-parent-at-all/nested"
run_preflight --check --suite freighter
assert_missing browser.profile_tmpdir
assert_exit "profile_tmpdir fault" 1 "$STATUS"
unset E2E_PROFILE_TMPDIR

# ---------------------------------------------------------------------------
# Test H: a fabricated env file with a syntactically valid DUMMY secret must
# never be echoed into stdout or stderr, in any form.
# ---------------------------------------------------------------------------
# Split into adjacent literals (functionally one string at runtime) so this
# source file itself never contains a contiguous 56-char run matching the
# real Stellar secret-key shape.
DUMMY_SECRET_A="SDUMMY""AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
DUMMY_SECRET_B="SDUMMY""BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
DUMMY_SECRET_C="SDUMMY""CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
DUMMY_SECRET_D="SDUMMY""DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
DUMMY_ADDR_A="GDUMMYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
DUMMY_ADDR_B="GDUMMYBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
DUMMY_ADDR_C="GDUMMYCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
DUMMY_ADDR_D="GDUMMYDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
DUMMY_ENV_FILE="$TMP_ROOT/dummy.env"
cat > "$DUMMY_ENV_FILE" <<EOF
E2E_NETWORK=testnet
E2E_RPC_URL=https://soroban-testnet.stellar.org
E2E_POOL_CONTRACT=CCPNFGD7A6LJ7H4FGFLTBSU6XGCPFR5DN76N5WNXOTDPOKASJIU4EMFV
E2E_ACCOUNT_A_ALIAS=dummy-a
E2E_ACCOUNT_A_ADDRESS=$DUMMY_ADDR_A
E2E_ACCOUNT_A_SECRET=$DUMMY_SECRET_A
E2E_ACCOUNT_B_ALIAS=dummy-b
E2E_ACCOUNT_B_ADDRESS=$DUMMY_ADDR_B
E2E_ACCOUNT_B_SECRET=$DUMMY_SECRET_B
E2E_ACCOUNT_C_ALIAS=dummy-c
E2E_ACCOUNT_C_ADDRESS=$DUMMY_ADDR_C
E2E_ACCOUNT_C_SECRET=$DUMMY_SECRET_C
E2E_ACCOUNT_D_ALIAS=dummy-d
E2E_ACCOUNT_D_ADDRESS=$DUMMY_ADDR_D
E2E_ACCOUNT_D_SECRET=$DUMMY_SECRET_D
E2E_FREIGHTER_PASSWORD=Dummy1Password2Three
EOF
chmod 600 "$DUMMY_ENV_FILE"
export E2E_ENV_FILE="$DUMMY_ENV_FILE"
run_preflight --check --suite all
# The checks must have genuinely read the fabricated file
assert_ok env.vars.required
assert_ok env.address.format
assert_not_contains "$COMBINED" "$DUMMY_SECRET_A" "fabricated secret A"
assert_not_contains "$COMBINED" "$DUMMY_SECRET_B" "fabricated secret B"
assert_not_contains "$COMBINED" "$DUMMY_SECRET_C" "fabricated secret C"
assert_not_contains "$COMBINED" "$DUMMY_SECRET_D" "fabricated secret D"
unset E2E_ENV_FILE

# ---------------------------------------------------------------------------
# Test I: an unknown flag exits 2 (usage error).
# ---------------------------------------------------------------------------
run_preflight --bogus-flag
assert_exit "unknown flag" 2 "$STATUS"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
if [ "$FAILURES" -eq 0 ]; then
  echo "e2e-preflight-selftest: $CHECKS_RUN assertions passed"
  exit 0
else
  echo "e2e-preflight-selftest: $FAILURES/$CHECKS_RUN assertions FAILED" >&2
  exit 1
fi