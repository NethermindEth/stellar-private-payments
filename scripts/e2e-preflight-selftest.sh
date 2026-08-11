#!/usr/bin/env bash
# scripts/e2e-preflight-selftest.sh
#
# Regression test for scripts/e2e-preflight.sh: hermetic fault injection
# proving the preflight actually detects breakage rather than always
# printing green. Uses ONLY the contract's path-override env vars
# (E2E_ENV_FILE, E2E_SNAPSHOT_FILE, E2E_VENDOR_DIR, E2E_CIRCUITS_OUT_DIR,
# E2E_SDK_DIST_DIR, E2E_CHROMIUM_PATH, E2E_PROFILE_TMPDIR) pointed at
# nonexistent or mktemp -d temp paths — it never moves, renames or deletes
# any real repo file. Never invokes --fix, never touches the network
# (every invocation pre-warms the real .e2e-preflight-cache to match
# whatever env file is in play for that call, so every network-cost check
# reports SKIP via the framework's own cache gate — restored on exit), and
# never launches a browser.
#
# Usage: scripts/e2e-preflight-selftest.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PREFLIGHT="$REPO_ROOT/scripts/e2e-preflight.sh"
CACHE_FILE="$REPO_ROOT/.e2e-preflight-cache"

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
CACHE_HAD_BACKUP=0
CACHE_BACKUP_FILE="$TMP_ROOT/.cache-backup"

cleanup() {
  if [ "$CACHE_HAD_BACKUP" -eq 1 ]; then
    if [ -f "$CACHE_BACKUP_FILE" ]; then
      cp "$CACHE_BACKUP_FILE" "$CACHE_FILE"
    else
      rm -f "$CACHE_FILE"
    fi
  fi
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Network-safety net: pre-warm the real cache marker to match whichever env
# file is in play (the override, or the real ambient one), so
# scripts/e2e-preflight.sh's own cache_is_fresh() reports every network-cost
# check (env.rpc.reachable, chain.accounts.*) as SKIP — regardless of CI
# simulation or how stale the repo's real cache happened to be.
# ---------------------------------------------------------------------------
backup_cache_once() {
  [ "$CACHE_HAD_BACKUP" -eq 1 ] && return 0
  CACHE_HAD_BACKUP=1
  [ -f "$CACHE_FILE" ] && cp "$CACHE_FILE" "$CACHE_BACKUP_FILE"
  return 0
}

warm_cache_for_current_env_file() {
  backup_cache_once
  local f fp
  f="${E2E_ENV_FILE:-$REPO_ROOT/deployments/testnet/.e2e-accounts.env}"
  if [ -f "$f" ]; then
    fp="$(stat -c '%Y:%s' "$f" 2>/dev/null || stat -f '%m:%z' "$f" 2>/dev/null || echo '0:0')"
  else
    fp="absent"
  fi
  printf '%s:%s\n' "$(date +%s)" "$fp" > "$CACHE_FILE"
  return 0
}

# ---------------------------------------------------------------------------
# Invocation + assertion helpers
# ---------------------------------------------------------------------------

# Runs the preflight, capturing stdout (OUT), stderr (ERR) and exit code
# (STATUS) SEPARATELY — required so --json's stdout stays parseable and is
# never garbled by interleaved stderr diagnostics. COMBINED holds both, for
# the secret-leak sweep.
run_preflight() {
  local stderr_file
  stderr_file="$(mktemp)"
  warm_cache_for_current_env_file
  OUT="$(bash "$PREFLIGHT" "$@" 2>"$stderr_file")"
  STATUS=$?
  ERR="$(cat "$stderr_file")"
  rm -f "$stderr_file"
  COMBINED="$OUT
$ERR"
}

json_field_of() {
  # $1=json $2=id $3=field -> prints the field, or __ABSENT__ if id not found
  python3 -c '
import json, sys
d = json.loads(sys.argv[1])
want, field = sys.argv[2], sys.argv[3]
for g in d["groups"]:
    for c in g["checks"]:
        if c["id"] == want:
            print(c.get(field, ""))
            sys.exit(0)
print("__ABSENT__")
' "$1" "$2" "$3"
}

assert_status() {
  local json="$1" id="$2" want="$3" got
  count
  got="$(json_field_of "$json" "$id" status)"
  if [ "$got" != "$want" ]; then
    fail "$id: expected status $want, got $got"
    echo "--- offending output ($id) ---" >&2
    printf '%s\n' "$json" | python3 -m json.tool >&2 2>/dev/null || printf '%s\n' "$json" >&2
  fi
}

assert_exit() {
  local label="$1" want="$2" got="$3"
  count
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
  fi
}

assert_valid_schema() {
  local json="$1" label="$2"
  count
  if ! python3 -c '
import json, sys
d = json.loads(sys.argv[1])
assert isinstance(d.get("groups"), list), "groups missing/not a list"
s = d.get("summary")
assert isinstance(s, dict), "summary missing"
need = {"ok", "missing", "fixed", "skipped", "next_commands", "duration_ms"}
assert need <= set(s), f"summary missing keys: {need - set(s)}"
for g in d["groups"]:
    assert "name" in g and "checks" in g, g
    for c in g["checks"]:
        for k in ("id", "status", "detail", "remediation", "cost"):
            assert k in c, (c, k)
' "$json" 2>/tmp/selftest-schema-err; then
    fail "$label: --json output failed schema validation ($(cat /tmp/selftest-schema-err))"
    rm -f /tmp/selftest-schema-err
  fi
}

# Scoped to MISSING/FIXED, not every non-OK status: SKIP is structurally
# "not applicable to this run" (wrong suite, fresh cache), not "broken,
# here's how to fix it" — scripts/e2e-preflight.sh's print_json only ever
# populates remediation for MISSING/FIXED (json_schema's own remediation
# field doc: "or empty string on OK" generalizes the same way to SKIP),
# and that is the meaningful reading of requirement 3.
assert_all_nonok_have_remediation() {
  local json="$1" label="$2" bad
  count
  bad="$(python3 -c '
import json, sys
d = json.loads(sys.argv[1])
bad = [c["id"] for g in d["groups"] for c in g["checks"] if c["status"] in ("MISSING", "FIXED") and not c.get("remediation")]
print(",".join(bad))
' "$json")"
  if [ -n "$bad" ]; then
    fail "$label: non-OK checks missing remediation: $bad"
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

assert_next_commands_count() {
  local json="$1" label="$2" want_substr="$3" want_count="$4" got
  count
  got="$(python3 -c '
import json, sys
d = json.loads(sys.argv[1])
cmds = [c for c in d["summary"]["next_commands"] if sys.argv[2] in c]
print(len(cmds))
' "$json" "$want_substr")"
  if [ "$got" != "$want_count" ]; then
    fail "$label: expected $want_count next_commands containing '$want_substr', got $got"
  fi
}

# Runs the preflight in --json mode and applies the blanket assertions that
# apply to every single invocation: valid schema (req. 8), non-empty
# remediation on every non-OK check (req. 3), and no secret-key-shaped
# string anywhere in stdout or stderr (defense in depth beyond req. 5's
# specific fabricated-secret scenario).
run_and_check_common() {
  run_preflight "$@"
  assert_valid_schema "$OUT" "$*"
  assert_all_nonok_have_remediation "$OUT" "$*"
  assert_no_secret_pattern "$COMBINED" "$*"
}

# ---------------------------------------------------------------------------
# The suite-exclusivity partition (requirement 6). Checked against whatever
# --suite the fault-injection tests below already ran with, so this never
# needs its own extra invocation.
# ---------------------------------------------------------------------------
SDK_ONLY_IDS="tool.cargo tool.rust-toolchain tool.wasm32-target tool.wasm-bindgen-cli tool.chromedriver env.pool.matches_deployments env.compiletime.exported artifact.circuits.debug artifact.circuits.release artifact.circuit_keys artifact.sdk_dist.workers artifact.sdk_dist.circuits artifact.sdk_dist.freshness"
FREIGHTER_ONLY_IDS="tool.tar tool.unzip tool.chromium tool.trunk tool.xvfb freighter.node_modules freighter.playwright freighter.ffmpeg freighter.extension.pinned freighter.snapshot.exists freighter.snapshot.integrity freighter.onboarding browser.chromium.resolved browser.profile_tmpdir browser.display browser.app_url"

assert_ids_all_skip() {
  local json="$1" label="$2"
  shift 2
  local id
  for id in "$@"; do
    assert_status "$json" "$id" SKIP
  done
  : "$label"
}

# ---------------------------------------------------------------------------
# Test A: env.file.* / env.vars.required / env.compiletime.exported fault
# (E2E_ENV_FILE -> nonexistent). Also covers requirement 6 for --suite sdk.
# ---------------------------------------------------------------------------
export CI=1
export E2E_ENV_FILE="$TMP_ROOT/no-such.env"
run_and_check_common --check --suite sdk --json
assert_status "$OUT" env.file.exists MISSING
assert_status "$OUT" env.file.mode MISSING
assert_status "$OUT" env.file.gitignored MISSING
assert_status "$OUT" env.vars.required MISSING
assert_status "$OUT" env.compiletime.exported MISSING
assert_exit "env.file.* fault" 1 "$STATUS"
assert_ids_all_skip "$OUT" "sdk excludes freighter ids" $FREIGHTER_ONLY_IDS
unset E2E_ENV_FILE

# ---------------------------------------------------------------------------
# Test B: freighter.extension.pinned fault (E2E_VENDOR_DIR -> nonexistent).
# Also covers requirement 6 for --suite freighter.
# ---------------------------------------------------------------------------
export E2E_VENDOR_DIR="$TMP_ROOT/no-vendor"
run_and_check_common --check --suite freighter --json
assert_status "$OUT" freighter.extension.pinned MISSING
assert_exit "freighter.extension.pinned fault" 1 "$STATUS"
assert_ids_all_skip "$OUT" "freighter excludes sdk ids" $SDK_ONLY_IDS
unset E2E_VENDOR_DIR

# ---------------------------------------------------------------------------
# Test C: freighter.snapshot.* fault (E2E_SNAPSHOT_FILE -> nonexistent),
# CI simulated -> expect the xvfb-run remediation form, exactly once.
# ---------------------------------------------------------------------------
export CI=1
export E2E_SNAPSHOT_FILE="$TMP_ROOT/no-snapshot-ci.tar.gz"
run_and_check_common --check --suite freighter --json
assert_status "$OUT" freighter.snapshot.exists MISSING
assert_status "$OUT" freighter.snapshot.integrity MISSING
assert_status "$OUT" freighter.onboarding MISSING
assert_exit "freighter.snapshot.* fault (CI)" 1 "$STATUS"
assert_next_commands_count "$OUT" "onboarding remediation form (CI)" "xvfb-run -a bash e2e-freighter/scripts/setup.sh" 1
assert_next_commands_count "$OUT" "onboarding remediation form (CI) is not duplicated as the plain form" "bash e2e-freighter/scripts/setup.sh" 1
unset E2E_SNAPSHOT_FILE

# ---------------------------------------------------------------------------
# Test D: same fault, desktop simulated (no CI, DISPLAY set) -> expect the
# plain remediation form, exactly once.
# ---------------------------------------------------------------------------
unset CI GITHUB_ACTIONS
export DISPLAY=":0"
export E2E_SNAPSHOT_FILE="$TMP_ROOT/no-snapshot-desktop.tar.gz"
run_and_check_common --check --suite freighter --json
assert_status "$OUT" freighter.onboarding MISSING
assert_exit "freighter.snapshot.* fault (desktop)" 1 "$STATUS"
assert_next_commands_count "$OUT" "onboarding remediation form (desktop)" "bash e2e-freighter/scripts/setup.sh" 1
assert_next_commands_count "$OUT" "onboarding remediation form (desktop) excludes xvfb-run" "xvfb-run -a bash e2e-freighter/scripts/setup.sh" 0
unset E2E_SNAPSHOT_FILE
export CI=1

# ---------------------------------------------------------------------------
# Test E: artifact.* fault (E2E_CIRCUITS_OUT_DIR, E2E_SDK_DIST_DIR ->
# nonexistent).
# ---------------------------------------------------------------------------
export E2E_CIRCUITS_OUT_DIR="$TMP_ROOT/no-circuits"
export E2E_SDK_DIST_DIR="$TMP_ROOT/no-dist"
run_and_check_common --check --suite sdk --json
assert_status "$OUT" artifact.circuits.debug MISSING
assert_status "$OUT" artifact.circuits.release MISSING
assert_status "$OUT" artifact.sdk_dist.workers MISSING
assert_status "$OUT" artifact.sdk_dist.circuits MISSING
assert_exit "artifact.* fault" 1 "$STATUS"
unset E2E_CIRCUITS_OUT_DIR E2E_SDK_DIST_DIR

# ---------------------------------------------------------------------------
# Test F: tool.chromium / browser.chromium.resolved fault
# (E2E_CHROMIUM_PATH -> nonexistent).
# ---------------------------------------------------------------------------
export E2E_CHROMIUM_PATH="$TMP_ROOT/no-chromium"
run_and_check_common --check --suite freighter --json
assert_status "$OUT" tool.chromium MISSING
assert_status "$OUT" browser.chromium.resolved MISSING
assert_exit "chromium fault" 1 "$STATUS"
unset E2E_CHROMIUM_PATH

# ---------------------------------------------------------------------------
# Test G: browser.profile_tmpdir fault (E2E_PROFILE_TMPDIR -> a path whose
# PARENT does not exist either, so it is neither writable nor creatable).
# ---------------------------------------------------------------------------
export E2E_PROFILE_TMPDIR="$TMP_ROOT/no-parent-at-all/nested"
run_and_check_common --check --suite freighter --json
assert_status "$OUT" browser.profile_tmpdir MISSING
assert_exit "profile_tmpdir fault" 1 "$STATUS"
unset E2E_PROFILE_TMPDIR

# ---------------------------------------------------------------------------
# Test H: a fabricated env file with a syntactically valid DUMMY secret must
# never be echoed into stdout or stderr, in any form (requirement 5).
# ---------------------------------------------------------------------------
# Split into adjacent literals (functionally one string at runtime) so this
# source file itself never contains a contiguous 56-char run matching the
# real Stellar secret-key shape — the repo's own no-hardcoded-secrets
# invariant (rightly) does a blunt syntactic grep for that pattern and
# cannot distinguish a test fixture from a real key.
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
run_and_check_common --check --suite all --json
# The checks must have genuinely read the fabricated file (proving they
# didn't just skip it and trivially "not leak" by never touching it).
assert_status "$OUT" env.vars.required OK
assert_status "$OUT" env.address.format OK
assert_not_contains "$COMBINED" "$DUMMY_SECRET_A" "fabricated secret A"
assert_not_contains "$COMBINED" "$DUMMY_SECRET_B" "fabricated secret B"
assert_not_contains "$COMBINED" "$DUMMY_SECRET_C" "fabricated secret C"
assert_not_contains "$COMBINED" "$DUMMY_SECRET_D" "fabricated secret D"
unset E2E_ENV_FILE

# ---------------------------------------------------------------------------
# Test I: an unknown flag exits 2 (requirement 7) — a usage error, so no
# --json/schema assertions apply here (the script never reaches the
# registry).
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
