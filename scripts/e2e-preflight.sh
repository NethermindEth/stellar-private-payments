#!/usr/bin/env bash
# scripts/e2e-preflight.sh
#
# Single entry point that verifies (and, with --fix, safely auto-heals)
# every dependency and piece of state the two e2e suites in this repo need:
# the pre-signing SDK wasm-bindgen browser tests (sdk/web) and the
# real-Freighter browser tests (e2e-freighter). Safe to run before every
# test invocation — a bare `--check` never builds, installs, or launches a
# browser; it only inspects the filesystem, PATH, and (for a small, capped
# set of checks) the network.
#
# This file is the FRAMEWORK only: CLI parsing, the check registry, the
# runner, the human report and the --json emitter. Domain checks (tools,
# env, chain, artifacts, freighter, browser groups) register themselves via
# `register_check` in later phase-2 steps. Two trivial self-referential
# checks (tool.bash, tool.git) are registered here so the framework is
# exercisable end to end before any domain checks exist.
#
# The frozen contract this script implements (CLI surface, JSON schema,
# exit codes, env overrides, caching, CI behaviour) lives at
# plans/active-plan/artifacts/phase1/step_1_2_artifact.json.
#
# Usage: scripts/e2e-preflight.sh [--check|--fix] [--suite sdk|freighter|all]
#                                 [--json] [--deep] [--quiet] [-h|--help]

set -euo pipefail

SCRIPT_NAME="e2e-preflight.sh"
die() { echo "$SCRIPT_NAME: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }
warn() { echo "warning: $*" >&2; }
ok() { echo "ok: $*" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_FILE="$REPO_ROOT/.e2e-preflight-cache"
CACHE_TTL_SECONDS=900

# Colorized OK/MISSING tokens on an interactive terminal only, matching the
# convention already used in e2e-freighter/scripts/run-e2e.sh.
if [ -t 1 ]; then
  C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_RESET=$'\033[0m'
else
  C_GREEN=""; C_RED=""; C_YELLOW=""; C_RESET=""
fi

# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------
MODE="check"
MODE_EXPLICIT=0
SUITE="all"
JSON_OUTPUT=0
DEEP=0
QUIET=0

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/e2e-preflight.sh [OPTIONS]

Verifies (and, with --fix, safely auto-heals) everything the sdk/web and
e2e-freighter e2e suites need. Safe to run before every test invocation —
a bare --check never builds, installs, or launches a browser.

Options:
  --check         Verify only, never mutate anything (default).
  --fix           Verify and run the auto-heal action for anything that is
                  safe to heal and currently missing. Mutually exclusive
                  with --check.
  --suite VALUE   Restrict checks to one suite: sdk, freighter, or all
                  (default: all).
  --json          Emit machine-readable JSON on stdout instead of the
                  human report. Diagnostics always go to stderr.
  --deep          Force every network-cost check to run even if its cache
                  is fresh.
  --quiet         Suppress per-check OK lines in the human report.
  -h, --help      Show this help.

Environment:
  E2E_SKIP_PREFLIGHT=1   Read by the CALLERS of this script (run-all.sh,
                         run-e2e.sh, e2e-browser-test.sh) to bypass it
                         entirely; this script itself does not read it.
  E2E_PREFLIGHT_DONE     Set to 1 by this script on a successful run.

Examples:
  scripts/e2e-preflight.sh --check --suite sdk
  scripts/e2e-preflight.sh --fix --suite all --json
USAGE
}

usage_error() {
  usage
  echo "$SCRIPT_NAME: $*" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check)
      if [ "$MODE_EXPLICIT" -eq 1 ] && [ "$MODE" != "check" ]; then
        usage_error "--check and --fix are mutually exclusive"
      fi
      MODE="check"; MODE_EXPLICIT=1; shift ;;
    --fix)
      if [ "$MODE_EXPLICIT" -eq 1 ] && [ "$MODE" != "fix" ]; then
        usage_error "--check and --fix are mutually exclusive"
      fi
      MODE="fix"; MODE_EXPLICIT=1; shift ;;
    --suite)
      [ $# -ge 2 ] || usage_error "--suite needs a value"
      SUITE="$2"; shift 2 ;;
    --json) JSON_OUTPUT=1; shift ;;
    --deep) DEEP=1; shift ;;
    --quiet) QUIET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage_error "unknown argument '$1'" ;;
  esac
done

case "$SUITE" in
  sdk|freighter|all) ;;
  *) usage_error "--suite must be one of: sdk, freighter, all" ;;
esac

# ---------------------------------------------------------------------------
# Check registry
#
# register_check ID GROUP SUITE COST CHECK_FN HEAL_FN REMEDIATION
#   ID          stable dotted id, e.g. tool.git — treated as a public API
#               (plans/active-plan/artifacts/phase1/step_1_2_artifact.json)
#   GROUP       one of: tools env chain artifacts freighter browser
#   SUITE       sdk | freighter | both
#   COST        instant | network
#   CHECK_FN    function name; called with no args, must set _STATUS
#               (OK|MISSING) and _DETAIL (a string, never a secret value)
#   HEAL_FN     function name to run under --fix when _STATUS is MISSING,
#               or "" if this check can never be auto-healed
#   REMEDIATION human remediation string; also shown as what ran when
#               HEAL_FN just succeeded (status FIXED)
# ---------------------------------------------------------------------------
CHECK_IDS=()
CHECK_GROUPS=()
CHECK_SUITES=()
CHECK_COSTS=()
CHECK_FNS=()
CHECK_HEAL_FNS=()
CHECK_REMEDIATIONS=()

register_check() {
  CHECK_IDS+=("$1")
  CHECK_GROUPS+=("$2")
  CHECK_SUITES+=("$3")
  CHECK_COSTS+=("$4")
  CHECK_FNS+=("$5")
  CHECK_HEAL_FNS+=("$6")
  CHECK_REMEDIATIONS+=("$7")
}

GROUP_ORDER=(tools env chain artifacts freighter browser)

# ---------------------------------------------------------------------------
# Env-file helpers, shared by the cache and by the `env` group's checks.
# Values are only ever read into a subshell (via env_var_value) so a
# sourced secret never leaks into this process's own environment; callers
# must never put a return value from env_var_value into _DETAIL or a
# remediation string.
# ---------------------------------------------------------------------------
env_file_path() {
  printf '%s' "${E2E_ENV_FILE:-$REPO_ROOT/deployments/testnet/.e2e-accounts.env}"
}

env_var_value() {
  local key="$1" f
  if [ -n "${!key:-}" ]; then
    printf '%s' "${!key}"
    return 0
  fi
  f="$(env_file_path)"
  if [ -f "$f" ]; then
    ( set -a; . "$f" >/dev/null 2>&1; if [ -n "${!key:-}" ]; then printf '%s' "${!key}"; else exit 1; fi )
    return $?
  fi
  return 1
}

env_var_present() {
  env_var_value "$1" >/dev/null
}

# ---------------------------------------------------------------------------
# Network-check cache: a cache hit yields SKIP (never a silent OK) for
# cost=network checks, keyed off the env file's mtime+size so an edited env
# file always invalidates a fresh cache even within the TTL. Git-ignored;
# never holds a secret value.
# ---------------------------------------------------------------------------
env_file_fingerprint() {
  local f
  f="$(env_file_path)"
  if [ -f "$f" ]; then
    stat -c '%Y:%s' "$f" 2>/dev/null || stat -f '%m:%z' "$f" 2>/dev/null || echo "0:0"
  else
    echo "absent"
  fi
}

cache_read() {
  [ -f "$CACHE_FILE" ] || return 1
  IFS=: read -r cache_ts cache_fp < "$CACHE_FILE" || return 1
  [ -n "${cache_ts:-}" ] && [ -n "${cache_fp:-}" ]
}

cache_is_fresh() {
  cache_read || return 1
  [ "$cache_fp" = "$(env_file_fingerprint)" ] || return 1
  local now age
  now="$(date +%s)"
  age=$((now - cache_ts))
  [ "$age" -lt "$CACHE_TTL_SECONDS" ] || return 1
  CACHE_AGE_SECONDS="$age"
  return 0
}

cache_mark_fresh() {
  printf '%s:%s\n' "$(date +%s)" "$(env_file_fingerprint)" > "$CACHE_FILE"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
RESULT_STATUS=()
RESULT_DETAIL=()

run_check() {
  local idx="$1" id group suite cost check_fn heal_fn remediation status detail
  id="${CHECK_IDS[$idx]}"; group="${CHECK_GROUPS[$idx]}"; suite="${CHECK_SUITES[$idx]}"
  cost="${CHECK_COSTS[$idx]}"; check_fn="${CHECK_FNS[$idx]}"; heal_fn="${CHECK_HEAL_FNS[$idx]}"
  remediation="${CHECK_REMEDIATIONS[$idx]}"

  if [ "$SUITE" != "all" ] && [ "$suite" != "both" ] && [ "$suite" != "$SUITE" ]; then
    RESULT_STATUS[$idx]="SKIP"
    RESULT_DETAIL[$idx]="not selected: --suite $SUITE"
    return 0
  fi

  if [ "$cost" = "network" ] && [ "$DEEP" -ne 1 ] && cache_is_fresh; then
    RESULT_STATUS[$idx]="SKIP"
    RESULT_DETAIL[$idx]="cache fresh (${CACHE_AGE_SECONDS}s old, ttl ${CACHE_TTL_SECONDS}s)"
    return 0
  fi

  _STATUS=""; _DETAIL=""
  "$check_fn" || true
  status="$_STATUS"; detail="$_DETAIL"

  if [ "$status" = "MISSING" ] && [ "$MODE" = "fix" ] && [ -n "$heal_fn" ]; then
    step "healing $id"
    if "$heal_fn"; then
      _STATUS=""; _DETAIL=""
      "$check_fn" || true
      status="$_STATUS"; detail="$_DETAIL"
      [ "$status" = "OK" ] && status="FIXED"
    else
      warn "heal action for $id failed"
    fi
  fi

  RESULT_STATUS[$idx]="$status"
  RESULT_DETAIL[$idx]="$detail"
}

run_all_checks() {
  local i
  for ((i = 0; i < ${#CHECK_IDS[@]}; i++)); do
    run_check "$i"
  done
  return 0
}

group_check_indices() {
  local group="$1" i
  for ((i = 0; i < ${#CHECK_IDS[@]}; i++)); do
    [ "${CHECK_GROUPS[$i]}" = "$group" ] && printf '%s\n' "$i"
  done
  # Explicit trailing success: under `set -e`, a function whose last
  # executed command happens to be a false test (no group match on the
  # final loop iteration) would otherwise propagate that failure to the
  # caller — fatal here since callers use this in `x="$(group_check_indices ...)"`.
  return 0
}

# ---------------------------------------------------------------------------
# Human report
# ---------------------------------------------------------------------------
print_human_report() {
  local group indices i id status detail token
  for group in "${GROUP_ORDER[@]}"; do
    indices="$(group_check_indices "$group")"
    [ -n "$indices" ] || continue
    echo "-- $group --"
    while IFS= read -r i; do
      [ -n "$i" ] || continue
      id="${CHECK_IDS[$i]}"; status="${RESULT_STATUS[$i]}"; detail="${RESULT_DETAIL[$i]}"
      case "$status" in
        OK) [ "$QUIET" -eq 1 ] && continue; token="${C_GREEN}OK${C_RESET}" ;;
        MISSING) token="${C_RED}MISSING${C_RESET}" ;;
        FIXED) token="${C_GREEN}FIXED${C_RESET}" ;;
        SKIP) token="${C_YELLOW}SKIP${C_RESET}" ;;
        *) token="$status" ;;
      esac
      printf '  %s  %-28s  %s\n' "$token" "$id" "$detail"
    done <<< "$indices"
  done
  return 0
}

print_next_commands() {
  [ "${#NEXT_COMMANDS[@]}" -gt 0 ] || return 0
  echo
  echo "Run this next:"
  local c
  for c in "${NEXT_COMMANDS[@]}"; do
    echo "  $c"
  done
  return 0
}

print_summary_line() {
  echo
  echo "suite=$SUITE mode=$MODE: $OK_COUNT ok, $MISSING_COUNT missing, $FIXED_COUNT fixed, $SKIP_COUNT skipped (${DURATION_MS}ms)"
  if [ "$MODE" = "fix" ]; then
    if [ "${#FIXED_IDS[@]}" -gt 0 ]; then
      echo "  healed: $(IFS=,; echo "${FIXED_IDS[*]}")"
    fi
    if [ "${#MISSING_IDS[@]}" -gt 0 ]; then
      echo "  still missing: $(IFS=,; echo "${MISSING_IDS[*]}")"
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# JSON emitter (dependency-free: printf + a small escaping helper, no jq)
# ---------------------------------------------------------------------------
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}

print_json() {
  local group indices i first_group=1 first_check id status detail cost rem_out

  printf '{"groups":['
  for group in "${GROUP_ORDER[@]}"; do
    indices="$(group_check_indices "$group")"
    [ -n "$indices" ] || continue
    [ "$first_group" -eq 1 ] || printf ','
    first_group=0
    printf '{"name":"%s","checks":[' "$(json_escape "$group")"
    first_check=1
    while IFS= read -r i; do
      [ -n "$i" ] || continue
      [ "$first_check" -eq 1 ] || printf ','
      first_check=0
      id="${CHECK_IDS[$i]}"; status="${RESULT_STATUS[$i]}"; detail="${RESULT_DETAIL[$i]}"
      cost="${CHECK_COSTS[$i]}"
      case "$status" in
        MISSING|FIXED) rem_out="${CHECK_REMEDIATIONS[$i]}" ;;
        *) rem_out="" ;;
      esac
      printf '{"id":"%s","status":"%s","detail":"%s","remediation":"%s","cost":"%s"}' \
        "$(json_escape "$id")" "$(json_escape "$status")" "$(json_escape "$detail")" \
        "$(json_escape "$rem_out")" "$(json_escape "$cost")"
    done <<< "$indices"
    printf ']}'
  done
  printf '],"summary":{"ok":%d,"missing":%d,"fixed":%d,"skipped":%d,"next_commands":[' \
    "$OK_COUNT" "$MISSING_COUNT" "$FIXED_COUNT" "$SKIP_COUNT"
  local first_cmd=1 c
  for c in ${NEXT_COMMANDS[@]+"${NEXT_COMMANDS[@]}"}; do
    [ "$first_cmd" -eq 1 ] || printf ','
    first_cmd=0
    printf '"%s"' "$(json_escape "$c")"
  done
  printf '],"duration_ms":%d}}\n' "$DURATION_MS"
}

# ---------------------------------------------------------------------------
# Summary counters + the "Run this next:" command list.
#
# next_commands must contain nothing but bare, copy-pasteable commands, one
# per line — no prose. That is a stricter bar than a check's own
# `remediation` field (json_schema; shown per-check, prose is fine there),
# so it is derived separately via fix_command_for_id rather than reusing
# CHECK_REMEDIATIONS directly: many remediations are pure prose ("Install
# bash via your OS package manager") or wrap a command in explanatory text,
# and a destructive one-liner (env file --force) is deliberately never
# surfaced here even though the per-check remediation text explains it.
# ---------------------------------------------------------------------------

# Maps a check id to the single bare command that fixes it, or "" when
# there is no safe one-liner (prose-only advisories, or a fix that would be
# destructive to suggest as a casual copy-paste, like regenerating the env
# file with --force). Kept as one explicit table rather than parsing
# CHECK_REMEDIATIONS, since a handful of ids intentionally have a different
# (or no) fix command from their human-readable remediation text.
fix_command_for_id() {
  case "$1" in
    tool.wasm32-target) printf '%s' "rustup target add wasm32-unknown-unknown" ;;
    tool.wasm-bindgen-cli) printf '%s' "cargo install wasm-bindgen-cli --version 0.2.126 --locked --force" ;;
    tool.spp) printf '%s' "cargo build --release -p stellar-private-payments-cli" ;;
    env.file.exists|env.vars.required) printf '%s' "bash deployments/scripts/e2e-accounts-setup.sh" ;;
    env.file.mode) printf '%s' "chmod 600 deployments/testnet/.e2e-accounts.env" ;;
    env.compiletime.exported) printf '%s' "set -a; . deployments/testnet/.e2e-accounts.env; set +a" ;;
    chain.accounts.funded|chain.accounts.registered) printf '%s' "bash deployments/scripts/e2e-accounts-setup.sh" ;;
    artifact.circuits.debug) printf '%s' "cargo build -p circuits" ;;
    artifact.circuits.release) printf '%s' "cargo build -p circuits --release" ;;
    artifact.circuit_keys) printf '%s' "git checkout -- deployments/testnet/circuit_keys" ;;
    artifact.sdk_dist.workers|artifact.sdk_dist.circuits) printf '%s' "npm ci --prefix sdk/web && npm run build --prefix sdk/web" ;;
    freighter.node_modules|freighter.playwright) printf '%s' "npm ci --prefix e2e-freighter" ;;
    freighter.ffmpeg) printf '%s' "npx playwright install ffmpeg --prefix e2e-freighter" ;;
    freighter.extension.pinned) printf '%s' "bash e2e-freighter/scripts/fetch-extension.sh --force" ;;
    freighter.snapshot.exists|freighter.snapshot.integrity|freighter.onboarding) onboarding_remediation_command ;;
    browser.profile_tmpdir) printf 'mkdir -p %s' "$(resolve_profile_tmpdir_base)" ;;
    # env.address.format / env.pool.matches_deployments: the only real fix
    # is --force, which regenerates all four keypairs and overwrites the
    # env file — too destructive to hand out as a casual one-liner here;
    # the per-check remediation text explains the tradeoff instead.
    # Everything else (tool.bash, tool.git, tool.node, ..., chain.cache.freshness,
    # browser.chromium.resolved, browser.display, browser.app_url, ...) is
    # prose-only advice with no single safe command.
    *) printf '%s' "" ;;
  esac
}

# Reorders a deduped NEXT_COMMANDS according to a fixed dependency list —
# env/accounts before the profile snapshot, circuits before the sdk dist
# build, npm ci before anything that uses the resulting node_modules — so
# remediation always reads in run order, never registration order. Glob
# patterns (not exact strings) so a dynamically-built command like
# `mkdir -p <resolved path>` still sorts correctly.
sort_next_commands() {
  local priority=(
    "bash deployments/scripts/e2e-accounts-setup.sh*"
    "cargo build -p circuits"
    "cargo build -p circuits --release"
    "npm ci --prefix sdk/web*"
    "npm ci --prefix e2e-freighter*"
    "npx playwright install ffmpeg*"
    "bash e2e-freighter/scripts/fetch-extension.sh*"
    "bash e2e-freighter/scripts/setup.sh*"
    "xvfb-run -a bash e2e-freighter/scripts/setup.sh*"
    "mkdir -p*"
  )
  local ordered=() c p existing found
  for p in "${priority[@]}"; do
    for c in ${NEXT_COMMANDS[@]+"${NEXT_COMMANDS[@]}"}; do
      if [[ "$c" == $p ]]; then
        found=0
        for existing in ${ordered[@]+"${ordered[@]}"}; do
          [ "$existing" = "$c" ] && found=1 && break
        done
        [ "$found" -eq 0 ] && ordered+=("$c")
      fi
    done
  done
  for c in ${NEXT_COMMANDS[@]+"${NEXT_COMMANDS[@]}"}; do
    found=0
    for existing in ${ordered[@]+"${ordered[@]}"}; do
      [ "$existing" = "$c" ] && found=1 && break
    done
    [ "$found" -eq 0 ] && ordered+=("$c")
  done
  NEXT_COMMANDS=(${ordered[@]+"${ordered[@]}"})
  return 0
}

compute_summary() {
  OK_COUNT=0; MISSING_COUNT=0; FIXED_COUNT=0; SKIP_COUNT=0
  NEXT_COMMANDS=()
  FIXED_IDS=()
  MISSING_IDS=()
  local i id status fix_cmd existing seen
  for ((i = 0; i < ${#CHECK_IDS[@]}; i++)); do
    id="${CHECK_IDS[$i]}"
    status="${RESULT_STATUS[$i]}"
    case "$status" in
      OK) OK_COUNT=$((OK_COUNT + 1)) ;;
      MISSING)
        MISSING_COUNT=$((MISSING_COUNT + 1))
        MISSING_IDS+=("$id")
        fix_cmd="$(fix_command_for_id "$id")"
        if [ -n "$fix_cmd" ]; then
          seen=0
          for existing in ${NEXT_COMMANDS[@]+"${NEXT_COMMANDS[@]}"}; do
            [ "$existing" = "$fix_cmd" ] && seen=1 && break
          done
          [ "$seen" -eq 0 ] && NEXT_COMMANDS+=("$fix_cmd")
        fi
        ;;
      FIXED) FIXED_COUNT=$((FIXED_COUNT + 1)); FIXED_IDS+=("$id") ;;
      SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac
  done
  sort_next_commands
  return 0
}

# ---------------------------------------------------------------------------
# tools group: host tool presence, on PATH, plus a few version floors.
# No heal functions in this group by contract — installing OS packages is
# out of scope. Every check here is cost=instant (PATH lookups and cheap
# version-string parsing only). A version that can't be parsed reports OK
# with a "version unknown" detail rather than a false MISSING.
# ---------------------------------------------------------------------------
check_tool_bash() {
  _STATUS="OK"
  _DETAIL="$(bash --version | head -n1)"
}

check_tool_git() {
  if command -v git >/dev/null 2>&1; then
    _STATUS="OK"
    _DETAIL="$(command -v git)"
  else
    _STATUS="MISSING"
    _DETAIL="git not found on PATH"
  fi
}

check_tool_cargo() {
  if command -v cargo >/dev/null 2>&1; then
    _STATUS="OK"
    _DETAIL="$(cargo --version 2>/dev/null || echo 'version unknown')"
  else
    _STATUS="MISSING"
    _DETAIL="cargo not found on PATH"
  fi
}

check_tool_rust_toolchain() {
  if ! command -v rustc >/dev/null 2>&1; then
    _STATUS="MISSING"
    _DETAIL="rustc not found on PATH"
    return
  fi
  local pinned have
  pinned="$(grep -oE 'channel[[:space:]]*=[[:space:]]*"[^"]+"' "$REPO_ROOT/rust-toolchain.toml" 2>/dev/null \
    | grep -oE '"[^"]+"' | tr -d '"' || true)"
  have="$(rustc --version 2>/dev/null | awk '{print $2}')"
  if [ -z "$have" ]; then
    _STATUS="OK"; _DETAIL="rustc version unknown, could not parse"
  elif [ -z "$pinned" ]; then
    _STATUS="OK"; _DETAIL="rustc $have (no pin found in rust-toolchain.toml)"
  elif [ "$have" = "$pinned" ]; then
    _STATUS="OK"; _DETAIL="rustc $have (matches rust-toolchain.toml pin)"
  else
    # rustup auto-installs the pinned toolchain from rust-toolchain.toml on
    # the next cargo invocation, so a mismatch here is informational, not
    # a hard failure.
    _STATUS="OK"; _DETAIL="rustc $have (rust-toolchain.toml pins $pinned; rustup auto-selects it on the next cargo invocation)"
  fi
}

check_tool_wasm32_target() {
  # Process substitution, not a `cmd | grep -q` pipe: under set -o pipefail,
  # grep -q's early exit on a match SIGPIPEs the upstream producer, and
  # pipefail then reports THAT nonzero exit for the whole pipeline even
  # though grep found what it was looking for — a real, timing-dependent
  # false-MISSING bug (confirmed on the slower tar -tzf case below; harmless
  # here in casual testing only because rustup's tiny output finishes
  # writing before grep can close the pipe, which is not a guarantee).
  if command -v rustup >/dev/null 2>&1; then
    if grep -q '^wasm32-unknown-unknown$' < <(rustup target list --installed 2>/dev/null); then
      _STATUS="OK"; _DETAIL="wasm32-unknown-unknown installed (rustup target list --installed)"
    else
      _STATUS="MISSING"; _DETAIL="wasm32-unknown-unknown not in 'rustup target list --installed'"
    fi
  elif command -v rustc >/dev/null 2>&1; then
    if grep -q '^wasm32-unknown-unknown$' < <(rustc --print target-list 2>/dev/null); then
      _STATUS="OK"; _DETAIL="wasm32-unknown-unknown is a known rustc target (no rustup on PATH to confirm it is installed)"
    else
      _STATUS="MISSING"; _DETAIL="wasm32-unknown-unknown not found via 'rustc --print target-list'"
    fi
  else
    _STATUS="MISSING"; _DETAIL="neither rustup nor rustc found on PATH"
  fi
}

check_tool_wasm_bindgen_cli() {
  if command -v wasm-bindgen >/dev/null 2>&1; then
    _STATUS="OK"
    _DETAIL="$(wasm-bindgen --version 2>/dev/null || echo 'version unknown')"
  else
    _STATUS="MISSING"
    _DETAIL="wasm-bindgen (wasm-bindgen-cli) not found on PATH"
  fi
}

check_tool_node() {
  if ! command -v node >/dev/null 2>&1; then
    _STATUS="MISSING"; _DETAIL="node not found on PATH"
    return
  fi
  local v major
  v="$(node --version 2>/dev/null)"
  major="$(printf '%s' "$v" | sed -E 's/^v([0-9]+).*/\1/')"
  case "$major" in
    ''|*[!0-9]*)
      _STATUS="OK"; _DETAIL="node $v (version unknown, could not parse)" ;;
    *)
      if [ "$major" -ge 18 ]; then
        _STATUS="OK"; _DETAIL="node $v"
      else
        _STATUS="MISSING"; _DETAIL="node $v is older than the required 18+"
      fi
      ;;
  esac
}

check_tool_npm() {
  if command -v npm >/dev/null 2>&1; then
    _STATUS="OK"
    _DETAIL="npm $(npm --version 2>/dev/null || echo 'version unknown')"
  else
    _STATUS="MISSING"
    _DETAIL="npm not found on PATH"
  fi
}

check_tool_python3() {
  if command -v python3 >/dev/null 2>&1; then
    _STATUS="OK"
    _DETAIL="$(python3 --version 2>/dev/null || echo 'version unknown')"
  else
    _STATUS="MISSING"
    _DETAIL="python3 not found on PATH"
  fi
}

check_tool_curl() {
  if command -v curl >/dev/null 2>&1; then
    _STATUS="OK"
    _DETAIL="$(command -v curl)"
  else
    _STATUS="MISSING"
    _DETAIL="curl not found on PATH"
  fi
}

check_tool_tar() {
  if command -v tar >/dev/null 2>&1; then
    _STATUS="OK"
    _DETAIL="$(command -v tar)"
  else
    _STATUS="MISSING"
    _DETAIL="tar not found on PATH"
  fi
}

check_tool_unzip() {
  if command -v unzip >/dev/null 2>&1; then
    _STATUS="OK"
    _DETAIL="$(command -v unzip)"
  else
    _STATUS="MISSING"
    _DETAIL="unzip not found on PATH"
  fi
}

check_tool_stellar() {
  if ! command -v stellar >/dev/null 2>&1; then
    _STATUS="MISSING"; _DETAIL="stellar CLI not found on PATH"
    return
  fi
  local v major
  v="$(stellar --version 2>/dev/null | head -n1)"
  major="$(printf '%s' "$v" | grep -oE '[0-9]+' | head -n1)"
  case "$major" in
    ''|*[!0-9]*)
      _STATUS="OK"; _DETAIL="$v (version unknown, could not parse)" ;;
    *)
      if [ "$major" -ge 27 ]; then
        _STATUS="OK"; _DETAIL="$v"
      else
        _STATUS="MISSING"
        _DETAIL="$v is older than the required 27+ (spp passes --auto-sign to 'stellar tx sign', which older releases do not know)"
      fi
      ;;
  esac
}

check_tool_spp() {
  if command -v spp >/dev/null 2>&1; then
    _STATUS="OK"; _DETAIL="$(command -v spp)"
  elif [ -x "$REPO_ROOT/target/release/spp" ]; then
    _STATUS="OK"; _DETAIL="$REPO_ROOT/target/release/spp"
  else
    _STATUS="MISSING"
    _DETAIL="no 'spp' binary on PATH and no target/release/spp build"
  fi
}

check_tool_chromium() {
  local path=""
  if [ -n "${E2E_CHROMIUM_PATH:-}" ]; then
    path="$E2E_CHROMIUM_PATH"
  else
    path="$(command -v chromium 2>/dev/null || command -v google-chrome 2>/dev/null || true)"
  fi
  if [ -n "$path" ] && [ -x "$path" ]; then
    _STATUS="OK"; _DETAIL="$path"
  elif [ -n "$path" ]; then
    _STATUS="MISSING"; _DETAIL="resolved Chromium path '$path' is not executable"
  else
    _STATUS="MISSING"
    _DETAIL="no Chromium/Chrome found (checked E2E_CHROMIUM_PATH, chromium, google-chrome)"
  fi
}

check_tool_chromedriver() {
  local path=""
  if [ -n "${CHROMEDRIVER:-}" ]; then
    path="$CHROMEDRIVER"
  else
    path="$(command -v chromedriver 2>/dev/null || true)"
  fi
  if [ -n "$path" ] && [ -x "$path" ]; then
    _STATUS="OK"; _DETAIL="$path"
  else
    _STATUS="MISSING"
    _DETAIL="chromedriver not resolvable via \$CHROMEDRIVER or PATH"
  fi
}

# Optional: only needed when APP_URL points at a locally-served app. Reports
# SKIP (never MISSING) otherwise — the check function itself may set
# _STATUS="SKIP" directly; the runner passes any status string through
# unchanged (only "MISSING" is special-cased for healing).
check_tool_trunk() {
  case "${APP_URL:-}" in
    http://localhost*|http://127.0.0.1*)
      if command -v trunk >/dev/null 2>&1; then
        _STATUS="OK"; _DETAIL="$(command -v trunk)"
      else
        _STATUS="MISSING"
        _DETAIL="trunk not found on PATH (needed because APP_URL points at a local server)"
      fi
      ;;
    *)
      _STATUS="SKIP"
      _DETAIL="not needed unless APP_URL points at localhost"
      ;;
  esac
}

check_tool_xvfb() {
  # xvfb is only ever a stand-in for a missing real display during a
  # headed run (setup.sh's onboarding) — never required otherwise, and
  # never required when a real DISPLAY/WAYLAND_DISPLAY already exists.
  if ! need_headed_run; then
    _STATUS="SKIP"; _DETAIL="not needed for the default headless run"
    return
  fi
  if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
    _STATUS="SKIP"; _DETAIL="a headed run is needed, but a real display is already available"
    return
  fi
  if command -v xvfb-run >/dev/null 2>&1; then
    _STATUS="OK"; _DETAIL="$(command -v xvfb-run)"
  else
    _STATUS="MISSING"; _DETAIL="xvfb-run not found on PATH"
  fi
}

register_check "tool.bash" "tools" "both" "instant" "check_tool_bash" "" \
  "Install bash via your OS package manager; it is a hard prerequisite of every entry script in this repo."
register_check "tool.git" "tools" "both" "instant" "check_tool_git" "" \
  "Install git via your OS package manager."
register_check "tool.cargo" "tools" "sdk" "instant" "check_tool_cargo" "" \
  "Install Rust via https://rustup.rs (rust-toolchain.toml pins the exact toolchain)."
register_check "tool.rust-toolchain" "tools" "sdk" "instant" "check_tool_rust_toolchain" "" \
  "Run 'rustup show' from the repo root; rustup auto-installs the pinned toolchain from rust-toolchain.toml."
register_check "tool.wasm32-target" "tools" "sdk" "instant" "check_tool_wasm32_target" "" \
  "rustup target add wasm32-unknown-unknown"
register_check "tool.wasm-bindgen-cli" "tools" "sdk" "instant" "check_tool_wasm_bindgen_cli" "" \
  "cargo install wasm-bindgen-cli --version 0.2.126 --locked --force"
register_check "tool.node" "tools" "both" "instant" "check_tool_node" "" \
  "Install Node 18+ (see e2e-freighter/README.md's Requirements section; nvm/nodesource are recommended over an old apt package)."
register_check "tool.npm" "tools" "both" "instant" "check_tool_npm" "" \
  "Bundled with Node.js; reinstall Node if missing."
register_check "tool.python3" "tools" "both" "instant" "check_tool_python3" "" \
  "Install python3 via your OS package manager."
register_check "tool.curl" "tools" "both" "instant" "check_tool_curl" "" \
  "Install curl via your OS package manager."
register_check "tool.tar" "tools" "freighter" "instant" "check_tool_tar" "" \
  "Install tar via your OS package manager (present by default on virtually every Linux/macOS system)."
register_check "tool.unzip" "tools" "freighter" "instant" "check_tool_unzip" "" \
  "Install unzip via your OS package manager."
register_check "tool.stellar" "tools" "both" "instant" "check_tool_stellar" "" \
  "Install/upgrade the Stellar CLI to 27+ (see https://developers.stellar.org/docs/tools/developer-tools/cli)."
register_check "tool.spp" "tools" "both" "instant" "check_tool_spp" "" \
  "cargo build --release -p stellar-private-payments-cli"
register_check "tool.chromium" "tools" "freighter" "instant" "check_tool_chromium" "" \
  "Install Chromium (see e2e-freighter/README.md's per-distro sections) or set E2E_CHROMIUM_PATH to your install."
register_check "tool.chromedriver" "tools" "sdk" "instant" "check_tool_chromedriver" "" \
  "Install chromedriver matching your Chrome/Chromium version, or set CHROMEDRIVER to its path."
register_check "tool.trunk" "tools" "freighter" "instant" "check_tool_trunk" "" \
  "cargo install trunk (or pin trunk@0.21.14 as CI does) — only needed for local-app test runs (APP_URL=http://localhost:...)."
register_check "tool.xvfb" "tools" "freighter" "instant" "check_tool_xvfb" "" \
  "Install xvfb (e.g. 'apt install xvfb'); preinstalled on ubuntu-latest."

# ---------------------------------------------------------------------------
# env group: the accounts env file at ${E2E_ENV_FILE:-deployments/testnet/
# .e2e-accounts.env} and the compile-time variables the SDK suite needs.
# Values are read only via env_var_value (a subshell) and NEVER placed in
# _DETAIL or a remediation string — only key names, paths, and booleans.
#
# CI story (settled in plan step 3.5, option (c) from the 1.2 contract):
# CI has no .e2e-accounts.env at all — every variable arrives as an
# injected `env:` on the workflow step from GitHub secrets instead. The
# file-existence/mode/gitignore checks would otherwise report MISSING on
# every green CI run, so they report SKIP when $CI/$GITHUB_ACTIONS is set
# AND the vars the SELECTED suite actually needs are already present in
# the process environment (ci_env_already_satisfied). env.vars.required
# and env.compiletime.exported still run for real (against the
# environment, not a file) and can still fail if CI is missing a secret —
# that is a real, actionable CI failure, not something to relax. Their
# key lists are suite-aware and trimmed to variables with no compiled-in
# default (sdk/web/src/client/e2e_tests.rs's option_env! calls): the
# ALIAS fields and E2E_NETWORK are never read by any test, only by
# e2e-accounts-setup.sh's own bookkeeping, so they are not "required" here.
# ---------------------------------------------------------------------------

# The env keys the SELECTED suite (via $SUITE) actually needs at test run
# time, with no compiled-in / hardcoded default — i.e. the ones that must
# come from somewhere (file or environment), not the full account shape
# e2e-accounts-setup.sh happens to write to its file.
set_required_keys_for_suite() {
  case "$SUITE" in
    sdk)
      REQUIRED_KEYS_FOR_SUITE=(E2E_ACCOUNT_A_ADDRESS E2E_ACCOUNT_A_SECRET E2E_ACCOUNT_B_ADDRESS) ;;
    freighter)
      REQUIRED_KEYS_FOR_SUITE=(E2E_FREIGHTER_PASSWORD E2E_ACCOUNT_C_SECRET E2E_ACCOUNT_C_ADDRESS E2E_ACCOUNT_D_ADDRESS) ;;
    *)
      REQUIRED_KEYS_FOR_SUITE=(
        E2E_ACCOUNT_A_ADDRESS E2E_ACCOUNT_A_SECRET E2E_ACCOUNT_B_ADDRESS
        E2E_FREIGHTER_PASSWORD E2E_ACCOUNT_C_SECRET E2E_ACCOUNT_C_ADDRESS E2E_ACCOUNT_D_ADDRESS
      ) ;;
  esac
}

# True when CI is detected and every key the selected suite needs is
# already exported in THIS process's environment (not via the file) — the
# signal that CI provided everything via secrets and no env file is
# expected at all.
ci_env_already_satisfied() {
  is_ci || return 1
  set_required_keys_for_suite
  local key
  for key in "${REQUIRED_KEYS_FOR_SUITE[@]}"; do
    [ -n "${!key:-}" ] || return 1
  done
  return 0
}

check_env_file_exists() {
  if ci_env_already_satisfied; then
    _STATUS="SKIP"; _DETAIL="CI detected and required vars are already exported — no env file expected"
    return
  fi
  local f
  f="$(env_file_path)"
  if [ -s "$f" ]; then
    _STATUS="OK"; _DETAIL="$f"
  else
    _STATUS="MISSING"; _DETAIL="$f not found or empty"
  fi
}

heal_env_accounts_setup() {
  bash "$REPO_ROOT/deployments/scripts/e2e-accounts-setup.sh"
}

check_env_file_mode() {
  if ci_env_already_satisfied; then
    _STATUS="SKIP"; _DETAIL="CI detected and required vars are already exported — no env file expected"
    return
  fi
  local f mode
  f="$(env_file_path)"
  if [ ! -f "$f" ]; then
    _STATUS="MISSING"; _DETAIL="$f does not exist"
    return
  fi
  mode="$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f" 2>/dev/null || true)"
  if [ "$mode" = "600" ]; then
    _STATUS="OK"; _DETAIL="mode 600"
  else
    _STATUS="MISSING"
    _DETAIL="mode is ${mode:-unknown}, expected 600 (it holds secret keys)"
  fi
}

check_env_file_gitignored() {
  if ci_env_already_satisfied; then
    _STATUS="SKIP"; _DETAIL="CI detected and required vars are already exported — no env file expected"
    return
  fi
  local f
  f="$(env_file_path)"
  if [ ! -f "$f" ]; then
    _STATUS="MISSING"; _DETAIL="$f does not exist"
    return
  fi
  if ( cd "$REPO_ROOT" && git check-ignore -q "$f" ); then
    _STATUS="OK"; _DETAIL="git-ignored"
  else
    _STATUS="MISSING"; _DETAIL="$f is NOT git-ignored — add it to .gitignore before continuing"
  fi
}

check_env_vars_required() {
  set_required_keys_for_suite
  local key missing=()
  for key in "${REQUIRED_KEYS_FOR_SUITE[@]}"; do
    env_var_present "$key" || missing+=("$key")
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    _STATUS="OK"
    _DETAIL="all ${#REQUIRED_KEYS_FOR_SUITE[@]} keys required by suite=$SUITE are present and non-empty"
  else
    _STATUS="MISSING"
    _DETAIL="missing/empty (suite=$SUITE): $(IFS=,; echo "${missing[*]}")"
  fi
}

check_env_address_format() {
  local key addr bad=() present=0
  for key in E2E_ACCOUNT_A_ADDRESS E2E_ACCOUNT_B_ADDRESS E2E_ACCOUNT_C_ADDRESS E2E_ACCOUNT_D_ADDRESS; do
    addr="$(env_var_value "$key")" || continue
    [ -n "$addr" ] || continue
    present=$((present + 1))
    if [[ ! "$addr" =~ ^G[A-Z2-7]{55}$ ]]; then
      bad+=("$key")
    fi
  done
  if [ "$present" -eq 0 ]; then
    _STATUS="MISSING"
    _DETAIL="no account addresses available to check (see env.vars.required / env.file.exists)"
  elif [ "${#bad[@]}" -eq 0 ]; then
    _STATUS="OK"; _DETAIL="$present address(es) checked, all well-formed"
  else
    _STATUS="MISSING"
    _DETAIL="malformed address for: $(IFS=,; echo "${bad[*]}")"
  fi
}

check_env_pool_matches_deployments() {
  local pool_env pool_json deployments_json
  pool_env="$(env_var_value E2E_POOL_CONTRACT)" || pool_env=""
  if [ -z "$pool_env" ]; then
    _STATUS="MISSING"; _DETAIL="E2E_POOL_CONTRACT not set (see env.vars.required)"
    return
  fi
  deployments_json="$REPO_ROOT/deployments/testnet/deployments.json"
  if [ ! -f "$deployments_json" ]; then
    _STATUS="MISSING"; _DETAIL="$deployments_json not found"
    return
  fi
  pool_json="$(python3 - "$deployments_json" <<'PYEOF'
import json, sys
pools = json.load(open(sys.argv[1]))["pools"]
native = [p for p in pools if p.get("enabled") and p.get("asset", {}).get("kind") == "native"]
if len(native) != 1:
    sys.exit(1)
print(native[0]["poolContractId"])
PYEOF
)"
  if [ -z "$pool_json" ]; then
    _STATUS="MISSING"
    _DETAIL="could not resolve a single enabled native pool from $deployments_json"
    return
  fi
  if [ "$pool_env" = "$pool_json" ]; then
    _STATUS="OK"; _DETAIL="matches deployments.json ($pool_json)"
  else
    _STATUS="MISSING"
    _DETAIL="E2E_POOL_CONTRACT ($pool_env) does not match the enabled native pool in deployments.json ($pool_json) — a redeploy invalidated the env file"
  fi
}

check_env_rpc_reachable() {
  local url
  url="$(env_var_value E2E_RPC_URL)" || url=""
  [ -n "$url" ] || url="https://soroban-testnet.stellar.org"
  if curl -fsS --max-time 5 -X POST "$url" -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' >/dev/null 2>&1; then
    _STATUS="OK"; _DETAIL="getHealth OK ($url)"
  else
    _STATUS="MISSING"; _DETAIL="getHealth failed or timed out ($url)"
  fi
}

check_env_compiletime_exported() {
  # Only the three option_env! vars with NO compiled-in default
  # (sdk/web/src/client/e2e_tests.rs) are "required" here — E2E_STATIC_ORIGIN,
  # E2E_RPC_URL and E2E_POOL_CONTRACT all fall back to a working default when
  # unset, so leaving them unexported is fine (env.pool.matches_deployments
  # separately catches a stale POOL_CONTRACT when one IS set).
  local vars=(E2E_ACCOUNT_A_ADDRESS E2E_ACCOUNT_A_SECRET E2E_ACCOUNT_B_ADDRESS)
  local key missing=()
  for key in "${vars[@]}"; do
    [ -n "${!key:-}" ] || missing+=("$key")
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    _STATUS="OK"; _DETAIL="all no-default option_env! variables are already exported in this shell"
  else
    _STATUS="MISSING"
    _DETAIL="not exported in the current shell, a file on disk is not enough: $(IFS=,; echo "${missing[*]}")"
  fi
}

register_check "env.file.exists" "env" "both" "instant" "check_env_file_exists" "heal_env_accounts_setup" \
  "bash deployments/scripts/e2e-accounts-setup.sh"
register_check "env.file.mode" "env" "both" "instant" "check_env_file_mode" "" \
  "chmod 600 deployments/testnet/.e2e-accounts.env"
register_check "env.file.gitignored" "env" "both" "instant" "check_env_file_gitignored" "" \
  "Add the path to .gitignore before continuing — never commit this file."
register_check "env.vars.required" "env" "both" "instant" "check_env_vars_required" "heal_env_accounts_setup" \
  "bash deployments/scripts/e2e-accounts-setup.sh"
register_check "env.address.format" "env" "both" "instant" "check_env_address_format" "" \
  "Regenerate the env file (deployments/scripts/e2e-accounts-setup.sh --force) if an address is malformed."
register_check "env.pool.matches_deployments" "env" "sdk" "instant" "check_env_pool_matches_deployments" "" \
  "Re-run deployments/scripts/e2e-accounts-setup.sh (it re-resolves the pool from deployments.json on every run)."
register_check "env.rpc.reachable" "env" "both" "network" "check_env_rpc_reachable" "" \
  "Check connectivity to \$E2E_RPC_URL, or that testnet RPC is not degraded (https://status.stellar.org)."
register_check "env.compiletime.exported" "env" "sdk" "instant" "check_env_compiletime_exported" "" \
  "set -a; . deployments/testnet/.e2e-accounts.env; set +a   (then run cargo/e2e-browser-test.sh in the same shell)"

# ---------------------------------------------------------------------------
# chain group: on-chain state (friendbot funding + public-key registry
# registration) for accounts A-D. Delegates entirely to
# `deployments/scripts/e2e-accounts-setup.sh --verify`, which already
# verifies all four accounts in a single pass — never reimplement the
# Horizon/registry queries here. Both account checks are cost=network, so
# run_check()'s generic cache logic (step 2.1) already SKIPs them on a
# fresh cache and never even calls these check functions in that case.
#
# chain.accounts.funded and chain.accounts.registered share one delegated
# verification: run_chain_verify_once() performs it at most once per
# invocation and both checks read its cached result, so registering two
# checks against the same underlying script never doubles the network cost.
# ---------------------------------------------------------------------------
CHAIN_VERIFY_ATTEMPTED=0
CHAIN_VERIFY_STATUS=""
CHAIN_VERIFY_DETAIL=""
CHAIN_HEAL_ATTEMPTED=0
CHAIN_HEAL_LAST_STATUS=0

run_chain_verify_once() {
  if [ "$CHAIN_VERIFY_ATTEMPTED" -eq 1 ]; then
    return 0
  fi
  CHAIN_VERIFY_ATTEMPTED=1
  local err_file err
  err_file="$(mktemp)"
  if bash "$REPO_ROOT/deployments/scripts/e2e-accounts-setup.sh" --verify >/dev/null 2>"$err_file"; then
    CHAIN_VERIFY_STATUS="OK"
    CHAIN_VERIFY_DETAIL="verified"
    cache_mark_fresh
  else
    # Truncate and strip anything resembling a secret key before this ever
    # reaches _DETAIL — the script's stderr names which account and why,
    # which is exactly what we want to surface, minus any key material.
    err="$(tail -c 400 "$err_file" 2>/dev/null | tr '\n' ' ' \
      | sed -E 's/S[A-Z2-7]{55}/[REDACTED_SECRET]/g')"
    CHAIN_VERIFY_STATUS="MISSING"
    CHAIN_VERIFY_DETAIL="${err:-e2e-accounts-setup.sh --verify failed (see stderr)}"
  fi
  rm -f "$err_file"
  return 0
}

heal_chain_accounts() {
  if [ "$CHAIN_HEAL_ATTEMPTED" -eq 1 ]; then
    return "$CHAIN_HEAL_LAST_STATUS"
  fi
  CHAIN_HEAL_ATTEMPTED=1
  # Never --verify (we want it to provision/backfill) and never --force
  # (that would regenerate all four keypairs and overwrite the env file).
  if bash "$REPO_ROOT/deployments/scripts/e2e-accounts-setup.sh"; then
    CHAIN_HEAL_LAST_STATUS=0
  else
    CHAIN_HEAL_LAST_STATUS=1
  fi
  # Force the next check_fn call to re-verify instead of replaying the
  # pre-heal cached result.
  CHAIN_VERIFY_ATTEMPTED=0
  return "$CHAIN_HEAL_LAST_STATUS"
}

check_chain_accounts_funded() {
  # e2e-accounts-setup.sh --verify has no path override and hard-requires
  # deployments/testnet/.e2e-accounts.env to exist (`die`s immediately
  # otherwise) — a file that never exists on CI. CI provisions these
  # accounts exactly once, out of band, then copies the secrets in (see
  # e2e-freighter/README.md's CI section); trust that one-time human
  # verification rather than re-querying chain state every single run.
  if is_ci; then
    _STATUS="SKIP"
    _DETAIL="CI detected — trusting the account state verified once before its secrets were copied into CI"
    return
  fi
  run_chain_verify_once
  _STATUS="$CHAIN_VERIFY_STATUS"
  _DETAIL="funding (delegated to a single e2e-accounts-setup.sh --verify pass for A/B/C/D): $CHAIN_VERIFY_DETAIL"
}

check_chain_accounts_registered() {
  if is_ci; then
    _STATUS="SKIP"
    _DETAIL="CI detected — trusting the account state verified once before its secrets were copied into CI"
    return
  fi
  run_chain_verify_once
  _STATUS="$CHAIN_VERIFY_STATUS"
  _DETAIL="public-key registry (delegated to a single e2e-accounts-setup.sh --verify pass for A/B/C/D): $CHAIN_VERIFY_DETAIL"
}

check_chain_cache_freshness() {
  if cache_is_fresh; then
    _STATUS="OK"
    _DETAIL="fresh (${CACHE_AGE_SECONDS}s old, ttl ${CACHE_TTL_SECONDS}s)"
  elif [ -f "$CACHE_FILE" ]; then
    _STATUS="OK"
    _DETAIL="stale or fingerprint mismatch — the next network check will re-verify"
  else
    _STATUS="OK"
    _DETAIL="no cache marker yet — the next network check will verify fresh"
  fi
}

register_check "chain.accounts.funded" "chain" "both" "network" "check_chain_accounts_funded" "heal_chain_accounts" \
  "bash deployments/scripts/e2e-accounts-setup.sh"
register_check "chain.accounts.registered" "chain" "both" "network" "check_chain_accounts_registered" "heal_chain_accounts" \
  "bash deployments/scripts/e2e-accounts-setup.sh"
register_check "chain.cache.freshness" "chain" "both" "instant" "check_chain_cache_freshness" "" \
  "Delete .e2e-preflight-cache to force a fresh chain verification, or pass --deep."

# ---------------------------------------------------------------------------
# artifacts group (suite=sdk): the compiled circuit artifacts and the
# sdk/web npm dist the pre-signing SDK e2e tests need. Every check here is
# cost=instant (filesystem probes only) — the slow heal actions (cargo
# build, npm run build) only ever run under --fix, never --check.
#
# The .r1cs/.graph.bin filenames come from stage-circuits-dist.sh's own
# CIRCUIT_ARTIFACTS array, read by sourcing that script with
# STAGE_CIRCUITS_DIST_SOURCE_ONLY=1 (which makes it `return` before doing
# anything else) rather than hardcoding the list. Its own ROOT/WEB/etc
# resolve incorrectly when sourced this way (they depend on $0, which
# points at this script, not stage-circuits-dist.sh) — harmless, since we
# only ever read the static CIRCUIT_ARTIFACTS array from it, in a subshell,
# and use our own REPO_ROOT-based paths for everything else.
# ---------------------------------------------------------------------------
circuits_out_base() {
  printf '%s' "${E2E_CIRCUITS_OUT_DIR:-$REPO_ROOT/target/circuits-artifacts}"
}

sdk_dist_base() {
  printf '%s' "${E2E_SDK_DIST_DIR:-$REPO_ROOT/sdk/web/dist}"
}

read_circuit_artifacts() {
  local script="$REPO_ROOT/sdk/web/scripts/stage-circuits-dist.sh"
  [ -f "$script" ] || return 1
  (
    STAGE_CIRCUITS_DIST_SOURCE_ONLY=1
    # shellcheck disable=SC1090,SC1091
    source "$script"
    # Tolerate a future rename of this variable with a clear failure here
    # rather than an unbound-variable crash at the call site.
    if [ -z "${CIRCUIT_ARTIFACTS+x}" ]; then
      exit 1
    fi
    printf '%s\n' "${CIRCUIT_ARTIFACTS[@]}"
  )
}

CIRCUIT_ARTIFACTS_LOADED=0
CIRCUIT_ARTIFACTS_CACHE=()

load_circuit_artifacts() {
  if [ "$CIRCUIT_ARTIFACTS_LOADED" -eq 1 ]; then
    return 0
  fi
  CIRCUIT_ARTIFACTS_LOADED=1
  local out line
  out="$(read_circuit_artifacts || true)"
  CIRCUIT_ARTIFACTS_CACHE=()
  if [ -n "$out" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] && CIRCUIT_ARTIFACTS_CACHE+=("$line")
    done <<< "$out"
  fi
  return 0
}

check_circuits_profile() {
  local profile="$1" out_dir name missing=()
  load_circuit_artifacts
  if [ "${#CIRCUIT_ARTIFACTS_CACHE[@]}" -eq 0 ]; then
    _STATUS="MISSING"
    _DETAIL="could not read CIRCUIT_ARTIFACTS from sdk/web/scripts/stage-circuits-dist.sh"
    return
  fi
  out_dir="$(circuits_out_base)/$profile"
  if [ ! -d "$out_dir" ]; then
    _STATUS="MISSING"; _DETAIL="$out_dir does not exist"
    return
  fi
  for name in "${CIRCUIT_ARTIFACTS_CACHE[@]}"; do
    case "$name" in
      *.r1cs) [ -f "$out_dir/$name" ] || missing+=("$name") ;;
    esac
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    _STATUS="OK"; _DETAIL="$out_dir holds all required .r1cs files"
  else
    _STATUS="MISSING"
    _DETAIL="$out_dir missing: $(IFS=,; echo "${missing[*]}")"
  fi
}

check_artifact_circuits_debug() { check_circuits_profile debug; }
check_artifact_circuits_release() { check_circuits_profile release; }

heal_circuits_debug() {
  step "building debug circuit artifacts: cargo build -p circuits (sdk/web/build.rs panics without target/circuits-artifacts/debug)"
  ( cd "$REPO_ROOT" && cargo build -p circuits )
}

heal_circuits_release() {
  step "building release circuit artifacts: cargo build -p circuits --release (feeds the sdk/web dist the prover fetches at runtime)"
  ( cd "$REPO_ROOT" && cargo build -p circuits --release )
}

check_artifact_circuit_keys() {
  local keys_dir name stem missing=()
  load_circuit_artifacts
  if [ "${#CIRCUIT_ARTIFACTS_CACHE[@]}" -eq 0 ]; then
    _STATUS="MISSING"
    _DETAIL="could not read CIRCUIT_ARTIFACTS from sdk/web/scripts/stage-circuits-dist.sh"
    return
  fi
  keys_dir="$REPO_ROOT/deployments/testnet/circuit_keys"
  if [ ! -d "$keys_dir" ]; then
    _STATUS="MISSING"; _DETAIL="$keys_dir does not exist"
    return
  fi
  for name in "${CIRCUIT_ARTIFACTS_CACHE[@]}"; do
    case "$name" in
      *.graph.bin)
        [ -f "$keys_dir/$name" ] || missing+=("$name")
        # build.rs's proving-key filename convention is <stem>_proving_key.bin
        # for the same stem as <stem>.graph.bin — derived here since the KEYS
        # array in stage-circuits-dist.sh lives past the
        # STAGE_CIRCUITS_DIST_SOURCE_ONLY=1 early-return guard and is not
        # reachable from read_circuit_artifacts.
        stem="${name%.graph.bin}"
        [ -f "$keys_dir/${stem}_proving_key.bin" ] || missing+=("${stem}_proving_key.bin")
        ;;
    esac
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    _STATUS="OK"; _DETAIL="$keys_dir holds all required .graph.bin and proving-key files"
  else
    _STATUS="MISSING"
    _DETAIL="$keys_dir missing: $(IFS=,; echo "${missing[*]}")"
  fi
}

check_artifact_sdk_dist_workers() {
  local workers
  workers="$(sdk_dist_base)/workers/storage-worker.js"
  if [ -f "$workers" ]; then
    _STATUS="OK"; _DETAIL="$workers"
  else
    _STATUS="MISSING"; _DETAIL="$workers not found"
  fi
}

check_artifact_sdk_dist_circuits() {
  local circuits_dir
  circuits_dir="$(sdk_dist_base)/circuits"
  if [ -d "$circuits_dir" ] && [ -n "$(ls -A "$circuits_dir" 2>/dev/null)" ]; then
    _STATUS="OK"; _DETAIL="$circuits_dir is populated"
  else
    _STATUS="MISSING"; _DETAIL="$circuits_dir missing or empty"
  fi
}

SDK_DIST_HEAL_ATTEMPTED=0
SDK_DIST_HEAL_LAST_STATUS=0

heal_sdk_dist() {
  if [ "$SDK_DIST_HEAL_ATTEMPTED" -eq 1 ]; then
    return "$SDK_DIST_HEAL_LAST_STATUS"
  fi
  SDK_DIST_HEAL_ATTEMPTED=1
  step "building sdk/web dist: npm ci --prefix sdk/web && npm run build --prefix sdk/web"
  if ( cd "$REPO_ROOT" && npm ci --prefix sdk/web && npm run build --prefix sdk/web ); then
    SDK_DIST_HEAL_LAST_STATUS=0
  else
    SDK_DIST_HEAL_LAST_STATUS=1
  fi
  return "$SDK_DIST_HEAL_LAST_STATUS"
}

check_artifact_sdk_dist_freshness() {
  # Warning-only staleness signal: NEVER MISSING, matching the existing
  # warning in e2e-browser-test.sh — rebuilding a stale dist is the
  # caller's choice, not something the preflight forces.
  local dist_circuits release_dir newest_dist newest_release dist_epoch release_epoch
  dist_circuits="$(sdk_dist_base)/circuits"
  release_dir="$(circuits_out_base)/release"
  if [ ! -d "$dist_circuits" ] || [ ! -d "$release_dir" ]; then
    _STATUS="OK"; _DETAIL="cannot compare freshness (dist/circuits or the release artifacts dir is missing)"
    return
  fi
  newest_dist="$(find "$dist_circuits" -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -n1)"
  newest_release="$(find "$release_dir" -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -n1)"
  if [ -z "$newest_dist" ] || [ -z "$newest_release" ]; then
    _STATUS="OK"; _DETAIL="cannot compare freshness (no files found)"
    return
  fi
  dist_epoch="${newest_dist%.*}"
  release_epoch="${newest_release%.*}"
  if [ "$dist_epoch" -lt "$release_epoch" ]; then
    _STATUS="OK"
    _DETAIL="stale: dist/circuits is older than the newest release circuit artifact — run 'npm run build --prefix sdk/web' to refresh"
  else
    _STATUS="OK"
    _DETAIL="dist/circuits is at least as new as the release circuit artifacts"
  fi
}

register_check "artifact.circuits.debug" "artifacts" "sdk" "instant" "check_artifact_circuits_debug" "heal_circuits_debug" \
  "cargo build -p circuits"
register_check "artifact.circuits.release" "artifacts" "sdk" "instant" "check_artifact_circuits_release" "heal_circuits_release" \
  "cargo build -p circuits --release"
register_check "artifact.circuit_keys" "artifacts" "sdk" "instant" "check_artifact_circuit_keys" "" \
  "These files are committed to git under deployments/testnet/circuit_keys — re-clone or 'git checkout -- deployments/testnet/circuit_keys' rather than rebuilding."
register_check "artifact.sdk_dist.workers" "artifacts" "sdk" "instant" "check_artifact_sdk_dist_workers" "heal_sdk_dist" \
  "npm ci --prefix sdk/web && npm run build --prefix sdk/web"
register_check "artifact.sdk_dist.circuits" "artifacts" "sdk" "instant" "check_artifact_sdk_dist_circuits" "heal_sdk_dist" \
  "npm ci --prefix sdk/web && npm run build --prefix sdk/web"
register_check "artifact.sdk_dist.freshness" "artifacts" "sdk" "instant" "check_artifact_sdk_dist_freshness" "" \
  "npm run build --prefix sdk/web (rebuild is the caller's choice, never forced)"

# ---------------------------------------------------------------------------
# freighter + browser groups (suite=freighter): the real-Freighter e2e
# suite's own state (node_modules, the vendored/pinned extension, the
# profile snapshot) and the browser environment it launches into. Heal only
# node_modules and the vendored extension per contract — never rebuild or
# overwrite an existing profile snapshot, and never launch a browser from
# the preflight itself. Every probe here stays side-effect-free under
# --check: browser.profile_tmpdir only tests writability, it never mkdirs.
# ---------------------------------------------------------------------------
is_ci() {
  [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ]
}

freighter_root() {
  printf '%s' "$REPO_ROOT/e2e-freighter"
}

vendor_dir() {
  printf '%s' "${E2E_VENDOR_DIR:-$REPO_ROOT/e2e-freighter/vendor/freighter}"
}

snapshot_file() {
  printf '%s' "${E2E_SNAPSHOT_FILE:-$REPO_ROOT/e2e-freighter/profile-snapshot.tar.gz}"
}

snapshot_has_onboarding() {
  local f
  f="$(snapshot_file)"
  [ -s "$f" ] || return 1
  # Process substitution, not a pipe: under set -o pipefail, grep -qi's
  # early exit on a match SIGPIPEs tar, and pipefail reports THAT nonzero
  # exit for the pipeline even though grep found the marker — confirmed
  # reproducible on this exact check (tar -tzf a 355-entry/47MB archive is
  # slow enough that grep can close the pipe before tar finishes writing).
  grep -qi 'Local Extension Settings/' < <(tar -tzf "$f" 2>/dev/null)
}

# True when a headed browser run is actually required right now: an
# explicit HEADFUL=1, or the profile snapshot not (yet) having the
# onboarding wizard baked in (which can only be completed headed). Shared
# by browser.display and tool.xvfb, which both key off the same condition.
need_headed_run() {
  [ "${HEADFUL:-}" = "1" ] && return 0
  ! snapshot_has_onboarding
}

# The one command to fix a missing/invalid snapshot: xvfb-run on CI or when
# no display is available (the onboarding step needs a headed browser),
# the plain form otherwise (a machine with a desktop session).
onboarding_remediation_command() {
  if is_ci || { [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; }; then
    printf '%s' "xvfb-run -a bash e2e-freighter/scripts/setup.sh"
  else
    printf '%s' "bash e2e-freighter/scripts/setup.sh"
  fi
}

check_freighter_node_modules() {
  local dir
  dir="$(freighter_root)/node_modules"
  if [ -d "$dir" ]; then
    _STATUS="OK"; _DETAIL="$dir"
  else
    _STATUS="MISSING"; _DETAIL="$dir not found"
  fi
}

heal_freighter_node_modules() {
  step "installing e2e-freighter npm dependencies: npm ci --prefix e2e-freighter"
  ( cd "$REPO_ROOT" && npm ci --prefix e2e-freighter )
}

check_freighter_playwright() {
  if ( cd "$(freighter_root)" 2>/dev/null && node -e "require.resolve('playwright')" ) >/dev/null 2>&1; then
    _STATUS="OK"; _DETAIL="playwright resolves from e2e-freighter/node_modules"
  else
    _STATUS="MISSING"
    _DETAIL="playwright does not resolve from e2e-freighter (node_modules missing or corrupt — see freighter.node_modules)"
  fi
}

check_freighter_ffmpeg() {
  if ! is_ci; then
    _STATUS="SKIP"; _DETAIL="not needed off CI (runner.mjs only records video when \$CI is set)"
    return
  fi
  # No cheap 'playwright --version'-style probe for this; Playwright's own
  # ffmpeg build lives under its browsers cache directory on Linux.
  local cache_dir
  cache_dir="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
  if [ -d "$cache_dir" ] && grep -q . < <(find "$cache_dir" -maxdepth 1 -iname 'ffmpeg*' 2>/dev/null); then
    _STATUS="OK"; _DETAIL="ffmpeg build found under $cache_dir"
  else
    _STATUS="MISSING"; _DETAIL="no ffmpeg build found under $cache_dir (needed because \$CI is set)"
  fi
}

parse_freighter_pin() {
  local script="$REPO_ROOT/e2e-freighter/scripts/fetch-extension.sh"
  [ -f "$script" ] || return 1
  grep -oE '^FREIGHTER_VERSION="[^"]+"' "$script" | head -n1 | sed -E 's/^FREIGHTER_VERSION="([^"]+)"$/\1/'
}

freighter_manifest_version() {
  local manifest="$1"
  [ -f "$manifest" ] || return 1
  node -p "JSON.parse(require('fs').readFileSync('$manifest','utf8')).version || ''" 2>/dev/null
}

check_freighter_extension_pinned() {
  local pin manifest have
  pin="$(parse_freighter_pin)" || true
  if [ -z "$pin" ]; then
    _STATUS="MISSING"
    _DETAIL="could not parse FREIGHTER_VERSION from e2e-freighter/scripts/fetch-extension.sh"
    return
  fi
  manifest="$(vendor_dir)/manifest.json"
  if [ ! -f "$manifest" ]; then
    _STATUS="MISSING"; _DETAIL="no vendored extension at $(vendor_dir) (pin wants $pin)"
    return
  fi
  have="$(freighter_manifest_version "$manifest")" || true
  if [ -z "$have" ]; then
    _STATUS="MISSING"; _DETAIL="could not read a version from $manifest"
  elif [ "$have" = "$pin" ]; then
    _STATUS="OK"; _DETAIL="vendored Freighter $have matches the pin"
  else
    _STATUS="MISSING"; _DETAIL="vendored Freighter is $have, pin wants $pin (version mismatch)"
  fi
}

heal_freighter_extension() {
  local manifest pin have
  manifest="$(vendor_dir)/manifest.json"
  pin="$(parse_freighter_pin)" || true
  have="$(freighter_manifest_version "$manifest")" || true
  if [ -n "$have" ] && [ -n "$pin" ] && [ "$have" != "$pin" ]; then
    step "vendored Freighter is $have, pin wants $pin: bash e2e-freighter/scripts/fetch-extension.sh --force"
    bash "$REPO_ROOT/e2e-freighter/scripts/fetch-extension.sh" --force
  else
    step "fetching the pinned Freighter extension: bash e2e-freighter/scripts/fetch-extension.sh"
    bash "$REPO_ROOT/e2e-freighter/scripts/fetch-extension.sh"
  fi
}

check_freighter_snapshot_exists() {
  local f size
  f="$(snapshot_file)"
  if [ ! -s "$f" ]; then
    _STATUS="MISSING"; _DETAIL="$f not found or empty"
    return
  fi
  size="$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f" 2>/dev/null || echo 0)"
  if [ "$size" -gt 1024 ]; then
    _STATUS="OK"; _DETAIL="$f (${size} bytes)"
  else
    _STATUS="MISSING"; _DETAIL="$f is suspiciously small (${size} bytes)"
  fi
}

check_freighter_snapshot_integrity() {
  local f
  f="$(snapshot_file)"
  if [ ! -s "$f" ]; then
    _STATUS="MISSING"; _DETAIL="$f not found or empty (see freighter.snapshot.exists)"
    return
  fi
  # Listing-only (tar -tzf never extracts) and grep -q stops at the first
  # match, so this stays fast even on a several-tens-of-MB archive. Process
  # substitution, not a pipe: under set -o pipefail, grep's early exit on a
  # match SIGPIPEs tar, and pipefail then reports tar's SIGPIPE exit for the
  # whole pipeline even though grep found the marker — this was a real,
  # confirmed false-MISSING bug on exactly this check.
  if grep -qi 'Local Extension Settings/' < <(tar -tzf "$f" 2>/dev/null); then
    _STATUS="OK"; _DETAIL="archive contains a 'Local Extension Settings' directory"
  else
    _STATUS="MISSING"
    _DETAIL="archive has no 'Local Extension Settings' directory — prepare-profile.sh cannot locate the profile subdir"
  fi
}

check_freighter_onboarding() {
  if snapshot_has_onboarding; then
    _STATUS="OK"; _DETAIL="onboarding is baked into the existing profile snapshot"
  else
    _STATUS="MISSING"
    _DETAIL="onboarding wizard completion is not baked into a valid snapshot yet"
  fi
}

check_browser_chromium_resolved() {
  local path="${E2E_CHROMIUM_PATH:-/usr/bin/chromium}"
  if [ -x "$path" ]; then
    _STATUS="OK"; _DETAIL="$path"
  else
    _STATUS="MISSING"; _DETAIL="$path is not executable"
  fi
}

resolve_profile_tmpdir_base() {
  local base="${E2E_PROFILE_TMPDIR:-}" chromium_path resolved
  if [ -z "$base" ]; then
    chromium_path="${E2E_CHROMIUM_PATH:-$(command -v chromium 2>/dev/null || true)}"
    if [ -n "$chromium_path" ]; then
      resolved="$(readlink -f "$chromium_path" 2>/dev/null || printf '%s' "$chromium_path")"
      case "$resolved" in
        /snap/*|/var/snap/*|/var/lib/snapd/*) base="$REPO_ROOT/e2e-freighter/.tmp-profiles" ;;
      esac
    fi
  fi
  printf '%s' "${base:-${TMPDIR:-/tmp}}"
}

check_browser_profile_tmpdir() {
  local base parent
  base="$(resolve_profile_tmpdir_base)"
  if [ -d "$base" ]; then
    if [ -w "$base" ]; then
      _STATUS="OK"; _DETAIL="$base exists and is writable"
    else
      _STATUS="MISSING"; _DETAIL="$base exists but is not writable"
    fi
    return
  fi
  parent="$(dirname "$base")"
  if [ -d "$parent" ] && [ -w "$parent" ]; then
    _STATUS="OK"; _DETAIL="$base does not exist yet, but $parent is writable"
  else
    _STATUS="MISSING"; _DETAIL="$base does not exist and $parent is not writable"
  fi
}

heal_browser_profile_tmpdir() {
  local base
  base="$(resolve_profile_tmpdir_base)"
  step "creating profile tmpdir: mkdir -p $base"
  mkdir -p "$base"
}

check_browser_display() {
  if ! need_headed_run; then
    _STATUS="SKIP"; _DETAIL="not needed for the default headless run"
    return
  fi
  if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
    _STATUS="OK"; _DETAIL="DISPLAY/WAYLAND_DISPLAY is set"
  else
    _STATUS="MISSING"
    _DETAIL="no DISPLAY/WAYLAND_DISPLAY set, and a headed run is required (HEADFUL=1, or the profile snapshot needs (re)building)"
  fi
}

check_browser_app_url() {
  local url="${APP_URL:-https://nethermindeth.github.io/stellar-private-payments/#move-funds}"
  case "$url" in
    http://localhost*|http://127.0.0.1*)
      _STATUS="OK"; _DETAIL="$url (local — a server must already be running: trunk serve or a built app-dist)" ;;
    *)
      _STATUS="OK"; _DETAIL="$url" ;;
  esac
}

register_check "freighter.node_modules" "freighter" "freighter" "instant" "check_freighter_node_modules" "heal_freighter_node_modules" \
  "npm ci --prefix e2e-freighter"
register_check "freighter.playwright" "freighter" "freighter" "instant" "check_freighter_playwright" "" \
  "npm ci --prefix e2e-freighter (a corrupt/partial node_modules needs a clean reinstall)"
register_check "freighter.ffmpeg" "freighter" "freighter" "instant" "check_freighter_ffmpeg" "" \
  "npx playwright install ffmpeg --prefix e2e-freighter (CI only; off-CI this is SKIP, never MISSING)"
register_check "freighter.extension.pinned" "freighter" "freighter" "instant" "check_freighter_extension_pinned" "heal_freighter_extension" \
  "bash e2e-freighter/scripts/fetch-extension.sh [--force]"
register_check "freighter.snapshot.exists" "freighter" "freighter" "instant" "check_freighter_snapshot_exists" "" \
  "$(onboarding_remediation_command)"
register_check "freighter.snapshot.integrity" "freighter" "freighter" "instant" "check_freighter_snapshot_integrity" "" \
  "$(onboarding_remediation_command)"
register_check "freighter.onboarding" "freighter" "freighter" "instant" "check_freighter_onboarding" "" \
  "$(onboarding_remediation_command)"
register_check "browser.chromium.resolved" "browser" "freighter" "instant" "check_browser_chromium_resolved" "" \
  "Install Chromium at /usr/bin/chromium, or set E2E_CHROMIUM_PATH to your install (see tool.chromium)."
register_check "browser.profile_tmpdir" "browser" "freighter" "instant" "check_browser_profile_tmpdir" "heal_browser_profile_tmpdir" \
  "mkdir -p e2e-freighter/.tmp-profiles (snap Chromium) or set E2E_PROFILE_TMPDIR to a directory your sandboxed browser can see (Flatpak, etc.)."
register_check "browser.display" "browser" "freighter" "instant" "check_browser_display" "" \
  "Run on a machine with a desktop session, or wrap the command in 'xvfb-run -a'."
register_check "browser.app_url" "browser" "freighter" "instant" "check_browser_app_url" "" \
  "For a local APP_URL, start 'trunk serve' (or serve app-dist) in a separate terminal before running the suite."

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
main() {
  local start_ns end_ns

  start_ns="$(date +%s%N)"
  run_all_checks
  compute_summary
  end_ns="$(date +%s%N)"
  DURATION_MS=$(( (end_ns - start_ns) / 1000000 ))

  if [ "$JSON_OUTPUT" -eq 1 ]; then
    print_json
  else
    print_human_report
    print_next_commands
    print_summary_line
  fi

  if [ "$MISSING_COUNT" -eq 0 ]; then
    export E2E_PREFLIGHT_DONE=1
    return 0
  fi
  return 1
}

main
