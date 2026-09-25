#!/usr/bin/env bash
# scripts/e2e-preflight.sh
#
# Single entry point that verifies (and, with --fix, safely auto-heals)
# every dependency and piece of state the two e2e suites in this repo need:
# the pre-signing SDK wasm-bindgen browser tests (sdk/web) and the
# real-Freighter browser tests (e2e-freighter). Safe to run before every
# test invocation — a bare `--check` never builds, installs, launches a
# browser, or touches the network.
#
# Usage: scripts/e2e-preflight.sh [--check|--fix] [--suite sdk|freighter|all]
#                                 [-h|--help]
#
# Environment:
#   E2E_SKIP_PREFLIGHT=1     Read by callers (run-all.sh, run-e2e.sh,
#                             e2e-browser-test.sh) to bypass entirely.
#   E2E_PREFLIGHT_DONE       Set to 1 by this script on a successful run.

set -euo pipefail

SCRIPT_NAME="e2e-preflight.sh"
die() { echo "$SCRIPT_NAME: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }
warn() { echo "warning: $*" >&2; }
ok() { echo "ok: $*" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------
MODE="check"
MODE_EXPLICIT=0
SUITE="all"

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
  -h, --help      Show this help.

Environment:
  E2E_SKIP_PREFLIGHT=1   Read by the CALLERS of this script (run-all.sh,
                         run-e2e.sh, e2e-browser-test.sh) to bypass it
                         entirely; this script itself does not read it.
  E2E_PREFLIGHT_DONE     Set to 1 by this script on a successful run.

Examples:
  scripts/e2e-preflight.sh --check --suite sdk
  scripts/e2e-preflight.sh --fix --suite all
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
    -h|--help) usage; exit 0 ;;
    *) usage_error "unknown argument '$1'" ;;
  esac
done

case "$SUITE" in
  sdk|freighter|all) ;;
  *) usage_error "--suite must be one of: sdk, freighter, all" ;;
esac

# ---------------------------------------------------------------------------
# Shared helpers
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
  grep -qi 'Local Extension Settings/' < <(tar -tzf "$f" 2>/dev/null)
}

need_headed_run() {
  [ "${HEADFUL:-}" = "1" ] && return 0
  ! snapshot_has_onboarding
}

onboarding_remediation_command() {
  if is_ci || { [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; }; then
    printf '%s' "xvfb-run -a bash e2e-freighter/scripts/setup.sh"
  else
    printf '%s' "bash e2e-freighter/scripts/setup.sh"
  fi
}

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

# ---------------------------------------------------------------------------
# SDK dist heal-once helper
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

# --- tools ---
check_tool_bash() { _STATUS="OK"; _DETAIL="$(bash --version | head -n1)"; }
check_tool_git() {
  if command -v git >/dev/null 2>&1; then _STATUS="OK"; _DETAIL="$(command -v git)"; else _STATUS="MISSING"; _DETAIL="git not found on PATH"; fi; }
check_tool_cargo() {
  if command -v cargo >/dev/null 2>&1; then _STATUS="OK"; _DETAIL="$(cargo --version 2>/dev/null || echo 'version unknown')"; else _STATUS="MISSING"; _DETAIL="cargo not found on PATH"; fi; }
check_tool_rust_toolchain() {
  if ! command -v rustc >/dev/null 2>&1; then _STATUS="MISSING"; _DETAIL="rustc not found on PATH"; return; fi
  local pinned have
  pinned="$(grep -oE 'channel[[:space:]]*=[[:space:]]*"[^"]+"' "$REPO_ROOT/rust-toolchain.toml" 2>/dev/null | grep -oE '"[^"]+"' | tr -d '"' || true)"
  have="$(rustc --version 2>/dev/null | awk '{print $2}')"
  if [ -z "$have" ]; then _STATUS="OK"; _DETAIL="rustc version unknown, could not parse"
  elif [ -z "$pinned" ]; then _STATUS="OK"; _DETAIL="rustc $have (no pin found in rust-toolchain.toml)"
  elif [ "$have" = "$pinned" ]; then _STATUS="OK"; _DETAIL="rustc $have (matches rust-toolchain.toml pin)"
  else _STATUS="OK"; _DETAIL="rustc $have (rust-toolchain.toml pins $pinned; rustup auto-selects it on the next cargo invocation)"; fi; }

check_tool_wasm32_target() {
  if command -v rustup >/dev/null 2>&1; then
    if grep -q '^wasm32-unknown-unknown$' < <(rustup target list --installed 2>/dev/null); then _STATUS="OK"; _DETAIL="wasm32-unknown-unknown installed (rustup target list --installed)"
    else _STATUS="MISSING"; _DETAIL="wasm32-unknown-unknown not in 'rustup target list --installed'"; fi
  elif command -v rustc >/dev/null 2>&1; then
    if grep -q '^wasm32-unknown-unknown$' < <(rustc --print target-list 2>/dev/null); then _STATUS="OK"; _DETAIL="wasm32-unknown-unknown is a known rustc target (no rustup on PATH to confirm it is installed)"
    else _STATUS="MISSING"; _DETAIL="wasm32-unknown-unknown not found via 'rustc --print target-list'"; fi
  else _STATUS="MISSING"; _DETAIL="neither rustup nor rustc found on PATH"; fi; }

check_tool_wasm_bindgen_cli() {
  if command -v wasm-bindgen >/dev/null 2>&1; then _STATUS="OK"; _DETAIL="$(wasm-bindgen --version 2>/dev/null || echo 'version unknown')"
  else _STATUS="MISSING"; _DETAIL="wasm-bindgen (wasm-bindgen-cli) not found on PATH"; fi; }

check_tool_node() {
  if ! command -v node >/dev/null 2>&1; then _STATUS="MISSING"; _DETAIL="node not found on PATH"; return; fi
  local v major; v="$(node --version 2>/dev/null)"; major="$(printf '%s' "$v" | sed -E 's/^v([0-9]+).*/\1/')"
  case "$major" in ''|*[!0-9]*) _STATUS="OK"; _DETAIL="node $v (version unknown, could not parse)" ;; *)
    if [ "$major" -ge 18 ]; then _STATUS="OK"; _DETAIL="node $v"; else _STATUS="MISSING"; _DETAIL="node $v is older than the required 18+"; fi ;; esac; }

check_tool_npm() {
  if command -v npm >/dev/null 2>&1; then _STATUS="OK"; _DETAIL="npm $(npm --version 2>/dev/null || echo 'version unknown')"
  else _STATUS="MISSING"; _DETAIL="npm not found on PATH"; fi; }

check_tool_python3() {
  if command -v python3 >/dev/null 2>&1; then _STATUS="OK"; _DETAIL="$(python3 --version 2>/dev/null || echo 'version unknown')"
  else _STATUS="MISSING"; _DETAIL="python3 not found on PATH"; fi; }

check_tool_curl() {
  if command -v curl >/dev/null 2>&1; then _STATUS="OK"; _DETAIL="$(command -v curl)"; else _STATUS="MISSING"; _DETAIL="curl not found on PATH"; fi; }

check_tool_tar() {
  if command -v tar >/dev/null 2>&1; then _STATUS="OK"; _DETAIL="$(command -v tar)"; else _STATUS="MISSING"; _DETAIL="tar not found on PATH"; fi; }

check_tool_unzip() {
  if command -v unzip >/dev/null 2>&1; then _STATUS="OK"; _DETAIL="$(command -v unzip)"; else _STATUS="MISSING"; _DETAIL="unzip not found on PATH"; fi; }

check_tool_stellar() {
  if ! command -v stellar >/dev/null 2>&1; then _STATUS="MISSING"; _DETAIL="stellar CLI not found on PATH"; return; fi
  local v major; v="$(stellar --version 2>/dev/null | head -n1)"; major="$(printf '%s' "$v" | grep -oE '[0-9]+' | head -n1)"
  case "$major" in ''|*[!0-9]*) _STATUS="OK"; _DETAIL="$v (version unknown, could not parse)" ;; *)
    if [ "$major" -ge 27 ]; then _STATUS="OK"; _DETAIL="$v"; else _STATUS="MISSING"; _DETAIL="$v is older than the required 27+ (spp passes --auto-sign to 'stellar tx sign', which older releases do not know)"; fi ;; esac; }

check_tool_chromium() {
  local path="" ; if [ -n "${E2E_CHROMIUM_PATH:-}" ]; then path="$E2E_CHROMIUM_PATH"; else path="$(command -v chromium 2>/dev/null || command -v google-chrome 2>/dev/null || true)"; fi
  if [ -n "$path" ] && [ -x "$path" ]; then _STATUS="OK"; _DETAIL="$path"; elif [ -n "$path" ]; then _STATUS="MISSING"; _DETAIL="resolved Chromium path '$path' is not executable"
  else _STATUS="MISSING"; _DETAIL="no Chromium/Chrome found (checked E2E_CHROMIUM_PATH, chromium, google-chrome)"; fi; }

check_tool_chromedriver() {
  local path=""; if [ -n "${CHROMEDRIVER:-}" ]; then path="$CHROMEDRIVER"; else path="$(command -v chromedriver 2>/dev/null || true)"; fi
  if [ -n "$path" ] && [ -x "$path" ]; then _STATUS="OK"; _DETAIL="$path"; else _STATUS="MISSING"; _DETAIL="chromedriver not resolvable via \$CHROMEDRIVER or PATH"; fi; }

check_tool_trunk() {
  case "${APP_URL:-}" in
    http://localhost*|http://127.0.0.1*)
      if command -v trunk >/dev/null 2>&1; then _STATUS="OK"; _DETAIL="$(command -v trunk)"; else _STATUS="MISSING"; _DETAIL="trunk not found on PATH (needed because APP_URL points at a local server)"; fi ;;
    *) _STATUS="SKIP"; _DETAIL="not needed unless APP_URL points at localhost" ;;
  esac; }

check_tool_xvfb() {
  if ! need_headed_run; then _STATUS="SKIP"; _DETAIL="not needed for the default headless run"; return; fi
  if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then _STATUS="SKIP"; _DETAIL="a headed run is needed, but a real display is already available"; return; fi
  if command -v xvfb-run >/dev/null 2>&1; then _STATUS="OK"; _DETAIL="$(command -v xvfb-run)"; else _STATUS="MISSING"; _DETAIL="xvfb-run not found on PATH"; fi; }

# --- artifacts ---
check_artifact_circuits() {
  local out_dir name missing=(); load_circuit_artifacts
  if [ "${#CIRCUIT_ARTIFACTS_CACHE[@]}" -eq 0 ]; then _STATUS="MISSING"; _DETAIL="could not read CIRCUIT_ARTIFACTS from sdk/web/scripts/stage-circuits-dist.sh"; return; fi
  out_dir="$(circuits_out_base)"
  if [ ! -d "$out_dir" ]; then _STATUS="MISSING"; _DETAIL="$out_dir does not exist"; return; fi
  for name in "${CIRCUIT_ARTIFACTS_CACHE[@]}"; do case "$name" in *.r1cs) [ -f "$out_dir/$name" ] || missing+=("$name") ;; esac; done
  if [ "${#missing[@]}" -eq 0 ]; then _STATUS="OK"; _DETAIL="$out_dir holds all required .r1cs files"
  else _STATUS="MISSING"; _DETAIL="$out_dir missing: $(IFS=,; echo "${missing[*]}")"; fi; }

heal_circuits() { step "building circuit artifacts"; ( cd "$REPO_ROOT" && make circuits ); }

check_artifact_circuit_keys() {
  local keys_dir name stem missing=(); load_circuit_artifacts
  if [ "${#CIRCUIT_ARTIFACTS_CACHE[@]}" -eq 0 ]; then _STATUS="MISSING"; _DETAIL="could not read CIRCUIT_ARTIFACTS from sdk/web/scripts/stage-circuits-dist.sh"; return; fi
  keys_dir="$REPO_ROOT/deployments/testnet/circuit_keys"
  if [ ! -d "$keys_dir" ]; then _STATUS="MISSING"; _DETAIL="$keys_dir does not exist"; return; fi
  for name in "${CIRCUIT_ARTIFACTS_CACHE[@]}"; do case "$name" in *.graph.bin)
    [ -f "$keys_dir/$name" ] || missing+=("$name"); stem="${name%.graph.bin}"; [ -f "$keys_dir/${stem}_proving_key.bin" ] || missing+=("${stem}_proving_key.bin") ;; esac; done
  if [ "${#missing[@]}" -eq 0 ]; then _STATUS="OK"; _DETAIL="$keys_dir holds all required .graph.bin and proving-key files"
  else _STATUS="MISSING"; _DETAIL="$keys_dir missing: $(IFS=,; echo "${missing[*]}")"; fi; }

check_artifact_sdk_dist_workers() {
  local workers; workers="$(sdk_dist_base)/workers/storage-worker.js"
  if [ -f "$workers" ]; then _STATUS="OK"; _DETAIL="$workers"; else _STATUS="MISSING"; _DETAIL="$workers not found"; fi; }

check_artifact_sdk_dist_circuits() {
  local circuits_dir; circuits_dir="$(sdk_dist_base)/circuits"
  if [ -d "$circuits_dir" ] && [ -n "$(ls -A "$circuits_dir" 2>/dev/null)" ]; then _STATUS="OK"; _DETAIL="$circuits_dir is populated"; else _STATUS="MISSING"; _DETAIL="$circuits_dir missing or empty"; fi; }

check_artifact_sdk_dist_freshness() {
  local dist_circuits circuits_dir newest_dist newest_circuits dist_epoch circuits_epoch
  dist_circuits="$(sdk_dist_base)/circuits"; circuits_dir="$(circuits_out_base)"
  if [ ! -d "$dist_circuits" ] || [ ! -d "$circuits_dir" ]; then _STATUS="OK"; _DETAIL="cannot compare freshness (dist/circuits or the circuit artifacts dir is missing)"; return; fi
  newest_dist="$(find "$dist_circuits" -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -n1)"
  newest_circuits="$(find "$circuits_dir" -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -n1)"
  if [ -z "$newest_dist" ] || [ -z "$newest_circuits" ]; then _STATUS="OK"; _DETAIL="cannot compare freshness (no files found)"; return; fi
  dist_epoch="${newest_dist%.*}"; circuits_epoch="${newest_circuits%.*}"
  if [ "$dist_epoch" -lt "$circuits_epoch" ]; then _STATUS="OK"; _DETAIL="stale: dist/circuits is older than the newest circuit artifact — run 'npm run build --prefix sdk/web' to refresh"
  else _STATUS="OK"; _DETAIL="dist/circuits is at least as new as the circuit artifacts"; fi; }

# --- freighter ---
check_freighter_node_modules() {
  local dir; dir="$(freighter_root)/node_modules"
  if [ -d "$dir" ]; then _STATUS="OK"; _DETAIL="$dir"; else _STATUS="MISSING"; _DETAIL="$dir not found"; fi; }

heal_freighter_node_modules() { step "installing e2e-freighter npm dependencies: npm ci --prefix e2e-freighter"; ( cd "$REPO_ROOT" && npm ci --prefix e2e-freighter ); }

check_freighter_playwright() {
  if ( cd "$(freighter_root)" 2>/dev/null && node -e "require.resolve('playwright')" ) >/dev/null 2>&1; then _STATUS="OK"; _DETAIL="playwright resolves from e2e-freighter/node_modules"
  else _STATUS="MISSING"; _DETAIL="playwright does not resolve from e2e-freighter (node_modules missing or corrupt — see freighter.node_modules)"; fi; }

check_freighter_ffmpeg() {
  if ! is_ci; then _STATUS="SKIP"; _DETAIL="not needed off CI (runner.mjs only records video when \$CI is set)"; return; fi
  local cache_dir; cache_dir="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
  if [ -d "$cache_dir" ] && grep -q . < <(find "$cache_dir" -maxdepth 1 -iname 'ffmpeg*' 2>/dev/null); then _STATUS="OK"; _DETAIL="ffmpeg build found under $cache_dir"
  else _STATUS="MISSING"; _DETAIL="no ffmpeg build found under $cache_dir (needed because \$CI is set)"; fi; }

check_freighter_extension_pinned() {
  local pin manifest have; pin="$(parse_freighter_pin)" || true
  if [ -z "$pin" ]; then _STATUS="MISSING"; _DETAIL="could not parse FREIGHTER_VERSION from e2e-freighter/scripts/fetch-extension.sh"; return; fi
  manifest="$(vendor_dir)/manifest.json"
  if [ ! -f "$manifest" ]; then _STATUS="MISSING"; _DETAIL="no vendored extension at $(vendor_dir) (pin wants $pin)"; return; fi
  have="$(freighter_manifest_version "$manifest")" || true
  if [ -z "$have" ]; then _STATUS="MISSING"; _DETAIL="could not read a version from $manifest"
  elif [ "$have" = "$pin" ]; then _STATUS="OK"; _DETAIL="vendored Freighter $have matches the pin"
  else _STATUS="MISSING"; _DETAIL="vendored Freighter is $have, pin wants $pin (version mismatch)"; fi; }

heal_freighter_extension() {
  local manifest pin have; manifest="$(vendor_dir)/manifest.json"; pin="$(parse_freighter_pin)" || true; have="$(freighter_manifest_version "$manifest")" || true
  if [ -n "$have" ] && [ -n "$pin" ] && [ "$have" != "$pin" ]; then step "vendored Freighter is $have, pin wants $pin: bash e2e-freighter/scripts/fetch-extension.sh --force"; bash "$REPO_ROOT/e2e-freighter/scripts/fetch-extension.sh" --force
  else step "fetching the pinned Freighter extension: bash e2e-freighter/scripts/fetch-extension.sh"; bash "$REPO_ROOT/e2e-freighter/scripts/fetch-extension.sh"; fi; }

check_freighter_snapshot_exists() {
  local f size; f="$(snapshot_file)"
  if [ ! -s "$f" ]; then _STATUS="MISSING"; _DETAIL="$f not found or empty"; return; fi
  size="$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f" 2>/dev/null || echo 0)"
  if [ "$size" -gt 1024 ]; then _STATUS="OK"; _DETAIL="$f (${size} bytes)"; else _STATUS="MISSING"; _DETAIL="$f is suspiciously small (${size} bytes)"; fi; }

check_freighter_snapshot_integrity() {
  local f; f="$(snapshot_file)"
  if [ ! -s "$f" ]; then _STATUS="MISSING"; _DETAIL="$f not found or empty (see freighter.snapshot.exists)"; return; fi
  if grep -qi 'Local Extension Settings/' < <(tar -tzf "$f" 2>/dev/null); then _STATUS="OK"; _DETAIL="archive contains a 'Local Extension Settings' directory"
  else _STATUS="MISSING"; _DETAIL="archive has no 'Local Extension Settings' directory — prepare-profile.sh cannot locate the profile subdir"; fi; }

check_freighter_onboarding() {
  if snapshot_has_onboarding; then _STATUS="OK"; _DETAIL="onboarding is baked into the existing profile snapshot"
  else _STATUS="MISSING"; _DETAIL="onboarding wizard completion is not baked into a valid snapshot yet"; fi; }

# --- browser ---
check_browser_chromium_resolved() {
  local path resolved=""
  path="${E2E_CHROMIUM_PATH:-/usr/bin/chromium}"
  if [ ! -x "$path" ]; then _STATUS="MISSING"; _DETAIL="$path is not executable"; return; fi
  resolved="$(readlink -f "$path" 2>/dev/null || echo "$path")"
  case "$resolved" in
    /snap/*|/var/snap/*|/var/lib/snapd/*)
      _STATUS="MISSING"
      _DETAIL="$path resolves to $resolved — snap chromium cannot load unpacked extensions for e2e tests. Install real Chromium: sudo add-apt-repository ppa:canonical-chromium-builds/stable && sudo apt install chromium-browser"
      ;;
    *)
      _STATUS="OK"; _DETAIL="$path" ;;
  esac
}

heal_browser_profile_tmpdir() { local base; base="$(resolve_profile_tmpdir_base)"; step "creating profile tmpdir: mkdir -p $base"; mkdir -p "$base"; }

check_browser_profile_tmpdir() {
  local base parent; base="$(resolve_profile_tmpdir_base)"
  if [ -d "$base" ]; then if [ -w "$base" ]; then _STATUS="OK"; _DETAIL="$base exists and is writable"; else _STATUS="MISSING"; _DETAIL="$base exists but is not writable"; fi; return; fi
  parent="$(dirname "$base")"
  if [ -d "$parent" ] && [ -w "$parent" ]; then _STATUS="OK"; _DETAIL="$base does not exist yet, but $parent is writable"; else _STATUS="MISSING"; _DETAIL="$base does not exist and $parent is not writable"; fi; }

check_browser_display() {
  if ! need_headed_run; then _STATUS="SKIP"; _DETAIL="not needed for the default headless run"; return; fi
  if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then _STATUS="OK"; _DETAIL="DISPLAY/WAYLAND_DISPLAY is set"
  else _STATUS="MISSING"; _DETAIL="no DISPLAY/WAYLAND_DISPLAY set, and a headed run is required (HEADFUL=1, or the profile snapshot needs (re)building)"; fi; }

check_browser_app_url() {
  local url="${APP_URL:-}"
  if [ -z "$url" ]; then _STATUS="MISSING"; _DETAIL="APP_URL is not set — set it to the deployed app or local server URL"; return; fi
  case "$url" in http://localhost*|http://127.0.0.1*) _STATUS="OK"; _DETAIL="$url (local — a server must already be running)" ;; *) _STATUS="OK"; _DETAIL="$url" ;; esac; }

# ---------------------------------------------------------------------------
# Group runners
# ---------------------------------------------------------------------------
FAILURES=0

# Each group function: run_check <id> <suite> <check_fn> [heal_fn] [remediation]
run_check() {
  local id="$1"; local suite_filter="$2"; local check_fn="$3"; local heal_fn="${4:-}"; local remediation="${5:-}"
  local detail="" status=""

  if [ "$SUITE" != "all" ] && [ "$suite_filter" != "both" ] && [ "$suite_filter" != "$SUITE" ]; then return 0; fi

  _STATUS=""; _DETAIL=""
  "$check_fn" || true
  status="$_STATUS"; detail="$_DETAIL"

  if [ "$status" = "MISSING" ] && [ "$MODE" = "fix" ] && [ -n "$heal_fn" ]; then
    step "healing $id"
    if "$heal_fn"; then
      _STATUS=""; _DETAIL=""; "$check_fn" || true
      status="$_STATUS"; detail="$_DETAIL"
      [ "$status" = "OK" ] && status="FIXED"
    else
      warn "heal action for $id failed"
    fi
  fi

  case "$status" in
    OK) [ -n "$detail" ] && ok "$id  $detail" ;;
    MISSING) echo "MISSING  $id  $detail" >&2; [ -n "$remediation" ] && echo "         $id  fix: $remediation" >&2; FAILURES=$((FAILURES + 1)) ;;
    FIXED) ok "$id  $detail (fixed)" ;;
    SKIP) ;;
    *) echo "$status  $id  $detail" >&2 ;;
  esac
  return 0
}

group_tools() {
  echo "-- tools --"
  run_check tool.bash both check_tool_bash "" "Install bash via your OS package manager; it is a hard prerequisite of every entry script in this repo."
  run_check tool.git both check_tool_git "" "Install git via your OS package manager."
  run_check tool.cargo sdk check_tool_cargo "" "Install Rust via https://rustup.rs (rust-toolchain.toml pins the exact toolchain)."
  run_check tool.rust-toolchain sdk check_tool_rust_toolchain "" "Run 'rustup show' from the repo root; rustup auto-installs the pinned toolchain from rust-toolchain.toml."
  run_check tool.wasm32-target sdk check_tool_wasm32_target "" "rustup target add wasm32-unknown-unknown"
  run_check tool.wasm-bindgen-cli sdk check_tool_wasm_bindgen_cli "" "cargo install wasm-bindgen-cli --version 0.2.126 --locked --force"
  run_check tool.node both check_tool_node "" "Install Node 18+ (see e2e-freighter/README.md's Requirements section; nvm/nodesource are recommended over an old apt package)."
  run_check tool.npm both check_tool_npm "" "Bundled with Node.js; reinstall Node if missing."
  run_check tool.python3 both check_tool_python3 "" "Install python3 via your OS package manager."
  run_check tool.curl both check_tool_curl "" "Install curl via your OS package manager."
  run_check tool.tar freighter check_tool_tar "" "Install tar via your OS package manager (present by default on virtually every Linux/macOS system)."
  run_check tool.unzip freighter check_tool_unzip "" "Install unzip via your OS package manager."
  run_check tool.stellar both check_tool_stellar "" "Install/upgrade the Stellar CLI to 27+ (see https://developers.stellar.org/docs/tools/developer-tools/cli)."
  run_check tool.chromium freighter check_tool_chromium "" "Install Chromium (see e2e-freighter/README.md's per-distro sections) or set E2E_CHROMIUM_PATH to your install."
  run_check tool.chromedriver sdk check_tool_chromedriver "" "Install chromedriver matching your Chrome/Chromium version, or set CHROMEDRIVER to its path."
  run_check tool.trunk freighter check_tool_trunk "" "cargo install trunk (or pin trunk@0.21.14 as CI does) — only needed for local-app test runs (APP_URL=http://localhost:...)."
  run_check tool.xvfb freighter check_tool_xvfb "" "Install xvfb (e.g. 'apt install xvfb'); preinstalled on ubuntu-latest."
}

group_artifacts() {
  echo "-- artifacts --"
  run_check artifact.circuits sdk check_artifact_circuits heal_circuits "make circuits"
  run_check artifact.circuit_keys sdk check_artifact_circuit_keys "" "These files are committed to git under deployments/testnet/circuit_keys — re-clone or 'git checkout -- deployments/testnet/circuit_keys' rather than rebuilding."
  run_check artifact.sdk_dist.workers sdk check_artifact_sdk_dist_workers heal_sdk_dist "npm ci --prefix sdk/web && npm run build --prefix sdk/web"
  run_check artifact.sdk_dist.circuits sdk check_artifact_sdk_dist_circuits heal_sdk_dist "npm ci --prefix sdk/web && npm run build --prefix sdk/web"
  run_check artifact.sdk_dist.freshness sdk check_artifact_sdk_dist_freshness "" "npm run build --prefix sdk/web (rebuild is the caller's choice, never forced)"
}

group_freighter() {
  echo "-- freighter --"
  run_check freighter.node_modules freighter check_freighter_node_modules heal_freighter_node_modules "npm ci --prefix e2e-freighter"
  run_check freighter.playwright freighter check_freighter_playwright "" "npm ci --prefix e2e-freighter (a corrupt/partial node_modules needs a clean reinstall)"
  run_check freighter.ffmpeg freighter check_freighter_ffmpeg "" "npx playwright install ffmpeg --prefix e2e-freighter (CI only; off-CI this is SKIP, never MISSING)"
  run_check freighter.extension.pinned freighter check_freighter_extension_pinned heal_freighter_extension "bash e2e-freighter/scripts/fetch-extension.sh [--force]"
  run_check freighter.snapshot.exists freighter check_freighter_snapshot_exists "" "$(onboarding_remediation_command)"
  run_check freighter.snapshot.integrity freighter check_freighter_snapshot_integrity "" "$(onboarding_remediation_command)"
  run_check freighter.onboarding freighter check_freighter_onboarding "" "$(onboarding_remediation_command)"
}

group_browser() {
  echo "-- browser --"
  run_check browser.chromium.resolved freighter check_browser_chromium_resolved "" "Install Chromium at /usr/bin/chromium, or set E2E_CHROMIUM_PATH to your install (see tool.chromium)."
  run_check browser.profile_tmpdir freighter check_browser_profile_tmpdir heal_browser_profile_tmpdir "mkdir -p e2e-freighter/.tmp-profiles (snap Chromium) or set E2E_PROFILE_TMPDIR to a directory your sandboxed browser can see (Flatpak, etc.)."
  run_check browser.display freighter check_browser_display "" "Run on a machine with a desktop session, or wrap the command in 'xvfb-run -a'."
  run_check browser.app_url freighter check_browser_app_url "" "For a local APP_URL, start 'trunk serve' (or serve app-dist) in a separate terminal before running the suite."
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
main() {
  group_tools
  group_artifacts
  group_freighter
  group_browser

  echo
  if [ "$FAILURES" -eq 0 ]; then
    echo "suite=$SUITE mode=$MODE: all checks passed"
    export E2E_PREFLIGHT_DONE=1
    return 0
  else
    echo "suite=$SUITE mode=$MODE: $FAILURES check(s) MISSING" >&2
    return 1
  fi
}

main