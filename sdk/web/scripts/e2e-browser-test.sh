#!/usr/bin/env bash
# Run browser e2e tests for sdk/web with the static asset server they require.
# Usage: e2e-browser-test.sh <command> [args...]

set -euo pipefail

die() { echo "e2e-browser-test.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
step() { echo "==> $*" >&2; }
warn() { echo "warning: $*" >&2; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WEB="$ROOT/sdk/web"
DIST="$WEB/dist"

# Load the provisioned account material, if present. The E2E_* values are read
# at COMPILE time by option_env! (sdk/web/src/client/e2e_tests.rs), so they must
# be exported before cargo runs, not merely before the test does; when they are
# absent cargo silently bakes in None and the e2e tests panic on their own guard
# message. Sourcing here — before the defaults below — rather than making every
# caller remember `set -a; . …; set +a`.
#
# Precedence: an already-exported, non-empty variable is NEVER overwritten. In
# CI every value is an injected secret and must win over any file on disk.
# Deliberately not `set -a; . "$file"; set +a`, which would clobber them.
#
# Values are never echoed: this file holds testnet secret keys.
E2E_ENV_FILE="${E2E_ENV_FILE:-$ROOT/deployments/testnet/.e2e-accounts.env}"
if [ -f "$E2E_ENV_FILE" ]; then
  step "loading account env from $E2E_ENV_FILE (already-exported vars win)"
  while IFS= read -r _line || [ -n "$_line" ]; do
    case "$_line" in ''|'#'*) continue ;; esac
    case "$_line" in *=*) ;; *) continue ;; esac
    _key="${_line%%=*}"
    case "$_key" in E2E_*) ;; *) continue ;; esac
    [ -n "${!_key:-}" ] && continue
    export "$_key=${_line#*=}"
  done < "$E2E_ENV_FILE"
  unset _line _key
fi

# The origin the test page fetches worker JS and circuit artifacts from. Must
# match the value compiled into the tests (option_env!("E2E_STATIC_ORIGIN") in
# sdk/web/src/client/e2e_tests.rs, same default).
E2E_STATIC_ORIGIN="${E2E_STATIC_ORIGIN:-http://127.0.0.1:8099}"

READY_PATH="/workers/storage-worker.js"
READY_RETRIES=40
SERVER_PID=""
SERVER_LOG=""

usage() {
  cat >&2 <<'USAGE'
Usage: e2e-browser-test.sh <command> [args...]

Runs <command> with everything the sdk/web browser e2e tests need:

  1. sdk/web/dist is built (built on demand when dist/workers is missing).
  2. A CORS-enabled static server rooted at sdk/web/dist is listening on
     $E2E_STATIC_ORIGIN. Plain `python3 -m http.server` is NOT sufficient: the
     test page loads these assets cross-origin, so they need
     Access-Control-Allow-Origin headers.
  3. The server is ready (polled, not raced) before <command> starts.
  4. E2E_STATIC_ORIGIN is exported, and CHROMEDRIVER is set from PATH if unset.
  5. The provisioned account material in $E2E_ENV_FILE is exported, when that
     file exists. Variables already exported win over the file, so injected CI
     secrets are never clobbered. These are read at COMPILE time by option_env!,
     so they must be set for the cargo invocation, not just for the test run.
  6. scripts/e2e-preflight.sh --check --suite sdk has passed. It runs after the
     env-file load, so it can verify the values are coherent (notably that
     E2E_POOL_CONTRACT matches deployments.json) rather than merely present.
     E2E_SKIP_PREFLIGHT=1 bypasses it.

An already-running server on that origin is reused and left running. A server
this script started is stopped on exit.

Environment:
  E2E_ENV_FILE               Account material to export (default
                             deployments/testnet/.e2e-accounts.env; written by
                             deployments/scripts/e2e-accounts-setup.sh). Missing
                             file is not an error.
  E2E_SKIP_PREFLIGHT         Set to 1 to bypass scripts/e2e-preflight.sh
  E2E_STATIC_ORIGIN          Origin to serve assets on (default http://127.0.0.1:8099)
  CHROMEDRIVER               Path to chromedriver (default: from PATH)
  WASM_BINDGEN_TEST_TIMEOUT  Per-test timeout in seconds (default 600). The
                             wasm-bindgen default of 20s is far too short for
                             real proving plus testnet confirmation.

Examples:
  sdk/web/scripts/e2e-browser-test.sh \
    cargo test --target wasm32-unknown-unknown \
      -p stellar-private-payments-sdk-web e2e_smoke_client_construction

  E2E_STATIC_ORIGIN=http://127.0.0.1:8123 \
    sdk/web/scripts/e2e-browser-test.sh cargo test --target wasm32-unknown-unknown \
      -p stellar-private-payments-sdk-web e2e_
USAGE
}

case "${1:-}" in
  ''|-h|--help) usage; [ -n "${1:-}" ] && exit 0 || die "a command to run is required" ;;
esac

need curl
need python3

# http://host:port -> host / port
origin_host_port() {
  local hostport="${E2E_STATIC_ORIGIN#*://}"
  hostport="${hostport%%/*}"
  case "$hostport" in
    *:*) HOST="${hostport%%:*}"; PORT="${hostport##*:}" ;;
    *)   HOST="$hostport"; PORT="80" ;;
  esac
  case "$PORT" in
    ''|*[!0-9]*) die "could not parse a port from E2E_STATIC_ORIGIN='$E2E_STATIC_ORIGIN'" ;;
  esac
}

serves_assets() {
  curl -fsS -o /dev/null "$E2E_STATIC_ORIGIN$READY_PATH" 2>/dev/null
}

ensure_dist() {
  if [ ! -d "$DIST/workers" ]; then
    step "sdk/web/dist/workers missing; building the npm package"
    need npm
    npm ci --prefix "$WEB" >&2
    npm run build --prefix "$WEB" >&2
    [ -d "$DIST/workers" ] || die "build did not produce $DIST/workers"
  else
    # A stale dist silently tests old code; rebuilding is the caller's choice.
    warn "reusing existing $DIST (run 'npm run build --prefix sdk/web' if it is stale)"
  fi
}

SERVER_PY=""

write_server_py() {
  SERVER_PY="$(mktemp -t e2e-static-server.XXXXXX.py)"
  cat > "$SERVER_PY" <<'PYSERVER'
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

host, port, root = sys.argv[1], int(sys.argv[2]), sys.argv[3]


class CORSHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=root, **kwargs)

    def end_headers(self):
        # The test page loads these assets cross-origin.
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("REQ " + (fmt % args) + "\n")


ThreadingHTTPServer((host, port), CORSHandler).serve_forever()
PYSERVER
}

start_server() {
  origin_host_port
  write_server_py
  SERVER_LOG="$(mktemp -t e2e-static-server.XXXXXX.log)"
  step "starting CORS static server on $E2E_STATIC_ORIGIN (root: $DIST)"

  # Keep the server off this script's stdout so callers can pipe <command>.
  python3 "$SERVER_PY" "$HOST" "$PORT" "$DIST" >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  wait_ready
}

wait_ready() {
  local attempt=1
  while [ "$attempt" -le "$READY_RETRIES" ]; do
    if serves_assets; then
      step "static server ready after $attempt attempt(s)"
      return 0
    fi
    if [ -n "$SERVER_PID" ] && ! kill -0 "$SERVER_PID" 2>/dev/null; then
      [ -n "$SERVER_LOG" ] && cat "$SERVER_LOG" >&2
      die "static server exited before becoming ready"
    fi
    sleep 0.25
    attempt=$((attempt + 1))
  done
  [ -n "$SERVER_LOG" ] && cat "$SERVER_LOG" >&2
  die "static server did not serve $READY_PATH after $READY_RETRIES attempts"
}

cleanup() {
  # Only ever stop a server this script started, never a reused one.
  if [ -n "$SERVER_PID" ]; then
    step "stopping static server"
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  [ -n "$SERVER_LOG" ] && rm -f "$SERVER_LOG"
  [ -n "$SERVER_PY" ] && rm -f "$SERVER_PY"
  return 0
}
trap cleanup EXIT

main() {
  # Runs AFTER the env-file load above, deliberately: the preflight's
  # env.compiletime.exported check wants the E2E_* values already exported, and
  # env.pool.matches_deployments compares E2E_POOL_CONTRACT against
  # deployments.json — neither can do real work on variables the loader has not
  # supplied yet. Reversed, the preflight fails on its own missing prerequisite.
  #
  # Skipped entirely with E2E_SKIP_PREFLIGHT=1. On failure, abort with the
  # preflight's own report already printed — no extra wrapping. Its sdk group
  # deliberately overlaps ensure_dist below (both know about dist/workers): the
  # preflight must be able to report a missing dist without building it, so it
  # does not replace ensure_dist here.
  if [ "${E2E_SKIP_PREFLIGHT:-}" != "1" ]; then
    bash "$ROOT/scripts/e2e-preflight.sh" --check --suite sdk || exit 1
  fi

  ensure_dist

  if serves_assets; then
    warn "reusing the server already serving $E2E_STATIC_ORIGIN (left running on exit)"
  else
    start_server
  fi

  export E2E_STATIC_ORIGIN

  # wasm-bindgen's headless runner defaults to a 20s per-test timeout and then
  # SIGKILLs the driver. These tests do real Groth16 proving, submit to testnet
  # and wait for confirmation, so they need far longer.
  export WASM_BINDGEN_TEST_TIMEOUT="${WASM_BINDGEN_TEST_TIMEOUT:-600}"
  step "WASM_BINDGEN_TEST_TIMEOUT=${WASM_BINDGEN_TEST_TIMEOUT}s"

  if [ -z "${CHROMEDRIVER:-}" ]; then
    CHROMEDRIVER="$(command -v chromedriver || true)"
    [ -n "$CHROMEDRIVER" ] || die "chromedriver not found on PATH; set CHROMEDRIVER"
    export CHROMEDRIVER
  fi
  step "CHROMEDRIVER=$CHROMEDRIVER"

  step "running: $*"
  "$@"
}

main "$@"
