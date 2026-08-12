#!/usr/bin/env bash
# Run the Freighter e2e suite against a locally served app, starting the
# server first and stopping it afterwards — including when the tests fail,
# when the build never comes up, and when the run is interrupted.
#
# Usage: serve-and-run.sh [--url URL] [TEST_FILE ...]   (default: whole suite)
#
# This script owns the server, so it decides the URL: an APP_URL inherited
# from the environment is REPLACED with the one actually being served, and
# said so out loud. Honouring it instead makes a stale export — left over
# from a manual run in the same shell — silently point the suite at a port
# with nothing behind it, and every test then fails on connection refused
# having never started a server at all.
#
# --url targets something else explicitly (a deployed app, a server on
# another host). That path starts and stops nothing.
#
# A server this script did not start is never stopped. Running the suite
# should not kill the dev server someone already had open on the same port.

set -uo pipefail

die() { echo "serve-and-run.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PKG_ROOT/.." && pwd)"

PORT="${E2E_SERVE_PORT:-8000}"
LOCAL_URL="http://localhost:$PORT"
# Cold `make serve` builds the circuits and the wasm SDK before it listens.
READY_TIMEOUT="${E2E_SERVE_TIMEOUT:-900}"
SERVE_LOG="${E2E_SERVE_LOG:-$PKG_ROOT/test-results/serve.log}"

EXPLICIT_URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    --url) [ $# -ge 2 ] || die "--url needs a URL"; EXPLICIT_URL="$2"; shift 2 ;;
    --url=*) EXPLICIT_URL="${1#--url=}"; shift ;;
    *) break ;;
  esac
done

command -v curl >/dev/null 2>&1 || die "missing 'curl'"

server_responds() { curl -fsS -o /dev/null --max-time 3 "$LOCAL_URL/" 2>/dev/null; }

# Say it before anything else runs, so the replacement is visible in the log
# above the first test rather than inferred from a connection-refused later.
if [ -n "${APP_URL:-}" ] && [ -z "$EXPLICIT_URL" ] && [ "$APP_URL" != "$LOCAL_URL" ]; then
  step "replacing inherited APP_URL=$APP_URL with the server this run controls"
fi

SERVER_PGID=""

# Kill the whole process group, not the `make` pid: make execs trunk as a
# child, and killing make alone orphans trunk still holding the port. The
# group is created below with setsid precisely so this can find it.
stop_server() {
  [ -n "$SERVER_PGID" ] || return 0
  step "stopping the app server (pgid $SERVER_PGID)"
  kill -TERM "-$SERVER_PGID" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "-$SERVER_PGID" 2>/dev/null || { SERVER_PGID=""; return 0; }
    sleep 0.1
  done
  step "server did not exit on TERM — sending KILL"
  kill -KILL "-$SERVER_PGID" 2>/dev/null || true
  SERVER_PGID=""
}

# EXIT covers the normal and failing paths; INT/TERM cover Ctrl-C and a
# killed make, which would otherwise leave the server running.
trap stop_server EXIT
trap 'stop_server; exit 130' INT
trap 'stop_server; exit 143' TERM

if [ -n "$EXPLICIT_URL" ]; then
  step "--url $EXPLICIT_URL — starting no server"
  export APP_URL="$EXPLICIT_URL"
elif server_responds; then
  # Reuse rather than fail: this is the common case of a dev server the
  # user already has open. It stays running when the suite finishes.
  step "something is already serving $LOCAL_URL — reusing it, and leaving it running"
  export APP_URL="$LOCAL_URL"
else
  mkdir -p "$(dirname "$SERVE_LOG")"
  step "starting the app server: make serve (log: $SERVE_LOG)"
  # setsid puts make and every child it spawns in a fresh process group, so
  # stop_server can take all of them down together.
  setsid make -C "$REPO_ROOT" serve > "$SERVE_LOG" 2>&1 &
  SERVE_PID=$!
  SERVER_PGID="$(ps -o pgid= -p "$SERVE_PID" 2>/dev/null | tr -d ' ')"
  [ -n "$SERVER_PGID" ] || die "could not determine the server's process group"

  step "waiting up to ${READY_TIMEOUT}s for $LOCAL_URL (a cold build takes minutes)"
  deadline=$(( $(date +%s) + READY_TIMEOUT ))
  until server_responds; do
    if ! kill -0 "-$SERVER_PGID" 2>/dev/null; then
      echo "--- last 40 lines of $SERVE_LOG ---" >&2
      tail -n 40 "$SERVE_LOG" >&2
      die "the app server exited before it began serving"
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "--- last 40 lines of $SERVE_LOG ---" >&2
      tail -n 40 "$SERVE_LOG" >&2
      die "the app server did not come up within ${READY_TIMEOUT}s"
    fi
    sleep 2
  done
  step "app server is up at $LOCAL_URL"
  export APP_URL="$LOCAL_URL"
fi

# APPROVE=auto drives Freighter's approval prompts from the test runner.
# Override with APPROVE=human (and HEADFUL=1) to approve them by hand.
export APPROVE="${APPROVE:-auto}"

bash "$PKG_ROOT/scripts/run-all.sh" "$@"
STATUS=$?

# stop_server runs here via the EXIT trap, on success and failure alike.
exit "$STATUS"
