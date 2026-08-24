#!/usr/bin/env bash
# Run something against a locally served app, starting the server first and
# stopping it afterwards — including when the command fails, when the build
# never comes up, and when the run is interrupted.
#
# Usage: serve-and-run.sh [--url URL] [TEST_FILE ...]         (default: whole suite)
#        serve-and-run.sh [--url URL] -- COMMAND [ARG ...]    (run COMMAND instead)
#
# The -- form also supports profile provisioning, whose onboarding flow
# navigates to APP_URL.
#
# When this script starts the server, it sets APP_URL to that server's URL.
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
CUSTOM_CMD=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 0 ;;
    --url) [ $# -ge 2 ] || die "--url needs a URL"; EXPLICIT_URL="$2"; shift 2 ;;
    --url=*) EXPLICIT_URL="${1#--url=}"; shift ;;
    --) CUSTOM_CMD=1; shift; break ;;
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
  local server_pgid="$SERVER_PGID"
  # Clear this before signalling anything. If the process-group lookup was
  # wrong, or CI delivers TERM while this trap is running, the EXIT/TERM trap
  # must not recursively try to stop the same group.
  SERVER_PGID=""
  [ -n "$server_pgid" ] || return 0
  step "stopping the app server (pgid $server_pgid)"
  kill -TERM "-$server_pgid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "-$server_pgid" 2>/dev/null || return 0
    sleep 0.1
  done
  step "server did not exit on TERM — sending KILL"
  kill -KILL "-$server_pgid" 2>/dev/null || true
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
  # Put make and every child it spawns in a fresh process group, so
  # stop_server can take all of them down together with `kill -TERM -$PGID`.
  # Linux has `setsid` (util-linux); macOS does not, so use a portable shim:
  # perl's setpgrp(0,0) makes the process a new group leader, then execs the
  # command in its place. This works on both platforms.
  if command -v setsid >/dev/null 2>&1; then
    setsid make -C "$REPO_ROOT" serve > "$SERVE_LOG" 2>&1 &
  else
    perl -e 'setpgrp(0,0) or die "setpgrp: $!"; exec @ARGV' make -C "$REPO_ROOT" serve > "$SERVE_LOG" 2>&1 &
  fi
  SERVE_PID=$!
  # The child keeps this wrapper's process group from fork(2) until it is
  # scheduled and setsid/setpgrp runs in it, so an immediate ps can read the
  # old pgid. Poll until the pgid settles into a group of its own instead of
  # racing that window (observed on loaded CI runners, e.g. under xvfb-run).
  CONTROLLER_PGID="$(ps -o pgid= -p "$$" 2>/dev/null | tr -d ' ')"
  SERVER_PGID=""
  for _ in $(seq 1 50); do
    pgid="$(ps -o pgid= -p "$SERVE_PID" 2>/dev/null | tr -d ' ')"
    if [ -n "$pgid" ] && [ "$pgid" != "$CONTROLLER_PGID" ]; then
      SERVER_PGID="$pgid"
      break
    fi
    kill -0 "$SERVE_PID" 2>/dev/null || break
    sleep 0.1
  done
  if [ -z "$SERVER_PGID" ]; then
    # Never signal by group here: the group may still be this wrapper's.
    kill -TERM "$SERVE_PID" 2>/dev/null || true
    echo "--- last 40 lines of $SERVE_LOG ---" >&2
    tail -n 40 "$SERVE_LOG" >&2
    die "the app server did not move into its own process group (setsid/setpgrp failed)"
  fi

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

if [ "$CUSTOM_CMD" -eq 1 ]; then
  [ $# -gt 0 ] || die "-- given with no command to run"
  "$@"
else
  bash "$PKG_ROOT/scripts/run-all.sh" "$@"
fi
STATUS=$?

# stop_server runs here via the EXIT trap, on success and failure alike.
exit "$STATUS"
