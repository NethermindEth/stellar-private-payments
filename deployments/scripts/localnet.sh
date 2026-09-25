#!/usr/bin/env bash
# Start/stop a local `stellar/quickstart` container. See deploy-local.sh to
# deploy contracts to it.
#
# Usage: localnet.sh start|stop

set -uo pipefail

die() { echo "localnet.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

CONTAINER_NAME="stellar-localnet"
PORT=8000
RPC_URL="http://localhost:$PORT/rpc"
READY_TIMEOUT="${SPP_NETWORK_TIMEOUT:-60}"

is_healthy() {
  curl -fsS -X POST -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' "$RPC_URL" 2>/dev/null \
    | grep -q '"status":"healthy"'
}

# RPC's own health check says nothing about Horizon, which ingests ledgers on
# its own separate pipeline and can still be mid-catch-up for a while after
# RPC reports healthy -- long enough that an account funded right after start
# can 404 on Horizon's /accounts lookup. quickstart's own supervisor prints
# this exact line once Horizon's ingestion is caught up, so key off that
# rather than guessing at an undocumented HTTP endpoint/response shape.
is_horizon_ready() {
  docker logs "$CONTAINER_NAME" 2>&1 | grep -q "horizon: ingestion caught up"
}

cmd_start() {
  command -v docker >/dev/null 2>&1 || die "missing 'docker'"

  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  step "starting $CONTAINER_NAME on port $PORT"
  docker run -d --name "$CONTAINER_NAME" -p "$PORT:$PORT" \
    stellar/quickstart:testing \
    --local --enable rpc,horizon --limits unlimited >/dev/null \
    || die "failed to start stellar/quickstart"

  step "waiting up to ${READY_TIMEOUT}s for $RPC_URL"
  deadline=$(($(date +%s) + READY_TIMEOUT))
  until is_healthy; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "--- container logs ---" >&2
      docker logs "$CONTAINER_NAME" 2>&1 | tail -n 40 >&2
      die "stellar/quickstart did not become healthy within ${READY_TIMEOUT}s"
    fi
    sleep 1
  done

  step "waiting up to ${READY_TIMEOUT}s for Horizon to catch up"
  deadline=$(($(date +%s) + READY_TIMEOUT))
  until is_horizon_ready; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "--- container logs ---" >&2
      docker logs "$CONTAINER_NAME" 2>&1 | tail -n 40 >&2
      die "Horizon did not catch up within ${READY_TIMEOUT}s"
    fi
    sleep 1
  done
}

cmd_stop() {
  step "stopping $CONTAINER_NAME"
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

case "${1:-}" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  *) die "usage: $(basename "$0") start|stop" ;;
esac
