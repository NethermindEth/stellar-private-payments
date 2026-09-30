#!/usr/bin/env bash
# Run the integration-tests crate against a fresh `stellar/quickstart`
# container: start it, run the tests, then stop and remove it — on success,
# on failure, and on Ctrl-C.
#
# Usage: run.sh [test command...]   (default: cargo test --lib)
#   run.sh cargo test --lib -- --test-threads=1
#   run.sh cargo nextest run

set -uo pipefail

die() { echo "run.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

PKG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v docker >/dev/null 2>&1 || die "missing 'docker'"

CONTAINER_NAME="stellar-localnet"
PORT=8000
RPC_URL="http://localhost:$PORT/rpc"
READY_TIMEOUT="${SPP_NETWORK_TIMEOUT:-60}"

stop_container() {
  step "stopping $CONTAINER_NAME"
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

trap stop_container EXIT
trap 'stop_container; exit 130' INT
trap 'stop_container; exit 143' TERM

# In case a previous run was killed before its own trap could fire.
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

# Clear network.rs's cross-process deploy cache — stale on a fresh network.
rm -f "$PKG_ROOT"/../target/integration-tests-deploy-*.lock "$PKG_ROOT"/../target/integration-tests-deploy-*.json

step "starting $CONTAINER_NAME on port $PORT"
docker run -d --name "$CONTAINER_NAME" -p "$PORT:$PORT" \
  stellar/quickstart:testing \
  --local --enable rpc,horizon --limits unlimited >/dev/null \
  || die "failed to start stellar/quickstart"

# network.rs also waits for health, per test process; this just fails fast
# with the container logs if it never comes up at all.
step "waiting up to ${READY_TIMEOUT}s for $RPC_URL"
deadline=$(($(date +%s) + READY_TIMEOUT))
until curl -fsS -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' "$RPC_URL" 2>/dev/null \
  | grep -q '"status":"healthy"'; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "--- container logs ---" >&2
    docker logs "$CONTAINER_NAME" 2>&1 | tail -n 40 >&2
    die "stellar/quickstart did not become healthy within ${READY_TIMEOUT}s"
  fi
  sleep 1
done

# network.rs's deploy() reads verification keys from here.
LOCAL_VK_DIR="$PKG_ROOT/../deployments/local"
LOCAL_VK_LINK="$LOCAL_VK_DIR/circuit_keys"
if [ ! -L "$LOCAL_VK_LINK" ]; then
  step "linking $LOCAL_VK_LINK -> deployments/testnet/circuit_keys"
  mkdir -p "$LOCAL_VK_DIR"
  rm -rf "$LOCAL_VK_LINK"
  ln -s ../testnet/circuit_keys "$LOCAL_VK_LINK"
fi

TEST_CMD=("$@")
[ ${#TEST_CMD[@]} -gt 0 ] || TEST_CMD=(cargo test --lib)

step "running: ${TEST_CMD[*]}"
(cd "$PKG_ROOT" && "${TEST_CMD[@]}")
STATUS=$?

# stop_container runs here via the EXIT trap, on success and failure alike.
exit "$STATUS"
