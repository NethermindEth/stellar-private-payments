#!/usr/bin/env bash
# Deploy fresh contracts to an already-running local `stellar/quickstart`
# network (see localnet.sh).

set -euo pipefail

die() { echo "deploy-local.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PORT=8000

# deployments/local/ is git-ignored, so circuit_keys must be linked in.
mkdir -p "$REPO_ROOT/deployments/local"
if [ -L "$REPO_ROOT/deployments/local/circuit_keys" ] && [ ! -e "$REPO_ROOT/deployments/local/circuit_keys" ]; then
  rm -f "$REPO_ROOT/deployments/local/circuit_keys"
fi
if [ ! -e "$REPO_ROOT/deployments/local/circuit_keys" ]; then
  ln -s "$REPO_ROOT/deployments/testnet/circuit_keys" "$REPO_ROOT/deployments/local/circuit_keys"
fi

step "deploying to localnet"
deployer_alias="spp-e2e-local-deployer"
stellar keys generate "$deployer_alias" --network local --overwrite
deployer_address="$(stellar keys address "$deployer_alias")"
for _ in 1 2 3 4 5; do
  curl -fsS "http://localhost:$PORT/friendbot?addr=$deployer_address" >/dev/null 2>&1 && break
  sleep 2
done

stellar contract asset deploy --asset native --source-account "$deployer_alias" --network local >/dev/null 2>&1 || true

bash "$REPO_ROOT/deployments/scripts/deploy.sh" local \
  --deployer "$deployer_alias" \
  --policy-flags blocklist \
  --asp-levels 10 \
  --pool-levels 20 \
  --max-deposit 1000000000
