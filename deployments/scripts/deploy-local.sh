#!/usr/bin/env bash
# Deploy fresh contracts to an already-running local `stellar/quickstart`
# network (see localnet.sh).

set -euo pipefail

die() { echo "deploy-local.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOCAL_DIR="$REPO_ROOT/deployments/local"

# Isolate the deployer's keys from the developer's real Stellar CLI keystore.
export XDG_CONFIG_HOME="$LOCAL_DIR/.config"
mkdir -p "$XDG_CONFIG_HOME"

# deployments/local/ is git-ignored, so circuit_keys must be linked in.
mkdir -p "$LOCAL_DIR"
if [ -L "$LOCAL_DIR/circuit_keys" ] && [ ! -e "$LOCAL_DIR/circuit_keys" ]; then
  rm -f "$LOCAL_DIR/circuit_keys"
fi
if [ ! -e "$LOCAL_DIR/circuit_keys" ]; then
  ln -s "$REPO_ROOT/deployments/testnet/circuit_keys" "$LOCAL_DIR/circuit_keys"
fi

step "deploying to localnet"
deployer_alias="spp-e2e-local-deployer"
stellar keys generate "$deployer_alias" --network local --overwrite
stellar keys fund "$deployer_alias" --network local \
  || die "funding failed for deployer $deployer_alias"

stellar contract asset deploy --asset native --source-account "$deployer_alias" --network local >/dev/null 2>&1 || true

bash "$REPO_ROOT/deployments/scripts/deploy.sh" local \
  --deployer "$deployer_alias" \
  --policy-flags blocklist \
  --asp-levels 10 \
  --pool-levels 20 \
  --max-deposit 1000000000 \
  --kdf-domain tests
