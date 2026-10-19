#!/bin/sh
# Shared by Trunk and the alternate-network CI smoke check. Run from repo root.
set -eu
: "${TRUNK_STAGING_DIR:?set TRUNK_STAGING_DIR}"
network="${SPP_NETWORK:-testnet}"
case "$network" in ''|*[!a-zA-Z0-9_-]*) echo "invalid SPP_NETWORK" >&2; exit 1 ;; esac
mkdir -p "$TRUNK_STAGING_DIR/js"
cp "deployments/$network/deployments.json" "$TRUNK_STAGING_DIR/deployments.json"
for entry in ui admin disclosure; do
    ./app/node_modules/.bin/esbuild "app/js/$entry.js" --bundle --minify \
        --alias:app-circuit-lock="./deployments/$network/circuits.json" \
        --external:stellar-private-payments --external:stellar-private-payments/freighter \
        --outfile="$TRUNK_STAGING_DIR/js/$entry.js" --format=esm
done
# The service worker must be served from the root for full-page scope.
cp app/js/sw.js "$TRUNK_STAGING_DIR/sw.js"
