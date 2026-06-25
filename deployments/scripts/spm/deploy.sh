#!/bin/bash
# Social Prediction Market Deployment Script
# Deploys the SPM contract to Soroban testnet

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     Social Prediction Market - Deployment Script              ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
CONTRACT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACT_WASM="$CONTRACT_DIR/contracts/spm/target/wasm32v1-none/release/social_prediction_market.wasm"
NETWORK=${NETWORK:-testnet}
IDENTITY=${IDENTITY:-default}

# Check if contract is built
if [ ! -f "$CONTRACT_WASM" ]; then
    echo "⚠️  Contract not built. Building now..."
    cd "$CONTRACT_DIR/contracts/spm"
    stellar contract build
fi

echo "📦 Contract: $CONTRACT_WASM"
echo "🌐 Network: $NETWORK"
echo "🔑 Identity: $IDENTITY"
echo ""

# Step 1: Build contract (if needed)
echo "Step 1: Building contract..."
cd "$CONTRACT_DIR/contracts/spm"
stellar contract build
echo "✅ Contract built"
echo ""

# Step 2: Deploy contract
echo "Step 2: Deploying contract..."
DEPLOY_OUTPUT=$(stellar contract deploy \
    --wasm "$CONTRACT_WASM" \
    --network "$NETWORK" \
    --identity "$IDENTITY" \
    --source-account "$IDENTITY" \
    2>&1)

CONTRACT_ID=$(echo "$DEPLOY_OUTPUT" | grep -oP '(?:0x)?[a-fA-F0-9]{56}' | head -1)
echo "✅ Contract deployed: $CONTRACT_ID"
echo ""

# Step 3: Initialize contract
echo "Step 3: Initializing contract..."
echo ""

# Generate random values for initialization
VK_HASH="0000000000000000000000000000000000000000000000000000000000000000"
NULLIFIER_ROOT="0000000000000000000000000000000000000000000000000000000000000001"

echo "   VK Hash: $VK_HASH"
echo "   Nullifier Root: $NULLIFIER_ROOT"

stellar contract invoke \
    --network "$NETWORK" \
    --identity "$IDENTITY" \
    --source-account "$IDENTITY" \
    --id "$CONTRACT_ID" \
    -- \
    initialize \
    --vk "$VK_HASH" \
    --nullifier-root "$NULLIFIER_ROOT"

echo "✅ Contract initialized"
echo ""

# Step 4: Save deployment info
DEPLOYMENT_DIR="$CONTRACT_DIR/deployments/testnet/spm"
mkdir -p "$DEPLOYMENT_DIR"

cat > "$DEPLOYMENT_DIR/deployment.json" << EOF
{
    "contract_id": "$CONTRACT_ID",
    "network": "$NETWORK",
    "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "vk_hash": "$VK_HASH",
    "nullifier_root": "$NULLIFIER_ROOT",
    "version": "0.1.0"
}
EOF

echo "📄 Deployment info saved to: $DEPLOYMENT_DIR/deployment.json"
echo ""

# Summary
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    Deployment Complete!                      ║"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║  Contract ID: $CONTRACT_ID"
echo "║  Network: $NETWORK"
echo "║  Run 'stellar contract invoke' with --id $CONTRACT_ID to interact"
echo "╚════════════════════════════════════════════════════════════════╝"
