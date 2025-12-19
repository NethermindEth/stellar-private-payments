#!/usr/bin/env bash
# Deploy all Stellar private transaction contracts and optionally initialize them.
# Usage: deploy.sh <network> [options]

set -euo pipefail

# Helpers

die() { echo "deploy.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
step() { echo "==> $*" >&2; }

usage() {
  cat >&2 <<'USAGE'
Usage: deploy.sh <network> [OPTIONS]

Deploys and initializes the ASP membership, ASP non-membership,
Circom Groth16 verifier, and Pool contracts.

Arguments:
  network               Network name from Stellar CLI config (e.g. testnet, futurenet)

Options:
  --deployer NAME       Stellar identity or secret key used to deploy (required)
  --admin ADDRESS       Admin address (G... or C...). Defaults to deployer address
  --token ADDRESS       Token contract address for the pool (defaults to native XLM)
  --asp-levels N        Merkle tree levels for asp-membership (required)
  --pool-levels N       Merkle tree levels for pool (required)
  --max-deposit U256    Maximum deposit amount (required)
  --vk-json JSON        VerificationKeyBytes JSON for circom verifier init
  --vk-file PATH        JSON file containing VerificationKeyBytes
  --skip-init           Deploy only, do not call init
  --yes                 Skip confirmation for mainnet
  -h, --help            Show this help

Examples:
  scripts/deploy.sh futurenet \
    --deployer alice \
    --token CB... \
    --asp-levels 8 \
    --pool-levels 8 \
    --max-deposit 1000000000 \
    --vk-file ./vk.json

Notes:
  - VerificationKeyBytes must match the contract type:
    {"alpha":"...","beta":"...","gamma":"...","delta":"...","ic":["..."]}
  - Use --vk-json to pass the JSON inline or --vk-file to read it from disk.
  - snarkjs-style vk.json files are converted automatically.
  - If --token is omitted, defaults to the Soroban native XLM contract for the selected network.
  - Deployment output is written to scripts/deployments.json.
USAGE
  exit 2
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WASM_DIR="$ROOT_DIR/target/stellar"

NETWORK="${1:-}"
shift || true

DEPLOYER=""
ADMIN=""
TOKEN=""
ASP_LEVELS=""
POOL_LEVELS=""
MAX_DEPOSIT=""
VK_JSON=""
VK_FILE=""
SKIP_INIT=false
YES=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deployer) DEPLOYER="$2"; shift 2 ;;
    --admin) ADMIN="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --asp-levels) ASP_LEVELS="$2"; shift 2 ;;
    --pool-levels) POOL_LEVELS="$2"; shift 2 ;;
    --max-deposit) MAX_DEPOSIT="$2"; shift 2 ;;
    --vk-json) VK_JSON="$2"; shift 2 ;;
    --vk-file) VK_FILE="$2"; shift 2 ;;
    --skip-init) SKIP_INIT=true; shift ;;
    --yes) YES=true; shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$NETWORK" ]] || usage
need stellar

[[ -n "$DEPLOYER" ]] || die "--deployer is required"
# If no token is provided, default to the Soroban native asset contract for XLM on this network.
if [[ -z "$TOKEN" ]]; then
  TOKEN="$(stellar contract id asset --asset native --network "$NETWORK")"
fi
[[ -n "$ASP_LEVELS" ]] || die "--asp-levels is required"
[[ -n "$POOL_LEVELS" ]] || die "--pool-levels is required"
[[ -n "$MAX_DEPOSIT" ]] || die "--max-deposit is required"

if [[ -n "$VK_JSON" && -n "$VK_FILE" ]]; then
  die "use only one of --vk-json or --vk-file"
fi

if [[ "$SKIP_INIT" != "true" ]]; then
  if [[ -n "$VK_FILE" ]]; then
    [[ -f "$VK_FILE" ]] || die "vk file not found: $VK_FILE"
    VK_JSON="$(tr -d '\n' < "$VK_FILE")"
  fi
  [[ -n "$VK_JSON" ]] || die "verification key required (use --vk-json or --vk-file)"
  if [[ "$VK_JSON" == *"vk_alpha_1"* ]]; then
    need python3
    VK_JSON="$(python3 -c 'import json,sys
data = json.load(sys.stdin)
def to_hex32(v):
    n = int(v)
    return n.to_bytes(32, "big").hex()
def g1_bytes(pt):
    return to_hex32(pt[0]) + to_hex32(pt[1])
def g2_bytes(pt):
    # snarkjs format uses [imag, real] for Fq2 components.
    x_im, x_re = pt[0]
    y_im, y_re = pt[1]
    return to_hex32(x_im) + to_hex32(x_re) + to_hex32(y_im) + to_hex32(y_re)
out = {
    "alpha": g1_bytes(data["vk_alpha_1"]),
    "beta": g2_bytes(data["vk_beta_2"]),
    "gamma": g2_bytes(data["vk_gamma_2"]),
    "delta": g2_bytes(data["vk_delta_2"]),
    "ic": [g1_bytes(p) for p in data["IC"]],
}
print(json.dumps(out, separators=(",", ":")))' <<<"$VK_JSON")"
  fi
fi

if [[ "$NETWORK" == "mainnet" && "$YES" != "true" ]]; then
  die "mainnet requires --yes"
fi

resolve_address() {
  local input="$1"
  if [[ "$input" =~ ^[GC][A-Z0-9]{55}$ ]]; then
    echo "$input"
    return
  fi
  if addr="$(stellar keys address "$input" 2>/dev/null)"; then
    echo "$addr"
    return
  fi
  echo "$input"
}

DEPLOYER_ADDR="$(resolve_address "$DEPLOYER")"
if [[ -z "$ADMIN" ]]; then
  ADMIN_ADDR="$DEPLOYER_ADDR"
else
  ADMIN_ADDR="$(resolve_address "$ADMIN")"
fi

step "build contracts"
mkdir -p "$WASM_DIR"
for pkg in asp-membership asp-non-membership circom-groth16-verifier pool; do
  stellar contract build --manifest-path "$ROOT_DIR/Cargo.toml" --out-dir "$WASM_DIR" --optimize \
    --package "$pkg" >/dev/null
done

ASP_MEMBERSHIP_WASM="$WASM_DIR/asp_membership.wasm"
ASP_NON_MEMBERSHIP_WASM="$WASM_DIR/asp_non_membership.wasm"
VERIFIER_WASM="$WASM_DIR/circom_groth16_verifier.wasm"
POOL_WASM="$WASM_DIR/pool.wasm"

[[ -f "$ASP_MEMBERSHIP_WASM" ]] || die "missing wasm: $ASP_MEMBERSHIP_WASM"
[[ -f "$ASP_NON_MEMBERSHIP_WASM" ]] || die "missing wasm: $ASP_NON_MEMBERSHIP_WASM"
[[ -f "$VERIFIER_WASM" ]] || die "missing wasm: $VERIFIER_WASM"
[[ -f "$POOL_WASM" ]] || die "missing wasm: $POOL_WASM"

deploy_contract() {
  local name="$1"
  local wasm="$2"
  local output
  output="$(stellar contract deploy --wasm "$wasm" --source-account "$DEPLOYER" --network "$NETWORK" 2>&1)"
  local id
  id="$(grep -Eo 'C[A-Z0-9]{55}' <<<"$output" | head -1 || true)"
  [[ -n "$id" ]] || { echo "$output" >&2; die "failed to parse contract id for $name"; }
  echo "$id"
}

step "deploy asp-membership"
ASP_MEMBERSHIP_ID="$(deploy_contract asp-membership "$ASP_MEMBERSHIP_WASM")"

step "deploy asp-non-membership"
ASP_NON_MEMBERSHIP_ID="$(deploy_contract asp-non-membership "$ASP_NON_MEMBERSHIP_WASM")"

step "deploy circom-groth16-verifier"
VERIFIER_ID="$(deploy_contract circom-groth16-verifier "$VERIFIER_WASM")"

step "deploy pool"
POOL_ID="$(deploy_contract pool "$POOL_WASM")"

if [[ "$SKIP_INIT" != "true" ]]; then
  step "init asp-membership"
  stellar contract invoke --id "$ASP_MEMBERSHIP_ID" --source-account "$DEPLOYER" --network "$NETWORK" -- \
    init --admin "$ADMIN_ADDR" --levels "$ASP_LEVELS" >/dev/null

  step "init asp-non-membership"
  stellar contract invoke --id "$ASP_NON_MEMBERSHIP_ID" --source-account "$DEPLOYER" --network "$NETWORK" -- \
    init --admin "$ADMIN_ADDR" >/dev/null

  step "init circom-groth16-verifier"
  stellar contract invoke --id "$VERIFIER_ID" --source-account "$DEPLOYER" --network "$NETWORK" -- \
    init --vk "$VK_JSON" >/dev/null

  step "init pool"
  stellar contract invoke --id "$POOL_ID" --source-account "$DEPLOYER" --network "$NETWORK" -- \
    init --admin "$ADMIN_ADDR" --token "$TOKEN" --verifier "$VERIFIER_ID" \
    --asp-membership "$ASP_MEMBERSHIP_ID" --asp-non-membership "$ASP_NON_MEMBERSHIP_ID" \
    --maximum-deposit-amount "$MAX_DEPOSIT" --levels "$POOL_LEVELS" >/dev/null
fi

cat >&2 <<EOF

  ┌─────────────────────────────────────────────────────────────────┐
  │                    ✅ DEPLOYMENT SUCCESSFUL                     │
  └─────────────────────────────────────────────────────────────────┘

Deployment complete
  Network:             $NETWORK
  Deployer:            $DEPLOYER_ADDR
  Admin:               $ADMIN_ADDR
  ASP membership:      $ASP_MEMBERSHIP_ID
  ASP non-membership:  $ASP_NON_MEMBERSHIP_ID
  Verifier:            $VERIFIER_ID
  Pool:                $POOL_ID
  Initialized:         $([[ "$SKIP_INIT" == "true" ]] && echo "no" || echo "yes")
EOF

DEPLOY_JSON="$(printf '{"network":"%s","deployer":"%s","admin":"%s","asp_membership":"%s","asp_non_membership":"%s","verifier":"%s","pool":"%s","initialized":%s}\n' \
  "$NETWORK" "$DEPLOYER_ADDR" "$ADMIN_ADDR" "$ASP_MEMBERSHIP_ID" "$ASP_NON_MEMBERSHIP_ID" "$VERIFIER_ID" "$POOL_ID" \
  "$([[ "$SKIP_INIT" == "true" ]] && echo false || echo true)")"

# Write deployment summary to a file for easy reuse.
printf '%s' "$DEPLOY_JSON" > "$SCRIPT_DIR/deployments.json"
printf '%s' "$DEPLOY_JSON"
