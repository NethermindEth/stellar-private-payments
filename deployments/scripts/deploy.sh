#!/usr/bin/env bash
# Deploy all Stellar private transaction contracts and optionally run constructors.
# Usage: deploy.sh <network> [options]

set -euo pipefail

die() { echo "deploy.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
step() { echo "==> $*" >&2; }

usage() {
  cat >&2 <<'USAGE'
Usage: deploy.sh <network> [OPTIONS]

Deploys and runs constructors for the ASP membership, ASP non-membership,
Circom Groth16 verifier, and one or more Pool contracts.

Arguments:
  network               Network name from Stellar CLI config (e.g. testnet, futurenet)

Options:
  --deployer NAME       Stellar identity or secret key used to deploy (required)
  --admin ADDRESS       Admin address (G... or C...). Defaults to deployer address
  --token ADDRESS       Legacy single-pool token contract address (cannot be mixed with --pool)
  --pool SPEC           Pool spec (repeatable):
                        contract:<TOKEN_CONTRACT_ID>
                        native:<TOKEN_CONTRACT_ID>
                        classic:<CODE>:<ISSUER>:<TOKEN_CONTRACT_ID>
  --asp-levels N        Merkle tree levels for asp-membership (required)
  --pool-levels N       Merkle tree levels for pool (required)
  --max-deposit U256    Maximum deposit amount (required)
  --vk-json JSON        Verification key as a JSON string (snarkjs or repo format)
  --vk-file PATH        Path to a verification key JSON file
  --skip-init           Deploy only, do not call constructors
  --yes                 Skip confirmation for mainnet
  -h, --help            Show this help

Examples:
  deployments/scripts/deploy.sh futurenet \
    --deployer alice \
    --vk-file ceremony/verification_key.json \
    --pool native:CB... \
    --pool contract:CC... \
    --pool classic:USDC:G...:CD... \
    --asp-levels 8 \
    --pool-levels 8 \
    --max-deposit 1000000000

Notes:
  - Provide --vk-file or --vk-json to embed the verification key and build the
    verifier contract automatically. Omit both only if the verifier WASM was
    already built via scripts/build-verifier-with-vk.sh.
  - Deployment output is written to deployments/<network>/deployments.json.
  - If neither --token nor --pool is provided, one native XLM pool is deployed by default.
USAGE
  exit 2
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WASM_DIR="$ROOT_DIR/target/stellar"

NETWORK="${1:-}"
shift || true

DEPLOYER=""
ADMIN=""
TOKEN=""
POOL_SPECS=()
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
    --pool) POOL_SPECS+=("$2"); shift 2 ;;
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
[[ -n "$ASP_LEVELS" ]] || die "--asp-levels is required"
[[ -n "$POOL_LEVELS" ]] || die "--pool-levels is required"
[[ -n "$MAX_DEPOSIT" ]] || die "--max-deposit is required"

if [[ -n "$VK_JSON" && -n "$VK_FILE" ]]; then
  die "use only one of --vk-json or --vk-file"
fi

if [[ "$NETWORK" == "mainnet" && "$YES" != "true" ]]; then
  die "mainnet requires --yes"
fi

if [[ -n "$TOKEN" && ${#POOL_SPECS[@]} -gt 0 ]]; then
  die "cannot mix --token with --pool"
fi

if [[ -n "$TOKEN" ]]; then
  POOL_SPECS+=("native:$TOKEN")
fi
if [[ ${#POOL_SPECS[@]} -eq 0 ]]; then
  NATIVE_TOKEN_ID="$(stellar contract id asset --asset native --network "$NETWORK" 2>/dev/null || true)"
  [[ -n "$NATIVE_TOKEN_ID" ]] || die "failed to resolve native XLM token contract id for network '$NETWORK'"
  POOL_SPECS+=("native:$NATIVE_TOKEN_ID")
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

get_latest_ledger_seq() {
  local out seq
  out="$(stellar ledger latest --network "$NETWORK" 2>&1)" || {
    echo "$out" >&2
    die "failed to query latest ledger via 'stellar ledger latest' (is your Stellar CLI up to date?)"
  }
  seq="$(grep -Eo '^Sequence:[[:space:]]*[0-9]+' <<<"$out" | grep -Eo '[0-9]+' | head -1 || true)"
  [[ -n "$seq" ]] || { echo "$out" >&2; die "failed to parse ledger sequence from 'stellar ledger latest' output"; }
  echo "$seq"
}

step "build contracts"
mkdir -p "$WASM_DIR"
for pkg in asp-membership asp-non-membership public-key-registry pool; do
  stellar contract build --manifest-path "$ROOT_DIR/Cargo.toml" --out-dir "$WASM_DIR" --optimize \
    --package "$pkg" >/dev/null
done

if [[ -n "$VK_FILE" || -n "$VK_JSON" ]]; then
  if [[ -n "$VK_FILE" ]]; then
    [[ -f "$VK_FILE" ]] || die "vk file not found: $VK_FILE"
    "$SCRIPT_DIR/../../scripts/build-verifier-with-vk.sh" "$VK_FILE" --out-dir "$WASM_DIR"
  else
    TMP_VK="$(mktemp --suffix=.json)"
    printf '%s' "$VK_JSON" > "$TMP_VK"
    "$SCRIPT_DIR/../../scripts/build-verifier-with-vk.sh" "$TMP_VK" --out-dir "$WASM_DIR"
    rm -f "$TMP_VK"
  fi
fi

ASP_MEMBERSHIP_WASM="$WASM_DIR/asp_membership.wasm"
ASP_NON_MEMBERSHIP_WASM="$WASM_DIR/asp_non_membership.wasm"
VERIFIER_WASM="$WASM_DIR/circom_groth16_verifier.wasm"
PUBLIC_KEY_REGISTRY_WASM="$WASM_DIR/public_key_registry.wasm"
POOL_WASM="$WASM_DIR/pool.wasm"

[[ -f "$ASP_MEMBERSHIP_WASM" ]] || die "missing wasm: $ASP_MEMBERSHIP_WASM"
[[ -f "$ASP_NON_MEMBERSHIP_WASM" ]] || die "missing wasm: $ASP_NON_MEMBERSHIP_WASM"
[[ -f "$VERIFIER_WASM" ]] || die "missing wasm: $VERIFIER_WASM"
[[ -f "$PUBLIC_KEY_REGISTRY_WASM" ]] || die "missing wasm: $PUBLIC_KEY_REGISTRY_WASM"
[[ -f "$POOL_WASM" ]] || die "missing wasm: $POOL_WASM"

deploy_contract() {
  local name="$1"
  local wasm="$2"
  shift 2
  local output
  if [[ $# -gt 0 ]]; then
    output="$(stellar contract deploy --wasm "$wasm" --source-account "$DEPLOYER" --network "$NETWORK" -- "$@" 2>&1)"
  else
    output="$(stellar contract deploy --wasm "$wasm" --source-account "$DEPLOYER" --network "$NETWORK" 2>&1)"
  fi
  local id
  id="$(grep -Eo 'C[A-Z0-9]{55}' <<<"$output" | head -1 || true)"
  [[ -n "$id" ]] || { echo "$output" >&2; die "failed to parse contract id for $name"; }
  echo "$id"
}

parse_pool_spec() {
  local spec="$1"
  local kind token code issuer rest
  kind="${spec%%:*}"
  rest="${spec#*:}"

  case "$kind" in
    contract)
      token="$rest"
      [[ -n "$token" ]] || die "invalid pool spec '$spec': missing token contract id"
      printf '%s\n' "$token"
      printf '%s\n' "{\"kind\":\"contract\",\"contractId\":\"$token\"}"
      ;;
    native)
      token="$rest"
      [[ -n "$token" ]] || die "invalid pool spec '$spec': missing native token contract id"
      printf '%s\n' "$token"
      printf '%s\n' "{\"kind\":\"native\"}"
      ;;
    classic)
      code="${rest%%:*}"
      rest="${rest#*:}"
      issuer="${rest%%:*}"
      token="${rest#*:}"
      if [[ -z "$code" || -z "$issuer" || -z "$token" || "$token" == "$rest" ]]; then
        die "invalid pool spec '$spec': expected classic:<CODE>:<ISSUER>:<TOKEN_CONTRACT_ID>"
      fi
      printf '%s\n' "$token"
      printf '%s\n' "{\"kind\":\"classic\",\"code\":\"$code\",\"issuer\":\"$issuer\"}"
      ;;
    *)
      die "invalid pool spec '$spec': expected contract:<id> | native:<id> | classic:<code>:<issuer>:<id>"
      ;;
  esac
}

step "deploy asp-membership"
if [[ "$SKIP_INIT" != "true" ]]; then
  ASP_MEMBERSHIP_ID="$(deploy_contract asp-membership "$ASP_MEMBERSHIP_WASM" --admin "$ADMIN_ADDR" --levels "$ASP_LEVELS")"
else
  ASP_MEMBERSHIP_ID="$(deploy_contract asp-membership "$ASP_MEMBERSHIP_WASM")"
fi

step "deploy asp-non-membership"
if [[ "$SKIP_INIT" != "true" ]]; then
  ASP_NON_MEMBERSHIP_ID="$(deploy_contract asp-non-membership "$ASP_NON_MEMBERSHIP_WASM" --admin "$ADMIN_ADDR")"
else
  ASP_NON_MEMBERSHIP_ID="$(deploy_contract asp-non-membership "$ASP_NON_MEMBERSHIP_WASM")"
fi

step "deploy circom-groth16-verifier"
VERIFIER_ID="$(deploy_contract circom-groth16-verifier "$VERIFIER_WASM")"

step "deploy public-key-registry"
PUBLIC_KEY_REGISTRY_ID="$(deploy_contract public-key-registry "$PUBLIC_KEY_REGISTRY_WASM")"

POOL_IDS=()
POOL_TOKEN_IDS=()
POOL_ASSET_JSONS=()
POOL_DEPLOYMENT_LEDGERS=()

for spec in "${POOL_SPECS[@]}"; do
  mapfile -t parsed < <(parse_pool_spec "$spec")
  token_id="${parsed[0]}"
  asset_json="${parsed[1]}"

  pool_deployment_ledger="$(get_latest_ledger_seq)"
  step "deploy pool for spec '$spec'"
  if [[ "$SKIP_INIT" != "true" ]]; then
    pool_id="$(deploy_contract pool "$POOL_WASM" \
      --admin "$ADMIN_ADDR" --token "$token_id" --verifier "$VERIFIER_ID" \
      --asp-membership "$ASP_MEMBERSHIP_ID" --asp-non-membership "$ASP_NON_MEMBERSHIP_ID" \
      --maximum-deposit-amount "$MAX_DEPOSIT" --levels "$POOL_LEVELS")"
  else
    pool_id="$(deploy_contract pool "$POOL_WASM")"
  fi

  POOL_IDS+=("$pool_id")
  POOL_TOKEN_IDS+=("$token_id")
  POOL_ASSET_JSONS+=("$asset_json")
  POOL_DEPLOYMENT_LEDGERS+=("$pool_deployment_ledger")
done

{
  cat >&2 <<__DEPLOY_SUMMARY__

  ┌─────────────────────────────────────────────────────────────────┐
  │                    ✅ DEPLOYMENT SUCCESSFUL                      │
  └─────────────────────────────────────────────────────────────────┘

Deployment complete
  Network:             $NETWORK
  Deployer:            $DEPLOYER_ADDR
  Admin:               $ADMIN_ADDR
  ASP membership:      $ASP_MEMBERSHIP_ID
  ASP non-membership:  $ASP_NON_MEMBERSHIP_ID
  Verifier:            $VERIFIER_ID
  Public key registry: $PUBLIC_KEY_REGISTRY_ID
  Pools deployed:      ${#POOL_IDS[@]}
  Constructed:         $([[ "$SKIP_INIT" == "true" ]] && echo "no" || echo "yes")
__DEPLOY_SUMMARY__
  for i in "${!POOL_IDS[@]}"; do
    printf '  Pool[%s]:            %s\n' "$i" "${POOL_IDS[$i]}" >&2
  done
}

pools_json="["
for i in "${!POOL_IDS[@]}"; do
  entry="{\"poolContractId\":\"${POOL_IDS[$i]}\",\"tokenContractId\":\"${POOL_TOKEN_IDS[$i]}\",\"deploymentLedger\":${POOL_DEPLOYMENT_LEDGERS[$i]},\"enabled\":true,\"asset\":${POOL_ASSET_JSONS[$i]}}"
  if [[ "$i" -gt 0 ]]; then
    pools_json+=","
  fi
  pools_json+="$entry"
done
pools_json+="]"

DEPLOY_JSON="{\"network\":\"$NETWORK\",\"deployer\":\"$DEPLOYER_ADDR\",\"admin\":\"$ADMIN_ADDR\",\"asp_membership\":\"$ASP_MEMBERSHIP_ID\",\"asp_non_membership\":\"$ASP_NON_MEMBERSHIP_ID\",\"verifier\":\"$VERIFIER_ID\",\"public_key_registry\":\"$PUBLIC_KEY_REGISTRY_ID\",\"pools\":$pools_json}"

DEPLOYMENTS_DIR="$ROOT_DIR/deployments/$NETWORK"
mkdir -p "$DEPLOYMENTS_DIR"
printf '%s\n' "$DEPLOY_JSON" > "$DEPLOYMENTS_DIR/deployments.json"
printf '%s\n' "$DEPLOY_JSON"
