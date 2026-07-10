#!/usr/bin/env bash
# Deploy all Stellar private transaction contracts and optionally run constructors.
# Usage: deploy.sh <network> [options]

set -euo pipefail

die() { echo "deploy.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
step() { echo "==> $*" >&2; }

# bash 3.2 + `set -u` errors on "${arr[@]}" when arr is empty; this form is safe.
array_values() {
  eval "echo \"\${$1[@]+\"\${$1[@]}\"}\""
}

array_len() {
  eval "echo \${#${1}[@]}"
}

usage() {
  cat >&2 <<'USAGE'
Usage: deploy.sh <network> [OPTIONS]

Deploys and runs constructors for the ASP membership, ASP non-membership,
one Circom Groth16 verifier per policy mode used, and one or more Pool contracts.

Arguments:
  network               Network name from Stellar CLI config (e.g. testnet, futurenet)

Options:
  --deployer NAME       Stellar identity or secret key used to deploy (required)
  --admin ADDRESS       Admin address (G... or C...). Defaults to deployer address
  --token ADDRESS       Legacy single-pool token contract address (cannot be mixed with --pool)
  --pool SPEC           Pool spec (repeatable). Optional policy prefix per pool:
                        open:<SPEC> | allowlist:<SPEC> | blocklist:<SPEC> | both:<SPEC>
                        where <SPEC> is one of:
                        contract:<TOKEN_CONTRACT_ID>
                        native:<TOKEN_CONTRACT_ID>
                        classic:<CODE>:<ISSUER>:<TOKEN_CONTRACT_ID>
  --asp-levels N        Merkle tree levels for asp-membership (required)
  --pool-levels N       Merkle tree levels for pool (required)
  --max-deposit U256    Maximum deposit amount (required)
  --policy-mode MODE    Default pool ASP policy when a --pool spec omits the prefix:
                        open, allowlist, blocklist, or both (required when running constructors
                        unless every --pool spec includes a policy prefix)
  --vk-json JSON        Verification key as a JSON string (snarkjs or repo format).
                        Applies to both-policy verifier builds only.
  --vk-file PATH        Path to a verification key JSON file (both policy only)
  --skip-init           Deploy WASM only (no constructors). Writes verifiers under the
                        policy mode key (open/allowlist/blocklist/both); use --policy-mode
                        or a per-pool prefix when the mode is not otherwise known.
  --yes                 Skip confirmation for mainnet
  -h, --help            Show this help

Examples:
  # Mixed policies in one deployment (two verifiers, shared ASP contracts)
  deployments/scripts/deploy.sh futurenet \
    --deployer alice \
    --pool blocklist:native:CB... \
    --pool both:contract:CC... \
    --asp-levels 8 \
    --pool-levels 8 \
    --max-deposit 1000000000

  # Same policy on every pool via --policy-mode
  deployments/scripts/deploy.sh futurenet \
    --deployer alice \
    --policy-mode blocklist \
    --pool native:CB... \
    --pool classic:USDC:G...:CD... \
    --asp-levels 8 \
    --pool-levels 8 \
    --max-deposit 1000000000

Notes:
  - Each policy mode needs its own verifier contract (VK is baked into the WASM).
  - Per-pool policyMode is written to deployments/<network>/deployments.json.
  - Provide --vk-file/--vk-json only for ceremony both-policy keys; blocklist VK
    is taken from deployments/<network>/circuit_keys/ automatically.
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
POLICY_MODE=""
SKIP_INIT=false
YES=false

normalize_policy_mode() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    open) printf '%s' "open" ;;
    allowlist) printf '%s' "allowlist" ;;
    blocklist) printf '%s' "blocklist" ;;
    both) printf '%s' "both" ;;
    *) die "invalid policy mode '$1' (expected open, allowlist, blocklist, or both)" ;;
  esac
}

policy_mode_constructor_arg() {
  case "$1" in
    open) printf '%s' "Open" ;;
    allowlist) printf '%s' "Allowlist" ;;
    blocklist) printf '%s' "Blocklist" ;;
    both) printf '%s' "Both" ;;
    *) die "internal error: unknown policy mode '$1'" ;;
  esac
}

default_vk_file() {
  local network="$1" mode="$2"
  printf '%s/deployments/%s/circuit_keys/policy_tx_2_2_%s_vk.json' "$ROOT_DIR" "$network" "$mode"
}

verifier_wasm_name_for_mode() {
  printf 'circom_groth16_verifier_%s.wasm' "$1"
}

# Stellar CLI sometimes prints contract ids wrapped in one or more layers of quotes.
strip_surrounding_quotes() {
  local s="$1"
  while [[ "$s" == \"*\" && "$s" == *\" ]]; do
    s="${s#\"}"
    s="${s%\"}"
  done
  printf '%s' "$s"
}

# Sets POOL_SPEC_MODE and POOL_SPEC_BODY for a --pool spec.
resolve_pool_spec_policy() {
  local spec="$1"
  local first="${spec%%:*}"
  POOL_SPEC_MODE=""
  POOL_SPEC_BODY=""
  case "$first" in
    open|allowlist|blocklist|both)
      POOL_SPEC_MODE="$(normalize_policy_mode "$first")"
      POOL_SPEC_BODY="${spec#*:}"
      ;;
    *)
      POOL_SPEC_BODY="$spec"
      ;;
  esac
}

VERIFIER_MODE_LIST=()
VERIFIER_ID_LIST=()

set_verifier_id() {
  local mode="$1" id="$2" i len
  len="$(array_len VERIFIER_MODE_LIST)"
  i=0
  while [[ "$i" -lt "$len" ]]; do
    if [[ "${VERIFIER_MODE_LIST[$i]}" == "$mode" ]]; then
      VERIFIER_ID_LIST[$i]="$id"
      return
    fi
    i=$((i + 1))
  done
  VERIFIER_MODE_LIST+=("$mode")
  VERIFIER_ID_LIST+=("$id")
}

get_verifier_id() {
  local mode="$1" i len
  len="$(array_len VERIFIER_MODE_LIST)"
  i=0
  while [[ "$i" -lt "$len" ]]; do
    if [[ "${VERIFIER_MODE_LIST[$i]}" == "$mode" ]]; then
      printf '%s' "${VERIFIER_ID_LIST[$i]}"
      return
    fi
    i=$((i + 1))
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deployer) DEPLOYER="$2"; shift 2 ;;
    --admin) ADMIN="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --pool) POOL_SPECS+=("$(strip_surrounding_quotes "$2")"); shift 2 ;;
    --asp-levels) ASP_LEVELS="$2"; shift 2 ;;
    --pool-levels) POOL_LEVELS="$2"; shift 2 ;;
    --max-deposit) MAX_DEPOSIT="$2"; shift 2 ;;
    --policy-mode) POLICY_MODE="$(normalize_policy_mode "$2")"; shift 2 ;;
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
need jq

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
  NATIVE_TOKEN_ID="$(strip_surrounding_quotes "$NATIVE_TOKEN_ID")"
  [[ -n "$NATIVE_TOKEN_ID" ]] || die "failed to resolve native XLM token contract id for network '$NETWORK'"
  POOL_SPECS+=("native:$NATIVE_TOKEN_ID")
fi

POOL_BODY_SPECS=()
POOL_POLICY_MODES=()

_ps_i=0
_ps_len="$(array_len POOL_SPECS)"
while [[ "$_ps_i" -lt "$_ps_len" ]]; do
  spec="$(strip_surrounding_quotes "${POOL_SPECS[$_ps_i]}")"
  resolve_pool_spec_policy "$spec"
  mode="$POOL_SPEC_MODE"
  body="$(strip_surrounding_quotes "$POOL_SPEC_BODY")"
  if [[ -z "$mode" ]]; then
    mode="$POLICY_MODE"
  fi
  if [[ "$SKIP_INIT" != "true" && -z "$mode" ]]; then
    die "pool spec '$spec' has no policy mode; prefix with open:, allowlist:, blocklist:, or both:, or pass --policy-mode"
  fi
  POOL_BODY_SPECS+=("$body")
  POOL_POLICY_MODES+=("$mode")
  _ps_i=$((_ps_i + 1))
done

UNIQUE_POLICY_MODES=()
for mode in $(array_values POOL_POLICY_MODES); do
  [[ -n "$mode" ]] || continue
  found=false
  for existing in $(array_values UNIQUE_POLICY_MODES); do
    if [[ "$existing" == "$mode" ]]; then
      found=true
      break
    fi
  done
  if [[ "$found" == "false" ]]; then
    UNIQUE_POLICY_MODES+=("$mode")
  fi
done

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

build_verifier_wasm_for_mode() {
  local mode="$1"
  local wasm_name vk_path tmp_vk=""
  wasm_name="$(verifier_wasm_name_for_mode "$mode")"

  if [[ "$mode" == "both" && -n "$VK_FILE" ]]; then
    [[ -f "$VK_FILE" ]] || die "vk file not found: $VK_FILE"
    vk_path="$VK_FILE"
  elif [[ "$mode" == "both" && -n "$VK_JSON" ]]; then
    tmp_vk="$(mktemp "${TMPDIR:-/tmp}/deploy-vk.XXXXXX.json")"
    printf '%s' "$VK_JSON" > "$tmp_vk"
    vk_path="$tmp_vk"
  else
    vk_path="$(default_vk_file "$NETWORK" "$mode")"
    [[ -f "$vk_path" ]] || die "VK not found for policy mode $mode: $vk_path (pass --vk-file for both)"
  fi

  step "building verifier WASM for $mode from $vk_path"
  "$SCRIPT_DIR/../../scripts/build-verifier-with-vk.sh" \
    "$vk_path" --out-dir "$WASM_DIR" --wasm-name "$wasm_name"
  [[ -z "$tmp_vk" ]] || rm -f "$tmp_vk"
}

step "build contracts"
mkdir -p "$WASM_DIR"
for pkg in asp-membership asp-non-membership public-key-registry pool; do
  stellar contract build --manifest-path "$ROOT_DIR/Cargo.toml" --out-dir "$WASM_DIR" --optimize \
    --package "$pkg" >/dev/null
done

if [[ "$SKIP_INIT" != "true" ]]; then
  for mode in $(array_values UNIQUE_POLICY_MODES); do
    build_verifier_wasm_for_mode "$mode"
  done
fi

ASP_MEMBERSHIP_WASM="$WASM_DIR/asp_membership.wasm"
ASP_NON_MEMBERSHIP_WASM="$WASM_DIR/asp_non_membership.wasm"
PUBLIC_KEY_REGISTRY_WASM="$WASM_DIR/public_key_registry.wasm"
POOL_WASM="$WASM_DIR/pool.wasm"

[[ -f "$ASP_MEMBERSHIP_WASM" ]] || die "missing wasm: $ASP_MEMBERSHIP_WASM"
[[ -f "$ASP_NON_MEMBERSHIP_WASM" ]] || die "missing wasm: $ASP_NON_MEMBERSHIP_WASM"
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

# Read the SEP-41 token symbol() from a Soroban token contract (read-only simulate).
# Returns the bare ticker (quotes/whitespace stripped), empty on failure.
fetch_token_symbol() {
  local id="$1" out
  out="$(stellar contract invoke --id "$id" --source-account "$DEPLOYER" --network "$NETWORK" -- symbol 2>/dev/null || true)"
  out="${out//\"/}"
  printf '%s' "$out" | tr -d '[:space:]'
}

parse_pool_spec() {
  local spec="$1"
  local kind token code issuer rest symbol
  kind="${spec%%:*}"
  rest="${spec#*:}"

  case "$kind" in
    contract)
      token="$(strip_surrounding_quotes "$rest")"
      [[ -n "$token" ]] || die "invalid pool spec '$spec': missing token contract id"
      symbol="$(fetch_token_symbol "$token")"
      [[ -n "$symbol" ]] || die "invalid pool spec '$spec': could not read symbol() from token contract $token"
      printf '%s\n' "$token"
      printf '%s\n' "{\"kind\":\"contract\",\"contractId\":\"$token\",\"symbol\":\"$symbol\"}"
      ;;
    native)
      token="$(strip_surrounding_quotes "$rest")"
      [[ -n "$token" ]] || die "invalid pool spec '$spec': missing native token contract id"
      printf '%s\n' "$token"
      printf '%s\n' "{\"kind\":\"native\"}"
      ;;
    classic)
      code="${rest%%:*}"
      rest="${rest#*:}"
      issuer="${rest%%:*}"
      token="${rest#*:}"
      token="$(strip_surrounding_quotes "$token")"
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

if [[ "$SKIP_INIT" == "true" ]]; then
  if [[ ${#UNIQUE_POLICY_MODES[@]} -gt 1 ]]; then
    die "--skip-init supports at most one policy mode; deploy without --skip-init for mixed policies"
  fi

  skip_init_verifier_mode=""
  if [[ ${#UNIQUE_POLICY_MODES[@]} -eq 1 ]]; then
    skip_init_verifier_mode="${UNIQUE_POLICY_MODES[0]}"
  elif [[ -n "$POLICY_MODE" ]]; then
    skip_init_verifier_mode="$POLICY_MODE"
  fi
  [[ -n "$skip_init_verifier_mode" ]] \
    || die "--skip-init requires a policy mode (--policy-mode or pool prefix open:|allowlist:|blocklist:|both:)"

  if [[ -f "$WASM_DIR/circom_groth16_verifier.wasm" ]]; then
    verifier_wasm="$WASM_DIR/circom_groth16_verifier.wasm"
  else
    verifier_wasm="$WASM_DIR/$(verifier_wasm_name_for_mode "$skip_init_verifier_mode")"
    [[ -f "$verifier_wasm" ]] \
      || die "missing verifier wasm for $skip_init_verifier_mode (run build-verifier-with-vk.sh or deploy without --skip-init)"
  fi
  step "deploy circom-groth16-verifier ($skip_init_verifier_mode)"
  set_verifier_id "$skip_init_verifier_mode" "$(deploy_contract circom-groth16-verifier "$verifier_wasm")"
else
  for mode in $(array_values UNIQUE_POLICY_MODES); do
    verifier_wasm="$WASM_DIR/$(verifier_wasm_name_for_mode "$mode")"
    [[ -f "$verifier_wasm" ]] || die "missing wasm: $verifier_wasm"
    step "deploy circom-groth16-verifier ($mode)"
    set_verifier_id "$mode" "$(deploy_contract circom-groth16-verifier "$verifier_wasm")"
  done
fi

step "deploy public-key-registry"
PUBLIC_KEY_REGISTRY_ID="$(deploy_contract public-key-registry "$PUBLIC_KEY_REGISTRY_WASM")"

POOL_IDS=()
POOL_TOKEN_IDS=()
POOL_ASSET_JSONS=()
POOL_DEPLOYMENT_LEDGERS=()

_pool_i=0
_pool_len="$(array_len POOL_BODY_SPECS)"
while [[ "$_pool_i" -lt "$_pool_len" ]]; do
  body="$(strip_surrounding_quotes "${POOL_BODY_SPECS[$_pool_i]}")"
  mode="${POOL_POLICY_MODES[$_pool_i]}"
  {
    IFS= read -r token_id
    IFS= read -r asset_json
  } < <(parse_pool_spec "$body")

  pool_deployment_ledger="$(get_latest_ledger_seq)"
  step "deploy pool ($mode) for spec '$body'"
  if [[ "$SKIP_INIT" != "true" ]]; then
    verifier_id="$(get_verifier_id "$mode")"
    [[ -n "$verifier_id" ]] || die "internal error: missing verifier id for policy mode $mode"
    pool_id="$(deploy_contract pool "$POOL_WASM" \
      --admin "$ADMIN_ADDR" --token "$token_id" --verifier "$verifier_id" \
      --asp-membership "$ASP_MEMBERSHIP_ID" --asp-non-membership "$ASP_NON_MEMBERSHIP_ID" \
      --maximum-deposit-amount "$MAX_DEPOSIT" --levels "$POOL_LEVELS" \
      --policy-mode "$(policy_mode_constructor_arg "$mode")")"
  else
    pool_id="$(deploy_contract pool "$POOL_WASM")"
  fi

  POOL_IDS+=("$pool_id")
  POOL_TOKEN_IDS+=("$token_id")
  POOL_ASSET_JSONS+=("$asset_json")
  POOL_DEPLOYMENT_LEDGERS+=("$pool_deployment_ledger")
  _pool_i=$((_pool_i + 1))
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
  Public key registry: $PUBLIC_KEY_REGISTRY_ID
  Pools deployed:      ${#POOL_IDS[@]}
  Constructed:         $([[ "$SKIP_INIT" == "true" ]] && echo "no" || echo "yes")
__DEPLOY_SUMMARY__
  _vi=0
  _vlen="$(array_len VERIFIER_MODE_LIST)"
  while [[ "$_vi" -lt "$_vlen" ]]; do
    printf '  Verifier (%s):     %s\n' "${VERIFIER_MODE_LIST[$_vi]}" "${VERIFIER_ID_LIST[$_vi]}" >&2
    _vi=$((_vi + 1))
  done
  _pi=0
  _plen="$(array_len POOL_IDS)"
  while [[ "$_pi" -lt "$_plen" ]]; do
    printf '  Pool[%s] (%s):       %s\n' "$_pi" "${POOL_POLICY_MODES[$_pi]}" "${POOL_IDS[$_pi]}" >&2
    _pi=$((_pi + 1))
  done
}

verifiers_json="\"verifiers\":{"
_vi=0
_vlen="$(array_len VERIFIER_MODE_LIST)"
while [[ "$_vi" -lt "$_vlen" ]]; do
  mode="${VERIFIER_MODE_LIST[$_vi]}"
  id="${VERIFIER_ID_LIST[$_vi]}"
  [[ "$_vi" -gt 0 ]] && verifiers_json+=","
  verifiers_json+="\"$mode\":\"$id\""
  _vi=$((_vi + 1))
done
verifiers_json+="}"

pools_json="["
_pi=0
_plen="$(array_len POOL_IDS)"
while [[ "$_pi" -lt "$_plen" ]]; do
  mode="${POOL_POLICY_MODES[$_pi]}"
  if [[ -n "$mode" ]]; then
    entry="{\"poolContractId\":\"${POOL_IDS[$_pi]}\",\"tokenContractId\":\"${POOL_TOKEN_IDS[$_pi]}\",\"deploymentLedger\":${POOL_DEPLOYMENT_LEDGERS[$_pi]},\"enabled\":true,\"policyMode\":\"$mode\",\"asset\":${POOL_ASSET_JSONS[$_pi]}}"
  else
    entry="{\"poolContractId\":\"${POOL_IDS[$_pi]}\",\"tokenContractId\":\"${POOL_TOKEN_IDS[$_pi]}\",\"deploymentLedger\":${POOL_DEPLOYMENT_LEDGERS[$_pi]},\"enabled\":true,\"asset\":${POOL_ASSET_JSONS[$_pi]}}"
  fi
  [[ "$_pi" -gt 0 ]] && pools_json+=","
  pools_json+="$entry"
  _pi=$((_pi + 1))
done
pools_json+="]"

DEPLOY_JSON="{\"network\":\"$NETWORK\",\"deployer\":\"$DEPLOYER_ADDR\",\"admin\":\"$ADMIN_ADDR\",\"asp_membership\":\"$ASP_MEMBERSHIP_ID\",\"asp_non_membership\":\"$ASP_NON_MEMBERSHIP_ID\",${verifiers_json},\"public_key_registry\":\"$PUBLIC_KEY_REGISTRY_ID\",\"pools\":$pools_json}"

DEPLOYMENTS_DIR="$ROOT_DIR/deployments/$NETWORK"
mkdir -p "$DEPLOYMENTS_DIR"
DEPLOY_JSON_PRETTY="$(printf '%s\n' "$DEPLOY_JSON" | jq .)"
printf '%s\n' "$DEPLOY_JSON_PRETTY" > "$DEPLOYMENTS_DIR/deployments.json"
printf '%s\n' "$DEPLOY_JSON_PRETTY"
