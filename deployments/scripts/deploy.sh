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
one Circom Groth16 verifier per policy flag combination used, and one or more Pool contracts.

Arguments:
  network               Network name from Stellar CLI config (e.g. testnet, futurenet)

Options:
  --deployer NAME       Stellar identity or secret key used to deploy (required)
  --admin ADDRESS       Admin address (G... or C...). Defaults to deployer address
  --token ADDRESS       Legacy single-pool token contract address (cannot be mixed with --pool)
  --pool SPEC           Pool spec (repeatable). Optional policy prefix per pool:
                        none:<SPEC> | allowlist:<SPEC> | blocklist:<SPEC> |
                        allowlist-blocklist:<SPEC>
                        where <SPEC> is one of:
                        contract:<TOKEN_CONTRACT_ID>
                        native:<TOKEN_CONTRACT_ID>
                        classic:<CODE>:<ISSUER>:<TOKEN_CONTRACT_ID>
  --asp-levels N        Merkle tree levels for asp-membership (required)
  --pool-levels N       Merkle tree levels for pool (required)
  --max-deposit U256    Maximum deposit amount (required)
  --policy-flags SPEC   Default pool ASP policy when a --pool spec omits the prefix:
                        none, allowlist, blocklist, or allowlist-blocklist (required when
                        running constructors unless every --pool spec includes a policy prefix)
  --vk-json JSON        Verification key as a JSON string (snarkjs or repo format).
                        Applies to allowlist-blocklist (AB suffix) verifier builds only.
  --vk-file PATH        Path to a verification key JSON file (allowlist-blocklist only)
  --skip-init           Deploy WASM only (no constructors). Writes verifiers under the
                        circuit suffix key ("", A, B, AB); use --policy-flags or a per-pool
                        prefix when the suffix is not otherwise known.
  --yes                 Skip confirmation for mainnet
  -h, --help            Show this help

Examples:
  # Mixed policies in one deployment (two verifiers, shared ASP contracts)
  deployments/scripts/deploy.sh futurenet \
    --deployer alice \
    --pool blocklist:native:CB... \
    --pool allowlist-blocklist:contract:CC... \
    --asp-levels 8 \
    --pool-levels 8 \
    --max-deposit 1000000000

  # Same policy on every pool via --policy-flags
  deployments/scripts/deploy.sh futurenet \
    --deployer alice \
    --policy-flags blocklist \
    --pool native:CB... \
    --pool classic:USDC:G...:CD... \
    --asp-levels 8 \
    --pool-levels 8 \
    --max-deposit 1000000000

Notes:
  - Each policy flag combination needs its own verifier contract (VK is baked into the WASM).
  - Per-pool policyFlags are written to deployments/<network>/deployments.json.
  - Provide --vk-file/--vk-json only for ceremony allowlist-blocklist (AB) keys; other VKs
    are taken from deployments/<network>/circuit_keys/ automatically.
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
POLICY_FLAGS_SUFFIX=""
POLICY_FLAGS_EXPLICIT=false
SKIP_INIT=false
YES=false

policy_suffix_label() {
  if [[ -z "$1" ]]; then
    printf '%s' "none"
  else
    printf '%s' "$1"
  fi
}

parse_policy_flags_spec() {
  local raw="$1" normalized allow=0 block=0 part
  normalized="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
  case "$normalized" in
    none) printf '%s' ""; return ;;
    allowlist) printf '%s' "A"; return ;;
    blocklist) printf '%s' "B"; return ;;
    allowlist-blocklist|blocklist-allowlist) printf '%s' "AB"; return ;;
  esac
  IFS='-' read -ra PARTS <<< "$normalized"
  for part in "${PARTS[@]}"; do
    case "$part" in
      allowlist) allow=1 ;;
      blocklist) block=1 ;;
      *) die "invalid policy flag '$part' in '$raw' (use allowlist and/or blocklist)" ;;
    esac
  done
  if [[ "$allow" == "1" && "$block" == "1" ]]; then printf '%s' "AB"
  elif [[ "$allow" == "1" ]]; then printf '%s' "A"
  elif [[ "$block" == "1" ]]; then printf '%s' "B"
  else die "empty policy flags in '$raw'"
  fi
}

policy_flags_constructor_arg() {
  case "$1" in
    "") echo 0 ;;
    A) echo 1 ;;
    B) echo 2 ;;
    AB) echo 3 ;;
    *) die "internal error: unknown policy suffix '$1'" ;;
  esac
}

policy_flags_to_json_array() {
  case "$1" in
    "") printf '[]' ;;
    A) printf '["allowlist"]' ;;
    B) printf '["blocklist"]' ;;
    AB) printf '["allowlist","blocklist"]' ;;
    *) die "internal error: unknown policy suffix '$1'" ;;
  esac
}

default_vk_file() {
  local network="$1" suffix="$2"
  if [[ -z "$suffix" ]]; then
    printf '%s/deployments/%s/circuit_keys/policy_tx_2_2_vk.json' "$ROOT_DIR" "$network"
  else
    printf '%s/deployments/%s/circuit_keys/policy_tx_2_2_%s_vk.json' "$ROOT_DIR" "$network" "$suffix"
  fi
}

verifier_wasm_name_for_suffix() {
  local suffix="$1"
  if [[ -z "$suffix" ]]; then
    printf 'circom_groth16_verifier.wasm'
  else
    printf 'circom_groth16_verifier_%s.wasm' "$suffix"
  fi
}

is_policy_flags_prefix() {
  local prefix="$1"
  case "$(printf '%s' "$prefix" | tr '[:upper:]' '[:lower:]')" in
    none|allowlist|blocklist) return 0 ;;
    native|classic|contract) return 1 ;;
  esac
  local part
  IFS='-' read -ra PARTS <<< "$(printf '%s' "$prefix" | tr '[:upper:]' '[:lower:]')"
  for part in "${PARTS[@]}"; do
    case "$part" in
      allowlist|blocklist) ;;
      *) return 1 ;;
    esac
  done
  return 0
}

# Sets POOL_SPEC_SUFFIX and POOL_SPEC_BODY for a --pool spec.
resolve_pool_spec_policy() {
  local spec="$1"
  local first="${spec%%:*}"
  POOL_SPEC_SUFFIX=""
  POOL_SPEC_BODY=""
  if [[ "$spec" == *:* ]] && is_policy_flags_prefix "$first"; then
    POOL_SPEC_SUFFIX="$(parse_policy_flags_spec "$first")"
    POOL_SPEC_BODY="${spec#*:}"
  else
    POOL_SPEC_BODY="$spec"
  fi
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

VERIFIER_SUFFIX_LIST=()
VERIFIER_ID_LIST=()

set_verifier_id() {
  local suffix="$1" id="$2" i len
  len="$(array_len VERIFIER_SUFFIX_LIST)"
  i=0
  while [[ "$i" -lt "$len" ]]; do
    if [[ "${VERIFIER_SUFFIX_LIST[$i]}" == "$suffix" ]]; then
      VERIFIER_ID_LIST[$i]="$id"
      return
    fi
    i=$((i + 1))
  done
  VERIFIER_SUFFIX_LIST+=("$suffix")
  VERIFIER_ID_LIST+=("$id")
}

get_verifier_id() {
  local suffix="$1" i len
  len="$(array_len VERIFIER_SUFFIX_LIST)"
  i=0
  while [[ "$i" -lt "$len" ]]; do
    if [[ "${VERIFIER_SUFFIX_LIST[$i]}" == "$suffix" ]]; then
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
    --policy-flags) POLICY_FLAGS_SUFFIX="$(parse_policy_flags_spec "$2")"; POLICY_FLAGS_EXPLICIT=true; shift 2 ;;
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
POOL_POLICY_SUFFIXES=()

_ps_i=0
_ps_len="$(array_len POOL_SPECS)"
while [[ "$_ps_i" -lt "$_ps_len" ]]; do
  spec="$(strip_surrounding_quotes "${POOL_SPECS[$_ps_i]}")"
  resolve_pool_spec_policy "$spec"
  local_has_suffix=false
  if [[ "$spec" == *:* ]] && is_policy_flags_prefix "${spec%%:*}"; then
    local_has_suffix=true
  fi
  suffix="$POOL_SPEC_SUFFIX"
  body="$(strip_surrounding_quotes "$POOL_SPEC_BODY")"
  if [[ "$local_has_suffix" == "false" ]]; then
    suffix="$POLICY_FLAGS_SUFFIX"
  fi
  if [[ "$SKIP_INIT" != "true" && "$local_has_suffix" == "false" && "$POLICY_FLAGS_EXPLICIT" != "true" ]]; then
    die "pool spec '$spec' has no policy flags; prefix with none:, allowlist:, blocklist:, allowlist-blocklist:, or pass --policy-flags"
  fi
  POOL_BODY_SPECS+=("$body")
  POOL_POLICY_SUFFIXES+=("$suffix")
  _ps_i=$((_ps_i + 1))
done

UNIQUE_POLICY_SUFFIXES=()
_ps_i=0
_ps_len="$(array_len POOL_POLICY_SUFFIXES)"
while [[ "$_ps_i" -lt "$_ps_len" ]]; do
  suffix="${POOL_POLICY_SUFFIXES[$_ps_i]}"
  found=false
  _u_i=0
  _u_len="$(array_len UNIQUE_POLICY_SUFFIXES)"
  while [[ "$_u_i" -lt "$_u_len" ]]; do
    if [[ "${UNIQUE_POLICY_SUFFIXES[$_u_i]}" == "$suffix" ]]; then
      found=true
      break
    fi
    _u_i=$((_u_i + 1))
  done
  if [[ "$found" == "false" ]]; then
    UNIQUE_POLICY_SUFFIXES+=("$suffix")
  fi
  _ps_i=$((_ps_i + 1))
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

build_verifier_wasm_for_suffix() {
  local suffix="$1"
  local wasm_name vk_path tmp_vk=""
  wasm_name="$(verifier_wasm_name_for_suffix "$suffix")"

  if [[ "$suffix" == "AB" && -n "$VK_FILE" ]]; then
    [[ -f "$VK_FILE" ]] || die "vk file not found: $VK_FILE"
    vk_path="$VK_FILE"
  elif [[ "$suffix" == "AB" && -n "$VK_JSON" ]]; then
    tmp_vk="$(mktemp "${TMPDIR:-/tmp}/deploy-vk.XXXXXX.json")"
    printf '%s' "$VK_JSON" > "$tmp_vk"
    vk_path="$tmp_vk"
  else
    vk_path="$(default_vk_file "$NETWORK" "$suffix")"
    [[ -f "$vk_path" ]] || die "VK not found for policy suffix '$suffix': $vk_path (pass --vk-file for AB)"
  fi

  step "building verifier WASM for $(policy_suffix_label "$suffix") from $vk_path"
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
  _u_i=0
  _u_len="$(array_len UNIQUE_POLICY_SUFFIXES)"
  while [[ "$_u_i" -lt "$_u_len" ]]; do
    build_verifier_wasm_for_suffix "${UNIQUE_POLICY_SUFFIXES[$_u_i]}"
    _u_i=$((_u_i + 1))
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
  _uniq_len="$(array_len UNIQUE_POLICY_SUFFIXES)"
  if [[ "$_uniq_len" -gt 1 ]]; then
    die "--skip-init supports at most one policy suffix; deploy without --skip-init for mixed policies"
  fi

  if [[ "$_uniq_len" -eq 1 ]]; then
    skip_init_verifier_suffix="${UNIQUE_POLICY_SUFFIXES[0]}"
  elif [[ "$POLICY_FLAGS_EXPLICIT" == "true" ]]; then
    skip_init_verifier_suffix="$POLICY_FLAGS_SUFFIX"
  else
    die "--skip-init requires policy flags (--policy-flags or pool prefix none:/allowlist:/blocklist:/allowlist-blocklist:)"
  fi

  verifier_wasm="$WASM_DIR/$(verifier_wasm_name_for_suffix "$skip_init_verifier_suffix")"
  [[ -f "$verifier_wasm" ]] \
    || die "missing verifier wasm for $(policy_suffix_label "$skip_init_verifier_suffix") (run build-verifier-with-vk.sh or deploy without --skip-init)"
  step "deploy circom-groth16-verifier ($(policy_suffix_label "$skip_init_verifier_suffix"))"
  set_verifier_id "$skip_init_verifier_suffix" "$(deploy_contract circom-groth16-verifier "$verifier_wasm")"
else
  _u_i=0
  _u_len="$(array_len UNIQUE_POLICY_SUFFIXES)"
  while [[ "$_u_i" -lt "$_u_len" ]]; do
    suffix="${UNIQUE_POLICY_SUFFIXES[$_u_i]}"
    verifier_wasm="$WASM_DIR/$(verifier_wasm_name_for_suffix "$suffix")"
    [[ -f "$verifier_wasm" ]] || die "missing wasm: $verifier_wasm"
    step "deploy circom-groth16-verifier ($(policy_suffix_label "$suffix"))"
    set_verifier_id "$suffix" "$(deploy_contract circom-groth16-verifier "$verifier_wasm")"
    _u_i=$((_u_i + 1))
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
  suffix="${POOL_POLICY_SUFFIXES[$_pool_i]}"
  {
    IFS= read -r token_id
    IFS= read -r asset_json
  } < <(parse_pool_spec "$body")

  pool_deployment_ledger="$(get_latest_ledger_seq)"
  step "deploy pool ($(policy_suffix_label "$suffix")) for spec '$body'"
  if [[ "$SKIP_INIT" != "true" ]]; then
    verifier_id="$(get_verifier_id "$suffix")"
    [[ -n "$verifier_id" ]] || die "internal error: missing verifier id for policy suffix '$suffix'"
    pool_id="$(deploy_contract pool "$POOL_WASM" \
      --admin "$ADMIN_ADDR" --token "$token_id" --verifier "$verifier_id" \
      --asp-membership "$ASP_MEMBERSHIP_ID" --asp-non-membership "$ASP_NON_MEMBERSHIP_ID" \
      --maximum-deposit-amount "$MAX_DEPOSIT" --levels "$POOL_LEVELS" \
      --policy-flags "$(policy_flags_constructor_arg "$suffix")")"
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
  _vlen="$(array_len VERIFIER_SUFFIX_LIST)"
  while [[ "$_vi" -lt "$_vlen" ]]; do
    printf '  Verifier (%s):     %s\n' "$(policy_suffix_label "${VERIFIER_SUFFIX_LIST[$_vi]}")" "${VERIFIER_ID_LIST[$_vi]}" >&2
    _vi=$((_vi + 1))
  done
  _pi=0
  _plen="$(array_len POOL_IDS)"
  while [[ "$_pi" -lt "$_plen" ]]; do
    printf '  Pool[%s] (%s):       %s\n' "$_pi" "$(policy_suffix_label "${POOL_POLICY_SUFFIXES[$_pi]}")" "${POOL_IDS[$_pi]}" >&2
    _pi=$((_pi + 1))
  done
}

verifiers_json="\"verifiers\":{"
_vi=0
_vlen="$(array_len VERIFIER_SUFFIX_LIST)"
while [[ "$_vi" -lt "$_vlen" ]]; do
  suffix="${VERIFIER_SUFFIX_LIST[$_vi]}"
  id="${VERIFIER_ID_LIST[$_vi]}"
  [[ "$_vi" -gt 0 ]] && verifiers_json+=","
  verifiers_json+="\"$suffix\":\"$id\""
  _vi=$((_vi + 1))
done
verifiers_json+="}"

pools_json="["
_pi=0
_plen="$(array_len POOL_IDS)"
while [[ "$_pi" -lt "$_plen" ]]; do
  suffix="${POOL_POLICY_SUFFIXES[$_pi]}"
  flags_json="$(policy_flags_to_json_array "$suffix")"
  entry="{\"poolContractId\":\"${POOL_IDS[$_pi]}\",\"tokenContractId\":\"${POOL_TOKEN_IDS[$_pi]}\",\"deploymentLedger\":${POOL_DEPLOYMENT_LEDGERS[$_pi]},\"enabled\":true,\"policyFlags\":${flags_json},\"asset\":${POOL_ASSET_JSONS[$_pi]}}"
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
