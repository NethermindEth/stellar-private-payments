#!/usr/bin/env bash
# Guide public deployment inputs; deploy.sh owns all on-chain changes.
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCHEMA="$ROOT/deployments/scripts/deploy-plan.jq"
PLAN=''
REPLY=''
TEMP_PLAN=''
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
cleanup() { [[ -z "$TEMP_PLAN" ]] || rm -f -- "$TEMP_PLAN"; }
trap cleanup EXIT
trap 'printf "\nInterrupted. If deployment started, inspect its output before retrying.\n" >&2; exit 130' INT TERM
cli() {
  stellar "$@" 2>/dev/null || { printf "Stellar CLI could not complete '%s %s'. Check its configuration.\n" "$1" "${2:-}" >&2; return 1; }
}
# Decode StrKey base32 and check CRC16-XMODEM without another runtime.
valid_address() {
  local value=$1 prefixes=${2:-GC} alphabet=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
  local buffer=0 bits=0 index byte crc=0 bit i tail
  local -a bytes=()
  [[ $value =~ ^[$prefixes][A-Z2-7]{55}$ ]] || return 1
  for ((i=0; i<56; i++)); do
    tail=${alphabet#*"${value:i:1}"}; index=$((31 - ${#tail}))
    buffer=$(((buffer << 5) | index)); bits=$((bits + 5))
    if ((bits >= 8)); then
      bits=$((bits - 8)); bytes+=( "$(((buffer >> bits) & 255))" )
      buffer=$((buffer & ((1 << bits) - 1)))
    fi
  done
  for ((i=0; i<33; i++)); do
    byte=${bytes[i]}; crc=$((crc ^ (byte << 8)))
    for ((bit=0; bit<8; bit++)); do
      if ((crc & 32768)); then crc=$((((crc << 1) ^ 4129) & 65535)); else crc=$(((crc << 1) & 65535)); fi
    done
  done
  ((crc == (bytes[33] | (bytes[34] << 8))))
}
valid_alias() { [[ $1 =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ && ! $1 =~ ^[SG][A-Z2-7]{55}$ ]]; }
valid_url() { [[ $1 =~ ^https?://[^/@?#[:space:]]+(/[^?#[:space:]]*)?$ ]]; }
optional_url() { [[ -z $1 ]] || valid_url "$1"; }
nonempty() { [[ $1 =~ [^[:space:]] ]]; }
valid_amount() {
  local value=$1 limit=115792089237316195423570985008687907853269984665640564039457584007913129639936
  [[ $value =~ ^[0-9]{1,78}$ ]] || return 1
  while [[ $value == 0* ]]; do value=${value#0}; done
  [[ -n $value ]] && { ((${#value} < 78)) || [[ $value < $limit ]]; }
}
valid_code() { [[ $1 =~ ^[A-Za-z0-9]{1,12}$ ]]; }
valid_account() { valid_address "$1" G; }
valid_contract() { valid_address "$1" C; }
valid_key_file() {
  [[ -f $1 ]] && jq -e 'type == "object" and keys == ["x","y"] and all(.[]; type == "string" and test("^(0x[0-9a-fA-F]+|[0-9]+)$"))' "$1" >/dev/null 2>&1
}
ask() {
  local label=$1 default=$2 validator=${3:-nonempty}
  while :; do
    printf '%s' "$label"; [[ -z $default ]] || printf ' [%s]' "$default"; printf ': '
    IFS= read -r REPLY || die 'Input ended; deployment was not requested.'
    REPLY=${REPLY:-$default}
    if "$validator" "$REPLY"; then return; fi
    printf 'Invalid value. Please try again.\n'
  done
}
yes_no() {
  local label=$1 default=${2:-no}
  while :; do
    ask "$label (yes/no)" "$default"
    case $REPLY in yes|y|YES|Y) REPLY=true; return;; no|n|NO|N) REPLY=false; return;; esac
  done
}
choose() {
  local label=$1 option index=0; shift
  local -a names=("$@")
  ((${#names[@]})) || die 'No choices available. Configure Stellar CLI first.'
  printf '\n%s\n' "$label"
  for option in "${names[@]}"; do index=$((index+1)); printf '  %s. %s\n' "$index" "$option"; done
  while :; do
    ask Choice ''
    for option in "${names[@]}"; do [[ $REPLY != "$option" ]] || return; done
    if [[ $REPLY =~ ^[0-9]{1,4}$ ]] && ((10#$REPLY >= 1 && 10#$REPLY <= ${#names[@]})); then
      REPLY=${names[10#$REPLY-1]}; return
    fi
    printf 'Choose a listed number or name.\n'
  done
}
network_listing() {
  local listing
  listing=$(cli network ls --long) || return 1
  printf '%s\n' "$listing" | jq -Rn '
    reduce inputs as $line ({current: null, networks: {}};
      ($line | capture("^\\s*(?<key>Name|RPC url|Network passphrase):\\s*(?<value>.*?)\\s*$")? // {}) as $part |
      if $part.key == "Name" then .current = $part.value
      elif .current != null and $part.key != null then .networks[.current][$part.key] //= $part.value else . end
    ) | .networks'
}
network_details() {
  local listing
  listing=$(network_listing) || die 'Cannot read Stellar networks.'
  PASSPHRASE=$(jq -r --arg name "$1" '.[$name]["Network passphrase"] // empty' <<< "$listing")
  RPC=$(jq -r --arg name "$1" '.[$name]["RPC url"] // empty' <<< "$listing")
  [[ -n $PASSPHRASE ]] && valid_url "$RPC" || die 'Network missing or invalid. Configure it with stellar network add.'
}
asset_contract() {
  local asset=$1 network=$2 value
  value=$(cli contract id asset --asset "$asset" --network "$network") || return 1
  value=${value#\"}; value=${value%\"}
  valid_contract "$value" || { printf 'Invalid asset contract address.\n' >&2; return 1; }
  printf '%s' "$value"
}
collect() {
  local listing network deployer payer admin display explorer testnet maximum kind code issuer token policy mode key=null pools='[]' pool
  local -a names=()
  printf 'Deployment setup\nOnly public configuration is saved. Use existing Stellar account aliases.\n'
  listing=$(network_listing) || die 'Cannot read Stellar networks.'
  while IFS= read -r name; do names+=("$name"); done < <(jq -r 'keys[] | select(. != "ci-test-network")' <<< "$listing")
  choose 'Choose a network' "${names[@]}"; network=$REPLY
  [[ $network =~ ^[A-Za-z0-9_-]+$ ]] || die 'Network names must use letters, digits, hyphens or underscores.'
  network_details "$network"
  printf 'Network identity: %s\nRPC: %s\n\nSaved Stellar account aliases:\n' "$PASSPHRASE" "$RPC"
  cli keys ls || die 'Cannot list saved accounts.'
  ask 'Deployer account alias (pays fees; do not enter a secret key)' '' valid_alias; deployer=$REPLY
  payer=$(cli keys address "$deployer") || die 'Cannot resolve deployer alias.'
  valid_account "$payer" || die 'Invalid deployer public address.'
  ask 'Administrator public address' "$payer" valid_address; admin=$REPLY
  ask 'Name to show in the app' "$network"; display=$REPLY
  ask 'Explorer HTTP(S) base URL (empty for none; no credentials or query)' '' optional_url; explorer=$REPLY
  testnet=no; case $network in testnet|futurenet|local) testnet=yes;; esac
  yes_no 'Is this a test network? Shows the test-network disclaimer' "$testnet"; testnet=$REPLY
  printf '\nThe deposit limit applies to every pool, in each token\047s smallest units.\nFor XLM, 10000000 units = 1 XLM. Different tokens can have different decimals.\n'
  ask 'Maximum deposit per transaction (positive integer below 2^256)' '' valid_amount; maximum=$REPLY
  printf 'Tree settings stay at ASP depth 10 and pool depth 20 to match the repository circuits.\n'
  while :; do
    choose 'Asset: native = XLM; classic = issued asset; contract = existing token contract' native classic contract; kind=$REPLY
    code=''; issuer=''
    case $kind in
      classic)
        ask 'Asset code (1–12 letters or digits)' '' valid_code; code=$REPLY
        ask 'Issuer public address' '' valid_account; issuer=$REPLY
        token=$(asset_contract "$code:$issuer" "$network") || die 'Cannot resolve asset.';;
      native) token=$(asset_contract native "$network") || die 'Cannot resolve XLM contract.';;
      contract) ask 'Token contract address' '' valid_contract; token=$REPLY;;
    esac
    printf 'Token contract: %s\n' "$token"
    choose 'Association-set policy: require approved membership, absence from blocked sets, both, or neither. Admin maintains lists.' none allowlist blocklist allowlist-blocklist; policy=$REPLY
    choose 'Viewing: off = no authority; viewonly = decrypt output notes; traceable = decrypt output and input notes' gvk-off gvk-viewonly gvk-traceable; mode=$REPLY
    pool=$(jq -n --arg kind "$kind" --arg code "$code" --arg issuer "$issuer" --arg token "$token" --arg policy "$policy" --arg mode "$mode" \
      '{kind:$kind,tokenContractId:$token,policy:$policy,gvkMode:$mode} + if $kind == "classic" then {code:$code,issuer:$issuer} else {} end')
    pools=$(jq --argjson pool "$pool" '. + [$pool]' <<< "$pools")
    yes_no 'Add another pool?'; [[ $REPLY == true ]] || break
  done
  if jq -e 'any(.[]; .gvkMode != "gvk-off")' <<< "$pools" >/dev/null; then
    printf 'All viewing-enabled pools use the same authority public key. Do not provide a private key file.\n'
    ask 'Path to authority PUBLIC key JSON (only x and y string coordinates)' '' valid_key_file
    key=$(jq -c . "$REPLY")
  fi
  PLAN=$(jq -n --arg network "$network" --arg passphrase "$PASSPHRASE" --arg rpc "$RPC" --arg display "$display" \
    --arg explorer "$explorer" --argjson testnet "$testnet" --arg deployer "$deployer" --arg payer "$payer" \
    --arg admin "$admin" --arg maximum "$maximum" --argjson pools "$pools" --argjson key "$key" \
    '{version:1,network:$network,networkPassphrase:$passphrase,rpcUrl:$rpc,displayName:$display,explorerUrl:$explorer,
      isTestnet:$testnet,deployer:$deployer,deployerAddress:$payer,admin:$admin,aspLevels:10,poolLevels:20,
      maxDeposit:$maximum,pools:$pools,gvkAuthorityPubKey:$key}')
}
validate_plan() {
  local value=$1 address
  jq -e -f "$SCHEMA" <<< "$value" >/dev/null 2>&1 || return 1
  while IFS= read -r address; do valid_address "$address" || return 1; done < <(
    jq -r '.deployerAddress,.admin, (.pools[] | .tokenContractId, (.issuer // empty))' <<< "$value")
}
field() { jq -r ".$1" <<< "$PLAN"; }
validate_live_identity() {
  local network payer pool kind asset token
  network=$(field network); network_details "$network"
  [[ $PASSPHRASE == "$(field networkPassphrase)" && $RPC == "$(field rpcUrl)" ]] || die 'Stellar network settings changed. Create a new plan and review the change.'
  payer=$(cli keys address "$(field deployer)") || die 'Cannot resolve deployer alias.'
  [[ $payer == "$(field deployerAddress)" ]] || die 'Deployer alias now resolves to a different address. Create a new plan.'
  while IFS= read -r pool; do
    kind=$(jq -r .kind <<< "$pool"); [[ $kind != contract ]] || continue
    asset=native
    [[ $kind != classic ]] || asset=$(jq -r '.code + ":" + .issuer' <<< "$pool")
    token=$(asset_contract "$asset" "$network") || die 'Cannot resolve asset.'
    [[ $token == "$(jq -r .tokenContractId <<< "$pool")" ]] || die 'Asset contract does not match the planned network and asset.'
  done < <(jq -c '.pools[]' <<< "$PLAN")
}
artifact_problems() {
  local folder="$ROOT/deployments/$(field network)" stem kind filename path digest expected
  if ! jq -e 'type == "object"' "$folder/circuits.json" >/dev/null 2>&1; then
    printf 'Cannot read circuit lock: %s/circuits.json\n' "$folder"; return
  fi
  while IFS= read -r stem; do
    for kind in graph.bin proving_key.bin; do
      if [[ $kind == graph.bin ]]; then filename="$stem.graph.bin"; else filename="${stem}_proving_key.bin"; fi
      path="$folder/circuit_keys/$filename"
      if [[ ! -r $path ]]; then printf 'Missing or unreadable artifact: %s\n' "$path"; continue; fi
      if command -v sha256sum >/dev/null; then
        digest=$(sha256sum -- "$path") || { printf 'Cannot fingerprint: %s\n' "$path"; continue; }
      else
        digest=$(shasum -a 256 -- "$path") || { printf 'Cannot fingerprint: %s\n' "$path"; continue; }
      fi
      digest=${digest%% *}
      expected=$(jq -r --arg stem "$stem" --arg kind "$kind" '.[$stem][$kind] // empty' "$folder/circuits.json")
      [[ $digest == "$expected" ]] || printf 'Fingerprint mismatch: %s\n' "$path"
    done
    path="$folder/circuit_keys/${stem}_vk.json"
    jq -e 'type == "object" and (.IC | type == "array" and length > 0)' "$path" >/dev/null 2>&1 || printf 'Invalid verification key: %s\n' "$path"
  done < <(jq -r '[.pools[] | "policy_tx_2_2" + ({none:"",allowlist:"_A",blocklist:"_B","allowlist-blocklist":"_AB"}[.policy]) +
    ({"gvk-off":"","gvk-viewonly":"_gvk_V","gvk-traceable":"_gvk_T"}[.gvkMode])] | unique[]' <<< "$PLAN")
}
prepare_command() {
  local pool key network
  network=$(field network)
  COMMAND=(bash "$ROOT/deployments/scripts/deploy.sh" "$network" --deployer "$(field deployer)" --admin "$(field admin)"
    --asp-levels 10 --pool-levels 20 --max-deposit "$(field maxDeposit)")
  while IFS= read -r pool; do COMMAND+=(--pool "$pool"); done < <(jq -r '.pools[] |
    .policy + ":" + .gvkMode + ":" + .kind + ":" +
    (if .kind == "classic" then .code + ":" + .issuer + ":" else "" end) + .tokenContractId' <<< "$PLAN")
  key=$(jq -c .gvkAuthorityPubKey <<< "$PLAN")
  [[ $key == null ]] || COMMAND+=(--gvk-authority-pubkey "$key")
  [[ $network != mainnet ]] || COMMAND+=(--yes)
  ENVIRONMENT=("SPP_NETWORK=$network" "SPP_DISPLAY_NAME=$(field displayName)" "SPP_EXPLORER_URL=$(field explorerUrl)" "SPP_IS_TESTNET=$(field isTestnet)")
}
show_summary() {
  printf '\nDeployment plan — creates NEW contracts, not an upgrade of existing contracts\n'
  jq -r '"  Network: \(.network)\n  Public network identity: \(.networkPassphrase)\n  RPC server: \(.rpcUrl)\n  Paying account alias: \(.deployer)\n  Paying account address: \(.deployerAddress)\n  Administrator: \(.admin)\n  App network name: \(.displayName)\n  Explorer: \(.explorerUrl)\n  Show test disclaimer: \(.isTestnet)\n  Maximum deposit (smallest units, all pools): \(.maxDeposit)",
    (.pools | to_entries[] | "  Pool \(.key + 1): \(.value.kind) \(.value.code // "") \(.value.issuer // ""), \(.value.tokenContractId), \(.value.policy), \(.value.gvkMode)"),
    "  Viewing authority public key: \(.gvkAuthorityPubKey)\n  Tree depths: ASP 10, pool 20\n  Deployment output: deployments/\(.network)/deployments.json"' <<< "$PLAN"
  [[ ! -e "$ROOT/deployments/$(field network)/deployments.json" ]] || printf '  Existing deployments.json will be replaced after successful deployment.\n'
  prepare_command
  printf '\nEquivalent command (submits transactions when run):\n'
  printf '%q ' env "${ENVIRONMENT[@]}" "${COMMAND[@]}"; printf '\n'
}
save_plan() {
  local path=$1 existing parent
  [[ ! -L $path ]] || die 'Refusing to overwrite a symbolic link.'
  case ${path##*/} in deployments.json|circuits.json) die 'Choose a separate plan file, not a deployment or circuit manifest.';; esac
  if [[ -e $path ]]; then
    existing=$(cat -- "$path")
    validate_plan "$existing" || die 'Existing output is not a deployment plan; refusing to overwrite it.'
    yes_no "Replace existing plan at $path?"
    [[ $REPLY == true ]] || die 'Plan not overwritten.'
  fi
  parent=$(dirname -- "$path"); mkdir -p -- "$parent"
  TEMP_PLAN=$(mktemp "$parent/.deployment-plan.XXXXXXXX")
  jq . <<< "$PLAN" > "$TEMP_PLAN"
  mv -f -- "$TEMP_PLAN" "$path"; TEMP_PLAN=''
  printf '\nSaved public deployment plan: %s\n' "$path"
}
main() {
  local config='' output='' save_only=false path problems tool confirmation status
  while (($#)); do
    case $1 in
      --config|--output)
        (($# >= 2)) || die "$1 requires a path."
        if [[ $1 == --config ]]; then config=$2; else output=$2; fi; shift 2;;
      --save-only) save_only=true; shift;;
      -h|--help) printf 'Usage: bash deployments/scripts/deploy-wizard.sh [--config PLAN] [--output PLAN] [--save-only]\nGuide deployment inputs; submit transactions only after explicit confirmation.\n'; return;;
      *) die "Unknown option: $1";;
    esac
  done
  for tool in jq stellar; do command -v "$tool" >/dev/null || die "Install $tool before starting the wizard."; done
  command -v sha256sum >/dev/null || command -v shasum >/dev/null || die 'Install sha256sum or shasum for circuit fingerprints.'
  if [[ -n $config ]]; then PLAN=$(cat -- "$config"); else collect; fi
  validate_plan "$PLAN" || die 'Invalid deployment plan. Check fields, public addresses and circuit depths (ASP 10, pool 20).'
  validate_live_identity; show_summary
  if [[ -n $config && -z $output ]]; then
    path=$config; printf '\nUsing saved plan: %s\n' "$path"
  else
    path=${output:-"$ROOT/.deployment-plans/$(field network).json"}; save_plan "$path"
  fi
  problems=$(artifact_problems)
  for tool in bash cargo; do command -v "$tool" >/dev/null || problems+=$'\n'"Missing prerequisite: $tool"; done
  if [[ -n $problems ]]; then printf '\nDeployment blocked:\n%s\nPrepare matching circuit artifacts and prerequisites, then reopen the saved plan.\n' "$problems"; fi
  printf '\nReopen with: '; printf '%q ' bash "$ROOT/deployments/scripts/deploy-wizard.sh" --config "$path"; printf '\n'
  [[ $save_only != true ]] || return 0
  [[ -z $problems ]] || return 1
  printf '\nDeployment spends fees from the deployer account. Cancelling here submits nothing.\n'
  printf 'Type "deploy %s" to deploy, or press Enter to leave the plan saved: ' "$(field network)"
  IFS= read -r confirmation || confirmation=''
  if [[ $confirmation != "deploy $(field network)" ]]; then printf 'Plan saved; no contracts deployed.\n'; return; fi
  validate_live_identity
  problems=$(artifact_problems); [[ -z $problems ]] || die "$problems"
  prepare_command
  if (cd "$ROOT" && env "${ENVIRONMENT[@]}" "${COMMAND[@]}"); then
    printf 'Contracts deployed. Configuration: deployments/%s/deployments.json\nStart native consumers with deployments/%s/deployments.json; see docs/src/multi-network.md.\n' "$(field network)" "$(field network)"
  else
    status=$?
    printf 'Deployment did not complete. Some transactions may already have succeeded.\nInspect deployment output before retrying; a retry can create more contracts.\n' >&2
    return "$status"
  fi
}
main "$@"
