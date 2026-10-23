#!/usr/bin/env bash
# Check a deployment's on-chain state against its manifest.
# Usage: verify-deployment.sh <network> [options]

set -euo pipefail

die() { echo "verify-deployment.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
step() { echo "==> $*" >&2; }

usage() {
  cat >&2 <<'USAGE'
Usage: verify-deployment.sh <network> [OPTIONS]

Reads a deployment manifest and checks the contracts it names against it. Every
check prints one line, and the run reports all of them before exiting.

Arguments:
  network            Network name from Stellar CLI config (e.g. testnet, futurenet)

Options:
  --manifest PATH    Manifest to check (default deployments/<network>/deployments.json)
  --base-manifest PATH
                     Manifest the change starts from, which decides which added
                     allowlists are new
  -h, --help         Show this help

Checks:
  - Every contract the manifest names has the manifest's admin and no pending
    admin transfer. An allowlist another party runs is checked against the
    admin its added_asp_memberships entry names.
  - The manifest names at most 25 contracts for clients to index: its enabled
    pools, its allowlists, and the public key registry.
  - The public key registry stores the manifest's KDF domain and its
    public_key_registry_verifier, which runs the code whose hash is
    public_key_registry_verifier_wasm_hash: deploy.sh's build of
    circuit_keys/keyOwnership_vk.json. A manifest without these fields, from
    before the registry had a verifier, skips these checks with a notice.
  - Every pool's token is its asset's own Stellar asset contract. A pool whose
    asset is a contract token fails. A classic asset's issuer prints as a notice
    listing each power its flags give it over the pool's balance.
  - Every pool, a disabled one too, stores the manifest's tree code hashes and
    reads an allowlist the manifest names. A manifest without the hashes, from
    before pools stored them, skips these checks with a notice.
  - Every tree a pool reads that the manifest does not name, such as a
    blocklist the pool was re-pointed to, has no pending admin transfer. Its
    admin prints as a notice when it is not the manifest's.
  - The admin account has master weight 0, three equal thresholds of at least 2,
    signers that are all ed25519 keys of weight 1, and no fewer signers than the
    threshold. Off mainnet, a failure here prints as a notice. A contract admin
    (a C address) has no account to read, so it fails this check on mainnet.
  - Clients can index every allowlist in added_asp_memberships: its deployment
    ledger is closed and the RPC still holds it, and its first leaf from that
    ledger has index 0. A ledger after the latest one always fails. One the RPC
    no longer holds fails only for an allowlist the base manifest does not
    name, and prints as a notice without --base-manifest. A new allowlist with
    less than a day of retention left prints a notice to restart the bootnode
    before then. The check reads the CLI's RPC in place of the bootnode's
    upstream, so an upstream that keeps less history can still lose an
    allowlist this check passes.

Exits 1 when any check failed, 0 otherwise.
USAGE
  exit 2
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

NETWORK="${1:-}"
shift || true

MANIFEST=""
BASE_MANIFEST=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest) MANIFEST="$2"; shift 2 ;;
    --base-manifest) BASE_MANIFEST="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$NETWORK" ]] || usage
need stellar
need jq

MANIFEST="${MANIFEST:-$ROOT_DIR/deployments/$NETWORK/deployments.json}"
[[ -f "$MANIFEST" ]] || die "manifest not found: $MANIFEST"
[[ -z "$BASE_MANIFEST" || -f "$BASE_MANIFEST" ]] || die "base manifest not found: $BASE_MANIFEST"

FAILED=0

# A failure labeled `notice` prints like any other but leaves the exit status alone.
check() {
  local contract="$1" key="$2" want="$3" got="$4" label="${5:-FAIL}"
  if [[ "$want" == "$got" ]]; then
    printf 'ok %s %s\n' "$contract" "$key"
  else
    printf '%s %s %s: expected %s, got %s\n' "$label" "$contract" "$key" "$want" "$got"
    [[ "$label" != FAIL ]] || FAILED=1
  fi
}

# Prints an entry's value as JSON, or `null` if absent. A failed read exits non-zero, so callers
# can tell it from an absent entry.
read_entry() {
  stellar ledger entry fetch contract-data --contract "$1" --network "$NETWORK" --key-xdr "$2" \
    | jq -c '.entries[0].val.contract_data.val'
}

# Prints a unit-variant key, a one-symbol ScVec, as XDR.
unit_key() { printf '{"vec":[{"symbol":"%s"}]}' "$1" | stellar xdr encode --type ScVal; }

# Prints the address under a unit-variant key, or `none`.
read_address() { read_entry "$1" "$(unit_key "$2")" | jq -r '.address // "none"'; }

# Prints the address that an instance entry from `read_entry` stores under a unit-variant key, or
# nothing.
stored() {
  jq -r --arg key "$2" '.contract_instance.storage[]? | select(.key.vec[0].symbol == $key)
    | .val.address' <<<"$1"
}

allowlists() { jq -r '.asp_membership, (.added_asp_memberships // [])[].contractId' "$1"; }

ADMIN="$(jq -r '.admin' "$MANIFEST")"
DEPLOYER="$(jq -r '.deployer' "$MANIFEST")"
# Disabled pools too: `enabled` only hides a pool from clients; on chain it still takes deposits.
POOLS="$(jq -r '.pools[].poolContractId' "$MANIFEST")"
ALLOWLISTS="$(allowlists "$MANIFEST")"

# Each contract and its expected admin. An allowlist another party runs names its own admin in
# its manifest entry.
TARGETS="$(jq -r --arg admin "$ADMIN" '(.pools[].poolContractId, .asp_membership
  | "\(.) \($admin)"), ((.added_asp_memberships // [])[] | "\(.contractId) \(.admin // $admin)"),
  (.asp_non_membership | "\(.) \($admin)")' "$MANIFEST")"

step "checking the admin of every contract in $MANIFEST"
while read -r target want <&3; do
  check "$target" Admin "$want" "$(read_address "$target" Admin || echo unreadable)"
  # A merged manifest names the admin that holds the role, so a transfer still pending fails.
  check "$target" PendingAdmin none "$(read_address "$target" PendingAdmin || echo unreadable)"
done 3<<<"$TARGETS"

step "counting the contracts clients index"
# The SDK reads enabled pools, every named allowlist, and the registry in one request of at most
# five filters of five contracts.
INDEXED="$(jq '([.pools[] | select(.enabled)] | length) + 2
  + ((.added_asp_memberships // []) | length)' "$MANIFEST")"
((INDEXED <= 25)) && GOT="at most 25" || GOT="$INDEXED"
check manifest "indexed contracts" "at most 25" "$GOT"

REGISTRY="$(jq -r '.public_key_registry' "$MANIFEST")"
REGISTRY_VERIFIER="$(jq -r '.public_key_registry_verifier // empty' "$MANIFEST")"
if [[ -z "$REGISTRY_VERIFIER" ]]; then
  step "no public_key_registry_verifier in $MANIFEST, skipping the registry checks"
else
  step "checking the public key registry"
  # Read-only simulations, so the source account only has to exist on the network.
  registry_get() {
    stellar contract invoke --id "$REGISTRY" --source-account "$DEPLOYER" --network "$NETWORK" \
      --send=no -- "$1" | jq -r . || echo unreadable
  }
  check "$REGISTRY" get_verifier "$REGISTRY_VERIFIER" "$(registry_get get_verifier)"
  check "$REGISTRY" get_kdf_domain "$(jq -r '.kdf_domain' "$MANIFEST")" \
    "$(registry_get get_kdf_domain)"
  VERIFIER_HASH="$(jq -r '.public_key_registry_verifier_wasm_hash // empty' "$MANIFEST")"
  if [[ -z "$VERIFIER_HASH" ]]; then
    step "no public_key_registry_verifier_wasm_hash in $MANIFEST, skipping the verifier code check"
  else
    # AAAAFA== is the key of the contract's instance entry, which names its code.
    check "$REGISTRY_VERIFIER" "code hash" "$VERIFIER_HASH" \
      "$(read_entry "$REGISTRY_VERIFIER" AAAAFA== | jq -r '.contract_instance.executable.wasm // "none"' \
        || echo unreadable)"
  fi
fi

HASHES="$(jq -c 'select(has("asp_membership_wasm_hash") or has("asp_non_membership_wasm_hash"))
  | [.asp_membership_wasm_hash, .asp_non_membership_wasm_hash]' "$MANIFEST")"
[[ -n "$HASHES" ]] || step "no tree code hashes in $MANIFEST, skipping the tree code checks"
# Trees the admin checks above cover. A re-pointed pool can read others, checked once below.
CHECKED="$(jq -r '.asp_membership, (.added_asp_memberships // [])[].contractId,
  .asp_non_membership' "$MANIFEST")"

step "checking the token and trees of every pool"
for pool in $POOLS; do
  # AAAAFA== is the key of the contract's instance entry, which holds the pool's token and trees.
  instance="$(read_entry "$pool" AAAAFA==)" \
    || { check "$pool" instance readable unreadable; instance=null; }
  # deploy.sh's token rule, checked against the token the pool stores.
  asset="$(jq -r --arg pool "$pool" 'first(.pools[] | select(.poolContractId == $pool)).asset
    | if .kind == "classic" then "\(.code):\(.issuer)" else .kind end' "$MANIFEST")"
  case "$asset" in
    native|*:*)
      token="$(stored "$instance" Token)"
      check "$pool" Token "$(stellar contract id asset --asset "$asset" --network "$NETWORK" \
        || echo unreadable)" "${token:-none}"
      ;;
    # A token contract's own code could move or freeze the pool's balance.
    *) check "$pool" asset "native or classic" "$asset" ;;
  esac
  if [[ "$asset" == *:* ]]; then
    issuer="${asset#*:}"
    flags="$(stellar ledger entry fetch account --account "$issuer" --network "$NETWORK" \
      | jq '.entries[0].val.account.flags' || echo unreadable)"
    # deploy.sh warns about these powers and deploys the pool anyway, so they print as a notice.
    rule="no power over the pool's balance"
    got="flags $flags"
    if [[ "$flags" =~ ^[0-9]+$ ]]; then
      got=""
      ((flags & 1)) && got+=", must authorize it (AUTH_REQUIRED)"
      ((flags & 2)) && got+=", can freeze it (AUTH_REVOCABLE)"
      ((flags & 8)) && got+=", can claw it back (AUTH_CLAWBACK_ENABLED)"
      ((flags & 4)) || got+=", can still set its flags (no AUTH_IMMUTABLE)"
      got="${got#, }"
    fi
    check "$pool" "issuer $issuer" "$rule" "${got:-$rule}" notice
  fi
  if [[ -n "$HASHES" ]]; then
    # Read-only simulation, so the source account only has to exist on the network.
    check "$pool" get_asp_wasm_hashes "$HASHES" "$(stellar contract invoke --id "$pool" \
      --source-account "$DEPLOYER" --network "$NETWORK" --send=no -- get_asp_wasm_hashes \
      | jq -c . || echo unreadable)"
    tree="$(stored "$instance" ASPMembership)"
    check "$pool" ASPMembership "an allowlist the manifest names" \
      "$(grep -qxF "$tree" <<<"$ALLOWLISTS" && echo "an allowlist the manifest names" \
        || echo "${tree:-none}")"
  fi
  for tree in $(stored "$instance" ASPMembership) $(stored "$instance" ASPNonMembership); do
    ! grep -qxF "$tree" <<<"$CHECKED" || continue
    CHECKED+=$'\n'"$tree"
    # A tree another party runs keeps its own admin, which no manifest entry names.
    check "$tree" "Admin (read by $pool)" "$ADMIN" \
      "$(read_address "$tree" Admin || echo unreadable)" notice
    check "$tree" PendingAdmin none "$(read_address "$tree" PendingAdmin || echo unreadable)"
  done
done

step "checking the custody of the admin account"
# Local and integration deployments use one key as the admin, so a custody failure fails the run
# only on mainnet.
MAINNET_PASSPHRASE="Public Global Stellar Network ; September 2015"
PASSPHRASE="$(stellar network info --network "$NETWORK" --output json \
  | jq -r '.passphrase // empty' || true)"
CUSTODY=notice
if [[ -n "$PASSPHRASE" ]]; then
  [[ "$PASSPHRASE" != "$MAINNET_PASSPHRASE" ]] || CUSTODY=FAIL
else
  [[ "$NETWORK" != mainnet ]] || CUSTODY=FAIL
fi
ACCOUNT="$(stellar ledger entry fetch account --account "$ADMIN" --network "$NETWORK" \
  | jq -c '.entries[0].val.account' || echo null)"
if [[ "$ACCOUNT" == null ]]; then
  check "$ADMIN" account "an account" unreadable "$CUSTODY"
else
  # Four hex bytes: the master key's weight, then the low, medium, and high thresholds.
  THRESHOLDS="$(jq -r '.thresholds' <<<"$ACCOUNT")"
  SIGNERS="$(jq '.signers | length' <<<"$ACCOUNT")"
  MASTER=$((16#${THRESHOLDS:0:2}))
  LOW=$((16#${THRESHOLDS:2:2}))
  MEDIUM=$((16#${THRESHOLDS:4:2}))
  HIGH=$((16#${THRESHOLDS:6:2}))
  check "$ADMIN" "master weight" 0 "$MASTER" "$CUSTODY"
  check "$ADMIN" thresholds "$HIGH $HIGH $HIGH" "$LOW $MEDIUM $HIGH" "$CUSTODY"
  # With every signer an ed25519 key of weight 1, the signer count is the total weight, and no
  # single key, hash, or pre-authorized transaction meets a threshold of 2 alone.
  KEYS="ed25519 keys of weight 1"
  check "$ADMIN" signers "$KEYS" "$(jq -r --arg keys "$KEYS" 'if all(.signers[];
    .weight == 1 and (.key | startswith("G"))) then $keys
    else [.signers[] | "\(.key):\(.weight)"] | join(" ") end' <<<"$ACCOUNT")" "$CUSTODY"
  # One signature survives no stolen signer, and more than the signers can give is never met.
  QUORUM="at least 2, at most $SIGNERS signers"
  ((HIGH >= 2 && HIGH <= SIGNERS)) && GOT="$QUORUM" || GOT="$HIGH"
  check "$ADMIN" threshold "$QUORUM" "$GOT" "$CUSTODY"
fi

ADDED="$(jq -r '(.added_asp_memberships // [])[] | "\(.contractId) \(.deploymentLedger | tojson)"' \
  "$MANIFEST")"
if [[ -n "$ADDED" ]]; then
  step "checking that clients can index every added allowlist"
  HEALTH="$(stellar network health --network "$NETWORK" --output json)"
  OLDEST="$(jq .oldestLedger <<<"$HEALTH")"
  LATEST="$(jq .latestLedger <<<"$HEALTH")"
  LEAF_ADDED="$(printf '{"symbol":"LeafAdded"}' | stellar xdr encode --type ScVal)"
  while read -r id ledger <&3; do
    # The bootnode fetches a new allowlist's events from its deployment ledger when it restarts,
    # and refuses the allowlist for good once its upstream no longer holds that ledger. An
    # allowlist the base manifest names was fetched when it was added.
    label=notice
    [[ -z "$BASE_MANIFEST" ]] || grep -qxF "$id" <<<"$(allowlists "$BASE_MANIFEST")" || label=FAIL
    # Clients parse the ledger only as a u32 JSON number, which `tojson` prints as at most ten
    # bare digits. Arithmetic on any other text can run a command substitution in it.
    [[ "$ledger" =~ ^[0-9]{1,10}$ ]] \
      || { check "$id" deploymentLedger "a ledger number" "$ledger"; continue; }
    # A ledger after the latest one is a typo, so it fails whatever the base manifest names.
    ((ledger <= LATEST)) || { check "$id" "deploymentLedger $ledger" "a closed ledger" \
      "after the latest ledger $LATEST"; continue; }
    ((ledger >= OLDEST)) && got="held by the RPC" || got="older than its oldest ledger $OLDEST"
    check "$id" "deploymentLedger $ledger" "held by the RPC" "$got" "$label"
    ((ledger >= OLDEST)) || continue
    if [[ "$label" == FAIL ]]; then
      ((ledger - OLDEST >= 17280)) && got="a day or more" \
        || got="$((ledger - OLDEST)) ledgers, restart the bootnode before then"
      check "$id" "retention left" "a day or more" "$got" notice
    fi
    # Clients index the allowlist from its deployment ledger, so they miss any leaf added before
    # it. One getEvents call scans at most 10,000 ledgers, and the CLI reports a call that finds
    # no event on stderr.
    index="" from="$ledger"
    while [[ -z "$index" ]] && ((from <= LATEST)); do
      index="$(stellar events --network "$NETWORK" --start-ledger "$from" --id "$id" \
        --topic "$LEAF_ADDED" --count 1 --output json 2>/dev/null \
        | jq -r '.params.index // "unreadable"' || echo unreadable)"
      from=$((from + 10000))
    done
    # With no leaf since the deployment ledger, the next one takes index NextIndex.
    [[ -n "$index" ]] || index="$(read_entry "$id" "$(unit_key NextIndex)" \
      | jq -r '.u64 // "unreadable"' || echo unreadable)"
    check "$id" "index of the first leaf from ledger $ledger" 0 "$index"
  done 3<<<"$ADDED"
fi

exit "$FAILED"
