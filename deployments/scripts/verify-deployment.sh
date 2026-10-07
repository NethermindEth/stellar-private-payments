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
  -h, --help         Show this help

Checks:
  - Every contract the manifest names has the manifest's admin and no pending
    admin transfer. An allowlist another party runs is checked against the
    admin its added_asp_memberships entry names.
  - The manifest names at most 25 contracts for clients to index: its enabled
    pools, its allowlists, and the public key registry.
  - Every pool's token is its asset's own Stellar asset contract, and a classic
    asset's issuer has AUTH_IMMUTABLE set and neither AUTH_REVOCABLE nor
    AUTH_CLAWBACK_ENABLED. A pool whose asset is a contract token fails.
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

Exits 1 when any check failed, 0 otherwise.
USAGE
  exit 2
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

NETWORK="${1:-}"
shift || true

MANIFEST=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest) MANIFEST="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$NETWORK" ]] || usage
need stellar
need jq

MANIFEST="${MANIFEST:-$ROOT_DIR/deployments/$NETWORK/deployments.json}"
[[ -f "$MANIFEST" ]] || die "manifest not found: $MANIFEST"

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

# Prints the address under a unit-variant key (a one-symbol ScVec, built as XDR), or `none`.
read_address() {
  local key
  key="$(printf '{"vec":[{"symbol":"%s"}]}' "$2" | stellar xdr encode --type ScVal)"
  read_entry "$1" "$key" | jq -r '.address // "none"'
}

# Prints the address that an instance entry from `read_entry` stores under a unit-variant key, or
# nothing.
stored() {
  jq -r --arg key "$2" '.contract_instance.storage[]? | select(.key.vec[0].symbol == $key)
    | .val.address' <<<"$1"
}

ADMIN="$(jq -r '.admin' "$MANIFEST")"
DEPLOYER="$(jq -r '.deployer' "$MANIFEST")"
# Disabled pools too: `enabled` only hides a pool from clients; on chain it still takes deposits.
POOLS="$(jq -r '.pools[].poolContractId' "$MANIFEST")"
ALLOWLISTS="$(jq -r '.asp_membership, (.added_asp_memberships // [])[].contractId' "$MANIFEST")"

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
    # AUTH_REVOCABLE (2) lets the issuer freeze a balance and AUTH_CLAWBACK_ENABLED (8) lets it
    # take one. AUTH_IMMUTABLE (4) stops it from ever setting either.
    rule="AUTH_IMMUTABLE without AUTH_REVOCABLE or AUTH_CLAWBACK_ENABLED"
    [[ "$flags" =~ ^[0-9]+$ ]] && (((flags & 14) == 4)) && got="$rule" || got="flags $flags"
    check "$pool" "issuer $issuer" "$rule" "$got"
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
CUSTODY=notice
[[ "$NETWORK" != mainnet ]] || CUSTODY=FAIL
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

exit "$FAILED"
