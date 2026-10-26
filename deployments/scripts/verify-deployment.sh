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
  --rebuild DIR      Check the manifest's contracts release against DIR, the
                     release downloaded with `gh release download`, then
                     rebuild every Wasm in DIR and compare hashes (needs Docker)
  --release-repo OWNER/REPO
                     Repository whose contracts-release.yml must have attested
                     DIR (default: NethermindEth/stellar-private-payments)
  --allow-unverified On mainnet, print a notice instead of failing when the
                     manifest records no contracts release. With --rebuild,
                     also print a notice when DIR's attestation cannot be
                     verified
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
    before the registry had a verifier, skips these checks with a notice. A
    manifest that records contracts_release fails without
    public_key_registry_verifier.
  - No contract appears twice among verifiers and public_key_registry_verifier.
  - Every pool stores its manifest entry's policyFlags and gvkMode, and the
    verifier that verifiers lists under the pool's key name, such as B or
    AB_gvk_T. The key name comes from the policy flags and GVK mode the pool
    stores, not from the manifest.
  - Every pool's token is its asset's own Stellar asset contract. A pool whose
    asset is a contract token fails. A classic asset's issuer prints as a notice
    listing each power its flags give it over the pool's balance.
  - Every pool, a disabled one too, stores the manifest's tree code hashes and
    reads an allowlist the manifest names. A manifest without the hashes, from
    before pools stored them, skips these checks with a notice.
  - Every tree a pool reads that the manifest does not name, such as a
    blocklist the pool was re-pointed to, has no pending admin transfer. Its
    admin prints as a notice when it is not the manifest's.
  - Every contract the manifest names, other than an added allowlist, runs the
    code contracts_release.code records for it, and every added allowlist runs
    asp_membership_wasm_hash. A contract with no code entry fails.
    asp_membership_wasm_hash and asp_non_membership_wasm_hash, the tree code
    every pool stores, are the code entries of asp_membership and
    asp_non_membership.
  - The Wasm meta of each of these contracts has exactly one bldopt
    --package=, naming the package that kind of contract is built from:
    pool-gvk for a pool that stores a GVK mode, pool for any other pool. A
    verifier's meta also has exactly one bldopt --features=, naming
    vk-<contracts_release.network>-<key name>. On mainnet,
    contracts_release.network must be the network argument.
  - A manifest without contracts_release prints a notice. On mainnet it fails
    unless --allow-unverified is passed.
  - With --rebuild: contracts_release.repo is --release-repo, and gh verifies
    that contracts-release.yml on that repository's main branch attested
    DIR/SHA256SUMS. With --allow-unverified and no attestation, only the
    vk_sha256 values in DIR/contracts.json say which key each verifier holds.
    That file has contracts_release.tag, and the entry with each contract's
    contracts_release.code hash has the package that contract is built from.
    A verifier's entry also has its key name, contracts_release.network, and
    the SHA-256 of its key file in deployments/<network>/circuit_keys, the
    file deploy.sh picks it by. Last, unless a check above failed,
    scripts/build-contracts.sh --rebuild DIR rebuilds every Wasm and compares
    hashes.
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
REBUILD=""
RELEASE_REPO="NethermindEth/stellar-private-payments"
ALLOW_UNVERIFIED=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest) MANIFEST="$2"; shift 2 ;;
    --base-manifest) BASE_MANIFEST="$2"; shift 2 ;;
    --rebuild) REBUILD="$2"; shift 2 ;;
    --release-repo) RELEASE_REPO="$2"; shift 2 ;;
    --allow-unverified) ALLOW_UNVERIFIED=true; shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$NETWORK" ]] || usage
need stellar
need jq

MANIFEST="${MANIFEST:-$ROOT_DIR/deployments/$NETWORK/deployments.json}"
[[ -f "$MANIFEST" ]] || die "manifest not found: $MANIFEST"
HAS_RELEASE="$(jq 'has("contracts_release")' "$MANIFEST")"
[[ -z "$BASE_MANIFEST" || -f "$BASE_MANIFEST" ]] || die "base manifest not found: $BASE_MANIFEST"
[[ -z "$REBUILD" || -d "$REBUILD" ]] || die "release directory not found: $REBUILD"
[[ -z "$REBUILD" || "$HAS_RELEASE" == true ]] \
  || die "--rebuild needs a manifest with contracts_release, which deploy.sh records only with" \
    "--release-dir; run the check without --rebuild"

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

# Prints the hash of the code a contract runs. AAAAFA== is the key of its instance entry, which
# names its code.
code_hash() {
  read_entry "$1" AAAAFA== | jq -r '.contract_instance.executable.wasm // "none"' || echo unreadable
}

# Prints the address or u32 that an instance entry from `read_entry` stores under a unit-variant
# key, or nothing.
stored() {
  jq -r --arg key "$2" '.contract_instance.storage[]? | select(.key.vec[0].symbol == $key)
    | .val | .address // .u32' <<<"$1"
}

# deploy.sh's verifier_key_for, from a pool's on-chain PolicyFlags and GvkMode.
pool_key_name() {
  local policy
  case "$1" in
    0) policy="" ;; 1) policy=A ;; 2) policy=B ;; 3) policy=AB ;; *) echo unknown; return ;;
  esac
  case "$2" in
    "") echo "$policy" ;;
    1) echo "${policy:+${policy}_}gvk_V" ;;
    2) echo "${policy:+${policy}_}gvk_T" ;;
    *) echo unknown ;;
  esac
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
# Only a manifest from before the registry had a verifier lacks one, and it records no release.
if [[ -z "$REGISTRY_VERIFIER" && "$HAS_RELEASE" == false ]]; then
  step "no public_key_registry_verifier in $MANIFEST, skipping the registry checks"
else
  step "checking the public key registry"
  # Read-only simulations, so the source account only has to exist on the network.
  registry_get() {
    stellar contract invoke --id "$REGISTRY" --source-account "$DEPLOYER" --network "$NETWORK" \
      --send=no -- "$1" | jq -r . || echo unreadable
  }
  check "$REGISTRY" get_verifier \
    "${REGISTRY_VERIFIER:-a public_key_registry_verifier in the manifest}" \
    "$(registry_get get_verifier)"
  check "$REGISTRY" get_kdf_domain "$(jq -r '.kdf_domain' "$MANIFEST")" \
    "$(registry_get get_kdf_domain)"
  VERIFIER_HASH="$(jq -r '.public_key_registry_verifier_wasm_hash // empty' "$MANIFEST")"
  if [[ -z "$VERIFIER_HASH" ]]; then
    step "no public_key_registry_verifier_wasm_hash in $MANIFEST, skipping the verifier code check"
  else
    check "$REGISTRY_VERIFIER" "code hash" "$VERIFIER_HASH" "$(code_hash "$REGISTRY_VERIFIER")"
  fi
fi

HASHES="$(jq -c 'select(has("asp_membership_wasm_hash") or has("asp_non_membership_wasm_hash"))
  | [.asp_membership_wasm_hash, .asp_non_membership_wasm_hash]' "$MANIFEST")"
[[ -n "$HASHES" ]] || step "no tree code hashes in $MANIFEST, skipping the tree code checks"
# Trees the admin checks above cover. A re-pointed pool can read others, checked once below.
CHECKED="$(jq -r '.asp_membership, (.added_asp_memberships // [])[].contractId,
  .asp_non_membership' "$MANIFEST")"

step "checking that no verifier is listed twice"
# One contract listed under two key names would pass as either key's verifier.
TWICE="$(jq -r '[.verifiers[]?, .public_key_registry_verifier // empty] | group_by(.)
  | map(select(length > 1)[0] + " listed twice") | join(", ")' "$MANIFEST")"
check manifest verifiers distinct "${TWICE:-distinct}"

# Each contract the manifest names, other than an added allowlist, with the package that builds it
# and a verifier's key name. The pool loop adds the pools, by the GVK mode each one stores.
ROLES="$(jq -r '"\(.asp_membership) asp-membership", "\(.asp_non_membership) asp-non-membership",
  "\(.public_key_registry) public-key-registry",
  (.public_key_registry_verifier // empty | "\(.) circom-groth16-verifier keyOwnership"),
  (.verifiers // {} | to_entries[] | "\(.value) circom-groth16-verifier \(.key)")' "$MANIFEST")"

step "checking the policy, verifier, token, and trees of every pool"
for pool in $POOLS; do
  # AAAAFA== is the key of the contract's instance entry, which holds the pool's token and trees.
  instance="$(read_entry "$pool" AAAAFA==)" \
    || { check "$pool" instance readable unreadable; instance=null; }
  flags="$(stored "$instance" PolicyFlags)"
  gvk="$(stored "$instance" GvkMode)"
  ROLES+=$'\n'"$pool pool${gvk:+-gvk}"
  case "$flags" in
    0) got='[]' ;; 1) got='["allowlist"]' ;; 2) got='["blocklist"]' ;;
    3) got='["allowlist","blocklist"]' ;; *) got="${flags:-none}" ;;
  esac
  check "$pool" PolicyFlags "$(jq -c --arg pool "$pool" \
    'first(.pools[] | select(.poolContractId == $pool)).policyFlags | unique' "$MANIFEST")" "$got"
  case "$gvk" in "") got=off ;; 1) got=viewOnly ;; 2) got=traceable ;; *) got="$gvk" ;; esac
  check "$pool" GvkMode "$(jq -r --arg pool "$pool" \
    'first(.pools[] | select(.poolContractId == $pool)).gvkMode // "off"' "$MANIFEST")" "$got"
  # The key name comes from the chain, so a manifest that misstates the policy cannot pick it.
  key="$(pool_key_name "$flags" "$gvk")"
  verifier="$(stored "$instance" Verifier)"
  check "$pool" Verifier "$(jq -r --arg key "$key" \
    '.verifiers[$key] // "a verifiers entry for key name \(if $key == "" then
      "none (the empty key)" else $key end)"' "$MANIFEST")" \
    "${verifier:-none}"
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

MAINNET_PASSPHRASE="Public Global Stellar Network ; September 2015"
PASSPHRASE="$(stellar network info --network "$NETWORK" --output json \
  | jq -r '.passphrase // empty' || true)"
IS_MAINNET=false
if [[ -n "$PASSPHRASE" ]]; then
  [[ "$PASSPHRASE" != "$MAINNET_PASSPHRASE" ]] || IS_MAINNET=true
else
  [[ "$NETWORK" != mainnet ]] || IS_MAINNET=true
fi

step "checking that every contract runs its release's code"
RELEASE_NETWORK="$(jq -r '.contracts_release.network' "$MANIFEST")"
if [[ "$HAS_RELEASE" == false ]]; then
  # deploy.sh records no release for code it built itself, which mainnet allows only with
  # --allow-unverified.
  label=notice
  [[ "$IS_MAINNET" == false || "$ALLOW_UNVERIFIED" == true ]] || label=FAIL
  check manifest contracts_release "a contracts release" none "$label"
else
  [[ "$IS_MAINNET" == false ]] \
    || check manifest "contracts_release network" "$NETWORK" "$RELEASE_NETWORK"
  # Every pool pins these hashes, so they must be the named trees' release code.
  for tree in asp_membership asp_non_membership; do
    check manifest "${tree}_wasm_hash release code" "$(jq -r --arg t "$tree" \
      '.contracts_release.code[.[$t]] // "a code entry for \($t)"' "$MANIFEST")" \
      "$(jq -r --arg h "${tree}_wasm_hash" '.[$h]' "$MANIFEST")"
  done
  while read -r id pkg key <&3; do
    check "$id" "release code" "$(jq -r --arg id "$id" \
      '.contracts_release.code[$id] // "an entry in contracts_release.code"' "$MANIFEST")" \
      "$(code_hash "$id")"
    want="--package=$pkg" pattern='^--package='
    if [[ "$pkg" == circom-groth16-verifier ]]; then
      # The Cargo feature that embeds this key, named by build.rs's rule.
      want+=" --features=$(printf 'vk-%s-%s' "$RELEASE_NETWORK" "${key:-none}" \
        | tr '[:upper:]' '[:lower:]' | tr _ -)"
      pattern='^--(package|features)='
    fi
    got="$(stellar contract info meta --quiet --contract-id "$id" --network "$NETWORK" \
      --output json | jq -r --arg p "$pattern" \
      '[.[].sc_meta_v0 | select(.key == "bldopt") | .val | select(test($p))] | join(" ")' \
      || echo unreadable)"
    check "$id" role "$want" "${got:-none}"
  done 3<<<"$ROLES"
  for tree in $(jq -r '(.added_asp_memberships // [])[].contractId' "$MANIFEST"); do
    check "$tree" "release code" "$(jq -r '.asp_membership_wasm_hash' "$MANIFEST")" \
      "$(code_hash "$tree")"
  done
fi

if [[ -n "$REBUILD" ]]; then
  step "checking the release in $REBUILD against the manifest"
  check manifest "contracts_release repo" "$RELEASE_REPO" \
    "$(jq -r '.contracts_release.repo' "$MANIFEST")"
  attested="an attestation by contracts-release.yml on main in $RELEASE_REPO"
  if ! command -v gh >/dev/null 2>&1; then
    got="none, because gh is not installed"
  elif gh attestation verify "$REBUILD/SHA256SUMS" \
    --repo "$RELEASE_REPO" --source-ref refs/heads/main --deny-self-hosted-runners \
    --cert-identity "https://github.com/$RELEASE_REPO/.github/workflows/contracts-release.yml@refs/heads/main" \
    >&2; then
    got="$attested"
  else
    got="none that gh could verify (its error is above)"
  fi
  [[ "$got" == "$attested" ]] \
    || got+=", so only $REBUILD/contracts.json vouches for the key each verifier holds"
  label=FAIL
  [[ "$ALLOW_UNVERIFIED" == false ]] || label=notice
  check "$REBUILD/SHA256SUMS" attestation "$attested" "$got" "$label"
  RELEASE_JSON="$REBUILD/contracts.json"
  check "$RELEASE_JSON" tag "$(jq -r '.contracts_release.tag' "$MANIFEST")" \
    "$(jq -r .tag "$RELEASE_JSON")"
  # Prints the role fields of the release's entry for code hash $1.
  release_role() {
    jq -rc --arg hash "$1" 'first(.contracts[] | select(.sha256 == $hash)
      | {package, network, key_name, vk_sha256} | with_entries(select(.value != null)))
      // "no entry with this hash"' "$RELEASE_JSON"
  }
  sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$1" | cut -d' ' -f1
    else
      shasum -a 256 "$1" | cut -d' ' -f1
    fi
  }
  while read -r id pkg key <&3; do
    want="$(printf '{"package":"%s"}' "$pkg")"
    if [[ "$pkg" == circom-groth16-verifier ]]; then
      vk="policy_tx_2_2${key:+_$key}_vk.json"
      [[ "$key" != keyOwnership ]] || vk=keyOwnership_vk.json
      want="$(jq -cn --arg package "$pkg" --arg network "$RELEASE_NETWORK" --arg key_name "$key" \
        --arg vk_sha256 "$(sha256 "$ROOT_DIR/deployments/$NETWORK/circuit_keys/$vk")" \
        '{$package, $network, $key_name, $vk_sha256}')"
    fi
    check "$id" "release role" "$want" \
      "$(release_role "$(jq -r --arg id "$id" '.contracts_release.code[$id]' "$MANIFEST")")"
  done 3<<<"$ROLES"
  # A rebuild takes minutes, and a failed check above already fails the run.
  got="skipped, since a check above failed"
  if [[ "$FAILED" == 0 ]]; then
    step "rebuilding every Wasm in $REBUILD"
    got="every Wasm rebuilt to its hash"
    "$ROOT_DIR/scripts/build-contracts.sh" --rebuild "$REBUILD" >&2 \
      || got="build-contracts.sh --rebuild failed, see above"
  fi
  check "$REBUILD" rebuild "every Wasm rebuilt to its hash" "$got"
fi

step "checking the custody of the admin account"
# Local and integration deployments use one key as the admin, so a custody failure fails the run
# only on mainnet.
CUSTODY=notice
[[ "$IS_MAINNET" == false ]] || CUSTODY=FAIL
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
