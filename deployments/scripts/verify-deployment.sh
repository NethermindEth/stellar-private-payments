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

Exits 1 when any check failed, 0 otherwise. A manifest with no governance block
skips the governance checks with a notice and still passes.
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

check() {
  local contract="$1" key="$2" want="$3" got="$4"
  if [[ "$want" == "$got" ]]; then
    printf 'ok %s %s\n' "$contract" "$key"
  else
    printf 'FAIL %s %s: expected %s, got %s\n' "$contract" "$key" "$want" "$got"
    FAILED=1
  fi
}

# Every DataKey variant is a unit variant, which the SDK encodes as a one-symbol ScVec, so
# `stellar contract read --key` cannot address the entry and the key is built as XDR instead.
read_entry() {
  local key out
  key="$(printf '{"vec":[{"symbol":"%s"}]}' "$2" | stellar xdr encode --type ScVal)"
  # The status is kept so a caller can tell an unreadable entry from a wrong value.
  out="$(stellar contract read --id "$1" --network "$NETWORK" --durability persistent \
    --key-xdr "$key" --output json)" || return 1
  printf '%s' "$out" | tr -d '\n ' | sed 's/""/"/g'
}
read_address() { read_entry "$1" "$2" | grep -Eo '"address":"[GC][A-Z0-9]{55}"' | head -1 | cut -d'"' -f4; }

# Read-only simulation, so the source account only has to exist on the network.
governor_call() {
  stellar contract invoke --id "$GOVERNOR" --source-account "$SOURCE" --network "$NETWORK" \
    --send=no -- "$@"
}

GOVERNANCE="$(jq -c '.governance // empty' "$MANIFEST")"
if [[ -z "$GOVERNANCE" ]]; then
  step "no governance block in $MANIFEST, skipping the governance checks"
else
  step "checking governance wiring in $MANIFEST"

  SOURCE="$(jq -r '.deployer' "$MANIFEST")"
  GOVERNOR="$(jq -r '.governor' <<<"$GOVERNANCE")"
  ASP_MEMBERSHIP="$(jq -r '.asp_membership' "$MANIFEST")"
  ASP_NON_MEMBERSHIP="$(jq -r '.asp_non_membership' "$MANIFEST")"

  check manifest admin "$GOVERNOR" "$(jq -r '.admin' "$MANIFEST")"

  TARGETS="$(jq -r '.asp_membership, .asp_non_membership,
    (.pools[] | select(.enabled) | .poolContractId)' "$MANIFEST")"
  for target in $TARGETS; do
    check "$target" Admin "$GOVERNOR" "$(read_address "$target" Admin || echo "unreadable")"
    check "$target" "fn_role(update_admin)" null \
      "$(governor_call get_fn_role --target "$target" --function update_admin)"
  done

  for role in council operator guardian recovery; do
    holder="$(jq -r --arg role "$role" '.[$role]' <<<"$GOVERNANCE")"
    check "$GOVERNOR" "has_role($role)" true \
      "$(governor_call has_role --member "$holder" --role "$role")"
    # `has_role` is a point query, so it cannot see a second holder the manifest does not
    # name. The count can, and the manifest names exactly one address per role.
    check "$GOVERNOR" "role_member_count($role)" 1 \
      "$(governor_call get_role_member_count --role "$role")"
  done
  check "$GOVERNOR" "has_role(council, operator)" false \
    "$(governor_call has_role --member "$(jq -r '.council' <<<"$GOVERNANCE")" --role operator)"

  # One failing call must not end the run, so the report still names every other check.
  DELAYS="$(governor_call get_delays || true)"
  check "$GOVERNOR" "get_delays(delay)" \
    "$(jq -r '.delay' <<<"$GOVERNANCE")" "$(jq -r '.delay' <<<"$DELAYS")"
  check "$GOVERNOR" "get_delays(recovery_delay)" \
    "$(jq -r '.recoveryDelay' <<<"$GOVERNANCE")" "$(jq -r '.recovery_delay' <<<"$DELAYS")"
  check "$GOVERNOR" "get_delays(grace)" \
    "$(jq -r '.grace' <<<"$GOVERNANCE")" "$(jq -r '.grace' <<<"$DELAYS")"
  check "$GOVERNOR" "get_delays(guardian_pause)" \
    "$(jq -r '.guardianPause' <<<"$GOVERNANCE")" "$(jq -r '.guardian_pause' <<<"$DELAYS")"

  check "$ASP_MEMBERSHIP" "fn_role(insert_leaf)" '"operator"' \
    "$(governor_call get_fn_role --target "$ASP_MEMBERSHIP" --function insert_leaf)"
  check "$ASP_NON_MEMBERSHIP" "fn_role(insert_leaf)" '"operator"' \
    "$(governor_call get_fn_role --target "$ASP_NON_MEMBERSHIP" --function insert_leaf)"
  check "$ASP_NON_MEMBERSHIP" "fn_role(delete_leaf)" '"operator"' \
    "$(governor_call get_fn_role --target "$ASP_NON_MEMBERSHIP" --function delete_leaf)"
fi

exit "$FAILED"
