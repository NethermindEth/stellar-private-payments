#!/usr/bin/env bash
# Turn a Stellar account into a multisig account with a signing threshold.
# Usage: create-multisig.sh <network> [options]

set -euo pipefail

die() { echo "create-multisig.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
step() { echo "==> $*" >&2; }

usage() {
  cat >&2 <<'USAGE'
Usage: create-multisig.sh <network> --account ALIAS --signer ADDRESS --threshold N [OPTIONS]

Gives an account a set of signers, each of weight 1, sets its low, medium, and
high thresholds to the same number, and disables its master key. One transaction
carries all of it, so the account never sits without a working signer set.

Never merge the account. Anyone can create it again at the same address, and it
comes back with its master key as the only signer.

Arguments:
  network            Network name from Stellar CLI config (e.g. testnet, futurenet)

Options:
  --account ALIAS    Stellar identity that owns the account and signs the change (required)
  --signer ADDRESS   Signer to add with weight 1 (repeatable, required)
  --threshold N      Signatures every later operation needs, at least 2 (required)
  --fund             Fund the account before the change, on a network with a friendbot
  --yes              Skip confirmation for mainnet
  -h, --help         Show this help

Example:
  scripts/gov/create-multisig.sh testnet --account admin --threshold 2 \
    --signer GA... --signer GB... --signer GC...
USAGE
  exit 2
}

NETWORK="${1:-}"
shift || true

ACCOUNT=""
THRESHOLD=""
FUND=false
YES=false
SIGNERS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --account) ACCOUNT="$2"; shift 2 ;;
    --signer) SIGNERS+=("$2"); shift 2 ;;
    --threshold) THRESHOLD="$2"; shift 2 ;;
    --fund) FUND=true; shift ;;
    --yes) YES=true; shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$NETWORK" ]] || usage
need stellar
need jq

[[ -n "$ACCOUNT" ]] || die "--account is required"
[[ -n "$THRESHOLD" ]] || die "--threshold is required"
[[ ${#SIGNERS[@]} -gt 0 ]] || die "at least one --signer is required"

if [[ "$NETWORK" == "mainnet" && "$YES" != "true" ]]; then
  die "mainnet requires --yes"
fi

# Addresses only: the CLI resolves aliases, so an alias plus its address would count as two signers
# and leave the account short of its threshold.
for signer in "${SIGNERS[@]}"; do
  [[ "$signer" =~ ^G[A-Z2-7]{55}$ ]] || die "--signer takes an account address (G...), got $signer"
done
[[ "$THRESHOLD" =~ ^[0-9]+$ && "$THRESHOLD" -ge 2 ]] \
  || die "--threshold must be 2 or more: a 1-of-N account survives no stolen signer"
[[ "$THRESHOLD" -le ${#SIGNERS[@]} ]] \
  || die "--threshold $THRESHOLD is above the ${#SIGNERS[@]} signers given"
[[ "$(printf '%s\n' "${SIGNERS[@]}" | sort -u | wc -l)" -eq ${#SIGNERS[@]} ]] \
  || die "the same signer was given twice"

ACCOUNT_ADDR="$(stellar keys address "$ACCOUNT")"

if [[ "$FUND" == "true" ]]; then
  [[ "$NETWORK" != "mainnet" ]] || die "--fund has no friendbot on mainnet"
  step "funding $ACCOUNT_ADDR"
  stellar keys fund "$ACCOUNT" --network "$NETWORK"
fi

# An existing signer would keep its weight beside the new set, possibly enough to act alone.
EXISTING="$(stellar ledger entry fetch account --account "$ACCOUNT" --network "$NETWORK" \
  --output json | jq '.entries[0].val.account.signers | length')"
[[ "$EXISTING" -eq 0 ]] || die "$ACCOUNT_ADDR already has $EXISTING signers; start from a fresh account"

# The network checks signatures against the account as it was before the transaction, so the
# account's own key can authorize the change that sets its weight to zero.
step "building the signer set for $ACCOUNT_ADDR"
# One operation per signer plus the one that sets the thresholds, each charged the 100-stroop
# base fee. See https://developers.stellar.org/docs/learn/fundamentals/fees-resource-limits-metering.
INCLUSION_FEE=$(( (${#SIGNERS[@]} + 1) * 100 ))
TX="$(stellar tx new set-options --source-account "$ACCOUNT" --network "$NETWORK" --build-only \
  --inclusion-fee "$INCLUSION_FEE" --low-threshold "$THRESHOLD" --med-threshold "$THRESHOLD" \
  --high-threshold "$THRESHOLD" --master-weight 0)"
for signer in "${SIGNERS[@]}"; do
  TX="$(stellar tx operation add set-options --source-account "$ACCOUNT" --network "$NETWORK" \
    --build-only --signer "$signer" --signer-weight 1 <<<"$TX")"
done

step "signing with the account's own key and sending"
stellar tx sign --sign-with-key "$ACCOUNT" --network "$NETWORK" <<<"$TX" \
  | stellar tx send --network "$NETWORK"

step "signers now on $ACCOUNT_ADDR"
stellar ledger entry fetch account --account "$ACCOUNT" --network "$NETWORK" --output json \
  | jq '.entries[0].val.account | {signers, thresholds}'
