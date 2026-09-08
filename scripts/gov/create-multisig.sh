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

Arguments:
  network            Network name from Stellar CLI config (e.g. testnet, futurenet)

Options:
  --account ALIAS    Stellar identity that owns the account and signs the change (required)
  --signer ADDRESS   Signer to add with weight 1 (repeatable, required)
  --threshold N      Signatures every later operation needs (required)
  --fund             Fund the account before the change, on a network with a friendbot
  --rpc-url URL      RPC to read the signer list back from (default: the network's own)
  --yes              Skip confirmation for mainnet
  -h, --help         Show this help

Example:
  scripts/gov/create-multisig.sh testnet --account council --threshold 3 \
    --signer GA... --signer GB... --signer GC... --signer GD... --signer GE...
USAGE
  exit 2
}

NETWORK="${1:-}"
shift || true

ACCOUNT=""
THRESHOLD=""
RPC_URL=""
FUND=false
YES=false
SIGNERS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --account) ACCOUNT="$2"; shift 2 ;;
    --signer) SIGNERS+=("$2"); shift 2 ;;
    --threshold) THRESHOLD="$2"; shift 2 ;;
    --fund) FUND=true; shift ;;
    --rpc-url) RPC_URL="$2"; shift 2 ;;
    --yes) YES=true; shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$NETWORK" ]] || usage
need stellar
need jq
need curl

[[ -n "$ACCOUNT" ]] || die "--account is required"
[[ -n "$THRESHOLD" ]] || die "--threshold is required"
[[ ${#SIGNERS[@]} -gt 0 ]] || die "at least one --signer is required"

if [[ "$NETWORK" == "mainnet" && "$YES" != "true" ]]; then
  die "mainnet requires --yes"
fi

[[ "$THRESHOLD" =~ ^[0-9]+$ && "$THRESHOLD" -gt 0 ]] || die "--threshold must be a positive number"
[[ "$THRESHOLD" -le ${#SIGNERS[@]} ]] \
  || die "--threshold $THRESHOLD is above the ${#SIGNERS[@]} signers given"
[[ "$(printf '%s\n' "${SIGNERS[@]}" | sort -u | wc -l)" -eq ${#SIGNERS[@]} ]] \
  || die "the same signer was given twice"

# Resolved before anything is sent, because the signer list is read back over this url and
# the built-in mainnet entry carries prose where a url would be.
if [[ -z "$RPC_URL" ]]; then
  RPC_URL="$(stellar network ls --long \
    | awk -v want="Name: $NETWORK" '$0 == want { found = 1 } found && /^RPC url:/ { print $3; exit }')"
fi
[[ "$RPC_URL" =~ ^https?:// ]] \
  || die "no RPC url for network '$NETWORK'; configure the network or pass --rpc-url"

ACCOUNT_ADDR="$(stellar keys address "$ACCOUNT")"

if [[ "$FUND" == "true" ]]; then
  [[ "$NETWORK" != "mainnet" ]] || die "--fund has no friendbot on mainnet"
  step "funding $ACCOUNT_ADDR"
  stellar keys fund "$ACCOUNT" --network "$NETWORK"
fi

# The master weight drops to zero in the same transaction that adds the signers, and the
# network checks the signature against the account as it was before the transaction, so the
# account's own key is enough to authorize the change.
step "building the signer set for $ACCOUNT_ADDR"
# One operation per signer plus the one that sets the thresholds, each charged the 100-stroop
# base fee. See https://developers.stellar.org/docs/learn/fundamentals/fees-resource-limits-metering.
INCLUSION_FEE=$(( (${#SIGNERS[@]} + 1) * 100 ))
TX=""
for signer in "${SIGNERS[@]}"; do
  if [[ -z "$TX" ]]; then
    TX="$(stellar tx new set-options --source-account "$ACCOUNT" --network "$NETWORK" \
      --build-only --inclusion-fee "$INCLUSION_FEE" --signer "$signer" --signer-weight 1)"
  else
    TX="$(stellar tx operation add set-options --source-account "$ACCOUNT" \
      --network "$NETWORK" --build-only --signer "$signer" --signer-weight 1 <<<"$TX")"
  fi
done
TX="$(stellar tx operation add set-options --source-account "$ACCOUNT" --network "$NETWORK" \
  --build-only --low-threshold "$THRESHOLD" --med-threshold "$THRESHOLD" \
  --high-threshold "$THRESHOLD" --master-weight 0 <<<"$TX")"

step "signing with the account's own key and sending"
stellar tx sign --sign-with-key "$ACCOUNT" --network "$NETWORK" <<<"$TX" \
  | stellar tx send --network "$NETWORK"

step "signers now on $ACCOUNT_ADDR"
KEY="$(printf '{"account":{"account_id":"%s"}}' "$ACCOUNT_ADDR" | stellar xdr encode --type LedgerKey)"
curl -sS -X POST "$RPC_URL" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getLedgerEntries\",\"params\":{\"keys\":[\"$KEY\"]}}" \
  | jq -r '.result.entries[0].xdr' \
  | stellar xdr decode --type LedgerEntryData --output json \
  | jq '.account | {signers, thresholds}'
