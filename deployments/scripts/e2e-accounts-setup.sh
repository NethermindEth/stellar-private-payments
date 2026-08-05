#!/usr/bin/env bash
# Provision the two test accounts the web-client e2e suite drives (issue #168).
# Usage: e2e-accounts-setup.sh [options]

set -euo pipefail

die() { echo "e2e-accounts-setup.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
step() { echo "==> $*" >&2; }
warn() { echo "warning: $*" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

NETWORK="testnet"
RPC_URL="https://soroban-testnet.stellar.org"
FRIENDBOT_URL="https://friendbot.stellar.org"
# Only the two accounts are needed: the target pool is the native XLM pool
# (policyFlags ["blocklist"]), which requires NO ASP membership leaf and hence
# no admin secret (membership proofs are Allowlist-gated —
# sdk/types/src/policy_tx.rs; the pool's flags are in
# deployments/testnet/deployments.json).
POOL_CONTRACT="CB6ESM54AS5S3WBLO6LFIZMT5BMXR2DUGMYFUWDXUPM73BPHVHHQAHKE"
# Passed explicitly to `spp onboard` so it never falls through to a prompt.
EXPLORER_URL="https://stellar.expert/explorer/testnet"

ALIAS_PREFIX="spp-e2e"
VERIFY_ONLY=0
FORCE=0
FUND_RETRIES=6

usage() {
  cat >&2 <<'USAGE'
Usage: e2e-accounts-setup.sh [OPTIONS]

Creates, funds and registers the two Stellar test accounts used by the
web-client e2e suite, then records them in deployments/<network>/.e2e-accounts.env
(git-ignored; contains secret keys).

What each account gets:
  1. a keypair in the `stellar keys` keystore (alias <prefix>-a / <prefix>-b)
  2. testnet XLM via friendbot (with retry/backoff)
  3. privacy keys derived and note/encryption public keys registered in the
     on-chain public-key registry, via `spp onboard` invoked fully
     non-interactively (every prompt pre-answered by an explicit flag, so a
     TTY-less CI run behaves identically to a local one)

Deliberately NOT done: inserting ASP membership leaves. The target pool carries
policyFlags ["blocklist"], so membership proofs are not required and the ASP
membership contract's insert_leaf is admin-only. Registration here means the
PUBLIC-KEY REGISTRY, which is self-service. If a future run targets the EURC
pool (policyFlags ["allowlist","blocklist"]) this script is NOT sufficient: that
needs the deployment admin secret plus an EURC trustline.

Options:
  --network NAME        Stellar CLI network name (default: testnet)
  --rpc-url URL         Soroban RPC endpoint (default: https://soroban-testnet.stellar.org)
  --explorer-url URL    Explorer base URL recorded during onboarding
                        (default: https://stellar.expert/explorer/testnet)
  --alias-prefix NAME   Keystore alias prefix (default: spp-e2e)
  --verify              Re-check existing accounts without creating anything
  --force               Recreate accounts even if the env file already exists
  --fund-retries N      Friendbot attempts per account (default: 6)
  -h, --help            Show this help

Idempotency:
  With an existing env file and no --force, the script verifies instead of
  provisioning (identical to --verify). --force regenerates keypairs and
  overwrites the env file.

Examples:
  deployments/scripts/e2e-accounts-setup.sh
  deployments/scripts/e2e-accounts-setup.sh --verify
  deployments/scripts/e2e-accounts-setup.sh --force --alias-prefix ci-e2e
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --network) [ $# -ge 2 ] || die "--network needs a value"; NETWORK="$2"; shift 2 ;;
    --rpc-url) [ $# -ge 2 ] || die "--rpc-url needs a value"; RPC_URL="$2"; shift 2 ;;
    --explorer-url) [ $# -ge 2 ] || die "--explorer-url needs a value"; EXPLORER_URL="$2"; shift 2 ;;
    --alias-prefix) [ $# -ge 2 ] || die "--alias-prefix needs a value"; ALIAS_PREFIX="$2"; shift 2 ;;
    --fund-retries) [ $# -ge 2 ] || die "--fund-retries needs a value"; FUND_RETRIES="$2"; shift 2 ;;
    --verify) VERIFY_ONLY=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument '$1'" ;;
  esac
done

case "$FUND_RETRIES" in
  ''|*[!0-9]*) die "--fund-retries must be a positive integer" ;;
  *) [ "$FUND_RETRIES" -ge 1 ] || die "--fund-retries must be >= 1" ;;
esac

ENV_DIR="$REPO_ROOT/deployments/$NETWORK"
ENV_FILE="$ENV_DIR/.e2e-accounts.env"
# Isolated wallet/data dir so a run never touches a developer's real spp state.
DATA_DIR="$REPO_ROOT/deployments/scripts/.e2e-wallet-$NETWORK"

ALIAS_A="$ALIAS_PREFIX-a"
ALIAS_B="$ALIAS_PREFIX-b"

need stellar
need curl
need git

# `spp` if installed on PATH, else run the workspace CLI from source.
# `type -P` (not `command -v`) because `command -v spp` would find THIS
# function and always take the first branch.
spp() {
  local spp_bin
  spp_bin="$(type -P spp || true)"
  if [ -n "$spp_bin" ]; then
    "$spp_bin" "$@"
  else
    ( cd "$REPO_ROOT" && cargo run --quiet --release -p stellar-private-payments-cli -- "$@" )
  fi
}

assert_env_file_ignored() {
  # Never let secret material become committable.
  ( cd "$REPO_ROOT" && git check-ignore -q "$ENV_FILE" ) \
    || die "$ENV_FILE is not git-ignored; add it to .gitignore before continuing"
}

address_for_alias() {
  stellar keys address "$1" --config-dir "$DATA_DIR/stellar" 2>/dev/null || true
}

ensure_keypair() {
  local alias="$1"
  if [ "$FORCE" -eq 0 ] && [ -n "$(address_for_alias "$alias")" ]; then
    step "keypair '$alias' already exists"
    return 0
  fi
  step "generating keypair '$alias'"
  # `stellar keys generate` does not fund unless asked (--fund); friendbot
  # funding is done separately below so it can retry with backoff.
  # bash 3.2 + `set -u` errors on "${arr[@]}" when empty; this form is safe.
  local extra=()
  [ "$FORCE" -eq 1 ] && extra+=(--overwrite)
  stellar keys generate "$alias" \
    --network "$NETWORK" \
    --config-dir "$DATA_DIR/stellar" \
    ${extra[@]+"${extra[@]}"}
}

account_exists_on_chain() {
  local address="$1"
  # Friendbot-funded accounts are visible on Horizon; a 404 means unfunded.
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' "https://horizon-testnet.stellar.org/accounts/$address" || echo "000")"
  [ "$code" = "200" ]
}

fund_account() {
  local address="$1" attempt=1 delay=2
  if account_exists_on_chain "$address"; then
    step "account already funded"
    return 0
  fi
  while [ "$attempt" -le "$FUND_RETRIES" ]; do
    step "friendbot funding attempt $attempt/$FUND_RETRIES"
    if curl -fsS "$FRIENDBOT_URL/?addr=$address" >/dev/null 2>&1; then
      if account_exists_on_chain "$address"; then
        step "funded"
        return 0
      fi
    fi
    # Friendbot is a shared, rate-limited faucet: back off rather than hammer it.
    sleep "$delay"
    delay=$((delay * 2))
    attempt=$((attempt + 1))
  done
  die "friendbot funding failed for $address after $FUND_RETRIES attempts"
}

# Derive privacy keys, accept the disclaimer, and register public keys on-chain.
# `spp onboard --register` is the self-service path the real client uses; no
# admin authority is involved.
#
# Every prompt is pre-answered by an explicit flag so behavior does not depend
# on stdin being a TTY: --accept (cli/src/onboard.rs:83), --no-bootnode
# (onboard.rs:154), --explorer-url (onboard.rs:190) and --register
# (onboard.rs:212) each short-circuit BEFORE their interactive branch. Relying
# on EOF-means-default instead would be fragile in CI.
# --no-bootnode: the provisioned account config needs no bootnode; the e2e tests
# pass bootnode_url to Client::new themselves if they ever need one.
onboard_account() {
  local alias="$1"
  step "onboarding + registering '$alias'"
  spp --account "$alias" \
      --network "$NETWORK" \
      --data-dir "$DATA_DIR" \
      --stellar-config-dir "$DATA_DIR/stellar" \
      onboard --accept --register --no-bootnode --explorer-url "$EXPLORER_URL"
}

registration_status() {
  local alias="$1"
  spp --account "$alias" \
      --network "$NETWORK" \
      --data-dir "$DATA_DIR" \
      --stellar-config-dir "$DATA_DIR/stellar" \
      --json \
      overview "$POOL_CONTRACT" 2>/dev/null || true
}

verify_account() {
  local alias="$1" address="$2" label="$3"
  step "verifying $label ($alias)"

  [ -n "$address" ] || die "$label has no address recorded"

  account_exists_on_chain "$address" \
    || die "$label $address is not funded on $NETWORK"

  local overview
  overview="$(registration_status "$alias")"
  [ -n "$overview" ] || die "$label: could not read overview for $address (is the CLI built?)"

  # `overview --json` reports registration state; require an explicit true.
  case "$overview" in
    *'"registered":true'*|*'"registered": true'*)
      step "$label registered in the public-key registry" ;;
    *)
      die "$label $address is not registered in the public-key registry (run without --verify)" ;;
  esac
}

write_env_file() {
  local addr_a="$1" secret_a="$2" addr_b="$3" secret_b="$4"
  mkdir -p "$ENV_DIR"
  assert_env_file_ignored

  # Create with restrictive permissions BEFORE writing secrets into it.
  local tmp="$ENV_FILE.tmp"
  rm -f "$tmp"
  (umask 077 && : > "$tmp")
  cat > "$tmp" <<ENVFILE
# Generated by deployments/scripts/e2e-accounts-setup.sh — DO NOT COMMIT.
# Contains $NETWORK secret keys. This file is git-ignored.
E2E_NETWORK=$NETWORK
E2E_RPC_URL=$RPC_URL
E2E_POOL_CONTRACT=$POOL_CONTRACT
E2E_ACCOUNT_A_ALIAS=$ALIAS_A
E2E_ACCOUNT_A_ADDRESS=$addr_a
E2E_ACCOUNT_A_SECRET=$secret_a
E2E_ACCOUNT_B_ALIAS=$ALIAS_B
E2E_ACCOUNT_B_ADDRESS=$addr_b
E2E_ACCOUNT_B_SECRET=$secret_b
ENVFILE
  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"
  step "wrote $ENV_FILE (mode 600)"
}

secret_for_alias() {
  stellar keys secret "$1" --config-dir "$DATA_DIR/stellar"
}

do_verify() {
  [ -f "$ENV_FILE" ] || die "$ENV_FILE not found; run without --verify to provision"
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  verify_account "${E2E_ACCOUNT_A_ALIAS:-$ALIAS_A}" "${E2E_ACCOUNT_A_ADDRESS:-}" "account A"
  verify_account "${E2E_ACCOUNT_B_ALIAS:-$ALIAS_B}" "${E2E_ACCOUNT_B_ADDRESS:-}" "account B"
  step "verification passed for both accounts"
}

do_provision() {
  assert_env_file_ignored
  mkdir -p "$DATA_DIR"

  ensure_keypair "$ALIAS_A"
  ensure_keypair "$ALIAS_B"

  local addr_a addr_b
  addr_a="$(address_for_alias "$ALIAS_A")"
  addr_b="$(address_for_alias "$ALIAS_B")"
  [ -n "$addr_a" ] || die "could not resolve address for $ALIAS_A"
  [ -n "$addr_b" ] || die "could not resolve address for $ALIAS_B"
  [ "$addr_a" != "$addr_b" ] || die "both aliases resolved to the same address"

  step "account A: $addr_a"
  step "account B: $addr_b"

  fund_account "$addr_a"
  fund_account "$addr_b"

  onboard_account "$ALIAS_A"
  onboard_account "$ALIAS_B"

  # Secrets are read straight into the env file; never echoed.
  write_env_file \
    "$addr_a" "$(secret_for_alias "$ALIAS_A")" \
    "$addr_b" "$(secret_for_alias "$ALIAS_B")"

  verify_account "$ALIAS_A" "$addr_a" "account A"
  verify_account "$ALIAS_B" "$addr_b" "account B"

  step "provisioning complete"
}

main() {
  if [ "$VERIFY_ONLY" -eq 1 ]; then
    do_verify
    return
  fi
  if [ -f "$ENV_FILE" ] && [ "$FORCE" -eq 0 ]; then
    step "$ENV_FILE exists; verifying instead of provisioning (use --force to recreate)"
    do_verify
    return
  fi
  do_provision
}

main
