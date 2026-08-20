#!/usr/bin/env bash
# Provision the two test accounts used by the SDK wasm e2e suite.
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
POOL_CONTRACT=""
EXPLORER_URL="https://stellar.expert/explorer/testnet"

ALIAS_PREFIX="spp-e2e"
VERIFY_ONLY=0
FORCE=0
FUND_RETRIES=6

usage() {
  cat >&2 <<'USAGE'
Usage: e2e-accounts-setup.sh [OPTIONS]

Creates, funds and registers the two Stellar test accounts used by the SDK
wasm e2e suite, then writes their material to
deployments/<network>/.e2e-accounts.env (git-ignored; contains secret keys).

What each account gets:
  1. a keypair in the `stellar keys` keystore (alias <prefix>-a / <prefix>-b)
  2. testnet XLM via friendbot (with retry/backoff)
  3. privacy keys derived and note/encryption public keys registered on-chain
     via `spp onboard --register`

Membership leaves are not inserted: the target native XLM pool is
blocklist-only, so membership proofs are not required.

Options:
  --verify              Re-check existing accounts without creating anything
  --force               Recreate accounts even if the env file already exists
  -h, --help            Show this help

Idempotency:
  With an existing env file and no --force, the script verifies instead of
  provisioning (identical to --verify). --force regenerates both keypairs and
  overwrites the env file.

Examples:
  deployments/scripts/e2e-accounts-setup.sh
  deployments/scripts/e2e-accounts-setup.sh --verify
  deployments/scripts/e2e-accounts-setup.sh --force
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --verify) VERIFY_ONLY=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument '$1'" ;;
  esac
done

ENV_DIR="$REPO_ROOT/deployments/$NETWORK"
ENV_FILE="$ENV_DIR/.e2e-accounts.env"

# Resolve the native XLM pool from the committed deployment config.
DEPLOYMENTS_JSON="$ENV_DIR/deployments.json"
[ -f "$DEPLOYMENTS_JSON" ] || die "no deployment config at $DEPLOYMENTS_JSON"
POOL_CONTRACT="$(python3 - "$DEPLOYMENTS_JSON" <<'EOF'
import json, sys
pools = json.load(open(sys.argv[1]))["pools"]
native = [p for p in pools if p.get("enabled") and p.get("asset", {}).get("kind") == "native"]
assert len(native) == 1, f"expected exactly one enabled native pool, found {len(native)}"
print(native[0]["poolContractId"])
EOF
)" || die "could not resolve the native pool from $DEPLOYMENTS_JSON"

# Isolated wallet/data dir so a run never touches a developer's real spp state.
DATA_DIR="$REPO_ROOT/deployments/scripts/.e2e-wallet-$NETWORK"

ALIAS_A="$ALIAS_PREFIX-a"
ALIAS_B="$ALIAS_PREFIX-b"

need stellar
need curl
need git
need python3

SPP_BIN=""
spp() {
  if [ -z "$SPP_BIN" ]; then
    if [ -n "${E2E_SPP_PATH:-}" ]; then
      SPP_BIN="$E2E_SPP_PATH"
    else
      # The CLI compiles deployments.json in, so an existing target/release/spp
      # may still target the previous deployment. Always let cargo decide
      # whether a rebuild is needed instead of reusing the binary on sight.
      need cargo
      step "building the spp CLI"
      ( cd "$REPO_ROOT" && cargo build --release -p stellar-private-payments-cli ) \
        || die "failed to build the spp CLI"
      SPP_BIN="$REPO_ROOT/target/release/spp"
    fi
  fi
  "$SPP_BIN" "$@"
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
  local extra=()
  [ "$FORCE" -eq 1 ] && extra+=(--overwrite)
  # bash 3.2 safe form for an empty array under `set -u`.
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

# Derive privacy keys and register public keys on-chain. Every prompt is
# pre-answered with explicit flags so the call is non-interactive.
onboard_account() {
  local alias="$1" attempt=1 delay=2 err_file
  step "onboarding + registering '$alias'"
  while [ "$attempt" -le 5 ]; do
    err_file="$(mktemp)"
    if spp --account "$alias" \
        --network "$NETWORK" \
        --data-dir "$DATA_DIR" \
        --stellar-config-dir "$DATA_DIR/stellar" \
        onboard --accept --register --no-bootnode --explorer-url "$EXPLORER_URL" 2>"$err_file"; then
      rm -f "$err_file"
      return 0
    fi
    local err
    err="$(cat "$err_file")"
    rm -f "$err_file"
    printf '%s\n' "$err" >&2
    if ! printf '%s' "$err" | grep -q 'Account not found'; then
      die "onboarding '$alias' failed"
    fi
    [ "$attempt" -lt 5 ] || die "onboarding '$alias' failed: account still not visible to RPC after retries"
    step "account not yet visible to RPC; retrying in ${delay}s ($attempt/5)"
    sleep "$delay"
    delay=$((delay * 2))
    attempt=$((attempt + 1))
  done
}

registration_status() {
  local alias="$1" out err_file
  err_file="$(mktemp)"
  out="$(spp --account "$alias" \
      --network "$NETWORK" \
      --data-dir "$DATA_DIR" \
      --stellar-config-dir "$DATA_DIR/stellar" \
      --json \
      overview "$POOL_CONTRACT" 2>"$err_file")" || true
  if [ -z "$out" ]; then
    warn "overview call failed for '$alias': $(tail -3 "$err_file")"
  fi
  rm -f "$err_file"
  printf '%s' "$out"
}

verify_account() {
  local alias="$1" address="$2" label="$3"
  step "verifying $label ($alias)"

  [ -n "$address" ] || die "$label has no address recorded"

  account_exists_on_chain "$address" \
    || die "$label $address is not funded on $NETWORK"

  # `overview --json` reports registration state; retry because the RPC view
  # can lag behind the chain.
  local overview attempt=1 delay=2
  while true; do
    overview="$(registration_status "$alias")"
    [ -n "$overview" ] || die "$label: could not read overview for $address (is the CLI built?)"
    case "$overview" in
      *'"registered":true'*|*'"registered": true'*)
        step "$label registered in the public-key registry"
        return 0 ;;
    esac
    [ "$attempt" -ge 5 ] && break
    step "$label not visible as registered yet; retrying in ${delay}s ($attempt/5)"
    sleep "$delay"
    delay=$((delay * 2))
    attempt=$((attempt + 1))
  done
  die "$label $address is not registered in the public-key registry (run without --verify)"
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
E2E_ACCOUNT_A_ALIAS=${E2E_ACCOUNT_A_ALIAS:-$ALIAS_A}
E2E_ACCOUNT_A_ADDRESS=$addr_a
E2E_ACCOUNT_A_SECRET=$secret_a
E2E_ACCOUNT_B_ALIAS=${E2E_ACCOUNT_B_ALIAS:-$ALIAS_B}
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

verify_ab() {
  verify_account "${E2E_ACCOUNT_A_ALIAS:-$ALIAS_A}" "${E2E_ACCOUNT_A_ADDRESS:-}" "account A"
  verify_account "${E2E_ACCOUNT_B_ALIAS:-$ALIAS_B}" "${E2E_ACCOUNT_B_ADDRESS:-}" "account B"
}

do_verify() {
  [ -f "$ENV_FILE" ] || die "$ENV_FILE not found; run without --verify to provision"
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  verify_ab
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
  if [ -s "$ENV_FILE" ] && [ "$FORCE" -eq 0 ]; then
    step "$ENV_FILE exists; verifying instead of provisioning (use --force to recreate)"
    do_verify
    return
  fi
  do_provision
}

main
