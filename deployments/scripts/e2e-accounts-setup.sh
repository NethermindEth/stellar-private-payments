#!/usr/bin/env bash
# Provision the four test accounts used by the e2e suites.
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
REREGISTER=0
FORCE=0
FUND_RETRIES=6

usage() {
  cat >&2 <<'USAGE'
Usage: e2e-accounts-setup.sh [OPTIONS]

Creates, funds and registers the four Stellar test accounts used by the e2e
suites (A/B: pre-signing SDK wasm suite; C/D: Freighter browser tests), then
writes their material to deployments/<network>/.e2e-accounts.env (git-ignored;
contains secret keys).

What each account gets:
  1. a keypair in the `stellar keys` keystore (alias <prefix>-a/-b/-c/-d)
  2. testnet XLM via friendbot (with retry/backoff)
  3. privacy keys derived and note/encryption public keys registered on-chain
     via `spp onboard --register`

Membership leaves are not inserted: the target native XLM pool is
blocklist-only, so membership proofs are not required.

Options:
  --verify              Re-check existing accounts without creating anything
  --reregister          Re-onboard the EXISTING accounts against the current
                        deployment, keeping their keypairs and the env file
  --force               Recreate accounts even if the env file already exists
  -h, --help            Show this help

Idempotency:
  With an existing env file and no --force, the script verifies instead of
  provisioning (identical to --verify). An env file left by an older,
  two-account version of this script (no C/D entries) is backfilled in place:
  C and D are provisioned and the file rewritten; A and B are untouched.
  --force regenerates all keypairs and overwrites the env file.

After a redeploy:
  Use --reregister to re-register the existing four accounts against the
  current deployment without changing keypairs, addresses, secrets, or the env
  file. Do NOT use --force for a redeploy; it regenerates every keypair.

Examples:
  deployments/scripts/e2e-accounts-setup.sh
  deployments/scripts/e2e-accounts-setup.sh --verify
  deployments/scripts/e2e-accounts-setup.sh --reregister
  deployments/scripts/e2e-accounts-setup.sh --force
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --verify) VERIFY_ONLY=1; shift ;;
    --reregister) REREGISTER=1; shift ;;
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
ALIAS_C="$ALIAS_PREFIX-c"
ALIAS_D="$ALIAS_PREFIX-d"

need stellar
need curl
need git
need python3

SPP_BIN=""
spp() {
  if [ -z "$SPP_BIN" ]; then
    # Prefer a project build over any unrelated `spp` on PATH.
    if [ -n "${E2E_SPP_PATH:-}" ]; then
      SPP_BIN="$E2E_SPP_PATH"
    elif [ -x "$REPO_ROOT/target/release/spp" ]; then
      SPP_BIN="$REPO_ROOT/target/release/spp"
    else
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

freighter_password() {
  if [ -n "${E2E_FREIGHTER_PASSWORD:-}" ]; then
    printf '%s' "$E2E_FREIGHTER_PASSWORD"
  else
    python3 -c '
import secrets, string
pw = [secrets.choice(string.ascii_uppercase),
      secrets.choice(string.ascii_lowercase),
      secrets.choice(string.digits)]
pw += [secrets.choice(string.ascii_letters + string.digits) for _ in range(21)]
secrets.SystemRandom().shuffle(pw)
print("".join(pw))'
  fi
}

write_env_file() {
  local addr_a="$1" secret_a="$2" addr_b="$3" secret_b="$4"
  local addr_c="$5" secret_c="$6" addr_d="$7" secret_d="$8" password="$9"
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
E2E_ACCOUNT_C_ALIAS=${E2E_ACCOUNT_C_ALIAS:-$ALIAS_C}
E2E_ACCOUNT_C_ADDRESS=$addr_c
E2E_ACCOUNT_C_SECRET=$secret_c
E2E_ACCOUNT_D_ALIAS=${E2E_ACCOUNT_D_ALIAS:-$ALIAS_D}
E2E_ACCOUNT_D_ADDRESS=$addr_d
E2E_ACCOUNT_D_SECRET=$secret_d
E2E_FREIGHTER_PASSWORD=$password
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

verify_cd() {
  verify_account "${E2E_ACCOUNT_C_ALIAS:-$ALIAS_C}" "${E2E_ACCOUNT_C_ADDRESS:-}" "account C"
  verify_account "${E2E_ACCOUNT_D_ALIAS:-$ALIAS_D}" "${E2E_ACCOUNT_D_ADDRESS:-}" "account D"
}

have_cd() {
  [ -n "${E2E_ACCOUNT_C_ADDRESS:-}" ] && [ -n "${E2E_ACCOUNT_D_ADDRESS:-}" ]
}

# Re-register the existing four accounts against the current deployment after a
# redeploy, without changing keypairs or the env file.
do_reregister() {
  [ -f "$ENV_FILE" ] || die "$ENV_FILE not found; run without --reregister to provision"
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  have_cd || die "env file has no C/D accounts; run without --reregister to backfill them"

  step "re-registering the existing accounts against pool $POOL_CONTRACT"

  local alias_a="${E2E_ACCOUNT_A_ALIAS:-$ALIAS_A}"
  local alias_b="${E2E_ACCOUNT_B_ALIAS:-$ALIAS_B}"
  local alias_c="${E2E_ACCOUNT_C_ALIAS:-$ALIAS_C}"
  local alias_d="${E2E_ACCOUNT_D_ALIAS:-$ALIAS_D}"

  local alias
  for alias in "$alias_a" "$alias_b" "$alias_c" "$alias_d"; do
    [ -n "$(address_for_alias "$alias")" ] \
      || die "no keypair for '$alias' in $DATA_DIR/stellar — the keystore and the env file disagree, which --reregister cannot repair"
  done

  fund_account "$E2E_ACCOUNT_A_ADDRESS"
  fund_account "$E2E_ACCOUNT_B_ADDRESS"
  fund_account "$E2E_ACCOUNT_C_ADDRESS"
  fund_account "$E2E_ACCOUNT_D_ADDRESS"

  onboard_account "$alias_a"
  onboard_account "$alias_b"
  onboard_account "$alias_c"
  onboard_account "$alias_d"

  verify_ab
  verify_cd
  step "re-registration complete — env file and keypairs untouched"
}

do_verify() {
  [ -f "$ENV_FILE" ] || die "$ENV_FILE not found; run without --verify to provision"
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  verify_ab
  if have_cd; then
    verify_cd
    step "verification passed for all four accounts"
  else
    warn "env file has no C/D accounts (needed by the Freighter tests); run without --verify to backfill them"
    step "verification passed for accounts A and B"
  fi
}

# Backfill C/D accounts into an older two-account env file.
backfill_cd() {
  step "backfilling Freighter accounts C and D"
  assert_env_file_ignored
  mkdir -p "$DATA_DIR"

  ensure_keypair "$ALIAS_C"
  ensure_keypair "$ALIAS_D"

  local addr_c addr_d
  addr_c="$(address_for_alias "$ALIAS_C")"
  addr_d="$(address_for_alias "$ALIAS_D")"
  [ -n "$addr_c" ] || die "could not resolve address for $ALIAS_C"
  [ -n "$addr_d" ] || die "could not resolve address for $ALIAS_D"
  [ "$addr_c" != "$addr_d" ] || die "aliases $ALIAS_C/$ALIAS_D resolved to the same address"
  case "$addr_c$addr_d" in
    *"$E2E_ACCOUNT_A_ADDRESS"*|*"$E2E_ACCOUNT_B_ADDRESS"*)
      die "C/D aliases resolved to an A/B address" ;;
  esac

  step "account C: $addr_c"
  step "account D: $addr_d"

  fund_account "$addr_c"
  fund_account "$addr_d"

  onboard_account "$ALIAS_C"
  onboard_account "$ALIAS_D"

  write_env_file \
    "$E2E_ACCOUNT_A_ADDRESS" "$E2E_ACCOUNT_A_SECRET" \
    "$E2E_ACCOUNT_B_ADDRESS" "$E2E_ACCOUNT_B_SECRET" \
    "$addr_c" "$(secret_for_alias "$ALIAS_C")" \
    "$addr_d" "$(secret_for_alias "$ALIAS_D")" \
    "$(freighter_password)"

  verify_account "$ALIAS_C" "$addr_c" "account C"
  verify_account "$ALIAS_D" "$addr_d" "account D"

  step "backfill complete"
}

do_provision() {
  assert_env_file_ignored
  mkdir -p "$DATA_DIR"

  ensure_keypair "$ALIAS_A"
  ensure_keypair "$ALIAS_B"
  ensure_keypair "$ALIAS_C"
  ensure_keypair "$ALIAS_D"

  local addr_a addr_b addr_c addr_d
  addr_a="$(address_for_alias "$ALIAS_A")"
  addr_b="$(address_for_alias "$ALIAS_B")"
  addr_c="$(address_for_alias "$ALIAS_C")"
  addr_d="$(address_for_alias "$ALIAS_D")"
  [ -n "$addr_a" ] || die "could not resolve address for $ALIAS_A"
  [ -n "$addr_b" ] || die "could not resolve address for $ALIAS_B"
  [ -n "$addr_c" ] || die "could not resolve address for $ALIAS_C"
  [ -n "$addr_d" ] || die "could not resolve address for $ALIAS_D"
  [ "$(printf '%s\n' "$addr_a" "$addr_b" "$addr_c" "$addr_d" | sort -u | wc -l)" -eq 4 ] \
    || die "aliases resolved to non-distinct addresses"

  step "account A: $addr_a"
  step "account B: $addr_b"
  step "account C: $addr_c"
  step "account D: $addr_d"

  fund_account "$addr_a"
  fund_account "$addr_b"
  fund_account "$addr_c"
  fund_account "$addr_d"

  onboard_account "$ALIAS_A"
  onboard_account "$ALIAS_B"
  onboard_account "$ALIAS_C"
  onboard_account "$ALIAS_D"

  # Secrets are read straight into the env file; never echoed.
  write_env_file \
    "$addr_a" "$(secret_for_alias "$ALIAS_A")" \
    "$addr_b" "$(secret_for_alias "$ALIAS_B")" \
    "$addr_c" "$(secret_for_alias "$ALIAS_C")" \
    "$addr_d" "$(secret_for_alias "$ALIAS_D")" \
    "$(freighter_password)"

  verify_account "$ALIAS_A" "$addr_a" "account A"
  verify_account "$ALIAS_B" "$addr_b" "account B"
  verify_account "$ALIAS_C" "$addr_c" "account C"
  verify_account "$ALIAS_D" "$addr_d" "account D"

  step "provisioning complete"
}

main() {
  if [ "$VERIFY_ONLY" -eq 1 ]; then
    do_verify
    return
  fi
  if [ "$REREGISTER" -eq 1 ]; then
    do_reregister
    return
  fi
  if [ -s "$ENV_FILE" ] && [ "$FORCE" -eq 0 ]; then
    step "$ENV_FILE exists; verifying instead of provisioning (use --force to recreate)"
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    verify_ab
    if have_cd; then
      verify_cd
      step "verification passed for all four accounts"
    else
      backfill_cd
    fi
    return
  fi
  do_provision
}

main
