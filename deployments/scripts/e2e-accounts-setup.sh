#!/usr/bin/env bash
# Provision the four test accounts the e2e suites drive (issue #168).
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
# Four accounts: A and B for the pre-signing SDK wasm suite, C (the wallet
# imported into the Freighter profile) and D (the registered transfer
# recipient) for the Freighter browser tests. The target pool is the native
# XLM pool
# (policyFlags ["blocklist"]), which requires NO ASP membership leaf and hence
# no admin secret (membership proofs are Allowlist-gated —
# sdk/types/src/policy_tx.rs; the pool's flags are in
# deployments/testnet/deployments.json).
# The pool address is resolved from deployments.json at runtime (after
# argument parsing, since the file path depends on --network) — a hardcoded
# address silently goes stale on every redeploy.
POOL_CONTRACT=""
# Passed explicitly to `spp onboard` so it never falls through to a prompt.
EXPLORER_URL="https://stellar.expert/explorer/testnet"

ALIAS_PREFIX="spp-e2e"
VERIFY_ONLY=0
FORCE=0
FUND_RETRIES=6

usage() {
  cat >&2 <<'USAGE'
Usage: e2e-accounts-setup.sh [OPTIONS]

Creates, funds and registers the four Stellar test accounts used by the e2e
suites (A/B: pre-signing SDK wasm suite; C: Freighter wallet; D: Freighter
transfer recipient), then records them in deployments/<network>/.e2e-accounts.env
(git-ignored; contains secret keys) along with a generated
E2E_FREIGHTER_PASSWORD.

What each account gets:
  1. a keypair in the `stellar keys` keystore (alias <prefix>-a/-b/-c/-d)
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
  provisioning (identical to --verify). An env file left by an older,
  two-account version of this script (no C/D entries) is BACKFILLED in place:
  C and D are provisioned and the file rewritten; A and B are untouched.
  --force regenerates all keypairs and overwrites the env file.

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

# Resolve the native XLM pool from the deployment config (the same file the
# CLI and sdk/web compile in), so a redeploy never leaves this script
# pointing at a pool the CLI no longer knows.
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

# Resolve the spp CLI once per run: an installed binary on PATH, else the
# workspace build. We build loudly and call the binary directly — NOT
# `cargo run`, which re-resolves (and can silently rebuild) on every call
# and whose failures were invisible behind swallowed stderr.
# `type -P` (not `command -v`) because `command -v spp` would find THIS
# function and always take the first branch.
SPP_BIN=""
spp() {
  if [ -z "$SPP_BIN" ]; then
    SPP_BIN="$(type -P spp || true)"
    if [ -z "$SPP_BIN" ]; then
      step "building the spp CLI (cargo build --release -p stellar-private-payments-cli)"
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
# Friendbot-funded accounts are visible on Horizon immediately, but the
# on-chain Soroban RPC node can lag behind by a few seconds. A registration
# attempt against a not-yet-visible account fails with "Account not found", so
# retry briefly before giving up.
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
    step "account not yet visible to RPC; retrying onboard in ${delay}s ($attempt/5)"
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
    # Surface the real failure instead of an opaque empty result.
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

  # `overview --json` reports registration state; require an explicit true.
  # Retry with backoff: a registration that just confirmed on-chain can take
  # seconds to show up in the RPC's ledger view, so a single immediate read
  # false-negatives right after provisioning.
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

# Reuse an existing password (sourced from the env file or exported) so a
# backfill/rewrite never invalidates a Freighter profile snapshot; generate
# one otherwise. Freighter enforces uppercase/lowercase/digit, so the
# generator guarantees all three classes (a bare token_hex would not).
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
  # Aliases come from the sourced env file when present (a backfill preserves
  # whatever aliases the original provisioning used), else the defaults.
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

# An env file left by the two-account version of this script is missing the
# Freighter accounts. Provision ONLY C and D and rewrite the file with the
# merged values — A and B keep their keypairs, addresses and secrets, so
# secrets already copied into CI environments stay valid.
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
  if [ -f "$ENV_FILE" ] && [ "$FORCE" -eq 0 ]; then
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
