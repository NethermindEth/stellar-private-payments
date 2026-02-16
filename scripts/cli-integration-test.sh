#!/usr/bin/env bash
# Integration test for stellar-spp CLI.
#
# Deploys fresh contracts on testnet with ephemeral identities, then exercises
# the full CLI flow: init, key derivation, registration, deposit, transfer,
# withdrawal — all with real ZK proofs.
#
# Usage: scripts/integration-test.sh
#
# Prerequisites: stellar, curl, cargo in PATH; internet access (testnet RPC +
# friendbot).

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$ROOT_DIR/target/debug/stellar-spp"
DEPLOYMENTS_JSON="$SCRIPT_DIR/deployments.json"
DEPLOYMENTS_BACKUP=""
NETWORK="testnet"

# dirs::config_dir() on macOS = ~/Library/Application Support, Linux = ~/.config
if [[ "$(uname)" == "Darwin" ]]; then
  SPP_CONFIG_DIR="$HOME/Library/Application Support/stellar/spp"
else
  SPP_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/stellar/spp"
fi

PASS_COUNT=0
FAIL_COUNT=0

# Identities
ADMIN_ID="spp-test-admin"
ALICE_ID="spp-test-alice"
BOB_ID="spp-test-bob"

# Colors (if terminal supports them)
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  YELLOW='\033[0;33m'
  BOLD='\033[1m'
  RESET='\033[0m'
else
  GREEN='' RED='' YELLOW='' BOLD='' RESET=''
fi

banner() { printf "\n${BOLD}=== %s ===${RESET}\n\n" "$*"; }

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf "  ${GREEN}PASS${RESET}  %s\n" "$*"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf "  ${RED}FAIL${RESET}  %s\n" "$*"
}

run_spp() {
  # Run the CLI binary with --network testnet and capture stdout+stderr.
  "$BINARY" --network "$NETWORK" "$@" 2>&1
}

# ---------------------------------------------------------------------------
# Cleanup: restore deployments.json on exit
# ---------------------------------------------------------------------------

cleanup() {
  banner "Cleanup"
  if [[ -n "$DEPLOYMENTS_BACKUP" && -f "$DEPLOYMENTS_BACKUP" ]]; then
    cp "$DEPLOYMENTS_BACKUP" "$DEPLOYMENTS_JSON"
    rm -f "$DEPLOYMENTS_BACKUP"
    echo "Restored original deployments.json"
  fi
  # Remove the testnet config created by `spp init` so it doesn't affect real use
  rm -f "$SPP_CONFIG_DIR/testnet.toml" "$SPP_CONFIG_DIR/testnet.json" "$SPP_CONFIG_DIR/testnet.db" 2>/dev/null
  rm -rf "$SPP_CONFIG_DIR/testnet" 2>/dev/null
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

banner "Preflight"

for cmd in stellar curl cargo; do
  if command -v "$cmd" >/dev/null 2>&1; then
    pass "$cmd found"
  else
    fail "$cmd not found — cannot continue"
    exit 1
  fi
done

# Save existing deployments.json
if [[ -f "$DEPLOYMENTS_JSON" ]]; then
  DEPLOYMENTS_BACKUP="$(mktemp)"
  cp "$DEPLOYMENTS_JSON" "$DEPLOYMENTS_BACKUP"
  echo "Backed up deployments.json to $DEPLOYMENTS_BACKUP"
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

banner "Build circuits (BUILD_TESTS=1)"

if BUILD_TESTS=1 cargo build --package circuits --manifest-path "$ROOT_DIR/Cargo.toml" 2>&1; then
  pass "circuits build"
else
  fail "circuits build"
  echo "Cannot proceed without circuit artifacts."
  exit 1
fi

banner "Build stellar-spp"

if cargo build --package stellar-spp --manifest-path "$ROOT_DIR/Cargo.toml" 2>&1; then
  pass "stellar-spp build"
else
  fail "stellar-spp build"
  echo "Cannot proceed without CLI binary."
  exit 1
fi

if [[ ! -x "$BINARY" ]]; then
  fail "binary not found at $BINARY"
  exit 1
fi

# ---------------------------------------------------------------------------
# Create & fund identities
# ---------------------------------------------------------------------------

banner "Create identities"

for id in "$ADMIN_ID" "$ALICE_ID" "$BOB_ID"; do
  # --overwrite in case the identity already exists from a prior run
  if stellar keys generate "$id" --overwrite 2>&1; then
    pass "created identity $id"
  else
    fail "created identity $id"
  fi
done

banner "Fund via friendbot"

fund_account() {
  local id="$1"
  local addr
  addr="$(stellar keys address "$id" 2>/dev/null)"
  if [[ -z "$addr" ]]; then
    fail "could not resolve address for $id"
    return 1
  fi

  local attempt
  for attempt in 1 2 3; do
    local http_code
    http_code="$(curl -s -o /dev/null -w '%{http_code}' \
      "https://friendbot.stellar.org/?addr=$addr")"
    if [[ "$http_code" == "200" ]]; then
      pass "funded $id (attempt $attempt)"
      return 0
    fi
    printf "  ${YELLOW}RETRY${RESET} friendbot returned %s for %s (attempt %d)\n" \
      "$http_code" "$id" "$attempt"
    sleep 3
  done
  fail "could not fund $id after 3 attempts"
  return 1
}

for id in "$ADMIN_ID" "$ALICE_ID" "$BOB_ID"; do
  fund_account "$id"
done

# ---------------------------------------------------------------------------
# Deploy contracts
# ---------------------------------------------------------------------------

banner "Deploy contracts"

VK_FILE="$SCRIPT_DIR/testdata/policy_test_vk.json"
if [[ ! -f "$VK_FILE" ]]; then
  fail "verification key not found at $VK_FILE"
  exit 1
fi

if "$SCRIPT_DIR/deploy.sh" "$NETWORK" \
  --deployer "$ADMIN_ID" \
  --asp-levels 10 \
  --pool-levels 10 \
  --max-deposit 1000000000 \
  --vk-file "$VK_FILE" 2>&1; then
  pass "contract deployment"
else
  fail "contract deployment"
  echo "Cannot proceed without deployed contracts."
  exit 1
fi

# ---------------------------------------------------------------------------
# PHASE 1 — Init & Sync
# ---------------------------------------------------------------------------

# Clean any stale spp data from prior runs before testing
rm -f "$SPP_CONFIG_DIR/testnet.toml" "$SPP_CONFIG_DIR/testnet.json" "$SPP_CONFIG_DIR/testnet.db" 2>/dev/null
rm -rf "$SPP_CONFIG_DIR/testnet" 2>/dev/null

banner "PHASE 1: Pool Add & Sync"

output="$(run_spp pool add default --sync)"
if echo "$output" | grep -q "Pool" && echo "$output" | grep -qi "C[A-Z0-9]\{55\}"; then
  pass "spp pool add default --sync — mentions Pool and contract ID"
else
  fail "spp pool add default --sync — expected Pool mention and contract ID"
  echo "$output"
fi

output="$(run_spp status)"
if echo "$output" | grep -q "Pool leaves"; then
  pass "spp status — shows Pool leaves"
else
  fail "spp status — expected 'Pool leaves' in output"
  echo "$output"
fi

# ---------------------------------------------------------------------------
# PHASE 2 — Key Derivation
# ---------------------------------------------------------------------------

banner "PHASE 2: Key Derivation"

for id in "$ALICE_ID" "$BOB_ID"; do
  output="$(run_spp keys show --source "$id")"
  if echo "$output" | grep -q "Note public key" && \
     echo "$output" | grep -q "Encryption public key"; then
    pass "keys show --source $id"
  else
    fail "keys show --source $id"
    echo "$output"
  fi
done

# ---------------------------------------------------------------------------
# PHASE 3 — Registration
# ---------------------------------------------------------------------------

banner "PHASE 3: Registration"

for id in "$ALICE_ID" "$BOB_ID"; do
  output="$(run_spp register --source "$id")"
  if [[ $? -eq 0 ]]; then
    pass "register --source $id"
  else
    fail "register --source $id"
    echo "$output"
  fi
done

output="$(run_spp sync)"
if [[ $? -eq 0 ]]; then
  pass "sync after registration"
else
  fail "sync after registration"
  echo "$output"
fi

# ---------------------------------------------------------------------------
# PHASE 4 — Admin: Add members to ASP
# ---------------------------------------------------------------------------

banner "PHASE 4: Admin — Add members"

for id in "$ALICE_ID" "$BOB_ID"; do
  output="$(run_spp admin add-member --account "$id" --source "$ADMIN_ID")"
  if [[ $? -eq 0 ]]; then
    pass "admin add-member --account $id"
  else
    fail "admin add-member --account $id"
    echo "$output"
  fi
done

output="$(run_spp sync)"
if [[ $? -eq 0 ]]; then
  pass "sync after add-member"
else
  fail "sync after add-member"
  echo "$output"
fi

# ---------------------------------------------------------------------------
# PHASE 5 — Deposit
# ---------------------------------------------------------------------------

banner "PHASE 5: Deposit"

output="$(run_spp deposit 10000 --source "$ALICE_ID")"
if [[ $? -eq 0 ]]; then
  pass "deposit 10000 --source $ALICE_ID"
else
  fail "deposit 10000 --source $ALICE_ID"
  echo "$output"
fi

output="$(run_spp sync)"
if [[ $? -eq 0 ]]; then
  pass "sync after deposit"
else
  fail "sync after deposit"
  echo "$output"
fi

output="$(run_spp status --source "$ALICE_ID")"
if echo "$output" | grep -q "Balance: 10000"; then
  pass "alice balance is 10000 after deposit"
else
  fail "alice balance — expected 10000"
  echo "$output"
fi

output="$(run_spp notes list --source "$ALICE_ID")"
if echo "$output" | grep -q "10000"; then
  pass "notes list shows 10000"
else
  fail "notes list — expected 10000 in output"
  echo "$output"
fi

# ---------------------------------------------------------------------------
# PHASE 6 — Transfer
# ---------------------------------------------------------------------------

banner "PHASE 6: Transfer"

output="$(run_spp transfer 3000 --to "$BOB_ID" --source "$ALICE_ID")"
if [[ $? -eq 0 ]]; then
  pass "transfer 3000 alice -> bob"
else
  fail "transfer 3000 alice -> bob"
  echo "$output"
fi

output="$(run_spp sync)"
if [[ $? -eq 0 ]]; then
  pass "sync after transfer"
else
  fail "sync after transfer"
  echo "$output"
fi

output="$(run_spp status --source "$ALICE_ID")"
if echo "$output" | grep -q "Balance: 7000"; then
  pass "alice balance is 7000 after transfer"
else
  fail "alice balance — expected 7000"
  echo "$output"
fi

output="$(run_spp notes scan --source "$BOB_ID")"
if echo "$output" | grep -q "Found 1 new note"; then
  pass "bob notes scan — found 1 new note"
else
  fail "bob notes scan — expected 'Found 1 new note'"
  echo "$output"
fi

output="$(run_spp status --source "$BOB_ID")"
if echo "$output" | grep -q "Balance: 3000"; then
  pass "bob balance is 3000"
else
  fail "bob balance — expected 3000"
  echo "$output"
fi

# ---------------------------------------------------------------------------
# PHASE 7 — Withdraw
# ---------------------------------------------------------------------------

banner "PHASE 7: Withdraw"

output="$(run_spp withdraw 2000 --to "$ALICE_ID" --source "$ALICE_ID")"
if [[ $? -eq 0 ]]; then
  pass "withdraw 2000 --to $ALICE_ID"
else
  fail "withdraw 2000 --to $ALICE_ID"
  echo "$output"
fi

output="$(run_spp sync)"
if [[ $? -eq 0 ]]; then
  pass "sync after withdraw"
else
  fail "sync after withdraw"
  echo "$output"
fi

output="$(run_spp status --source "$ALICE_ID")"
if echo "$output" | grep -q "Balance: 5000"; then
  pass "alice balance is 5000 after withdraw"
else
  fail "alice balance — expected 5000"
  echo "$output"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

banner "Summary"

TOTAL=$((PASS_COUNT + FAIL_COUNT))
printf "  Total:  %d\n" "$TOTAL"
printf "  ${GREEN}Passed: %d${RESET}\n" "$PASS_COUNT"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  printf "  ${RED}Failed: %d${RESET}\n" "$FAIL_COUNT"
  exit 1
else
  printf "  Failed: 0\n"
  echo ""
  echo "All tests passed."
  exit 0
fi
