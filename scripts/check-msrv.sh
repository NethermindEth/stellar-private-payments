#!/usr/bin/env bash
# The same checks run locally and in CI. Compiler selection applies to child commands.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export RUSTUP_TOOLCHAIN
RUSTUP_TOOLCHAIN=$(bash scripts/msrv.sh)
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
# Compile the verifier with a committed key; MSRV checks need no new ceremony.
export VERIFIER_VK_JSON="$ROOT/deployments/testnet/circuit_keys/policy_tx_2_2_AB_vk.json"

case "${1:-}" in
  native)
    cargo build --locked --workspace --all-targets
    cargo build --locked -p stellar-private-payments --lib
    cargo build --locked -p stellar-private-payments --lib --features parallel
    cargo build --locked --manifest-path integration-tests/Cargo.toml --all-targets
    cargo test --locked --manifest-path tools/bootnode/Cargo.toml
    ;;
  browser)
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" wasm32-unknown-unknown
    cargo build --locked --release --target wasm32-unknown-unknown -p stellar-private-payments-web --lib --bins
    cargo check --locked --target wasm32-unknown-unknown -p stellar-private-payments --tests
    # The e2e suite embeds this file at compile time. These checks never run
    # against a network; use a committed fixture only if no local deployment exists.
    fixture="$ROOT/deployments/local/deployments.json"
    if [[ ! -e "$fixture" && ! -L "$fixture" ]]; then
      mkdir -p "$(dirname "$fixture")"
      cp "$ROOT/deployments/testnet/deployments.json" "$fixture"
      trap 'rm -f "$fixture"' EXIT
    fi
    cargo check --locked --target wasm32-unknown-unknown --manifest-path integration-tests-web/Cargo.toml --all-targets
    ;;
  contracts)
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" wasm32v1-none
    for package in asp-membership asp-non-membership circom-groth16-verifier pool pool-gvk public-key-registry; do
      stellar contract build --package "$package" --locked
    done
    ;;
  consumer)
    # Exercise the published form with a fresh graph outside the workspace.
    consumer=$(mktemp -d)
    trap 'rm -rf "$consumer"' EXIT
    cargo package --locked --allow-dirty --no-verify -p stellar-private-payments \
      --target-dir "$consumer/package"
    sdk_version=$(cargo read-manifest --manifest-path sdk/native/Cargo.toml | jq -er '.version')
    tar -xzf "$consumer/package/package/stellar-private-payments-$sdk_version.crate" -C "$consumer"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}/msrv-consumer"
    mkdir "$consumer/src"
    cat > "$consumer/Cargo.toml" <<EOF
[package]
name = "msrv-sdk-consumer"
version = "0.0.0"
edition = "2024"
rust-version = "$RUSTUP_TOOLCHAIN"

[dependencies]
stellar-private-payments = { path = "$consumer/stellar-private-payments-$sdk_version" }
EOF
    echo 'pub use stellar_private_payments::*;' > "$consumer/src/lib.rs"
    cd "$consumer"
    cargo generate-lockfile
    cargo build --locked
    cargo build --locked --features stellar-private-payments/parallel
    ;;
  *)
    echo "Usage: $0 {native|browser|contracts|consumer}" >&2
    exit 2
    ;;
esac
