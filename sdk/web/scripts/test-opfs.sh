#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
# Use wasm-bindgen-test-runner matching Cargo.lock's wasm-bindgen version.
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="${CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER:-wasm-bindgen-test-runner}"
export WASM_BINDGEN_TEST_TIMEOUT="${WASM_BINDGEN_TEST_TIMEOUT:-60}"
cargo test -p stellar-private-payments-web --test opfs --target wasm32-unknown-unknown -- "$@"
