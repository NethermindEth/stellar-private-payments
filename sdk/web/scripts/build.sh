#!/usr/bin/env bash
# Build private-payments-web into sdk/web/dist/ (needs wasm-bindgen on PATH).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WEB="$ROOT/sdk/web"
PROFILE="${WASM_PROFILE:-release}"
TARGET="wasm32-unknown-unknown"
ARTIFACTS="$ROOT/target/$TARGET/$PROFILE"
WASM_BINDGEN_VERSION="${WASM_BINDGEN_VERSION:-0.2.120}"

echo "==> Building circuit artifacts (if needed)..."
if [[ ! -d "$ROOT/target/circuits-artifacts/$PROFILE" ]]; then
  cargo build -p circuits --"$PROFILE"
fi

echo "==> Building private-payments-web ($PROFILE)..."
cargo build -p private-payments-web --"$PROFILE" --target "$TARGET"
cargo build -p private-payments-web --"$PROFILE" --target "$TARGET" --bin storage-worker
cargo build -p private-payments-web --"$PROFILE" --target "$TARGET" --bin prover-worker

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "error: wasm-bindgen not found — cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION} --locked" >&2
  exit 1
fi

MAIN_WASM="$ARTIFACTS/private_payments_web.wasm"
STORAGE_WASM="$ARTIFACTS/storage_worker.wasm"
PROVER_WASM="$ARTIFACTS/prover_worker.wasm"

for f in "$MAIN_WASM" "$STORAGE_WASM" "$PROVER_WASM"; do
  [[ -f "$f" ]] || { echo "error: missing $f" >&2; exit 1; }
done

rm -rf "$WEB/dist"
mkdir -p "$WEB/dist/workers"

wasm-bindgen --target web --out-dir "$WEB/dist" --out-name private_payments_web "$MAIN_WASM"
wasm-bindgen --target web --out-dir "$WEB/dist/workers" --out-name storage-worker "$STORAGE_WASM"
wasm-bindgen --target web --out-dir "$WEB/dist/workers" --out-name prover-worker "$PROVER_WASM"

echo "==> Built sdk/web/dist/"
