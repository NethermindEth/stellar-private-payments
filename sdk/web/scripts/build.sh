#!/usr/bin/env bash
# Build stellar-private-payments-sdk-web into sdk/web/dist/ (needs wasm-bindgen on PATH).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WEB="$ROOT/sdk/web"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
PROFILE="${WASM_PROFILE:-release}"
TARGET="wasm32-unknown-unknown"
ARTIFACTS="$ROOT/target/$TARGET/$PROFILE"
WASM_BINDGEN_VERSION="${WASM_BINDGEN_VERSION:-0.2.120}"
WASM_OUT_NAME="stellar_private_payments_sdk_web"

echo "==> Building circuit artifacts (if needed)..."
if [[ ! -d "$ROOT/target/circuits-artifacts/$PROFILE" ]]; then
  cargo build -p circuits --"$PROFILE"
fi

echo "==> Building stellar-private-payments-sdk-web ($PROFILE)..."
cargo build -p stellar-private-payments-sdk-web --"$PROFILE" --target "$TARGET"
cargo build -p stellar-private-payments-sdk-web --"$PROFILE" --target "$TARGET" --bin storage-worker
cargo build -p stellar-private-payments-sdk-web --"$PROFILE" --target "$TARGET" --bin prover-worker

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "error: wasm-bindgen not found — cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION} --locked" >&2
  exit 1
fi

MAIN_WASM="$ARTIFACTS/${WASM_OUT_NAME}.wasm"
STORAGE_WASM="$ARTIFACTS/storage-worker.wasm"
PROVER_WASM="$ARTIFACTS/prover-worker.wasm"

for f in "$MAIN_WASM" "$STORAGE_WASM" "$PROVER_WASM"; do
  [[ -f "$f" ]] || { echo "error: missing $f" >&2; exit 1; }
done

rm -rf "$WEB/dist"
mkdir -p "$WEB/dist/workers"

wasm-bindgen --target web --out-dir "$WEB/dist" --out-name "$WASM_OUT_NAME" "$MAIN_WASM"
wasm-bindgen --target web --out-dir "$WEB/dist/workers" --out-name storage-worker-module "$STORAGE_WASM"
wasm-bindgen --target web --out-dir "$WEB/dist/workers" --out-name prover-worker-module "$PROVER_WASM"

write_worker_loader() {
  local name="$1"
  cat >"$WEB/dist/workers/${name}.js" <<EOF
import init from './${name}-module.js';
await init();
EOF
}

write_worker_loader storage-worker
write_worker_loader prover-worker

echo "==> Built sdk/web/dist/"
