#!/usr/bin/env bash
# Build stellar-private-payments-sdk-web into sdk/web/dist/ (needs wasm-bindgen on PATH).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WEB="$ROOT/sdk/web"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
PROFILE="${WASM_PROFILE:-release}"
TARGET="wasm32-unknown-unknown"
ARTIFACTS="$ROOT/target/$TARGET/$PROFILE"

# Cargo uses `--release` for the release profile and `--profile <name>` for custom profiles.
case "$PROFILE" in
  release)
    CARGO_PROFILE_FLAG="--release"
    ;;
  *)
    CARGO_PROFILE_FLAG="--profile $PROFILE"
    ;;
esac

WASM_BINDGEN_VERSION="${WASM_BINDGEN_VERSION:-0.2.126}"
WASM_OUT_NAME="stellar_private_payments_sdk_web"

echo "==> Building circuit artifacts (if needed)..."
# Circuit artifacts are profile-independent and are only published for release
# (and debug test circuits). Always use the release circuit artifacts.
if [[ ! -d "$ROOT/target/circuits-artifacts/release" ]]; then
  cargo build -p circuits --release
fi

echo "==> Building stellar-private-payments-sdk-web ($PROFILE)..."
cargo build -p stellar-private-payments-sdk-web $CARGO_PROFILE_FLAG --target "$TARGET"
cargo build -p stellar-private-payments-sdk-web $CARGO_PROFILE_FLAG --target "$TARGET" --bin storage-worker
cargo build -p stellar-private-payments-sdk-web $CARGO_PROFILE_FLAG --target "$TARGET" --bin prover-worker

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "error: wasm-bindgen not found — cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION} --locked --force" >&2
  exit 1
fi

installed_version="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}')"
if [[ "${installed_version}" != "${WASM_BINDGEN_VERSION}" ]]; then
  echo "error: wasm-bindgen ${installed_version} on PATH; need ${WASM_BINDGEN_VERSION}" >&2
  echo "  cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION} --locked --force" >&2
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
EOF
  if [[ "$name" == "prover-worker" ]]; then
    cat >>"$WEB/dist/workers/${name}.js" <<'EOF'
globalThis.__STELLAR_PRIVATE_PAYMENTS_CIRCUITS_BASE__ =
  new URL('../circuits/', import.meta.url).href;
EOF
  fi
  cat >>"$WEB/dist/workers/${name}.js" <<EOF
await init();
EOF
}

write_worker_loader storage-worker
write_worker_loader prover-worker

echo "==> Staging bundled circuit artifacts..."
bash "$WEB/scripts/stage-circuits-dist.sh"

echo "==> Built sdk/web/dist/"
