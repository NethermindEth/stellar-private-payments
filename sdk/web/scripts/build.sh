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

WASM_OPT_VERSION="${WASM_OPT_VERSION:-version_131}"
BINARYEN_DIR="$ROOT/target/tmp/binaryen/binaryen-$WASM_OPT_VERSION"

# sha256 of the pinned binaryen release tarballs, per platform. Only valid for
# the default WASM_OPT_VERSION above — bumping it means refreshing all four
# (see the .sha256 sidecars on the GitHub release).
binaryen_platform=""
binaryen_sha256=""
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    binaryen_platform="x86_64-linux"
    binaryen_sha256="b5bf1f0eaf17c63ee588ff7a5954dc8f6ce2c26989051c66f24dfe9ece3e46db" ;;
  Linux-aarch64 | Linux-arm64)
    binaryen_platform="aarch64-linux"
    binaryen_sha256="ba991f677edd9a21d2bc96c0144bc8ac5b112d4d98a3eb266e075e22e557df2a" ;;
  Darwin-x86_64)
    binaryen_platform="x86_64-macos"
    binaryen_sha256="d209fadd8a894bdaf3bd3612a23c32a0af184d2f4a979b8c789e6e4f6a4de883" ;;
  Darwin-arm64)
    binaryen_platform="arm64-macos"
    binaryen_sha256="e441b48dc22163d209b4f05e44dc7210909b01237642b6c9ae48fd710a3ef83e" ;;
esac

# Escape hatch for platforms with no prebuilt release (Windows, *BSD, Nix, ...)
# and for a locally built binaryen: point WASM_OPT at a wasm-opt binary and the
# download is skipped. The version gate below still applies.
WASM_OPT="${WASM_OPT:-$BINARYEN_DIR/bin/wasm-opt}"

sha256_check() {
  # macOS ships shasum rather than GNU coreutils' sha256sum.
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c -
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c -
  else
    echo "error: need sha256sum or shasum to verify the binaryen download" >&2
    exit 1
  fi
}

if [[ ! -x "$WASM_OPT" ]]; then
  if [[ -z "$binaryen_platform" ]]; then
    echo "error: no prebuilt binaryen for $(uname -s)-$(uname -m)" >&2
    echo "  install binaryen ${WASM_OPT_VERSION#version_} and set WASM_OPT=/path/to/wasm-opt" >&2
    exit 1
  fi
  if [[ "$WASM_OPT_VERSION" != "version_131" ]]; then
    echo "error: no pinned sha256 for binaryen $WASM_OPT_VERSION" >&2
    echo "  install it yourself and set WASM_OPT=/path/to/wasm-opt" >&2
    exit 1
  fi
  echo "==> Downloading binaryen $WASM_OPT_VERSION ($binaryen_platform)..."
  mkdir -p "$ROOT/target/tmp/binaryen"
  tmp_tar="$ROOT/target/tmp/binaryen/binaryen-$WASM_OPT_VERSION-$binaryen_platform.tar.gz"
  curl -sSfL -o "$tmp_tar" \
    "https://github.com/WebAssembly/binaryen/releases/download/$WASM_OPT_VERSION/binaryen-$WASM_OPT_VERSION-$binaryen_platform.tar.gz"
  echo "$binaryen_sha256  $tmp_tar" | sha256_check
  tar xzf "$tmp_tar" -C "$ROOT/target/tmp/binaryen"
  rm -f "$tmp_tar"
fi

installed_opt="$("$WASM_OPT" --version | awk '{print $3}')"
[[ "$installed_opt" == "${WASM_OPT_VERSION#version_}" ]] || {
  echo "error: wasm-opt $installed_opt; need ${WASM_OPT_VERSION#version_}" >&2; exit 1; }

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

echo "==> Running wasm-opt -Os on shipped wasm modules..."
for wasm in \
  "$WEB/dist/${WASM_OUT_NAME}_bg.wasm" \
  "$WEB/dist/workers/storage-worker-module_bg.wasm" \
  "$WEB/dist/workers/prover-worker-module_bg.wasm"; do
  "$WASM_OPT" -Os \
    --enable-bulk-memory \
    --enable-reference-types \
    --enable-multivalue \
    --enable-sign-ext \
    --enable-nontrapping-float-to-int \
    --enable-mutable-globals \
    "$wasm" -o "$wasm"
done

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
