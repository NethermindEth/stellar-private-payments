#!/usr/bin/env bash
# Build stellar-private-payments-web into sdk/web/dist/ (needs wasm-bindgen on PATH).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WEB="$ROOT/sdk/web"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
PROFILE="${WASM_PROFILE:-release}"
# The prover worker is compute-bound; the main module and storage worker stay
# on the size-optimised profile. See sdk/web/scripts/profile-key.sh.
case "$PROFILE" in
  release-with-logs) default_prover_profile="prover-hot-with-logs" ;;
  *) default_prover_profile="prover-hot" ;;
esac
PROVER_PROFILE="${PROVER_PROFILE:-$default_prover_profile}"
TARGET="wasm32-unknown-unknown"
ARTIFACTS="$CARGO_TARGET_DIR/$TARGET/$PROFILE"
PROVER_ARTIFACTS="$CARGO_TARGET_DIR/$TARGET/$PROVER_PROFILE"

# Cargo uses `--release` for the release profile and `--profile <name>` for custom profiles.
cargo_profile_flag() {
  if [ "$1" = "release" ]; then
    printf '%s' "--release"
  else
    printf '%s' "--profile $1"
  fi
}

CARGO_PROFILE_FLAG="$(cargo_profile_flag "$PROFILE")"
PROVER_PROFILE_FLAG="$(cargo_profile_flag "$PROVER_PROFILE")"

# Extra cargo feature flags, e.g. `--features unencrypted-storage` or
# `--no-default-features --features unencrypted-storage`.
CARGO_FEATURE_FLAGS="${SPP_WEB_CARGO_FEATURES:-}"

WASM_BINDGEN_VERSION="${WASM_BINDGEN_VERSION:-0.2.128}"
WASM_OUT_NAME="stellar_private_payments_web"

echo "==> Verifying circuit artifacts match lockfile..."
sh "$ROOT/deployments/scripts/circuit-artifacts.sh" verify

# Prefer Homebrew's clang for WebAssembly on macOS, preserving cc-rs overrides.
# The hyphenated target override is an environment key, not a Bash identifier.
if [[ "$(uname -s)" == "Darwin" && -z "$(printenv 'CC_wasm32-unknown-unknown' || true)${CC_wasm32_unknown_unknown:-}${TARGET_CC:-}${CC:-}" ]]; then
  MACOS_LLVM_PREFIX="$(brew --prefix llvm 2>/dev/null || true)"
  if [[ -n "$MACOS_LLVM_PREFIX" && -x "$MACOS_LLVM_PREFIX/bin/clang" ]]; then
    export CC_wasm32_unknown_unknown="$MACOS_LLVM_PREFIX/bin/clang"
  fi
fi

# Apple's ar silently drops wasm objects from archives, leaving sqlite-wasm-rs's
# SQLite library empty (link fails with undefined sqlite3_* symbols), and cc-rs
# only finds llvm-ar next to a non-Apple clang. On macOS, use the Rust toolchain's
# llvm-ar unless AR_wasm32_unknown_unknown, TARGET_AR or AR already picks one.
if [[ "$(uname -s)" == "Darwin" && -z "${AR_wasm32_unknown_unknown:-}${TARGET_AR:-}${AR:-}" ]]; then
  LLVM_AR="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-ar"
  if [[ ! -x "$LLVM_AR" ]]; then
    echo "error: llvm-ar not found at $LLVM_AR (Apple's ar cannot archive wasm objects)" >&2
    echo "  rustup component add llvm-tools" >&2
    echo "  or set AR_wasm32_unknown_unknown=/path/to/llvm-ar, e.g. \$(brew --prefix llvm)/bin/llvm-ar" >&2
    exit 1
  fi
  export AR_wasm32_unknown_unknown="$LLVM_AR"
fi

echo "==> Building stellar-private-payments-web ($PROFILE)..."
cargo build --locked -p stellar-private-payments-web $CARGO_PROFILE_FLAG --target "$TARGET" $CARGO_FEATURE_FLAGS
cargo build --locked -p stellar-private-payments-web $CARGO_PROFILE_FLAG --target "$TARGET" --bin storage-worker $CARGO_FEATURE_FLAGS
echo "==> Building prover-worker ($PROVER_PROFILE)..."
cargo build --locked -p stellar-private-payments-web $PROVER_PROFILE_FLAG --target "$TARGET" --bin prover-worker $CARGO_FEATURE_FLAGS

# Also build a prover worker that proves on a rayon pool of Web Workers sharing
# one wasm memory. Only cross-origin isolated pages can run it, so it ships
# beside the serial worker, not instead of it. SPP_WEB_THREADS=0 leaves it out,
# for a quicker build or a toolchain without the `rust-src` component.
THREADS=1
if [[ "${SPP_WEB_THREADS:-1}" == "0" ]]; then
  THREADS=0
fi
THREADS_TARGET_DIR="$CARGO_TARGET_DIR/web-threads"
THREADS_WASM="$THREADS_TARGET_DIR/$TARGET/$PROVER_PROFILE/prover-worker-threads.wasm"
if [[ "$THREADS" == "1" ]]; then
  # Appended to the rustflags in .cargo/config.toml, which already sets the
  # `--max-memory` that a shared memory has to declare.
  THREADS_RUSTFLAGS=(
    # atomics: atomic instructions and real thread-local storage, so that std's
    # locks and rayon's queues work across threads. bulk-memory is in the
    # target's baseline already; it is spelled out because shared memory
    # depends on it (data segments are copied in once, not by every thread).
    "-Ctarget-feature=+atomics,+bulk-memory"
    # Make the linear memory shared, i.e. backed by a SharedArrayBuffer.
    "-Clink-arg=--shared-memory"
    # Import the memory instead of defining it, so that every thread
    # instantiates the module over the same one. wasm-bindgen insists on it.
    "-Clink-arg=--import-memory"
    # wasm-bindgen sets up each thread's thread-local storage through these.
    "-Clink-arg=--export=__wasm_init_tls"
    "-Clink-arg=--export=__tls_size"
    "-Clink-arg=--export=__tls_align"
    "-Clink-arg=--export=__tls_base"
  )
  # The linker rejects shared memory unless every object was compiled for it,
  # and the crate's SQLite C objects are linked into this worker as well. cc-rs
  # reads the hyphenated key first, so passing the flags there, after whatever
  # CFLAGS it would have used, keeps an existing override.
  THREADS_CFLAGS="$(printenv "CFLAGS_$TARGET" || true)"
  THREADS_CFLAGS="${THREADS_CFLAGS:-${CFLAGS_wasm32_unknown_unknown:-${TARGET_CFLAGS:-${CFLAGS:-}}}}"

  echo "==> Building the threaded prover worker ($PROVER_PROFILE)..."
  # The prebuilt std assumes a single thread, so `-Z build-std` compiles std
  # with the flags above from the `rust-src` component. RUSTC_BOOTSTRAP=1 makes
  # the pinned stable toolchain accept that flag and the still unstable
  # `atomics` feature. Nothing can be shared with the default build's
  # artifacts, hence the separate target directory.
  RUSTC_BOOTSTRAP=1 CARGO_TARGET_DIR="$THREADS_TARGET_DIR" \
    env "CFLAGS_$TARGET=$THREADS_CFLAGS -matomics -mbulk-memory" \
    cargo build --locked -p stellar-private-payments-web $PROVER_PROFILE_FLAG --target "$TARGET" \
    --bin prover-worker-threads $CARGO_FEATURE_FLAGS --features threads \
    -Z build-std=panic_abort,std \
    --config "target.$TARGET.rustflags=[$(printf '"%s",' "${THREADS_RUSTFLAGS[@]}")]"
  [[ -f "$THREADS_WASM" ]] || { echo "error: missing $THREADS_WASM" >&2; exit 1; }
fi

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
PROVER_WASM="$PROVER_ARTIFACTS/prover-worker.wasm"

for f in "$MAIN_WASM" "$STORAGE_WASM" "$PROVER_WASM"; do
  [[ -f "$f" ]] || { echo "error: missing $f" >&2; exit 1; }
done

rm -rf "$WEB/dist"
mkdir -p "$WEB/dist/workers"

wasm-bindgen --target web --out-dir "$WEB/dist" --out-name "$WASM_OUT_NAME" "$MAIN_WASM"
wasm-bindgen --target web --out-dir "$WEB/dist/workers" --out-name storage-worker-module "$STORAGE_WASM"
wasm-bindgen --target web --out-dir "$WEB/dist/workers" --out-name prover-worker-module "$PROVER_WASM"

echo "==> Running wasm-opt (-Os main/storage, -O3 prover)..."
optimize_wasm() {
  local level="$1"
  local file="$2"
  shift 2
  "$WASM_OPT" "$level" \
    --enable-bulk-memory \
    --enable-reference-types \
    --enable-multivalue \
    --enable-sign-ext \
    --enable-nontrapping-float-to-int \
    --enable-mutable-globals \
    "$@" \
    "$file" -o "$file"
}

optimize_wasm -Os "$WEB/dist/${WASM_OUT_NAME}_bg.wasm"
optimize_wasm -Os "$WEB/dist/workers/storage-worker-module_bg.wasm"
# The prover worker is the only compute-bound module; -O3 costs ~nothing in
# size and is the only module where it is worth applying.
optimize_wasm -O3 "$WEB/dist/workers/prover-worker-module_bg.wasm"

write_worker_loader() {
  local name="$1"
  cat >"$WEB/dist/workers/${name}.js" <<EOF
import init from './${name}-module.js';
EOF
  if [[ "$name" == prover-worker* ]]; then
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

if [[ "$THREADS" == "1" ]]; then
  wasm-bindgen --target web --out-dir "$WEB/dist/workers" --out-name prover-worker-threads-module "$THREADS_WASM"
  # The pool's threads are started by this wasm-bindgen-rayon snippet, which is
  # only there if the worker really was compiled with atomics. RUSTFLAGS in the
  # environment, for one, replaces the flags passed above.
  THREADS_SNIPPET=("$WEB/dist/workers/snippets"/wasm-bindgen-rayon-*/src/workerHelpers.no-bundler.js)
  if [[ ! -f "${THREADS_SNIPPET[0]}" ]]; then
    echo "error: prover-worker-threads was built without atomics (is RUSTFLAGS set?)" >&2
    exit 1
  fi
  # Atomic instructions do not validate without --enable-threads.
  optimize_wasm -O3 "$WEB/dist/workers/prover-worker-threads-module_bg.wasm" --enable-threads
  write_worker_loader prover-worker-threads
fi

# js/index.js reads this to know whether a threaded worker is part of the
# build, without probing for it over the network. It is a module so that it
# works unbundled and bundled alike; the URL sits here, not in index.js, so a
# bundler only ever sees a `new URL` for a file that exists.
if [[ "$THREADS" == "1" ]]; then
  cat >"$WEB/dist/prover-threads.js" <<'EOF'
export const threadedProverWorkerUrl =
  new URL('./workers/prover-worker-threads.js', import.meta.url).href;
EOF
else
  cat >"$WEB/dist/prover-threads.js" <<'EOF'
export const threadedProverWorkerUrl = null;
EOF
fi

echo "==> Staging bundled circuit artifacts..."
bash "$WEB/scripts/stage-circuits-dist.sh"

echo "==> Staging wasm-bindgen TypeScript declarations..."
bash "$WEB/scripts/stage-wasm-types.sh"

# Shared with Trunk.toml and the Makefile; includes both wasm profiles and
# whether the threaded prover worker was built.
sh "$WEB/scripts/profile-key.sh" > "$WEB/.trunk-wasm-profile"

echo "==> Built sdk/web/dist/"
