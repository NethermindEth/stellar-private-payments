#!/usr/bin/env bash
# Compile the Circom circuits into target/circuits-artifacts/.
#
# Only the stems whose sources changed are recompiled, so a full run is cheap.
# Extra arguments are forwarded to `circuit-builder compile`, e.g.
#   scripts/build-circuits.sh --include-tests
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
OUT_DIR="${CIRCUITS_OUT_DIR:-$CARGO_TARGET_DIR/circuits-artifacts}"

# Circuit artifacts do not depend on the Rust profile, so there is one output
# directory. The builder itself is always compiled with optimisations because
# circom compilation is far too slow otherwise.
exec cargo run --quiet --release --manifest-path "$ROOT/Cargo.toml" -p circuit-builder -- \
  compile --circuits-dir "$ROOT/circuits" --out-dir "$OUT_DIR" "$@"
