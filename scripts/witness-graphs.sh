#!/usr/bin/env bash
# Regenerate the committed circom-witness-rs operation graphs under
# deployments/testnet/circuit_keys/*.graph.bin.
#
# Requires a Circom CLI matching circuits/circom.lock and a C++ toolchain.
#
# The circomlib black-box hint patch must be on disk before cargo runs:
# `circom-witness-rs` shells out to the `circom` CLI from its own build script,
# so a scope guard inside our binary would be applied far too late. Without the
# patch the graph runtime cannot evaluate circomlib's inline `<--` assignments
# in IsZero and Num2Bits.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
KEYS_DIR="${KEYS_DIR:-$ROOT/deployments/testnet/circuit_keys}"

builder() {
  cargo run --quiet --release --manifest-path "$ROOT/Cargo.toml" -p circuit-builder -- "$@"
}

# Production stems (keep in sync with the SDK). Override by naming stems as
# arguments, e.g. `scripts/witness-graphs.sh policy_tx_2_2`.
STEMS=(
  policy_tx_2_2
  policy_tx_2_2_A
  policy_tx_2_2_B
  policy_tx_2_2_AB
  selectiveDisclosure_1
  selectiveDisclosure_2
  selectiveDisclosure_3
  selectiveDisclosure_4
)
if [[ $# -gt 0 ]]; then
  STEMS=("$@")
fi

cleanup() { builder patch --undo --circuits-dir "$ROOT/circuits" || true; }
trap cleanup EXIT INT TERM

echo "==> Patching circomlib (Circom $(tr -d '[:space:]' < "$ROOT/circuits/circom.lock"))..."
builder patch --circuits-dir "$ROOT/circuits"

for stem in "${STEMS[@]}"; do
  echo "===== $stem ====="
  # circom-witness-rs bakes one circuit into its own build script, so it must be
  # rebuilt per stem for WITNESS_CPP to be re-read. `cargo clean -p` defaults to
  # the dev profile, so it must be told --release to match the build below --
  # otherwise nothing is invalidated and every stem silently reuses the first
  # circuit's graph.
  cargo clean -p circom-witness-rs --release >/dev/null
  CIRCOM_LIBRARY_PATH="$ROOT/circuits/src" \
  WITNESS_CPP="$ROOT/circuits/src/$stem.circom" \
  cargo run --release -p witness-graph-gen --features witness-graph-gen/build-witness -- \
    --keys-dir "$KEYS_DIR" --circom-lock "$ROOT/circuits/circom.lock"
done

# Distinct circuits cannot share a graph. Equal digests mean a stale build was
# reused, which would ship the wrong witness generator for every stem but one.
if [[ ${#STEMS[@]} -gt 1 ]]; then
  digests=$(cd "$KEYS_DIR" && for s in "${STEMS[@]}"; do shasum -a 256 "$s.graph.bin"; done | cut -d' ' -f1)
  if [[ $(echo "$digests" | sort -u | wc -l) -ne ${#STEMS[@]} ]]; then
    echo "error: two stems produced the same graph; the per-stem rebuild did not happen" >&2
    exit 1
  fi
fi

echo "Done. Graphs in $KEYS_DIR"
