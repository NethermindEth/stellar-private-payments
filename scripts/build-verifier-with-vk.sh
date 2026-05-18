#!/usr/bin/env bash
# Build the circom-groth16-verifier contract with a verification key embedded
# directly in the WASM binary.
#
# The VK is read from a snarkjs verification_key.json at compile time by the
# crate's build.rs and baked into the contract as static byte arrays.  The
# resulting WASM requires no constructor call and performs no storage reads
# during verification.
#
# Usage:
#   scripts/build-verifier-with-vk.sh <verification_key.json> [--out-dir DIR]
#
# Arguments:
#   verification_key.json   Path to a snarkjs Groth16 verification key JSON.
#
# Options:
#   --out-dir DIR   Directory to copy the built WASM into (default: target/stellar)
#   -h, --help      Show this help
#
# Example (after running the ceremony):
#   scripts/build-verifier-with-vk.sh ceremony/circuit_verification_key.json
#
# The WASM is then ready to be deployed with:
#   deployments/scripts/deploy.sh <network> --deployer alice ...

set -euo pipefail

die()  { echo "build-verifier-with-vk.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

usage() {
  sed -n '2,/^$/p' "$0" | sed 's/^# \?//' >&2
  exit 2
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$ROOT_DIR/target/stellar"

VK_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage ;;
    -*)        die "unknown option: $1" ;;
    *)
      [[ -z "$VK_FILE" ]] || die "unexpected argument: $1"
      VK_FILE="$1"
      shift
      ;;
  esac
done

[[ -n "$VK_FILE" ]] || { echo "error: verification_key.json path is required" >&2; usage; }
[[ -f "$VK_FILE" ]] || die "file not found: $VK_FILE"

VK_FILE="$(realpath "$VK_FILE")"

step "embedding VK from: $VK_FILE"
step "building circom-groth16-verifier (release)"

mkdir -p "$OUT_DIR"

VERIFIER_VK_JSON="$VK_FILE" \
  stellar contract build \
    --manifest-path "$ROOT_DIR/Cargo.toml" \
    --out-dir "$OUT_DIR" \
    --optimize \
    --package circom-groth16-verifier

WASM="$OUT_DIR/circom_groth16_verifier.wasm"
[[ -f "$WASM" ]] || die "expected WASM not found: $WASM"

SIZE="$(wc -c < "$WASM")"
step "done: $WASM ($SIZE bytes)"
step "deploy with: deployments/scripts/deploy.sh <network> --deployer <identity> ..."
