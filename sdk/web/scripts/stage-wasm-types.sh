#!/usr/bin/env bash
# Copy wasm-bindgen declarations into js/types/crates/ for package type-checking.
set -euo pipefail

WEB="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$WEB/dist/stellar_private_payments_web.d.ts"
DEST_DIR="$WEB/js/types/crates"
DEST="$DEST_DIR/stellar_private_payments_web.d.ts"

[[ -f "$SRC" ]] || {
  echo "error: missing $SRC — run wasm-bindgen via npm run build first" >&2
  exit 1
}

mkdir -p "$DEST_DIR"
cp "$SRC" "$DEST"
echo "Copied dist/stellar_private_payments_web.d.ts → js/types/crates/"
