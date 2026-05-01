#!/usr/bin/env sh
set -eu

OUT_TARBALL="${1:-circuits-source-bundle.tar.gz}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOCK_SHA="$(cat "$REPO_ROOT/circuits/circomlib.lock" 2>/dev/null | tr -d '\n' | tr -d '\r' | tr -d ' ')"
if [ -z "$LOCK_SHA" ]; then
  echo "missing circuits/circomlib.lock" >&2
  exit 1
fi

CIRCOMLIB_DIR="$REPO_ROOT/circuits/src/circomlib"
if [ ! -d "$CIRCOMLIB_DIR" ]; then
  echo "missing circuits/src/circomlib (build the project first so circomlib is staged)" >&2
  exit 1
fi

REPO_COMMIT="unknown"
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  REPO_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
fi

REPO_URL="https://github.com/NethermindEth/stellar-private-payments"

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR/src/circuits"

# Copy Circom sources + circomlib from the build-staged directory.
mkdir -p "$TMP_DIR/src/circuits/src"
cp -R "$REPO_ROOT/circuits/src/"* "$TMP_DIR/src/circuits/src/"

# Add build instructions and license texts for redistribution.
cat > "$TMP_DIR/src/BUILDING.md" <<EOF
# Circuits source bundle

This bundle is provided to help recipients rebuild the compiled artifacts
shipped under \`dist/circuits/\` and to satisfy LGPL-3.0 expectations.

## Contents
- \`circuits/src/\`: Circom sources from this repository (including the vendored \`circomlib\`)
- \`licenses/\`: License texts for redistribution

## Build (example)
This archive is **not** a standalone Rust workspace. To rebuild the compiled
artifacts, you need the full repository checkout.

1) Obtain the repository sources (at the same revision used to build the
distributed artifacts):

- Repository: $REPO_URL
- Commit: $REPO_COMMIT

2) Overlay the bundled circuits sources onto the repository checkout so that
\`circomlib\` is present at the expected path:

\`\`\`
cp -R circuits/src/ <REPO_ROOT>/circuits/src/
\`\`\`

At minimum, ensure:
\`<REPO_ROOT>/circuits/src/circomlib\` matches revision: $LOCK_SHA

3) Build the circuits crate from the repository root:

\`\`\`
cargo build -p circuits --release
\`\`\`

The build produces circuit artifacts under Cargo \`OUT_DIR\` and the frontend
build copies them into \`dist/circuits/\` via Trunk hooks.
EOF

mkdir -p "$TMP_DIR/src/licenses"
cp "$REPO_ROOT/LICENSE" "$TMP_DIR/src/licenses/Apache-2.0.txt"
cp "$REPO_ROOT/deployments/legal/licenses/LGPL-3.0.txt" "$TMP_DIR/src/licenses/LGPL-3.0.txt"
cp "$REPO_ROOT/circuits/COPYING" "$TMP_DIR/src/licenses/GPL-3.0.txt"

tar -C "$TMP_DIR/src" -czf "$OUT_TARBALL" .
