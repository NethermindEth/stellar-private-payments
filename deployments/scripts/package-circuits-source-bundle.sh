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

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR/src/circuits"

# Ensure we have circomlib sources at the locked revision.
CIRCOMLIB_DIR="$REPO_ROOT/circuits/src/circomlib"
if [ ! -d "$CIRCOMLIB_DIR/.git" ]; then
  rm -rf "$CIRCOMLIB_DIR"
  mkdir -p "$CIRCOMLIB_DIR"
  git -C "$CIRCOMLIB_DIR" init -q
  git -C "$CIRCOMLIB_DIR" remote add origin https://github.com/iden3/circomlib.git
fi
git -C "$CIRCOMLIB_DIR" fetch -q --depth 1 origin "$LOCK_SHA"
git -C "$CIRCOMLIB_DIR" checkout -q --detach FETCH_HEAD

# Copy Circom sources + circomlib.
mkdir -p "$TMP_DIR/src/circuits/src"
cp -R "$REPO_ROOT/circuits/src/"* "$TMP_DIR/src/circuits/src/"

# Add build instructions and license texts for redistribution.
cat > "$TMP_DIR/src/BUILDING.md" <<EOF
# Circuits source bundle

This bundle is provided to help recipients rebuild the compiled artifacts
shipped under \`dist/circuits/\` and to satisfy LGPL-3.0 expectations.

## Contents
- \`circuits/src/\`: Circom sources from this repository
- \`circuits/src/circomlib/\`: iden3/circomlib at revision: $LOCK_SHA

## Build (example)
From the repository root:

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
