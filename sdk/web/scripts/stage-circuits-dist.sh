#!/usr/bin/env bash
# Stage compiled circuits + LGPL corresponding source into sdk/web/dist/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WEB="$ROOT/sdk/web"
PROFILE="${WASM_PROFILE:-release}"
CIRCUITS_OUT="$ROOT/target/circuits-artifacts/$PROFILE"
DIST="$WEB/dist"

ARTIFACTS=(
  policy_tx_2_2_open.wasm
  policy_tx_2_2_open.r1cs
  policy_tx_2_2_allowlist.wasm
  policy_tx_2_2_allowlist.r1cs
  policy_tx_2_2_blocklist.wasm
  policy_tx_2_2_blocklist.r1cs
  policy_tx_2_2_both.wasm
  policy_tx_2_2_both.r1cs
  selectiveDisclosure_1.wasm
  selectiveDisclosure_1.r1cs
  selectiveDisclosure_2.wasm
  selectiveDisclosure_2.r1cs
  selectiveDisclosure_3.wasm
  selectiveDisclosure_3.r1cs
  selectiveDisclosure_4.wasm
  selectiveDisclosure_4.r1cs
)

if [[ ! -d "$CIRCUITS_OUT" ]]; then
  echo "error: missing $CIRCUITS_OUT — run cargo build -p circuits --$PROFILE" >&2
  exit 1
fi

mkdir -p "$DIST/circuits" "$DIST/licenses"

for name in "${ARTIFACTS[@]}"; do
  src="$CIRCUITS_OUT/$name"
  [[ -f "$src" ]] || { echo "error: missing circuit artifact $src" >&2; exit 1; }
  cp "$src" "$DIST/circuits/$name"
done

echo "==> Packaging circuits source bundle (LGPL corresponding source)..."
sh "$ROOT/deployments/scripts/package-circuits-source-bundle.sh" \
  "$DIST/circuits/source-bundle.tar.gz"

cp "$ROOT/LICENSE" "$DIST/LICENSE.txt"
cp "$ROOT/deployments/legal/licenses/LGPL-3.0.txt" "$DIST/licenses/LGPL-3.0.txt"
cp "$ROOT/circuits/COPYING" "$DIST/licenses/GPL-3.0.txt"

CIRCOMLIB_COMMIT="$(tr -d ' \n\r' < "$ROOT/circuits/circomlib.lock" 2>/dev/null || true)"
CIRCOMLIB_COMMIT="${CIRCOMLIB_COMMIT:-unknown}"

REPO_COMMIT="unknown"
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  REPO_COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
fi

BUILD_DATE_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
SOURCE_BUNDLE_URL="./source-bundle.tar.gz"

sed \
  -e "s|@REPO_COMMIT@|$REPO_COMMIT|g" \
  -e "s|@BUILD_DATE_UTC@|$BUILD_DATE_UTC|g" \
  -e "s|@CIRCOMLIB_COMMIT@|$CIRCOMLIB_COMMIT|g" \
  -e "s|@SOURCE_BUNDLE_URL@|$SOURCE_BUNDLE_URL|g" \
  -e 's|`dist/licenses/|`../licenses/|g' \
  -e 's|`dist/LICENSE.txt`|`../LICENSE.txt`|g' \
  "$ROOT/deployments/legal/dist/circuits-NOTICE.txt" > "$DIST/circuits/NOTICE.txt"

echo "==> Staged dist/circuits/ ($(du -sh "$DIST/circuits" | awk '{print $1}'))"
