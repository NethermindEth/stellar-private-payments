#!/usr/bin/env sh
set -eu

STAGING_DIR="${1:-}"
if [ -z "$STAGING_DIR" ]; then
  echo "usage: $0 <STAGING_DIR> [SOURCE_BUNDLE_URL]" >&2
  exit 2
fi

# Optional override for the Corresponding Source bundle URL baked into
# circuits/NOTICE.txt. Defaults to the published GitHub Pages location used by
# the web distribution; the CLI release passes its release-asset URL instead.
SOURCE_BUNDLE_URL="${2:-https://nethermindeth.github.io/stellar-private-payments/circuits/source-bundle.tar.gz}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

mkdir -p "$STAGING_DIR/licenses"
mkdir -p "$STAGING_DIR/circuits"

# Top-level distribution license (Apache-2.0 for this project’s code/assets).
cp "$REPO_ROOT/LICENSE" "$STAGING_DIR/LICENSE.txt"

# Aggregate distribution notices.
cp "$REPO_ROOT/deployments/legal/dist/NOTICE.txt" "$STAGING_DIR/NOTICE.txt"

# Terms & Conditions / disclaimer shown to users (kept as markdown).
cp "$REPO_ROOT/sdk/state/src/disclaimer.md" "$STAGING_DIR/DISCLAIMER.txt"

# License texts needed for the circomlib (LGPL) sub-distribution.
cp "$REPO_ROOT/deployments/legal/licenses/LGPL-3.0.txt" "$STAGING_DIR/licenses/LGPL-3.0.txt"
cp "$REPO_ROOT/circuits/COPYING" "$STAGING_DIR/licenses/GPL-3.0.txt"

# Fill in the circuits notice template. Placeholder substitution lives in a
# shared script (fill-circuits-notice.sh) so every consumer fills it the same way.
sh "$SCRIPT_DIR/fill-circuits-notice.sh" "$SOURCE_BUNDLE_URL" > "$STAGING_DIR/circuits/NOTICE.txt"
