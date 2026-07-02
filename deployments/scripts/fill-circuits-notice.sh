#!/usr/bin/env sh
set -eu

# Fill the circuits NOTICE template
# (`deployments/legal/dist/circuits-NOTICE.txt`) and print it to stdout.
#
# Single source of truth for the `@…@` placeholder substitution, shared by:
#   - deployments/scripts/stage-dist-legal.sh  (web `dist/` bundle)
#   - cli/build.rs                             (CLI binary, embedded via include_str!)
#
# usage: $0 [SOURCE_BUNDLE_URL]
#
# SOURCE_BUNDLE_URL fills @SOURCE_BUNDLE_URL@. When omitted it defaults to the
# published GitHub Pages location used by the web distribution. Callers that fill
# it themselves later (e.g. the CLI, which derives a version-specific release URL
# at runtime) can pass the literal `@SOURCE_BUNDLE_URL@` sentinel to leave it
# untouched.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SOURCE_BUNDLE_URL="${1:-https://nethermindeth.github.io/stellar-private-payments/circuits/source-bundle.tar.gz}"

CIRCOMLIB_COMMIT="$(cat "$REPO_ROOT/circuits/circomlib.lock" 2>/dev/null | tr -d '\n' | tr -d '\r' | tr -d ' ')"
if [ -z "$CIRCOMLIB_COMMIT" ]; then
  CIRCOMLIB_COMMIT="unknown"
fi

REPO_COMMIT="unknown"
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  REPO_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
fi

BUILD_DATE_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

sed \
  -e "s|@REPO_COMMIT@|$REPO_COMMIT|g" \
  -e "s|@BUILD_DATE_UTC@|$BUILD_DATE_UTC|g" \
  -e "s|@CIRCOMLIB_COMMIT@|$CIRCOMLIB_COMMIT|g" \
  -e "s|@SOURCE_BUNDLE_URL@|$SOURCE_BUNDLE_URL|g" \
  "$REPO_ROOT/deployments/legal/dist/circuits-NOTICE.txt"
