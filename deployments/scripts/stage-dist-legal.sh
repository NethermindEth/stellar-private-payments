#!/usr/bin/env sh
set -eu

STAGING_DIR="${1:-}"
if [ -z "$STAGING_DIR" ]; then
  echo "usage: $0 <TRUNK_STAGING_DIR>" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

mkdir -p "$STAGING_DIR/licenses"
mkdir -p "$STAGING_DIR/circuits"

# Top-level distribution license (Apache-2.0 for this project’s code/assets).
cp "$REPO_ROOT/LICENSE" "$STAGING_DIR/LICENSE"

# Aggregate distribution notices.
cp "$REPO_ROOT/deployments/legal/dist/NOTICE.txt" "$STAGING_DIR/NOTICE"

# License texts needed for the circomlib (LGPL) sub-distribution.
cp "$REPO_ROOT/deployments/legal/licenses/LGPL-3.0.txt" "$STAGING_DIR/licenses/LGPL-3.0.txt"
cp "$REPO_ROOT/circuits/COPYING" "$STAGING_DIR/licenses/GPL-3.0.txt"

# Fill in the circuits notice template.
CIRCOMLIB_COMMIT="$(cat "$REPO_ROOT/circuits/circomlib.lock" 2>/dev/null | tr -d '\n' | tr -d '\r' | tr -d ' ')"
if [ -z "$CIRCOMLIB_COMMIT" ]; then
  CIRCOMLIB_COMMIT="unknown"
fi

REPO_COMMIT="unknown"
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  REPO_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
fi

BUILD_DATE_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# normalize github url to https://...
REPO_URL="unknown"
if command -v git >/dev/null 2>&1; then
  ORIGIN_URL="$(git -C "$REPO_ROOT" config --get remote.origin.url 2>/dev/null || true)"
  if [ -n "$ORIGIN_URL" ]; then
    case "$ORIGIN_URL" in
      git@github.com:*.git)
        REPO_URL="https://github.com/$(echo "$ORIGIN_URL" | sed -e 's|^git@github.com:||' -e 's|\\.git$||')"
        ;;
      https://github.com/*.git)
        REPO_URL="$(echo "$ORIGIN_URL" | sed -e 's|\\.git$||')"
        ;;
      https://github.com/*)
        REPO_URL="$ORIGIN_URL"
        ;;
    esac
  fi
fi

SOURCE_BUNDLE_URL="$REPO_URL/releases"

sed \
  -e "s|@REPO_COMMIT@|$REPO_COMMIT|g" \
  -e "s|@BUILD_DATE_UTC@|$BUILD_DATE_UTC|g" \
  -e "s|@CIRCOMLIB_COMMIT@|$CIRCOMLIB_COMMIT|g" \
  -e "s|@SOURCE_BUNDLE_URL@|$SOURCE_BUNDLE_URL|g" \
  "$REPO_ROOT/deployments/legal/dist/circuits-NOTICE.txt" > "$STAGING_DIR/circuits/NOTICE"
