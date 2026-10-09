#!/usr/bin/env bash
# Ask Cargo to resolve inherited manifest fields; jq validates the resulting JSON.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

# Stable Cargo reads the policy before the minimum compiler is installed.
# The SDK inherits its rust-version from workspace.package.
version=$(cargo +stable read-manifest --manifest-path sdk/native/Cargo.toml |
  jq -er '.rust_version | select(type == "string" and test("^[0-9]+\\.[0-9]+(\\.[0-9]+)?$"))')

while IFS= read -r -d '' manifest; do
  case "$manifest" in
    Cargo.toml|vendor/*) continue ;;
  esac
  if ! cargo +stable read-manifest --manifest-path "$manifest" |
    jq -e --arg version "$version" '.rust_version == $version' > /dev/null; then
    echo "$manifest: rust-version must resolve to $version" >&2
    exit 1
  fi
done < <(git ls-files -z --cached --others --exclude-standard -- '*Cargo.toml')

printf '%s\n' "$version"
