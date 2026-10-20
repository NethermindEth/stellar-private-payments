#!/usr/bin/env bash
# Cargo discovers workspace members and validates TOML; jq checks resolved policy.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

fail() { echo "MSRV: $*" >&2; exit 1; }
metadata=$(cargo +stable metadata --locked --offline --no-deps --format-version 1)

# Read the authoritative field in the repository's canonical manifest layout.
# Reject unsupported formatting rather than silently taking a member's value.
version=$(awk '
  /^[[:space:]]*\[/ { section = ($0 ~ /^\[workspace\.package\][[:space:]]*(#.*)?$/) }
  section && /^rust-version[[:space:]]*=/ {
    if ($0 !~ /^rust-version[[:space:]]*=[[:space:]]*"[0-9]+\.[0-9]+(\.[0-9]+)?"[[:space:]]*(#.*)?$/) exit 1
    sub(/^[^"]*"/, ""); sub(/".*$/, ""); print
  }
' Cargo.toml) || fail 'expected rust-version = "X.Y[.Z]" in [workspace.package]'
[[ "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || fail 'missing or invalid workspace.package.rust-version'

invalid=$(jq -r --arg version "$version" '
  .workspace_members as $members |
  [.packages[] | select(.id as $id | $members | index($id))] |
  if length == 0 then error("workspace has no members")
  else map(select(.rust_version != $version) | .manifest_path) | join("\n") end
' <<< "$metadata")
[[ -z "$invalid" ]] || fail "missing or mismatched rust-version (expected $version): $invalid"

manifests=$(jq -r '.workspace_members as $members | .packages[] |
  select(.id as $id | $members | index($id)) | .manifest_path' <<< "$metadata")
while IFS= read -r manifest; do
  awk '
    /^[[:space:]]*\[/ { section = ($0 ~ /^\[package\][[:space:]]*(#.*)?$/) }
    section && /^rust-version\.workspace[[:space:]]*=[[:space:]]*true[[:space:]]*(#.*)?$/ { inherited = 1 }
    END { exit !inherited }
  ' "$manifest" || fail "$manifest must use rust-version.workspace = true in [package]"
done <<< "$manifests"

# These independent first-party packages have their own workspaces and lockfiles.
# Do not scan arbitrary untracked manifests or third-party patches as members.
for directory in integration-tests integration-tests-web tools/bootnode; do
  package=$(cargo +stable metadata --manifest-path "$directory/Cargo.toml" \
    --locked --offline --no-deps --format-version 1)
  jq -e --arg path "$ROOT/$directory/Cargo.toml" --arg version "$version" '
    [.packages[] | select(.manifest_path == $path)] |
    length == 1 and .[0].rust_version == $version
  ' <<< "$package" > /dev/null || fail "$directory/Cargo.toml must declare MSRV $version"
done
printf '%s\n' "$version"
