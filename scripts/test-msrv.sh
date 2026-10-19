#!/usr/bin/env bash
# Regression checks use real Cargo metadata in a disposable, Git-free workspace.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/scripts"
cp "$ROOT/scripts/msrv.sh" "$fixture/scripts/"
cat > "$fixture/Cargo.toml" <<'TOML'
[workspace]
members = ["member"]
exclude = ["integration-tests", "integration-tests-web", "tools/bootnode"]
resolver = "3"
[workspace.package]
rust-version = "1.95.0"
TOML
for directory in member integration-tests integration-tests-web tools/bootnode; do
  mkdir -p "$fixture/$directory/src"
  printf '[package]\nname = "%s"\nversion = "0.0.0"\n' "${directory##*/}" > "$fixture/$directory/Cargo.toml"
  if [[ "$directory" == member ]]; then
    echo 'rust-version.workspace = true' >> "$fixture/$directory/Cargo.toml"
  else
    echo 'rust-version = "1.95.0"' >> "$fixture/$directory/Cargo.toml"
  fi
  touch "$fixture/$directory/src/lib.rs"
done

expect_failure() {
  if bash "$fixture/scripts/msrv.sh" > "$fixture/output" 2> "$fixture/error"; then
    echo "Unexpected policy success: $1" >&2
    exit 1
  fi
  [[ -s "$fixture/error" ]] || { echo "Missing diagnostic: $1" >&2; exit 1; }
}

[[ $(bash "$fixture/scripts/msrv.sh") == 1.95.0 ]]
# Git failure cannot disable validation: discovery no longer uses Git.
export GIT_DIR="$fixture/no-such-git-directory"
printf '\n' >> "$fixture/member/Cargo.toml"
sed -i '/rust-version/d' "$fixture/member/Cargo.toml"
expect_failure 'missing member declaration with invalid GIT_DIR'
echo 'rust-version = "1.95.0"' >> "$fixture/member/Cargo.toml"
expect_failure 'hardcoded member version instead of inheritance'
sed -i 's/1.95.0/1.96.0/' "$fixture/Cargo.toml"
expect_failure 'root policy differs from hardcoded package declarations'
sed -i 's/1.96.0/1.95.0/' "$fixture/Cargo.toml"
sed -i 's/rust-version = "1.95.0"/rust-version.workspace = true/' "$fixture/member/Cargo.toml"
sed -i 's/1.95.0/1.96.0/' "$fixture/tools/bootnode/Cargo.toml"
expect_failure 'independent package mismatch'
sed -i 's/1.96.0/1.95.0/' "$fixture/tools/bootnode/Cargo.toml"
sed -i '/rust-version/d' "$fixture/Cargo.toml"
expect_failure 'missing authoritative root declaration'
echo 'rust-version = "1.95.0"' >> "$fixture/Cargo.toml"
mkdir -p "$fixture/scratch"
echo 'unrelated invalid TOML' > "$fixture/scratch/Cargo.toml"
[[ $(bash "$fixture/scripts/msrv.sh") == 1.95.0 ]]
sed -i 's/\["member"\]/["member*"]/' "$fixture/Cargo.toml"
mkdir -p "$fixture/member-new/src"
printf '[package]\nname = "member-new"\nversion = "0.0.0"\n' > "$fixture/member-new/Cargo.toml"
touch "$fixture/member-new/src/lib.rs"
expect_failure 'new workspace member without an MSRV'
echo 'MSRV policy regression checks passed'
