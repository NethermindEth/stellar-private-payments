#!/usr/bin/env bash
# Exercise release selection without a Git repository, tags, or registry writes.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture"/{scripts,sdk/native,sdk/web,cli,bin,previous}
cp "$ROOT/scripts/release-versions.sh" "$fixture/scripts/"
export RELEASE_TEST_ROOT="$fixture"
export GITHUB_OUTPUT="$fixture/output"

# Only the read operations used by planning and retry are available. Any tag,
# push, or other unexpected Git operation fails the test.
cat > "$fixture/bin/git" <<'SH'
#!/bin/sh
case "$*" in
  'rev-parse HEAD~1') test "${RELEASE_TEST_NO_PARENT:-0}" = 0 ;;
  'show HEAD~1:'*) cat "$RELEASE_TEST_ROOT/previous/${2#HEAD~1:}" ;;
  'rev-parse --verify refs/tags/'*) test "${RELEASE_TEST_MISSING_TAG:-0}" = 0 ;;
  'merge-base --is-ancestor refs/tags/'*) test "${RELEASE_TEST_NOT_ANCESTOR:-0}" = 0 ;;
  'diff --quiet refs/tags/'*) test "${RELEASE_TEST_SOURCE_CHANGED:-0}" = 0 ;;
  *) echo "unexpected Git operation: $*" >&2; exit 99 ;;
esac
SH
chmod +x "$fixture/bin/git"
export PATH="$fixture/bin:$PATH"

write_versions() {
  printf '[workspace.package]\nversion = "%s"\n' "$1" > "$fixture/Cargo.toml"
  printf '[package]\nversion = "%s"\n' "$1" > "$fixture/sdk/native/Cargo.toml"
  printf '{"name":"release-test","version":"%s"}\n' "$2" > "$fixture/sdk/web/package.json"
  printf '[package]\nversion = "%s"\n' "$3" > "$fixture/cli/Cargo.toml"
}
plan() {
  : > "$GITHUB_OUTPUT"
  sh "$fixture/scripts/release-versions.sh" plan "$1"
}

write_versions 0.2.0 0.2.0 0.2.0
cp -R "$fixture/sdk" "$fixture/cli" "$fixture/Cargo.toml" "$fixture/previous/"

# PRs validate every package even without a version bump (or a parent commit).
plan all
diff -u <(printf 'publish_sdk=0.2.0\npublish_npm=0.2.0\npublish_cli=0.2.0\n') "$GITHUB_OUTPUT"
# Pushes without bumps must not select any package for publication.
plan changed
test ! -s "$GITHUB_OUTPUT"
# A first commit can still be validated, but preserves the tag command's skip.
export RELEASE_TEST_NO_PARENT=1
plan all
test "$(wc -l < "$GITHUB_OUTPUT")" -eq 3
plan changed
test ! -s "$GITHUB_OUTPUT"
unset RELEASE_TEST_NO_PARENT
# Independent patch bumps select only their respective package.
for package in sdk npm cli; do
  case "$package" in
    sdk) write_versions 0.2.1 0.2.0 0.2.0 ;;
    npm) write_versions 0.2.0 0.2.1 0.2.0 ;;
    cli) write_versions 0.2.0 0.2.0 0.2.1 ;;
  esac
  plan changed
  diff -u <(printf 'publish_%s=0.2.1\n' "$package") "$GITHUB_OUTPUT"
done
# Workspace-inherited versions use the current and previous workspace values.
write_versions 0.2.2 0.2.0 0.2.0
printf '[package]\nversion.workspace = true\n' > "$fixture/sdk/native/Cargo.toml"
cp "$fixture/sdk/native/Cargo.toml" "$fixture/previous/sdk/native/Cargo.toml"
plan changed
diff -u <(printf 'publish_sdk=0.2.2\n') "$GITHUB_OUTPUT"
# Invalid release alignment must fail before producing any publish outputs.
write_versions 0.3.0 0.2.0 0.2.0
if plan all; then
  echo 'Expected mismatched major.minor to fail' >&2
  exit 1
fi
test ! -s "$GITHUB_OUTPUT"
if plan invalid; then
  echo 'Expected invalid mode to fail' >&2
  exit 1
fi
test ! -s "$GITHUB_OUTPUT"

# A workflow-only repair can retry any unchanged, previously tagged version.
# The stub rejects every tag/push operation, so these paths cannot move tags.
write_versions 0.2.0 0.2.0 0.2.0
retry() {
  : > "$GITHUB_OUTPUT"
  sh "$fixture/scripts/release-versions.sh" retry "$1"
}
for package in sdk npm cli; do
  retry "$package"
  diff -u <(printf 'publish_%s=0.2.0\n' "$package") "$GITHUB_OUTPUT"
done
for failure in RELEASE_TEST_MISSING_TAG RELEASE_TEST_NOT_ANCESTOR RELEASE_TEST_SOURCE_CHANGED; do
  export "$failure=1"
  if retry sdk; then
    echo "Expected retry rejection: $failure" >&2
    exit 1
  fi
  test ! -s "$GITHUB_OUTPUT"
  unset "$failure"
done
if retry invalid; then
  echo 'Expected invalid retry package to fail' >&2
  exit 1
fi
test ! -s "$GITHUB_OUTPUT"

# Feed the real CLI completion predicate synthetic read-only API responses.
cat > "$fixture/bin/curl" <<'SH'
#!/bin/sh
cat "$RELEASE_TEST_ROOT/release.json"
SH
chmod +x "$fixture/bin/curl"
node - <<'JS'
const fs = require('fs');
const names = ['dist.tar.gz', 'source-bundle.tar.gz',
  ...['x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl',
    'x86_64-apple-darwin', 'aarch64-apple-darwin'].map(t => `spp-${t}.tar.gz`)];
const assets = names.flatMap(name => [name, `${name}.sha256`])
  .map(name => ({name, state: 'uploaded', size: 10}));
fs.writeFileSync(`${process.env.RELEASE_TEST_ROOT}/complete.json`,
  JSON.stringify({draft: false, assets}));
JS
cp "$fixture/complete.json" "$fixture/release.json"
sh "$fixture/scripts/release-versions.sh" published cli 0.2.0
for mutation in dist-only draft empty uploading missing-0 missing-1 missing-2 missing-3 \
  missing-4 missing-5 missing-6 missing-7 missing-8 missing-9 missing-10 missing-11; do
  node - "$mutation" <<'JS'
const fs = require('fs');
const root = process.env.RELEASE_TEST_ROOT;
const r = JSON.parse(fs.readFileSync(`${root}/complete.json`));
const mode = process.argv[2];
if (mode === 'dist-only') r.assets = r.assets.filter(a => a.name === 'dist.tar.gz');
if (mode === 'draft') r.draft = true;
if (mode === 'empty') r.assets[0].size = 0;
if (mode === 'uploading') r.assets[0].state = 'new';
if (mode.startsWith('missing-')) r.assets.splice(Number(mode.slice(8)), 1);
fs.writeFileSync(`${root}/release.json`, JSON.stringify(r));
JS
  if sh "$fixture/scripts/release-versions.sh" published cli 0.2.0; then
    echo "Incomplete release incorrectly accepted: $mutation" >&2
    exit 1
  fi
done
echo 'Release planning, recovery, and asset completeness checks passed'
