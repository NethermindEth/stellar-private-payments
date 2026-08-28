#!/usr/bin/env sh
# Release version helpers for sdk (crates.io), npm, and cli.
#
#   check     — major.minor must match across sdk/native, npm, and cli
#   tag       — push sdk-v* / npm-v* / cli-v* for bumped versions; sets publish_* outputs
#   published — exit 0 if VERSION is already on the registry (crates.io / npm / GitHub)
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Resolve package.version from a crate Cargo.toml body. If the crate uses
# version.workspace = true, take [workspace.package].version from the workspace body.
crate_version() {
  crate_toml="$1"
  workspace_toml="$2"
  ver="$(printf '%s\n' "$crate_toml" | sed -n 's/^version = "\([^"]*\)".*/\1/p' | head -1)"
  if [ -n "$ver" ]; then
    printf '%s\n' "$ver"
    return 0
  fi
  printf '%s\n' "$crate_toml" | grep -q '^version.workspace = true' || return 0
  printf '%s\n' "$workspace_toml" \
    | sed -n '/^\[workspace.package\]/,/^\[/{s/^version = "\([^"]*\)".*/\1/p;}' \
    | head -1
}

read_cargo_version() {
  crate_version "$(cat "$1")" "$(cat Cargo.toml)"
}

previous_cargo_version() {
  crate_version "$(git show "HEAD~1:$1" 2>/dev/null || true)" \
    "$(git show "HEAD~1:Cargo.toml" 2>/dev/null || true)"
}

read_npm_version() {
  node -p "JSON.parse(require('fs').readFileSync('sdk/web/package.json','utf8')).version"
}

previous_npm_version() {
  git show "HEAD~1:sdk/web/package.json" 2>/dev/null \
    | node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).version" 2>/dev/null \
    || true
}

major_minor() {
  printf '%s\n' "$1" | sed -E 's/^([0-9]+\.[0-9]+).*/\1/'
}

cmd_check() {
  sdk_ver="$(read_cargo_version sdk/native/Cargo.toml)"
  cli_ver="$(read_cargo_version cli/Cargo.toml)"
  npm_ver="$(read_npm_version)"

  [ -n "$sdk_ver" ] && [ -n "$cli_ver" ] && [ -n "$npm_ver" ] || {
    echo "error: could not read sdk, cli, or npm version" >&2
    exit 1
  }

  sdk_mm="$(major_minor "$sdk_ver")"
  cli_mm="$(major_minor "$cli_ver")"
  npm_mm="$(major_minor "$npm_ver")"
  failed=0

  if [ "$sdk_mm" != "$cli_mm" ]; then
    echo "error: sdk/native ($sdk_mm) != cli ($cli_mm)" >&2
    failed=1
  fi
  if [ "$sdk_mm" != "$npm_mm" ]; then
    echo "error: sdk/native ($sdk_mm) != npm ($npm_mm)" >&2
    failed=1
  fi

  [ "$failed" = 0 ] || exit 1
  echo "ok: major.minor $sdk_mm (sdk $sdk_ver, npm $npm_ver, cli $cli_ver)"
}

maybe_tag() {
  prefix="$1"
  current="$2"
  previous="$3"

  [ -n "$current" ] || {
    echo "error: empty version for $prefix" >&2
    return 1
  }
  if [ "$current" = "$previous" ]; then
    echo "skip $prefix ($current unchanged)"
    return 0
  fi

  tag="${prefix}-v${current}"
  head_rev="$(git rev-parse HEAD)"
  if git rev-parse "$tag" >/dev/null 2>&1; then
    tag_rev="$(git rev-parse "$tag")"
    if [ "$tag_rev" != "$head_rev" ]; then
      echo "error: $tag points to $tag_rev but HEAD is $head_rev" >&2
      return 1
    fi
    echo "skip $tag (exists at HEAD)"
  else
    git tag "$tag" HEAD
    git push origin "refs/tags/$tag"
    echo "pushed $tag"
  fi
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "publish_${prefix}=${current}" >> "$GITHUB_OUTPUT"
  fi
}

cmd_tag() {
  # Intended for CI after merge to main (.github/workflows/release.yml gates the job).
  git rev-parse HEAD~1 >/dev/null 2>&1 || {
    echo "skip: no parent commit"
    exit 0
  }

  cmd_check
  maybe_tag sdk "$(read_cargo_version sdk/native/Cargo.toml)" "$(previous_cargo_version sdk/native/Cargo.toml)"
  maybe_tag npm "$(read_npm_version)" "$(previous_npm_version)"
  maybe_tag cli "$(read_cargo_version cli/Cargo.toml)" "$(previous_cargo_version cli/Cargo.toml)"
}

# Exit 0 when the version is already published (registry is source of truth).
cmd_published() {
  target="${1:-}"
  version="${2:-}"

  [ -n "$target" ] && [ -n "$version" ] || {
    echo "usage: $0 published sdk|npm|cli VERSION" >&2
    exit 2
  }

  case "$target" in
    sdk)
      curl -fsSL \
        -H "User-Agent: stellar-private-payments-release (https://github.com/NethermindEth/stellar-private-payments)" \
        "https://crates.io/api/v1/crates/stellar-private-payments/${version}" >/dev/null \
        || exit 1
      ;;
    npm)
      name="$(node -p "JSON.parse(require('fs').readFileSync('sdk/web/package.json','utf8')).name")"
      npm view "${name}@${version}" version >/dev/null 2>&1
      ;;
    cli)
      tag="cli-v${version}"
      repo="${GITHUB_REPOSITORY:-NethermindEth/stellar-private-payments}"
      release="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/tags/${tag}" 2>/dev/null)" || exit 1
      printf '%s\n' "$release" \
        | node -e "
          const r = JSON.parse(require('fs').readFileSync(0, 'utf8'));
          process.exit(r.assets?.some((a) => a.name === 'dist.tar.gz') ? 0 : 1);
        "
      ;;
    *)
      echo "unknown target: $target (expected sdk, npm, or cli)" >&2
      exit 2
      ;;
  esac
}

cmd="${1:-}"
case "$cmd" in
  check) cmd_check ;;
  tag) cmd_tag ;;
  published) cmd_published "$2" "$3" ;;
  *)
    echo "usage: $0 check | tag | published sdk|npm|cli VERSION" >&2
    exit 2
    ;;
esac
