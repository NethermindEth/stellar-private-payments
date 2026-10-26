#!/usr/bin/env bash
# Build every contract from a source archive of this checkout in a pinned build image.
# Usage: scripts/build-contracts.sh --out DIR [--tag TAG] [--repo OWNER/REPO]

set -euo pipefail
# The key-file glob, and so contracts.json and SHA256SUMS, must not follow the caller's locale.
export LC_ALL=C

die() { echo "build-contracts.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is not installed or not on PATH"; }
step() { echo "==> $*" >&2; }

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/build-contracts.sh --out DIR [--tag TAG] [--repo OWNER/REPO]

Archives this checkout with `stellar contract build archive`, builds every contract
from that archive in the pinned build image, and writes to DIR:

  asp_membership.wasm, asp_non_membership.wasm, public_key_registry.wasm,
  pool.wasm, pool_gvk.wasm
  circom_groth16_verifier_<network>_<key name>.wasm
                        one per key file (policy_tx_2_2*_vk.json or
                        keyOwnership_vk.json) in deployments/<network>/circuit_keys,
                        with "none" as the key name of policy_tx_2_2_vk.json
  contracts-source.tar.gz
                        the source archive
  contracts.json        what each Wasm is, its SHA-256, and its meta
  SHA256SUMS            the SHA-256 of every other file in DIR

Each Wasm records its build image, build flags, and source archive hash as SEP-58
meta, so anyone can rebuild it and compare hashes.

The archive step refuses a checkout with uncommitted changes or untracked files,
even files listed only in .git/info/exclude. To build such a checkout, build from
a fresh clone of it or from a worktree made with `git worktree add`.

Needs git, the Stellar CLI 28.1.0 or later, docker, jq, tar, and sha256sum or shasum.

Options:
  --out DIR             Output directory: new or empty, and outside the checkout (required)
  --tag TAG             Release tag; needs --repo. The meta then records
                        source_uri and source_repo
  --repo OWNER/REPO     GitHub repository the release is published from; needs --tag
  -h, --help            Show this help
USAGE
  exit 2
}

# Newest first. The first builds; older ones stay so the releases they built stay checkable.
ALLOWED_IMAGES=(
  'docker.io/stellar/stellar-cli:28.0.0-rust1.97.1-slim-trixie-amd64@sha256:14fe8ca0eb76de7eeaedc977c6d68cb1e5ea2d7ab2e7dc3c43b5389247aed2d0'
)
IMAGE="${ALLOWED_IMAGES[0]}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

OUT=""
TAG=""
REPO=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

[[ -n "$OUT" ]] || usage
[[ -n "$TAG" && -n "$REPO" || -z "$TAG$REPO" ]] || die "--tag and --repo go together"

need stellar
need docker
need jq
need tar
need git
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 \
  || die "install sha256sum or shasum"

cli="$(stellar --version | sed -n '1s/^stellar \([^ ]*\).*/\1/p')"
[[ "$(printf '%s\n' 28.1.0 "$cli" | sort -V | head -1)" == 28.1.0 ]] \
  || die "Stellar CLI $cli has no 'contract build archive'; install 28.1.0 or later"

[[ ! -e "$OUT" || -z "$(ls -A "$OUT")" ]] \
  || die "--out $OUT is not empty; pick a new or empty directory"
parent="$(cd "$(dirname "$OUT")" 2>/dev/null && pwd -P)" \
  || die "--out $OUT: its parent directory does not exist; create it first"
OUT="$parent/$(basename "$OUT")"
# Resolves a link too, so one into the checkout is refused.
[[ ! -d "$OUT" ]] || OUT="$(cd "$OUT" && pwd -P)"
case "$OUT/" in
  "$ROOT"/*) die "--out $OUT is inside the checkout; pick a directory outside it" ;;
esac
mkdir -p "$OUT"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Sets NET, KEY, and FEATURE for a key file under deployments/, by the rule the verifier's
# build.rs uses; fails for a file that is not a verifier key.
read_key_file() {
  local rel="${1#deployments/}" name="${1##*/}"
  NET="${rel%%/*}"
  case "$name" in
    keyOwnership_vk.json) KEY=keyOwnership ;;
    policy_tx_2_2_vk.json) KEY="" ;;
    policy_tx_2_2_*_vk.json) KEY="${name#policy_tx_2_2_}"; KEY="${KEY%_vk.json}" ;;
    *) return 1 ;;
  esac
  FEATURE="$(printf 'vk-%s-%s' "$NET" "${KEY:-none}" | tr '[:upper:]' '[:lower:]' | tr _ -)"
}

# Builds one package from the extraction with each bldopt entry as a flag and every entry as
# --meta, then copies its Wasm to $2.
build_one() {
  local package="$1" dest="$2" entry image="" flags=() metas=()
  shift 2
  for entry in "$@"; do
    case "${entry%%=*}" in
      bldimg) image="${entry#*=}" ;;
      bldopt) flags+=("${entry#*=}") ;;
    esac
    metas+=(--meta "$entry")
  done
  step "build $(basename "$dest")"
  # On a CI runner the image's user cannot write the extraction, and the caller cannot write the
  # image's /stellar, so run as the caller with a /stellar of its own.
  docker run --platform linux/amd64 --rm --user "$(id -u):$(id -g)" \
    -v "$WORK/stellar:/stellar" -v "$SRC:/source" \
    "$image" contract build "${flags[@]}" "${metas[@]}"
  # Every verifier build writes this same path, so copy it out before the next build.
  cp "$SRC/target/wasm32v1-none/release/${package//-/_}.wasm" "$dest"
}

# Builds a package into $OUT/$2 with the release meta and records it for contracts.json. A
# verifier passes its feature in $3 and its key fields as a JSON object in $4.
release_one() {
  local package="$1" file="$2" feature="${3:-}" kind=contract
  local meta=("bldimg=$IMAGE" "bldopt=--package=$package" bldopt=--locked bldopt=--optimize)
  if [[ -n "$feature" ]]; then
    kind=verifier
    meta+=("bldopt=--features=$feature")
  fi
  meta+=("source_sha256=$SOURCE_SHA256")
  [[ -z "$TAG" ]] || meta+=("source_uri=$SOURCE_URI" "source_repo=github:$REPO")
  build_one "$package" "$OUT/$file" "${meta[@]}"
  jq -cn --arg kind "$kind" --arg package "$package" --arg file "$file" \
    --arg sha256 "$(sha256 "$OUT/$file")" --argjson extra "${4:-null}" \
    '{kind: $kind, package: $package, file: $file, sha256: $sha256,
      meta: ($ARGS.positional | map(split("=") | [.[0], (.[1:] | join("="))]))} + $extra' \
    --args "${meta[@]}" >> "$WORK/contracts.jsonl"
}

SOURCE_URI=""
RELEASE_URL=""
if [[ -n "$TAG" ]]; then
  SOURCE_URI="https://github.com/$REPO/releases/download/$TAG/contracts-source.tar.gz"
  RELEASE_URL="https://github.com/$REPO/releases/tag/$TAG"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SRC="$WORK/source"
mkdir "$WORK/stellar"

step "archive $ROOT"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
(cd "$ROOT" && stellar contract build archive --out-file "$WORK/contracts-source.tar.gz") \
  || die "cannot archive $ROOT. If it has uncommitted changes or untracked files, build from a" \
    "fresh clone or from a worktree made with 'git worktree add'"
SOURCE_SHA256="$(sha256 "$WORK/contracts-source.tar.gz")"
tar -xzf "$WORK/contracts-source.tar.gz" -C "$WORK"
cd "$SRC"

step "check verifier features"
features="$(sed -n '/^\[features\]/,/^\[/p' contracts/circom-groth16-verifier/Cargo.toml)"
key_files=()
seen=" "
for f in deployments/*/circuit_keys/*_vk.json; do
  read_key_file "$f" || continue
  grep -q "^$FEATURE = " <<<"$features" \
    || die "$f needs feature $FEATURE in contracts/circom-groth16-verifier/Cargo.toml"
  case "$seen" in
    *" $FEATURE "*) die "$f maps to feature $FEATURE, which another key file already has" ;;
  esac
  seen="$seen$FEATURE "
  key_files+=("$f")
done

for pkg in asp-membership asp-non-membership public-key-registry pool pool-gvk; do
  release_one "$pkg" "${pkg//-/_}.wasm"
done
for f in ${key_files[@]+"${key_files[@]}"}; do
  read_key_file "$f"
  release_one circom-groth16-verifier "circom_groth16_verifier_${NET}_${KEY:-none}.wasm" \
    "$FEATURE" "$(jq -cn --arg network "$NET" --arg key_name "$KEY" \
      --arg vk_sha256 "$(sha256 "$f")" '$ARGS.named')"
done

mv "$WORK/contracts-source.tar.gz" "$OUT/"
jq -n --arg tag "$TAG" --arg repo "$REPO" --arg commit "$COMMIT" --arg bldimg "$IMAGE" \
  --arg release_url "$RELEASE_URL" --arg sha256 "$SOURCE_SHA256" --arg uri "$SOURCE_URI" \
  --slurpfile contracts "$WORK/contracts.jsonl" '
  def opt: if . == "" then null else . end;
  {tag: ($tag | opt), repo: ($repo | opt), commit: $commit, bldimg: $bldimg,
   release_url: ($release_url | opt),
   source: {file: "contracts-source.tar.gz", sha256: $sha256, uri: ($uri | opt)},
   contracts: $contracts}' > "$OUT/contracts.json"
(cd "$OUT" && for f in *; do printf '%s  %s\n' "$(sha256 "$f")" "$f"; done) \
  > "$WORK/SHA256SUMS"
mv "$WORK/SHA256SUMS" "$OUT/"
step "wrote $OUT"
