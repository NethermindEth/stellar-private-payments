#!/usr/bin/env bash
# Build every contract from a source archive of this checkout in a pinned build image, or rebuild
# a directory this script wrote and compare every hash.
# Usage: scripts/build-contracts.sh --out DIR [--tag TAG] [--repo OWNER/REPO]
#        scripts/build-contracts.sh --rebuild DIR

set -euo pipefail
# The key-file glob, and so contracts.json and SHA256SUMS, must not follow the caller's locale.
export LC_ALL=C

die() { echo "build-contracts.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is not installed or not on PATH"; }
step() { echo "==> $*" >&2; }

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/build-contracts.sh --out DIR [--tag TAG] [--repo OWNER/REPO]
       scripts/build-contracts.sh --rebuild DIR

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

With --rebuild, checks a directory this script wrote the way an outside SEP-58
rebuild would. Before the first build it refuses the directory unless:

  - it holds only contracts.json, SHA256SUMS, the source archive, and one Wasm
    per contract and key file in the archive
  - every file matches SHA256SUMS and contracts.json
  - every meta key is one this script writes, and every build image and build
    flag in the meta is one it allows
  - the source archive holds only regular files and directories under one
    top-level directory
  - each verifier's vk_sha256 and --features entry match its key file in the
    archive
  - each Wasm's own meta equals its meta in contracts.json

It then rebuilds every Wasm, prints "ok FILE" or "MISMATCH FILE" for each, and
exits 1 on any mismatch. A pass shows that the files rebuild from their own
source. It does not show who built them.

Needs git, the Stellar CLI 28.1.0 or later, docker, jq, tar, and sha256sum or shasum.
--rebuild needs only docker, jq, tar, and sha256sum or shasum.

Options:
  --out DIR             Output directory: new or empty, and outside the checkout
  --tag TAG             Release tag; needs --repo. The meta then records
                        source_uri and source_repo
  --repo OWNER/REPO     GitHub repository the release is published from; needs --tag
  --rebuild DIR         Directory to check by rebuilding it
  -h, --help            Show this help
USAGE
  exit 2
}

# Newest first. The first builds; older ones stay so the releases they built stay checkable.
ALLOWED_IMAGES=(
  'docker.io/stellar/stellar-cli:28.0.0-rust1.97.1-slim-trixie-amd64@sha256:14fe8ca0eb76de7eeaedc977c6d68cb1e5ea2d7ab2e7dc3c43b5389247aed2d0'
)
IMAGE="${ALLOWED_IMAGES[0]}"
CONTRACTS=(asp-membership asp-non-membership public-key-registry pool pool-gvk)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

OUT=""
TAG=""
REPO=""
REBUILD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --rebuild) REBUILD="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

[[ -n "$OUT$REBUILD" ]] || usage
[[ -z "$OUT$TAG$REPO" || -z "$REBUILD" ]] || die "--rebuild takes no other option"
[[ -n "$TAG" && -n "$REPO" || -z "$TAG$REPO" ]] || die "--tag and --repo go together"

need docker
need jq
need tar
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 \
  || die "install sha256sum or shasum"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Sets NET, KEY, FEATURE, and WASM for a key file under deployments/, by the rule the verifier's
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
  WASM="circom_groth16_verifier_${NET}_${KEY:-none}.wasm"
}

# Sets KEY_FILES to the extraction's key files, failing on one whose feature the verifier's
# Cargo.toml does not declare or another key file already has.
list_key_files() {
  local features f seen=" "
  [[ -f contracts/circom-groth16-verifier/Cargo.toml ]] \
    || die "the source archive has no contracts/circom-groth16-verifier/Cargo.toml"
  features="$(sed -n '/^\[features\]/,/^\[/p' contracts/circom-groth16-verifier/Cargo.toml)"
  KEY_FILES=()
  for f in deployments/*/circuit_keys/*_vk.json; do
    read_key_file "$f" || continue
    grep -q "^$FEATURE = " <<<"$features" \
      || die "$f in the source archive needs feature $FEATURE in" \
        "contracts/circom-groth16-verifier/Cargo.toml"
    case "$seen" in
      *" $FEATURE "*) die "$f in the source archive maps to feature $FEATURE, which another" \
        "key file already has" ;;
    esac
    seen="$seen$FEATURE "
    KEY_FILES+=("$f")
  done
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
  "${DOCKER_RUN[@]}" -v "$SRC:/source" "$image" contract build "${flags[@]}" "${metas[@]}"
  # Every verifier build writes this same path, so copy it out before the next build.
  cp "$SRC/target/wasm32v1-none/release/${package//-/_}.wasm" "$dest"
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SRC="$WORK/source"
mkdir "$WORK/stellar"
# On a CI runner the image's user cannot write the extraction, and the caller cannot write the
# image's /stellar, so run as the caller with a /stellar of its own.
DOCKER_RUN=(docker run --platform linux/amd64 --rm --user "$(id -u):$(id -g)"
  -v "$WORK/stellar:/stellar")

if [[ -n "$REBUILD" ]]; then
  dir="$(cd "$REBUILD" 2>/dev/null && pwd -P)" || die "--rebuild $REBUILD is not a directory"
  REBUILD="$dir"
  C="$REBUILD/contracts.json"
  # Prints filter $2 applied to contracts.json entry $1.
  entry() { jq -cr --argjson i "$1" ".contracts[\$i] | $2" "$C"; }
  # Fails unless file $1 has the hash SHA256SUMS lists for it.
  summed() {
    [[ -f "$REBUILD/$1" && "$(awk -v f="$1" '$2 == f { print $1 }' "$REBUILD/SHA256SUMS")" \
      == "$(sha256 "$REBUILD/$1")" ]] || die "$1 does not match SHA256SUMS"
  }
  # Fails unless file $1 matches SHA256SUMS and has hash $2.
  check_file() {
    summed "$1"
    [[ "$(sha256 "$REBUILD/$1")" == "$2" ]] || die "$1 does not match its sha256 in contracts.json"
  }
  # Fails unless sorted list $3 equals sorted list $2, naming what it lacks and adds; $1 says
  # what the lists are.
  same() {
    local lacks adds
    lacks="$(comm -23 <(printf '%s\n' "$2") <(printf '%s\n' "$3") | paste -s -d ' ' -)"
    adds="$(comm -13 <(printf '%s\n' "$2") <(printf '%s\n' "$3") | paste -s -d ' ' -)"
    [[ -z "$lacks$adds" ]] || die "$1: missing ${lacks:-nothing}; extra ${adds:-nothing}"
  }

  step "check $REBUILD"
  summed contracts.json
  ARCHIVE="$(jq -r .source.file "$C")"
  files="$(jq -r '"contracts.json", .source.file, .contracts[].file' "$C" | sort)"
  while IFS= read -r f; do
    [[ "$f" =~ ^[A-Za-z0-9_.-]+$ ]] \
      || die "contracts.json names '$f', which is not a plain file name"
  done <<<"$files"
  named="contracts.json and the files it names"
  same "$REBUILD does not hold exactly SHA256SUMS plus $named" "$files" \
    "$(cd "$REBUILD" && find . -mindepth 1 -maxdepth 1 ! -name SHA256SUMS | sed 's|^\./||' | sort)"
  same "SHA256SUMS does not list exactly $named" "$files" \
    "$(awk '{ print $2 }' "$REBUILD/SHA256SUMS" | sort)"
  check_file "$ARCHIVE" "$(jq -r .source.sha256 "$C")"
  n="$(jq '.contracts | length' "$C")"
  for ((i = 0; i < n; i++)); do
    check_file "$(entry "$i" .file)" "$(entry "$i" .sha256)"
  done

  SOURCE_SHA256="$(sha256 "$REBUILD/$ARCHIVE")"
  for ((i = 0; i < n; i++)); do
    file="$(entry "$i" .file)"
    package="$(entry "$i" .package)"
    grep -qxF -- "$package" <<<"$(printf '%s\n' "${CONTRACTS[@]}" circom-groth16-verifier)" \
      || die "$file: package $package is not one this script builds"
    # A newline would split one entry into two lines below.
    [[ "$(entry "$i" '.meta | flatten | all(test("[[:cntrl:]]") | not)')" == true ]] \
      || die "$file: a meta key or value holds a control character"
    images=0 packages=0 sources=0 uris=0 repos=0
    while IFS= read -r m; do
      case "$m" in
        bldimg=*)
          grep -qxF -- "${m#*=}" <<<"$(printf '%s\n' "${ALLOWED_IMAGES[@]}")" \
            || die "$file: build image ${m#*=} is not an allowed build image"
          images=$((images + 1)) ;;
        "bldopt=--package=$package") packages=$((packages + 1)) ;;
        bldopt=--locked | bldopt=--optimize) ;;
        bldopt=--features=vk-*)
          [[ "$package" == circom-groth16-verifier ]] \
            || die "$file: only a verifier takes ${m#*=}" ;;
        bldopt=* | bldarg=*) die "$file: ${m%%=*} ${m#*=} is not allowed" ;;
        "source_sha256=$SOURCE_SHA256") sources=$((sources + 1)) ;;
        source_sha256=*) die "$file: source_sha256 does not match $ARCHIVE" ;;
        source_uri=*) uris=$((uris + 1)) ;;
        source_repo=*) repos=$((repos + 1)) ;;
        *) die "$file: meta key ${m%%=*} is not one this script writes" ;;
      esac
    done < <(entry "$i" '.meta[] | "\(.[0])=\(.[1])"')
    [[ $images -eq 1 && $packages -eq 1 && $sources -eq 1 && $uris -le 1 && $repos -le 1 ]] \
      || die "$file: needs exactly one each of bldimg, bldopt=--package=$package, and" \
        "source_sha256, and at most one each of source_uri and source_repo"
  done

  # Lists the archive without extracting it, so a crafted entry is refused before tar writes it.
  listing="$(tar -tvzf "$REBUILD/$ARCHIVE")" || die "cannot list $ARCHIVE"
  names="$(tar -tzf "$REBUILD/$ARCHIVE")" || die "cannot list $ARCHIVE"
  ! grep -qv '^[-d]' <<<"$listing" \
    || die "$ARCHIVE holds an entry that is not a regular file or a directory"
  ! grep -q '^/' <<<"$names" || die "$ARCHIVE holds an absolute path"
  ! grep -qE '(^|/)\.\.(/|$)' <<<"$names" || die "$ARCHIVE holds a '..' path"
  [[ "$(sed 's|/.*||' <<<"$names" | sort -u | wc -l | tr -d ' ')" == 1 ]] \
    || die "$ARCHIVE needs exactly one top-level directory"

  mkdir "$SRC"
  tar -xzf "$REBUILD/$ARCHIVE" -C "$SRC" --strip-components=1 || die "cannot extract $ARCHIVE"
  cd "$SRC"
  list_key_files
  expected=()
  for pkg in "${CONTRACTS[@]}"; do expected+=("${pkg//-/_}.wasm"); done
  for f in ${KEY_FILES[@]+"${KEY_FILES[@]}"}; do read_key_file "$f"; expected+=("$WASM"); done
  same "contracts.json does not list exactly one Wasm per contract and key file in $ARCHIVE" \
    "$(printf '%s\n' "${expected[@]}" | sort)" "$(jq -r '.contracts[].file' "$C" | sort)"
  for ((i = 0; i < n; i++)); do
    file="$(entry "$i" .file)"
    package="$(entry "$i" .package)"
    kind="$(entry "$i" .kind)"
    case "$package" in
      circom-groth16-verifier) want=verifier ;;
      *) want=contract ;;
    esac
    [[ "$kind" == "$want" ]] || die "$file: package $package needs kind $want, not $kind"
    if [[ "$kind" == contract ]]; then
      [[ "$file" == "${package//-/_}.wasm" ]] \
        || die "$file: contracts.json gives it package $package, which builds ${package//-/_}.wasm"
      continue
    fi
    network="$(entry "$i" .network)"
    key_name="$(entry "$i" .key_name)"
    case "$key_name" in
      keyOwnership) f=keyOwnership_vk.json ;;
      "") f=policy_tx_2_2_vk.json ;;
      *) f="policy_tx_2_2_${key_name}_vk.json" ;;
    esac
    f="deployments/$network/circuit_keys/$f"
    # The round trip refuses a key name that holds a path.
    read_key_file "$f" && [[ "$NET" == "$network" && "$KEY" == "$key_name" ]] \
      || die "$file: no key file matches network '$network' and key name '$key_name'"
    [[ "$file" == "$WASM" ]] \
      || die "$file: contracts.json gives it network '$network' and key name '$key_name'," \
        "which build $WASM"
    [[ -f "$f" && "$(sha256 "$f")" == "$(entry "$i" .vk_sha256)" ]] \
      || die "$file: vk_sha256 does not match $f in $ARCHIVE"
    [[ "$(entry "$i" '[.meta[] | select(.[0] == "bldopt" and (.[1] | startswith("--features=")))
        | .[1]] | join(" ")')" == "--features=$FEATURE" ]] \
      || die "$file: needs bldopt=--features=$FEATURE as its only --features entry" \
        "(network '$network', key name '$key_name')"
  done

  step "read the meta of each Wasm"
  for ((i = 0; i < n; i++)); do
    file="$(entry "$i" .file)"
    meta="$("${DOCKER_RUN[@]}" -v "$REBUILD:/release:ro" "$IMAGE" contract info meta \
      --wasm "/release/$file" --output json \
      | jq -c '[.[].sc_meta_v0 | [.key, .val]
          | select(.[0] | IN("rsver", "rssdkver", "rssdk_spec_shaking", "cliver") | not)]')"
    [[ "$meta" == "$(entry "$i" .meta)" ]] \
      || die "$file: the meta inside the Wasm differs from its meta in contracts.json"
  done

  mkdir "$WORK/rebuilt"
  failed=0
  for ((i = 0; i < n; i++)); do
    file="$(entry "$i" .file)"
    meta=()
    while IFS= read -r m; do meta+=("$m"); done < <(entry "$i" '.meta[] | "\(.[0])=\(.[1])"')
    build_one "$(entry "$i" .package)" "$WORK/rebuilt/$file" "${meta[@]}"
    if [[ "$(sha256 "$WORK/rebuilt/$file")" == "$(entry "$i" .sha256)" ]]; then
      echo "ok $file"
    else
      echo "MISMATCH $file"
      failed=1
    fi
  done
  [[ $failed -eq 0 ]] || die "the files marked MISMATCH do not rebuild to the hashes in $REBUILD"
  exit 0
fi

need stellar
need git

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

step "archive $ROOT"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
(cd "$ROOT" && stellar contract build archive --out-file "$WORK/contracts-source.tar.gz") \
  || die "cannot archive $ROOT. If it has uncommitted changes or untracked files, build from a" \
    "fresh clone or from a worktree made with 'git worktree add'"
SOURCE_SHA256="$(sha256 "$WORK/contracts-source.tar.gz")"
tar -xzf "$WORK/contracts-source.tar.gz" -C "$WORK"
cd "$SRC"

step "check verifier features"
list_key_files

for pkg in "${CONTRACTS[@]}"; do
  release_one "$pkg" "${pkg//-/_}.wasm"
done
for f in ${KEY_FILES[@]+"${KEY_FILES[@]}"}; do
  read_key_file "$f"
  release_one circom-groth16-verifier "$WASM" "$FEATURE" "$(jq -cn --arg network "$NET" \
    --arg key_name "$KEY" --arg vk_sha256 "$(sha256 "$f")" '$ARGS.named')"
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
