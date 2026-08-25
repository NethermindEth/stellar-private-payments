#!/usr/bin/env sh
# Hash, verify, or pack production circuit artifacts (r1cs, graph, proving key).
# Usage: $0 lock [VERSION] | verify | pack DIR
# VERSION=major.minor  SETUP=local|ceremony
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACTS="$ROOT/target/circuits-artifacts"
KEYS="$ROOT/deployments/testnet/circuit_keys"
LOCK="$ROOT/deployments/testnet/circuits.json"
CRATE_LOCK="$ROOT/sdk/native/circuits.json"
GITHUB_REPO="NethermindEth/stellar-private-payments"
KINDS="r1cs graph.bin proving_key.bin"

STEMS="
policy_tx_2_2
policy_tx_2_2_A
policy_tx_2_2_B
policy_tx_2_2_AB
policy_tx_2_2_gvk_V
policy_tx_2_2_gvk_T
policy_tx_2_2_A_gvk_V
policy_tx_2_2_A_gvk_T
policy_tx_2_2_B_gvk_V
policy_tx_2_2_B_gvk_T
policy_tx_2_2_AB_gvk_V
policy_tx_2_2_AB_gvk_T
selectiveDisclosure_1
selectiveDisclosure_2
selectiveDisclosure_3
selectiveDisclosure_4
"

file_for() {
  stem="$1"
  kind="$2"
  case "$kind" in
    r1cs) printf '%s/%s.r1cs\n' "$ARTIFACTS" "$stem" ;;
    graph.bin) printf '%s/%s.graph.bin\n' "$KEYS" "$stem" ;;
    proving_key.bin) printf '%s/%s_proving_key.bin\n' "$KEYS" "$stem" ;;
    *) echo "unknown kind: $kind" >&2; exit 2 ;;
  esac
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

require_files() {
  for stem in $STEMS; do
    for kind in $KINDS; do
      path="$(file_for "$stem" "$kind")"
      [ -f "$path" ] || {
        echo "missing $path" >&2
        echo "run: make circuits" >&2
        exit 1
      }
    done
  done
}

trim_file() {
  tr -d '[:space:]' <"$1"
}

json_version() {
  [ -f "$LOCK" ] || return 0
  jq -r '.version // empty' "$LOCK"
}

json_field() {
  obj="$1"
  key="$2"
  [ -f "$LOCK" ] || return 0
  jq -r --arg obj "$obj" --arg key "$key" '.[$obj][$key] // empty' "$LOCK"
}

check_meta() {
  key="$1"
  want="$2"
  got="$(json_field meta "$key")"
  if [ -z "$got" ]; then
    echo "missing meta.$key in $LOCK" >&2
    return 1
  fi
  if [ "$got" != "$want" ]; then
    printf 'mismatch meta.%s\n  want %s\n  got  %s\n' "$key" "$want" "$got" >&2
    return 1
  fi
}

normalize_version() {
  ver="${1#v}"
  case "$ver" in
    *.*.*) echo "version must be major.minor (got $1)" >&2; return 1 ;;
    [0-9]*.[0-9]*) printf '%s\n' "$ver" ;;
    *) echo "version must be major.minor (got $1)" >&2; return 1 ;;
  esac
}

normalize_setup() {
  case "$1" in
    local|ceremony) printf '%s\n' "$1" ;;
    *) echo "setup must be local or ceremony (got $1)" >&2; return 1 ;;
  esac
}

stem_setup() {
  if [ -n "${SETUP:-}" ]; then
    normalize_setup "$SETUP"
    return 0
  fi
  existing="$(json_field "$1" setup)"
  if [ -n "$existing" ]; then
    normalize_setup "$existing"
    return 0
  fi
  printf 'local\n'
}

default_version() {
  ver="$(json_version)"
  if [ -n "$ver" ]; then
    normalize_version "$ver"
    return 0
  fi
  printf '0.1\n'
}

is_git_commit() {
  case "$1" in
    *[!0-9a-fA-F]* | "") return 1 ;;
  esac
  [ "${#1}" -eq 40 ]
}

write_lock() {
  require_files
  version="${1:-}"
  if [ -z "$version" ]; then
    version="$(default_version)"
  else
    version="$(normalize_version "$version")"
  fi
  witness="$(sed -n 's/^circom-witness-rs = { version = "\([^"]*\)".*/\1/p' "$ROOT/Cargo.toml" | head -1)"
  [ -n "$witness" ] || { echo "could not read circom-witness-rs version from Cargo.toml" >&2; exit 1; }
  commit="$(git -C "$ROOT" rev-parse HEAD)"
  is_git_commit "$commit" || { echo "could not read git commit at $ROOT" >&2; exit 1; }
  circuits=""
  for stem in $STEMS; do
    circuits="${circuits}$(printf ',
  "%s": {
    "setup": "%s",
    "r1cs": "%s",
    "graph.bin": "%s",
    "proving_key.bin": "%s"
  }' \
      "$stem" \
      "$(stem_setup "$stem")" \
      "$(sha256_file "$(file_for "$stem" r1cs)")" \
      "$(sha256_file "$(file_for "$stem" graph.bin)")" \
      "$(sha256_file "$(file_for "$stem" proving_key.bin)")")"
  done
  {
    printf '{\n'
    printf '  "version": "%s",\n' "$version"
    printf '  "meta": {\n'
    printf '    "repository": "%s",\n' "$GITHUB_REPO"
    printf '    "commit": "%s",\n' "$commit"
    printf '    "circom": "%s",\n' "$(trim_file "$ROOT/circuits/circom.lock")"
    printf '    "circomlib": "%s",\n' "$(trim_file "$ROOT/circuits/circomlib.lock")"
    printf '    "circom-witness-rs": "%s"\n' "$witness"
    printf '  }'
    printf '%s' "$circuits"
    printf '\n}\n'
  } >"$LOCK"
  cp "$LOCK" "$CRATE_LOCK"
  echo "wrote $LOCK and $CRATE_LOCK (version $version)"
}

verify_lock() {
  [ -f "$LOCK" ] || { echo "missing $LOCK" >&2; exit 1; }
  [ -f "$CRATE_LOCK" ] || { echo "missing $CRATE_LOCK" >&2; exit 1; }
  if [ "$(sha256_file "$LOCK")" != "$(sha256_file "$CRATE_LOCK")" ]; then
    echo "$CRATE_LOCK does not match $LOCK" >&2
    echo "run: make circuits-lock" >&2
    exit 1
  fi
  version="$(normalize_version "$(json_version)")" || exit 1
  failed=0
  check_meta repository "$GITHUB_REPO" || failed=1
  check_meta circom "$(trim_file "$ROOT/circuits/circom.lock")" || failed=1
  check_meta circomlib "$(trim_file "$ROOT/circuits/circomlib.lock")" || failed=1
  check_meta circom-witness-rs "$(sed -n 's/^circom-witness-rs = { version = "\([^"]*\)".*/\1/p' "$ROOT/Cargo.toml" | head -1)" || failed=1
  commit="$(json_field meta commit)"
  if ! is_git_commit "$commit"; then
    echo "missing or invalid meta.commit in $LOCK" >&2
    failed=1
  fi
  for stem in $STEMS; do
    if ! normalize_setup "$(json_field "$stem" setup)" >/dev/null; then
      echo "missing or invalid $stem setup in $LOCK" >&2
      failed=1
    fi
    for kind in $KINDS; do
      want="$(json_field "$stem" "$kind")"
      if [ -z "$want" ]; then
        echo "missing $stem $kind in $LOCK" >&2
        failed=1
        continue
      fi
      path="$(file_for "$stem" "$kind")"
      if [ ! -f "$path" ]; then
        echo "missing $path" >&2
        failed=1
        continue
      fi
      got="$(sha256_file "$path")"
      if [ "$got" != "$want" ]; then
        printf 'mismatch %s %s\n  want %s\n  got  %s\n' "$stem" "$kind" "$want" "$got" >&2
        failed=1
      fi
    done
  done
  [ "$failed" = 0 ] || exit 1
  echo "ok $LOCK (version $version)"
}

pack_dir() {
  dest="${1:-}"
  [ -n "$dest" ] || { echo "usage: $0 pack DIR" >&2; exit 2; }
  require_files
  mkdir -p "$dest"
  for stem in $STEMS; do
    for kind in $KINDS; do
      cp "$(file_for "$stem" "$kind")" "$dest/"
    done
  done
  cp "$LOCK" "$dest/circuits.json"
}

cmd="${1:-}"
case "$cmd" in
  lock) write_lock "${2:-}" ;;
  verify) verify_lock ;;
  pack) pack_dir "${2:-}" ;;
  *)
    echo "usage: $0 lock [VERSION] | verify | pack DIR" >&2
    exit 2
    ;;
esac
