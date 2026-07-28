#!/usr/bin/env sh

set -eu

INSTALLER=${INSTALLER:-scripts/install.sh}
OFFICIAL_COMMAND='curl -fsSL https://github.com/stellar/stellar-cli/raw/main/install.sh | sh'

tmp=$(mktemp -d)
cleanup() {
  rm -rf "$tmp"
}
trap cleanup 0 INT TERM

fake_bin="$tmp/bin"
install_bin="$tmp/install-bin"
data_dir="$tmp/data"
mkdir -p "$fake_bin"

# Keep command lookup deterministic: expose only the utilities the installer
# needs, and deliberately do not expose a `stellar` command.
for utility in awk basename chmod cp grep install mkdir mktemp rm sed; do
  utility_path=$(command -v "$utility")
  ln -s "$utility_path" "$fake_bin/$utility"
done

cat >"$fake_bin/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -s) printf '%s\n' Linux ;;
  -m) printf '%s\n' x86_64 ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$fake_bin/uname"

cat >"$fake_bin/curl" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$FAKE_CURL_LOG"

output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      output=$2
      shift 2
      ;;
    *) shift ;;
  esac
done

[ -n "$output" ] || exit 1
case "$output" in
  *.sha256) printf '%s  fixture\n' fixture-sha256 >"$output" ;;
  *) : >"$output" ;;
esac
EOF
chmod +x "$fake_bin/curl"

cat >"$fake_bin/sha256sum" <<'EOF'
#!/bin/sh
printf '%s  %s\n' fixture-sha256 "$1"
EOF
chmod +x "$fake_bin/sha256sum"

cat >"$fake_bin/tar" <<'EOF'
#!/bin/sh
set -eu
archive=
destination=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -xzf) archive=$2; shift 2 ;;
    -C) destination=$2; shift 2 ;;
    *) shift ;;
  esac
done
case "$archive" in
  */spp-*.tar.gz)
    printf '%s\n' '#!/bin/sh' 'exit 0' >"$destination/spp"
    chmod +x "$destination/spp"
    ;;
  */dist.tar.gz)
    mkdir -p "$destination"
    printf '%s\n' fixture >"$destination/runtime-data"
    ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$fake_bin/tar"

output="$tmp/output"
FAKE_CURL_LOG="$tmp/curl.log" \
PATH="$fake_bin" \
HOME="$tmp/home" \
SPP_VERSION=v0.0.0-test \
SPP_BIN_DIR="$install_bin" \
SPP_DATA_DIR="$data_dir" \
/bin/sh "$INSTALLER" >"$output" 2>&1

[ -x "$install_bin/spp" ] || {
  printf '%s\n' 'FAIL: spp was not installed' >&2
  exit 1
}
[ -f "$data_dir/runtime-data" ] || {
  printf '%s\n' 'FAIL: runtime data was not installed' >&2
  exit 1
}
if grep -F 'github.com/stellar/stellar-cli/raw/main/install.sh' "$tmp/curl.log" >/dev/null; then
  printf '%s\n' 'FAIL: installer attempted to download or install Stellar CLI' >&2
  exit 1
fi
if ! grep -F "$OFFICIAL_COMMAND" "$output" >/dev/null; then
  printf '%s\n' "FAIL: missing Stellar CLI installation command: $OFFICIAL_COMMAND" >&2
  printf '%s\n' 'Installer output:' >&2
  sed 's/^/  /' "$output" >&2
  exit 1
fi

cat >"$fake_bin/stellar" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$fake_bin/stellar"

present_output="$tmp/present-output"
FAKE_CURL_LOG="$tmp/present-curl.log" \
PATH="$fake_bin" \
HOME="$tmp/home" \
SPP_VERSION=v0.0.0-test \
SPP_BIN_DIR="$install_bin" \
SPP_DATA_DIR="$data_dir" \
/bin/sh "$INSTALLER" >"$present_output" 2>&1

if grep -F "$OFFICIAL_COMMAND" "$present_output" >/dev/null; then
  printf '%s\n' 'FAIL: installer printed the Stellar CLI command even though stellar is available' >&2
  exit 1
fi

printf '%s\n' 'PASS: installer reports missing Stellar CLI without prompting when it is available'
