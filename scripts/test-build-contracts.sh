#!/usr/bin/env bash
# Exercise build-contracts.sh's refusals without Docker: the rebuild check's on a synthetic
# release, and --out's.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir "$fixture/bin"
IMAGE=$(grep -m1 -o "docker\.io/stellar/[^']*" "$ROOT/scripts/build-contracts.sh")
VERIFIER=circom_groth16_verifier_testnet_A.wasm
echo '{"nPublic":9}' > "$fixture/key.json"

# Every case must stop before the first Docker call.
cat > "$fixture/bin/docker" <<'SH'
#!/bin/sh
echo 'unexpected docker call' >&2
exit 99
SH
chmod +x "$fixture/bin/docker"
export PATH="$fixture/bin:$PATH"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}
sums() {
  (cd "$1" && for f in *; do
    [ "$f" = SHA256SUMS ] || printf '%s  %s\n' "$(sha256 "$f")" "$f"
  done > SHA256SUMS)
}

# Writes a release to $1: placeholder Wasm for the five contracts and the A verifier, and a
# source archive holding the A key file, the verifier's Cargo.toml, and the crafted member $2
# names, if any.
make_release() {
  local src shas p
  rm -rf "${1:?}" && mkdir "$1"
  python3 - "$1/contracts-source.tar.gz" "$fixture/key.json" "${2:-}" <<'PY'
import io, sys, tarfile
out, key, member = sys.argv[1:]
keys = 'source/deployments/%s/circuit_keys/policy_tx_2_2_A_vk.json'
features = {'undeclared': '', 'collision': 'vk-test-net-a = []\nvk-testnet-a = []\n'}
with tarfile.open(out, 'w:gz') as t:
    t.add(key, keys % 'testnet')
    if member == 'collision':
        for net in ('test-net', 'test_net'):
            t.add(key, keys % net)
    if member != 'nocargo':
        cargo = ('[features]\n' + features.get(member, 'vk-testnet-a = []\n')).encode()
        info = tarfile.TarInfo('source/contracts/circom-groth16-verifier/Cargo.toml')
        info.size = len(cargo)
        t.addfile(info, io.BytesIO(cargo))
    crafted = {
        'symlink': ('source/link', tarfile.SYMTYPE, '/etc/passwd'),
        'hardlink': ('source/link', tarfile.LNKTYPE, keys % 'testnet'),
        'absolute': ('/tmp/x', tarfile.REGTYPE, ''),
        'dotdot': ('source/../x', tarfile.REGTYPE, ''),
        'second': ('other/x', tarfile.REGTYPE, ''),
    }.get(member)
    if crafted:
        info = tarfile.TarInfo(crafted[0])
        info.type, info.linkname = crafted[1:]
        t.addfile(info)
PY
  for p in pool asp_membership asp_non_membership public_key_registry pool_gvk; do
    printf '%s' "$p" > "$1/$p.wasm"
  done
  printf 'verifier' > "$1/$VERIFIER"
  src=$(sha256 "$1/contracts-source.tar.gz")
  shas=$(for p in "$1"/*.wasm; do
    jq -n --arg f "${p##*/}" --arg h "$(sha256 "$p")" '{($f): $h}'
  done | jq -s add)
  jq -n --arg image "$IMAGE" --arg src "$src" --arg verifier "$VERIFIER" --argjson sha "$shas" \
    --arg vk "$(sha256 "$fixture/key.json")" '
    def meta($p; $extra): [["bldimg", $image], ["bldopt", "--package=\($p)"],
      ["bldopt", "--locked"], ["bldopt", "--optimize"]] + $extra + [["source_sha256", $src]];
    def contract($p): ($p | gsub("-"; "_") + ".wasm") as $f
      | {kind: "contract", package: $p, file: $f, sha256: $sha[$f], meta: meta($p; [])};
    {source: {file: "contracts-source.tar.gz", sha256: $src},
     contracts: ([contract("pool"),
       {kind: "verifier", package: "circom-groth16-verifier", file: $verifier,
        sha256: $sha[$verifier], network: "testnet", key_name: "A", vk_sha256: $vk,
        meta: meta("circom-groth16-verifier"; [["bldopt", "--features=vk-testnet-a"]])}]
       + [("asp-membership", "asp-non-membership", "public-key-registry", "pool-gvk")
         | contract(.)])}' > "$1/contracts.json"
  sums "$1"
}
# Applies jq filter $1 to the case release's contracts.json and regenerates its SHA256SUMS.
edit() {
  jq "$1" "$rel/contracts.json" > "$fixture/contracts.json"
  mv "$fixture/contracts.json" "$rel/contracts.json"
  sums "$rel"
}
# Runs script and arguments $3..., by default the rebuild check on the case release, and fails
# unless it exits $1 with $2 on stderr.
expect() {
  local status=0 code="$1" message="$2"
  shift 2
  [ $# -gt 0 ] || set -- "$ROOT/scripts/build-contracts.sh" --rebuild "$rel"
  bash "$@" >/dev/null 2>"$fixture/err" || status=$?
  if [ "$status" -ne "$code" ] || ! grep -qF -- "$message" "$fixture/err"; then
    echo "expected exit $code and '$message', got exit $status:" >&2
    cat "$fixture/err" >&2
    exit 1
  fi
}

fresh() { rm -rf "$rel" && cp -R "$fixture/base" "$rel"; }

rel="$fixture/release"
make_release "$fixture/base"

# The untouched release passes every check that reads only files.
fresh
expect 99 'unexpected docker call'

rm -rf "${rel:?}"
expect 1 "--rebuild $rel is not a directory"

fresh
printf x >> "$rel/contracts-source.tar.gz"
expect 1 'contracts-source.tar.gz does not match SHA256SUMS'

fresh
printf ' ' >> "$rel/contracts.json"
expect 1 'contracts.json does not match SHA256SUMS'

fresh
printf x >> "$rel/pool.wasm"
expect 1 'pool.wasm does not match SHA256SUMS'

fresh
edit '.contracts[0].sha256 = "00"'
expect 1 'pool.wasm does not match its sha256 in contracts.json'

fresh
edit '.contracts[0].file = "sub/pool.wasm"'
expect 1 "contracts.json names 'sub/pool.wasm', which is not a plain file name"

fresh
edit '.contracts[1].meta[4][1] = "--features=vk-testnet-b"'
expect 1 "$VERIFIER: needs bldopt=--features=vk-testnet-a as its only --features entry \
(network 'testnet', key name 'A')"

fresh
edit '.contracts[1].vk_sha256 = "00"'
expect 1 "$VERIFIER: vk_sha256 does not match \
deployments/testnet/circuit_keys/policy_tx_2_2_A_vk.json in contracts-source.tar.gz"

fresh
edit '.contracts[1].key_name = "../A"'
expect 1 "$VERIFIER: no key file matches network 'testnet' and key name '../A'"

fresh
edit '.contracts[0].kind = "verifier"'
expect 1 'pool.wasm: package pool needs kind contract, not verifier'

fresh
edit '.contracts[0].meta[0][1] = "docker.io/library/rust:latest"'
expect 1 'pool.wasm: build image docker.io/library/rust:latest is not an allowed build image'

fresh
edit '.contracts[0].meta[2][1] = "--manifest-path=/tmp/x"'
expect 1 'pool.wasm: bldopt --manifest-path=/tmp/x is not allowed'

fresh
edit '.contracts[0].package = "token"'
expect 1 'pool.wasm: package token is not one this script builds'

fresh
edit '.contracts[0].meta += [["bldarg", "build"]]'
expect 1 'pool.wasm: bldarg build is not allowed'

fresh
edit '.contracts[0].meta += [["bldopt", "--features=vk-testnet-a"]]'
expect 1 'pool.wasm: only a verifier takes --features=vk-testnet-a'

fresh
edit '.contracts[0].meta[4][1] = "00"'
expect 1 'pool.wasm: source_sha256 does not match contracts-source.tar.gz'

for filter in 'map(select(.[0] != "bldimg"))' 'map(select(.[1] != "--package=pool"))' \
  'map(select(.[0] != "source_sha256"))' '. + [["source_uri", "a"], ["source_uri", "b"]]' \
  '. + [["source_repo", "github:a/b"], ["source_repo", "github:a/b"]]'; do
  fresh
  edit ".contracts[0].meta |= $filter"
  expect 1 "pool.wasm: needs exactly one each of bldimg, bldopt=--package=pool, and \
source_sha256, and at most one each of source_uri and source_repo"
done

fresh
edit '.contracts[0].meta += [["source_uri", "x\nbldopt=--manifest-path=/tmp/x"]]'
expect 1 'pool.wasm: a meta key or value holds a control character'

fresh
edit '.contracts[0].meta += [["foo", "bar"]]'
expect 1 'pool.wasm: meta key foo is not one this script writes'

for member in symlink hardlink; do
  make_release "$rel" "$member"
  expect 1 'contracts-source.tar.gz holds an entry that is not a regular file or a directory'
done
make_release "$rel" absolute
expect 1 'contracts-source.tar.gz holds an absolute path'
make_release "$rel" dotdot
expect 1 "contracts-source.tar.gz holds a '..' path"
make_release "$rel" second
expect 1 'contracts-source.tar.gz needs exactly one top-level directory'

fresh
printf junk > "$rel/junk.wasm"
sums "$rel"
expect 1 "does not hold exactly SHA256SUMS plus contracts.json and the files it names: \
missing nothing; extra junk.wasm"

fresh
echo "00  ghost.wasm" >> "$rel/SHA256SUMS"
expect 1 "SHA256SUMS does not list exactly contracts.json and the files it names: \
missing nothing; extra ghost.wasm"

fresh
rm "${rel:?}"/*.wasm
edit '.contracts = []'
expect 1 "contracts.json does not list exactly one Wasm per contract and key file in \
contracts-source.tar.gz: missing asp_membership.wasm"

fresh
edit '.contracts[0].package = "pool-gvk" | .contracts[0].meta[1][1] = "--package=pool-gvk"'
expect 1 'pool.wasm: contracts.json gives it package pool-gvk, which builds pool_gvk.wasm'

fresh
edit '.contracts[1].key_name = "a"'
expect 1 "$VERIFIER: contracts.json gives it network 'testnet' and key name 'a', which build \
circom_groth16_verifier_testnet_a.wasm"

make_release "$rel" undeclared
expect 1 "deployments/testnet/circuit_keys/policy_tx_2_2_A_vk.json in the source archive needs \
feature vk-testnet-a in contracts/circom-groth16-verifier/Cargo.toml"
make_release "$rel" collision
expect 1 "deployments/test_net/circuit_keys/policy_tx_2_2_A_vk.json in the source archive maps \
to feature vk-test-net-a, which another key file already has"
make_release "$rel" nocargo
expect 1 'the source archive has no contracts/circom-groth16-verifier/Cargo.toml'

# --out refuses a link into the checkout, and a new directory there before creating it. A copy of
# the script in $co makes $co the checkout.
co="$fixture/co"
mkdir -p "$co/scripts" "$co/empty"
cp "$ROOT/scripts/build-contracts.sh" "$co/scripts/"
ln -s "$co/empty" "$fixture/link"
printf '#!/bin/sh\necho "stellar 28.1.0"\n' > "$fixture/bin/stellar"
chmod +x "$fixture/bin/stellar"
for out in "$fixture/link" "$co/new"; do
  expect 1 'is inside the checkout; pick a directory outside it' \
    "$co/scripts/build-contracts.sh" --out "$out"
done
[ ! -e "$co/new" ] || { echo "a refused --out $co/new was created" >&2; exit 1; }

echo 'build-contracts.sh refusals passed'
