#!/usr/bin/env bash
# Exercise deploy.sh's refusals of a contracts release, on copies of a build-contracts.sh output
# directory. Every case must stop before deploy.sh builds or deploys anything.
# Usage: scripts/test-deploy-release.sh RELEASE_DIR
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[ $# -eq 1 ] && [ -f "$1/contracts.json" ] || { echo "usage: $0 RELEASE_DIR" >&2; exit 2; }
REL=$(cd "$1" && pwd)
REPO=NethermindEth/stellar-private-payments
A=circom_groth16_verifier_testnet_A.wasm
B=circom_groth16_verifier_testnet_B.wasm
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

# A checkout of deploy.sh and the testnet key files, so a case can add a network's directory.
co="$fixture/co"
keys="$co/deployments/testnet/circuit_keys"
mkdir -p "$co/deployments/scripts" "$keys"
cp "$ROOT/deployments/scripts/deploy.sh" "$co/deployments/scripts/"
cp "$ROOT"/deployments/testnet/circuit_keys/*_vk.json "$keys/"

# gh records its arguments, which expect clears before each case, and answers as for a release
# with no attestation, and stellar refuses to build or deploy.
mkdir "$fixture/bin"
cat > "$fixture/bin/gh" <<SH
#!/bin/sh
printf '%s\n' "\$@" > "$fixture/gh-args"
echo "gh: no attestation found" >&2
exit 1
SH
cat > "$fixture/bin/stellar" <<SH
#!/bin/sh
case "\$1 \$2" in
  "contract build" | "contract deploy") echo "unexpected stellar \$1 \$2" >&2; exit 99 ;;
esac
exec "$(command -v stellar)" "\$@"
SH
chmod +x "$fixture/bin/gh" "$fixture/bin/stellar"
export PATH="$fixture/bin:$PATH" XDG_CONFIG_HOME="$fixture/cfg"

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
# Applies jq arguments $@ to the case release's contracts.json and regenerates its SHA256SUMS.
edit() {
  jq "$@" "$rel/contracts.json" > "$fixture/contracts.json"
  mv "$fixture/contracts.json" "$rel/contracts.json"
  sums "$rel"
}
# Copies the release to the case release, naming this repository as a published release does.
fresh() {
  rm -rf "$rel" && cp -R "$REL" "$rel"
  edit --arg repo "$REPO" '.repo = $repo'
}
# Runs deploy.sh on $NET with one blocklist pool and arguments $3..., and fails unless it exits
# $1 with $2 in its last line on stderr, the line die prints, and writes no manifest.
expect() {
  local status=0 code="$1" message="$2"
  shift 2
  rm -f "$fixture/gh-args"
  bash "$co/deployments/scripts/deploy.sh" "$NET" --deployer "$DEPLOYER" --asp-levels 10 \
    --pool-levels 20 --max-deposit 1000000000 --kdf-domain Nethermind \
    --pool "blocklist:native:$(stellar contract id asset --asset native --network "$NET")" \
    "$@" >/dev/null 2>"$fixture/err" || status=$?
  if [ "$status" -ne "$code" ] || ! tail -n 1 "$fixture/err" | grep -qF -- "$message"; then
    echo "expected exit $code and '$message', got exit $status:" >&2
    cat "$fixture/err" >&2
    exit 1
  fi
  [ ! -e "$co/deployments/$NET/deployments.json" ] \
    || { echo "a refused run wrote a manifest" >&2; exit 1; }
}

NET=testnet
DEPLOYER=GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF
rel="$fixture/release"

# The untouched release passes every check and reaches the first deployment.
fresh
expect 1 'failed to parse contract id for asp-membership' --release-dir "$rel" --allow-unverified
grep -qF 'unexpected stellar contract deploy' "$fixture/err"

expect 1 '--release-dir cannot be combined with --vk-json, --vk-file, or --skip-init' \
  --release-dir "$rel" --vk-file "$keys/policy_tx_2_2_B_vk.json"
expect 1 '--release-dir cannot be combined with --vk-json, --vk-file, or --skip-init' \
  --release-dir "$rel" --skip-init

expect 1 "in $REPO attested $rel/SHA256SUMS; gh's error above says why" \
  --release-dir "$rel"
diff -u <(printf '%s\n' attestation verify "$rel/SHA256SUMS" --repo "$REPO" \
  --source-ref refs/heads/main --deny-self-hosted-runners --cert-identity \
  "https://github.com/$REPO/.github/workflows/contracts-release.yml@refs/heads/main") \
  "$fixture/gh-args"

rm "$rel/SHA256SUMS"
expect 1 "$rel/SHA256SUMS not found" --release-dir "$rel" --allow-unverified

fresh
printf x >> "$rel/pool.wasm"
expect 1 "pool.wasm is missing from $rel or does not match its SHA256SUMS" \
  --release-dir "$rel" --allow-unverified

fresh
printf ' ' >> "$rel/contracts.json"
expect 1 "contracts.json is missing from $rel or does not match its SHA256SUMS" \
  --release-dir "$rel" --allow-unverified

fresh
edit '.repo = null'
expect 1 'names no repository, because build-contracts.sh ran without --tag and --repo' \
  --release-dir "$rel" --allow-unverified

fresh
edit '.repo = "someone/else"'
expect 1 "names repository someone/else, not $REPO" --release-dir "$rel" --allow-unverified

fresh
rm "$rel/$B"
edit --arg b "$B" '.contracts |= map(select(.file != $b))'
expect 1 'the release has no verifier for key name B built from' \
  --release-dir "$rel" --allow-unverified

fresh
cp "$rel/$A" "$rel/$B"
edit --arg b "$B" --arg h "$(sha256 "$rel/$B")" \
  '(.contracts[] | select(.file == $b) | .sha256) = $h'
expect 1 "$B is not the build of circom-groth16-verifier with --features=vk-testnet-b" \
  --release-dir "$rel" --allow-unverified

# The A verifier claims the B key file, but its own meta still names vk-testnet-a.
fresh
rm "$rel/$B"
edit --arg a "$A" --arg b "$B" --arg vk "$(sha256 "$keys/policy_tx_2_2_B_vk.json")" \
  '.contracts |= map(select(.file != $b)
    | if .file == $a then .vk_sha256 = $vk | .key_name = "B" else . end)'
expect 1 "$A is not the build of circom-groth16-verifier with --features=vk-testnet-b" \
  --release-dir "$rel" --allow-unverified

# pubnet-dry has mainnet's passphrase and an address nothing listens on.
stellar network add pubnet-dry --rpc-url http://127.0.0.1:9 \
  --network-passphrase 'Public Global Stellar Network ; September 2015'
NET=pubnet-dry
dry="$co/deployments/pubnet-dry"
fresh

expect 1 'mainnet requires --yes' --skip-init
expect 1 'mainnet deploys only the contracts of a release; pass --release-dir' --skip-init --yes

linked='must be a real directory on mainnet, not a link and not inside a linked directory'
mkdir "$dry"
ln -s ../testnet/circuit_keys "$dry/circuit_keys"
expect 1 "$linked" --yes --allow-unverified --release-dir "$rel"
expect 1 "$linked" --yes --allow-unverified --skip-init
rm -r "$dry"
ln -s testnet "$dry"
expect 1 "$linked" --yes --allow-unverified --release-dir "$rel"
rm "$dry"

mkdir -p "$dry/circuit_keys"
cp "$keys"/*_vk.json "$dry/circuit_keys/"
expect 1 'mainnet refuses --vk-json and --vk-file' --yes --allow-unverified \
  --vk-file "$keys/policy_tx_2_2_AB_vk.json"
expect 1 "$B was built for network testnet, and mainnet deploys only verifiers built for $NET" \
  --yes --allow-unverified --release-dir "$rel"
ln -sf "$keys/policy_tx_2_2_B_vk.json" "$dry/circuit_keys/"
expect 1 "$dry/circuit_keys/policy_tx_2_2_B_vk.json must be a file on mainnet, not a link" \
  --yes --allow-unverified --release-dir "$rel"

echo 'deploy.sh release refusals passed'
