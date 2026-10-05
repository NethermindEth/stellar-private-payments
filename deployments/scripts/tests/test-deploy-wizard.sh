#!/usr/bin/env bash
# Exercise the real shell entrypoint with fake Stellar and deploy executables.
set -euo pipefail
SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SANDBOX=$(mktemp -d)
trap 'rm -rf -- "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/deployments/scripts" "$SANDBOX/deployments/custom/circuit_keys" "$SANDBOX/bin"
cp "$SOURCE_ROOT/deployments/scripts/deploy-wizard.sh" "$SOURCE_ROOT/deployments/scripts/deploy-plan.jq" "$SANDBOX/deployments/scripts/"
export TEST_ACCOUNT TEST_TOKEN TEST_ALT_ACCOUNT
TEST_ACCOUNT=$(jq -r .deployer "$SOURCE_ROOT/deployments/testnet/deployments.json")
TEST_ALT_ACCOUNT=$(jq -r .admin "$SOURCE_ROOT/deployments/testnet/deployments.json")
TEST_TOKEN=$(jq -r '.pools[0].tokenContractId' "$SOURCE_ROOT/deployments/testnet/deployments.json")
export CAPTURE_ARGS="$SANDBOX/args" CAPTURE_ENV="$SANDBOX/env"
export PATH="$SANDBOX/bin:$PATH"
cat > "$SANDBOX/bin/stellar" <<'FAKE'
#!/usr/bin/env bash
case "$1 $2" in
  'network ls')
    if [[ -n ${FAKE_CHANGE_MARKER:-} ]]; then
      if [[ -f $FAKE_CHANGE_MARKER ]]; then FAKE_PASSPHRASE=Changed; else touch "$FAKE_CHANGE_MARKER"; fi
    fi
    printf 'Configured networks:\n\nName: custom\nRPC url: %s\nNetwork passphrase: %s\n\n' "${FAKE_RPC:-http://localhost:8000/rpc}" "${FAKE_PASSPHRASE:-Custom : network}";;
  'keys ls') printf 'alice\n';;
  'keys address') printf '%s\n' "${FAKE_ADDRESS:-$TEST_ACCOUNT}";;
  'contract id') printf '%s\n' "$TEST_TOKEN";;
  *) exit 2;;
esac
FAKE
cat > "$SANDBOX/deployments/scripts/deploy.sh" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$CAPTURE_ARGS"
printf '%s\n' "$SPP_NETWORK" "$SPP_IS_TESTNET" "$SPP_EXPLORER_URL" "$SPP_DISPLAY_NAME" > "$CAPTURE_ENV"
exit "${DEPLOY_EXIT:-0}"
FAKE
printf '#!/bin/sh\nexit 0\n' > "$SANDBOX/bin/cargo"
chmod +x "$SANDBOX/bin/stellar" "$SANDBOX/bin/cargo"
PLAN_FILE="$SANDBOX/plan.json"
jq -n --arg account "$TEST_ACCOUNT" --arg token "$TEST_TOKEN" '{version:1,network:"custom",networkPassphrase:"Custom : network",
 rpcUrl:"http://localhost:8000/rpc",displayName:"Custom network",explorerUrl:"",isTestnet:true,deployer:"alice",deployerAddress:$account,
 admin:$account,aspLevels:10,poolLevels:20,maxDeposit:"10000000",pools:[{kind:"native",tokenContractId:$token,policy:"blocklist",gvkMode:"gvk-off"}],gvkAuthorityPubKey:null}' > "$PLAN_FILE"
cp "$PLAN_FILE" "$SANDBOX/original.json"
LOCK='{}'
# Stage all twelve combinations so multi-pool arguments and circuit selection are exercised.
for suffix in '' _A _B _AB; do
  for mode in '' _gvk_V _gvk_T; do
    stem="policy_tx_2_2$suffix$mode"
    printf 'test artifact' > "$SANDBOX/deployments/custom/circuit_keys/$stem.graph.bin"
    cp "$SANDBOX/deployments/custom/circuit_keys/$stem.graph.bin" "$SANDBOX/deployments/custom/circuit_keys/${stem}_proving_key.bin"
    printf '{"IC":[["1","2","1"]]}\n' > "$SANDBOX/deployments/custom/circuit_keys/${stem}_vk.json"
    if command -v sha256sum >/dev/null; then hash=$(sha256sum "$SANDBOX/deployments/custom/circuit_keys/$stem.graph.bin"); else hash=$(shasum -a 256 "$SANDBOX/deployments/custom/circuit_keys/$stem.graph.bin"); fi
    hash=${hash%% *}
    LOCK=$(jq --arg stem "$stem" --arg hash "$hash" '.[$stem]={"graph.bin":$hash,"proving_key.bin":$hash}' <<< "$LOCK")
  done
done
printf '%s\n' "$LOCK" > "$SANDBOX/deployments/custom/circuits.json"
COUNT=0
pass() { COUNT=$((COUNT+1)); printf 'ok %s - %s\n' "$COUNT" "$1"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; cat "$SANDBOX/log" >&2; exit 1; }
run() {
  local expected=$1 input=$2 status=0; shift 2
  rm -f "$CAPTURE_ARGS" "$CAPTURE_ENV"
  printf '%s' "$input" | bash "$SANDBOX/deployments/scripts/deploy-wizard.sh" "$@" > "$SANDBOX/log" 2>&1 || status=$?
  [[ $status == "$expected" ]] || fail "expected exit $expected, got $status"
}
no_deploy() { [[ ! -e $CAPTURE_ARGS ]] || fail 'unexpected deployment'; }
contains() { grep -Fq -- "$1" "$SANDBOX/log" || fail "missing output: $1"; }
run 0 '' --help; no_deploy; pass help
run 0 '' --config "$PLAN_FILE" --save-only; no_deploy; contains 'Using saved plan'; pass 'save-only with blank lines and colons in network listing'
run 0 $'\n' --config "$PLAN_FILE"; no_deploy; pass 'blank confirmation cancels'
run 0 $'yes\n' --config "$PLAN_FILE"; no_deploy; pass 'inexact confirmation cancels'
export SPP_EXPLORER_URL=https://wrong.example
run 0 $'deploy custom\n' --config "$PLAN_FILE"
grep -Fxq "blocklist:gvk-off:native:$TEST_TOKEN" "$CAPTURE_ARGS" || fail 'missing pool argument'
printf 'custom\ntrue\n\nCustom network\n' > "$SANDBOX/expected-env"
cmp "$SANDBOX/expected-env" "$CAPTURE_ENV" || fail 'wrong environment'
pass 'exact confirmation delegates arguments and explicit empty explorer'
export FAKE_PASSPHRASE=Other
run 1 '' --config "$PLAN_FILE"; no_deploy; contains 'network settings changed'; unset FAKE_PASSPHRASE; pass 'changed passphrase rejected'
export FAKE_RPC=http://localhost:9999/rpc
run 1 '' --config "$PLAN_FILE"; no_deploy; unset FAKE_RPC; pass 'changed RPC rejected'
export FAKE_ADDRESS=$TEST_ALT_ACCOUNT
run 1 '' --config "$PLAN_FILE"; no_deploy; contains 'different address'; unset FAKE_ADDRESS; pass 'changed account alias rejected'
for mutation in '.deployer="S" + ("A" * 55)' '.deployer="one two three"' '.network="../custom"' '.network="ci-test-network"' '.poolLevels=32' '.maxDeposit="0"' '.maxDeposit="115792089237316195423570985008687907853269984665640564039457584007913129639936"' '.maxDeposit="1.5"' '.isTestnet="false"' '.secret="oops"' '.rpcUrl="https://user:secret@example.org"' '.rpcUrl="https://example.org?key=secret"' '.admin="G" + ("A" * 55)' '.pools[0].secret="oops"' '.gvkAuthorityPubKey={x:"1",y:"2"}'; do
  jq "$mutation" "$SANDBOX/original.json" > "$PLAN_FILE"
  run 1 '' --config "$PLAN_FILE" --save-only; no_deploy; contains 'Invalid deployment plan'
done
cp "$SANDBOX/original.json" "$PLAN_FILE"; pass 'schema rejects secrets, invalid addresses, wrong types, overflow and unsafe URLs'
jq '.maxDeposit="115792089237316195423570985008687907853269984665640564039457584007913129639935"' "$SANDBOX/original.json" > "$PLAN_FILE"
run 0 '' --config "$PLAN_FILE" --save-only; pass 'maximum U256 amount preserved as text'
cp "$SANDBOX/original.json" "$PLAN_FILE"
run 0 $'1\nalice\n\n\n\nyes\n10000000\n1\n3\n1\nno\n' --save-only
no_deploy
jq -e '.deployer=="alice" and .pools[0].policy=="blocklist"' "$SANDBOX/.deployment-plans/custom.json" >/dev/null || fail 'interactive plan not saved'
pass 'interactive setup saves public plan'
for path in "$SANDBOX/deployments.json" "$SANDBOX/circuits.json"; do run 1 '' --config "$PLAN_FILE" --output "$path" --save-only; no_deploy; done
printf '{"unrelated":true}' > "$SANDBOX/other.json"
ln -s "$SANDBOX/other.json" "$SANDBOX/link.json"
for path in "$SANDBOX/other.json" "$SANDBOX/link.json"; do run 1 '' --config "$PLAN_FILE" --output "$path" --save-only; no_deploy; done
pass 'manifest, unrelated file and symlink overwrites refused'
run 1 $'no\n' --config "$PLAN_FILE" --output "$PLAN_FILE" --save-only
cmp "$PLAN_FILE" "$SANDBOX/original.json" || fail 'plan changed without consent'
run 0 $'yes\n' --config "$PLAN_FILE" --output "$PLAN_FILE" --save-only; no_deploy; pass 'existing plan replacement requires consent'
printf tampered > "$SANDBOX/deployments/custom/circuit_keys/policy_tx_2_2_B.graph.bin"
run 1 $'deploy custom\n' --config "$PLAN_FILE"; no_deploy; contains 'Fingerprint mismatch'
run 0 '' --config "$PLAN_FILE" --save-only; no_deploy; contains 'Deployment blocked'
printf 'test artifact' > "$SANDBOX/deployments/custom/circuit_keys/policy_tx_2_2_B.graph.bin"
pass 'tampered artifacts prevent deployment but allow saving'
mv "$SANDBOX/deployments/custom/circuits.json" "$SANDBOX/lock.json"
run 1 '' --config "$PLAN_FILE"; no_deploy; contains 'Cannot read circuit lock'
mv "$SANDBOX/lock.json" "$SANDBOX/deployments/custom/circuits.json"; pass 'missing circuit lock blocks deployment'
jq --arg issuer "$TEST_ACCOUNT" '.displayName="Example; $(do-not-run)" | .gvkAuthorityPubKey={x:"0x1",y:"2"} | .pools = [
 ["none","allowlist","blocklist","allowlist-blocklist"][] as $p | ["gvk-off","gvk-viewonly","gvk-traceable"][] as $m |
 {kind:"classic",code:"USD",issuer:$issuer,tokenContractId:.pools[0].tokenContractId,policy:$p,gvkMode:$m}]' "$SANDBOX/original.json" > "$PLAN_FILE"
run 0 $'deploy custom\n' --config "$PLAN_FILE"
[[ $(grep -c '^--pool$' "$CAPTURE_ARGS") == 12 ]] || fail 'wrong number of pools'
grep -Fxq "allowlist-blocklist:gvk-traceable:classic:USD:$TEST_ACCOUNT:$TEST_TOKEN" "$CAPTURE_ARGS" || fail 'classic asset arguments'
grep -Fxq 'Example; $(do-not-run)' "$CAPTURE_ENV" || fail 'display name interpreted'
pass 'all circuit combinations and classic pools preserve literal arguments'
cp "$SANDBOX/original.json" "$PLAN_FILE"
export FAKE_CHANGE_MARKER="$SANDBOX/network-read"
run 1 $'deploy custom\n' --config "$PLAN_FILE"; no_deploy; contains 'network settings changed'
unset FAKE_CHANGE_MARKER; pass 'network revalidated after confirmation'
printf '{"x":"0x1","y":"2"}\n' > "$SANDBOX/public-key.json"
run 0 "$(printf '1\nalice\n\n\n\nyes\n10000000\n3\n%s\n2\n2\nno\n%s\n' "$TEST_TOKEN" "$SANDBOX/public-key.json")"$'\n' --save-only --output "$SANDBOX/viewing-plan.json"
no_deploy
jq -e '.gvkAuthorityPubKey.x == "0x1" and .pools[0].kind == "contract" and .pools[0].gvkMode == "gvk-viewonly"' "$SANDBOX/viewing-plan.json" >/dev/null || fail 'viewing key plan incorrect'
pass 'interactive contract pool with public viewing key'
export DEPLOY_EXIT=7
run 7 $'deploy custom\n' --config "$PLAN_FILE"; contains 'Some transactions may already have succeeded'
[[ -f $PLAN_FILE ]] || fail 'plan lost'; unset DEPLOY_EXIT; pass 'partial deployment failure retains plan and exit status'
printf 'All %s shell checks passed. No live network used.\n' "$COUNT"
