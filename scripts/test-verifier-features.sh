#!/usr/bin/env bash
# Check that each vk-* feature of circom-groth16-verifier embeds its own key file: a build with the
# feature generates the same vk.rs as a build with VERIFIER_VK_JSON set to that file.
set -euo pipefail
cd "$(dirname "$0")/.."

# Prints the verifier build script's OUT_DIR for a `cargo check` given arguments "$@".
out_dir() {
  cargo check --locked -q -p circom-groth16-verifier --message-format=json "$@" \
    | jq -r 'select(.reason == "build-script-executed"
        and (.package_id | contains("circom-groth16-verifier"))) | .out_dir' | tail -1
}

n=0
# Assignments, so set -e stops on git's or cargo's own failure instead of blaming a key.
keys="$(git ls-files 'deployments/*/circuit_keys/*_vk.json')"
for k in $keys; do
  net="${k#deployments/}"
  net="${net%%/*}"
  name="${k##*/}"
  case "$name" in
    keyOwnership_vk.json) key=keyOwnership ;;
    policy_tx_2_2_vk.json) key=none ;;
    policy_tx_2_2_*_vk.json) key="${name#policy_tx_2_2_}"; key="${key%_vk.json}" ;;
    *) continue ;;
  esac
  feature="$(printf 'vk-%s-%s' "$net" "$key" | tr '[:upper:]' '[:lower:]' | tr _ -)"
  with_feature="$(out_dir --features "$feature")"
  with_env="$(VERIFIER_VK_JSON="$PWD/$k" out_dir)"
  cmp -s "$with_feature/vk.rs" "$with_env/vk.rs" \
    || { echo "feature $feature does not embed $k" >&2; exit 1; }
  n=$((n + 1))
done
[ "$n" -gt 0 ] || { echo "no key files in deployments/*/circuit_keys" >&2; exit 1; }
echo "$n vk-* features each embed their own key file"
