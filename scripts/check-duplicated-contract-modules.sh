#!/usr/bin/env bash
# Verify that the infrastructure modules duplicated between contracts/pool and
# contracts/pool-gvk are still byte-identical.
#
# The duplication is deliberate. Soroban's #[contractimpl] emits
# #[no_mangle] extern "C" exports that the linker never dead-code-eliminates,
# so a Cargo dependency edge from pool-gvk to pool would drag PoolContract's
# own exports into pool-gvk's WASM and collide with PoolGvkContract's
# identically-named methods. Cargo cannot depend on part of a crate, so the
# non-contract modules are copied instead.
#
# What that buys in link safety it costs in drift risk: these copies are
# consensus-critical Merkle-tree and policy-flag logic living in two places
# with nothing else checking that they agree. This script is that check.
#
# A failure does NOT mean "silence this script". It means one copy changed and
# the other did not; mirror the change, then re-run.
#
# Usage:
#   scripts/check-duplicated-contract-modules.sh
#
# Exit codes: 0 = copies identical, 1 = drift found, 2 = a tracked copy is
# missing (a rename would otherwise silently drop coverage while still
# reporting success).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SOURCE_CRATE="contracts/pool"
COPY_CRATE="contracts/pool-gvk"

# Modules that exist verbatim in both crates, relative to each crate's src/.
DUPLICATED_MODULES=(
  merkle_with_history.rs
  policy.rs
)

die() { echo "check-duplicated-contract-modules.sh: $*" >&2; exit 2; }

drift=0

for module in "${DUPLICATED_MODULES[@]}"; do
  source_file="$ROOT_DIR/$SOURCE_CRATE/src/$module"
  copy_file="$ROOT_DIR/$COPY_CRATE/src/$module"

  [[ -f "$source_file" ]] || die "missing $SOURCE_CRATE/src/$module (renamed or removed?)"
  [[ -f "$copy_file" ]] || die "missing $COPY_CRATE/src/$module (renamed or removed?)"

  if ! diff -u "$source_file" "$copy_file"; then
    echo "drift: $SOURCE_CRATE/src/$module and $COPY_CRATE/src/$module differ" >&2
    drift=1
  fi
done

if [[ "$drift" -ne 0 ]]; then
  cat >&2 <<'EOF'

These modules must stay byte-identical. Apply the same change to both copies.
If a change is meant to apply to only one crate, it does not belong in a
duplicated module: move it into the crate's own contract module instead.
EOF
  exit 1
fi

echo "duplicated contract modules are in sync (${#DUPLICATED_MODULES[@]} checked)"
