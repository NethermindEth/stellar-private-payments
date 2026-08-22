#!/usr/bin/env bash
# Prune state left behind by repeated testnet redeploys.
#
# Usage: e2e-cleanup.sh [--apply] [--live-only] [--data-dir DIR]
#
#   (default)     Dry run: report what would be removed, change nothing.
#   --apply       Actually remove it. Backs the wallet DB up first.
#   --live-only   Also drop the generation referenced by the COMMITTED
#                 deployments.json, keeping only the working tree's.
#   --data-dir    Wallet data dir (default: deployments/scripts/.e2e-wallet-testnet)
#
# Every redeploy mints a fresh set of contracts — two pools, two ASPs, two
# verifiers, a registry — and nothing ever forgets the old ones. The local
# wallet DB keeps their events, commitments, nullifiers, notes and indexer
# scan state indefinitely, so the file grows with every deployment and
# carries notes for pools that no longer exist.
#
# What this does NOT do, deliberately:
#   - Touch on-chain state. Orphaned Soroban contracts cannot be deleted;
#     they are reclaimed by TTL expiry once their rent lapses. Waiting is
#     the only option, and it needs no script.
#   - Delete any key material. Stellar identities under the user's global
#     ~/.config/stellar are reported and never removed: an alias with no
#     current reference may still hold a funded testnet account, and that
#     judgement belongs to a human.
#   - Touch the browser app's IndexedDB, which is separate storage with its
#     own lifecycle (clear it from the browser, or by wiping the Chrome
#     profile that e2e-freighter/scripts/provision.sh rebuilds anyway).

set -euo pipefail

die() { echo "e2e-cleanup.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$REPO_ROOT/deployments/scripts/.e2e-wallet-testnet"
APPLY=0
LIVE_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --live-only) LIVE_ONLY=1; shift ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,27p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) die "unknown argument '$1'" ;;
  esac
done

command -v sqlite3 >/dev/null 2>&1 || die "missing 'sqlite3'"
command -v python3 >/dev/null 2>&1 || die "missing 'python3'"

DB="$DATA_DIR/spp.db"
[ -f "$DB" ] || die "no wallet DB at $DB"

cd "$REPO_ROOT"

# ---------------------------------------------------------------- referenced

# A contract is live if any deployments.json still names it. Both the working
# tree and the committed blob count by default: the working tree is what the
# developer is testing against right now, while the committed version is what
# CI and every other checkout compile in (sdk/web and cli both embed it via
# include_str!, so the committed generation stays reachable even when the
# working tree has moved on). --live-only drops that second source.
collect_refs() {
  python3 - "$@" <<'PY'
import json, sys
out = []
for src in sys.argv[1:]:
    try:
        d = json.loads(open(src).read()) if not src.startswith('@') else json.loads(sys.stdin.read())
    except Exception:
        continue
    for key in ('asp_membership', 'asp_non_membership', 'public_key_registry'):
        if d.get(key):
            out.append(d[key])
    for v in (d.get('verifiers') or {}).values():
        out.append(v)
    for pool in d.get('pools') or []:
        for key in ('poolContractId', 'tokenContractId'):
            if pool.get(key):
                out.append(pool[key])
print('\n'.join(sorted(set(out))))
PY
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

REF_SOURCES=()
while IFS= read -r f; do REF_SOURCES+=("$f"); done < <(find deployments -name deployments.json -not -path '*/node_modules/*')
[ ${#REF_SOURCES[@]} -gt 0 ] || die "found no deployments.json to read references from"

if [ "$LIVE_ONLY" -eq 0 ]; then
  # Add the committed blob of each, when it differs from the working tree.
  for f in "${REF_SOURCES[@]}"; do
    if git show "HEAD:$f" > "$TMP_DIR/$(echo "$f" | tr / _)" 2>/dev/null; then
      REF_SOURCES+=("$TMP_DIR/$(echo "$f" | tr / _)")
    fi
  done
fi

collect_refs "${REF_SOURCES[@]}" | sort -u > "$TMP_DIR/referenced.txt"
step "$(wc -l < "$TMP_DIR/referenced.txt") contract addresses referenced by $( [ "$LIVE_ONLY" -eq 1 ] && echo 'the working tree' || echo 'the working tree and HEAD')"

# ---------------------------------------------------------------------- dead

sqlite3 "$DB" "select address from contracts;" | sort -u > "$TMP_DIR/known.txt"
comm -23 "$TMP_DIR/known.txt" "$TMP_DIR/referenced.txt" > "$TMP_DIR/dead.txt"
DEAD_COUNT=$(wc -l < "$TMP_DIR/dead.txt" | tr -d ' ')

if [ "$DEAD_COUNT" -eq 0 ]; then
  step "wallet DB: no unreferenced contracts — nothing to prune"
else
  step "wallet DB: $DEAD_COUNT unreferenced contracts"
  # Build an IN-list once, reused by the report and the delete.
  IN_LIST=$(sed "s/^/'/; s/$/'/" "$TMP_DIR/dead.txt" | paste -sd, -)
  sqlite3 -header -column "$DB" "
    select c.address,
           (select count(*) from raw_contract_events e where e.contract_id = c.contract_id) as events
      from contracts c
     where c.address in ($IN_LIST)
     order by events desc;" >&2
fi

# app_user_operations is the one table holding a pool id with no foreign key
# (it stores the address as TEXT), so the cascade below cannot reach it.
ORPHAN_OPS=0
if [ "$DEAD_COUNT" -gt 0 ]; then
  ORPHAN_OPS=$(sqlite3 "$DB" "select count(*) from app_user_operations where pool_contract_id in ($IN_LIST);")
  step "wallet DB: $ORPHAN_OPS app operation-history rows for those pools"
fi

# ------------------------------------------------------------ local aliases

IDENTITY_DIR="$DATA_DIR/stellar/identity"
ENV_FILE="$REPO_ROOT/deployments/testnet/.e2e-accounts.env"
STALE_ALIASES=()
if [ -d "$IDENTITY_DIR" ]; then
  REFERENCED_ALIASES=""
  if [ -f "$ENV_FILE" ]; then
    REFERENCED_ALIASES=$(grep -oE '^E2E_ACCOUNT_[A-Z]+_ALIAS=.*' "$ENV_FILE" | cut -d= -f2- | tr -d '"' || true)
  fi
  while IFS= read -r toml; do
    alias_name="$(basename "$toml" .toml)"
    if ! printf '%s\n' "$REFERENCED_ALIASES" | grep -qx "$alias_name"; then
      STALE_ALIASES+=("$alias_name")
    fi
  done < <(find "$IDENTITY_DIR" -name '*.toml' | sort)
fi
if [ ${#STALE_ALIASES[@]} -gt 0 ]; then
  step "repo-local aliases not referenced by .e2e-accounts.env: ${STALE_ALIASES[*]}"
fi

# --------------------------------------------------------- global identities

GLOBAL_IDENTITY_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/stellar/identity"
if [ -d "$GLOBAL_IDENTITY_DIR" ]; then
  GLOBAL_COUNT=$(find "$GLOBAL_IDENTITY_DIR" -name '*.toml' | wc -l | tr -d ' ')
  step "global stellar identities: $GLOBAL_COUNT in $GLOBAL_IDENTITY_DIR (reported only, never removed)"
  find "$GLOBAL_IDENTITY_DIR" -name '*.toml' -exec basename {} .toml \; | sort | sed 's/^/      /' >&2
fi

# -------------------------------------------------------------------- apply

if [ "$APPLY" -eq 0 ]; then
  echo >&2
  step "DRY RUN — nothing was changed. Re-run with --apply to remove the above."
  exit 0
fi

if [ "$DEAD_COUNT" -gt 0 ]; then
  BACKUP="$DB.bak-$(date +%Y%m%d-%H%M%S)"
  step "backing the wallet DB up to $BACKUP"
  sqlite3 "$DB" ".backup '$BACKUP'"

  # foreign_keys is OFF by default in sqlite, and every cascade below depends
  # on it: deleting a contracts row is what propagates to indexing_metadata,
  # raw_contract_events, account_commitment_scan and nullifier_scan_state, and
  # from raw_contract_events onward to pool_commitments, pool_nullifiers,
  # public_keys, asp_membership_leaves and finally user_notes. Without the
  # pragma the delete silently strands all of it.
  step "pruning $DEAD_COUNT contracts and everything cascading from them"
  sqlite3 "$DB" "
    pragma foreign_keys = ON;
    begin;
    delete from app_user_operations where pool_contract_id in ($IN_LIST);
    delete from contracts where address in ($IN_LIST);
    commit;
    vacuum;"
  step "wallet DB pruned"
fi

if [ ${#STALE_ALIASES[@]} -gt 0 ]; then
  for alias_name in "${STALE_ALIASES[@]}"; do
    step "removing repo-local alias $alias_name"
    rm -f "$IDENTITY_DIR/$alias_name.toml"
  done
fi

step "done"
