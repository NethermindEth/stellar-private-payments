#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/add_asp_membership_leaf.sh --leaf 0x... --source NAME [options]

Options:
  --leaf 0x...       Precomputed leaf (required)
  --source NAME      Stellar identity or secret key (required)
  --contract C...    ASP membership contract id (defaults to scripts/deployments.json)
  --network NAME     Network name (defaults to scripts/deployments.json)
  -h, --help         Show this help
USAGE
}

LEAF=""
SOURCE=""
CONTRACT=""
NETWORK=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --leaf) LEAF="$2"; shift 2 ;;
    --source) SOURCE="$2"; shift 2 ;;
    --contract) CONTRACT="$2"; shift 2 ;;
    --network) NETWORK="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

[[ -n "$LEAF" ]] || { echo "Missing --leaf" >&2; usage; exit 1; }
[[ -n "$SOURCE" ]] || { echo "Missing --source" >&2; usage; exit 1; }

DEPLOY_JSON="$(dirname "$0")/deployments.json"
if [[ -z "$CONTRACT" || -z "$NETWORK" ]]; then
  if [[ -f "$DEPLOY_JSON" && -x "$(command -v python3)" ]]; then
    CONTRACT="${CONTRACT:-$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["asp_membership"])' "$DEPLOY_JSON")}"
    NETWORK="${NETWORK:-$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["network"])' "$DEPLOY_JSON")}"
  fi
fi

[[ -n "$CONTRACT" ]] || { echo "Missing --contract (and couldn't read deployments.json)" >&2; exit 1; }
[[ -n "$NETWORK" ]] || { echo "Missing --network (and couldn't read deployments.json)" >&2; exit 1; }

stellar contract invoke \
  --id "$CONTRACT" \
  --source-account "$SOURCE" \
  --network "$NETWORK" \
  -- \
  insert_leaf \
  --leaf "$LEAF"
