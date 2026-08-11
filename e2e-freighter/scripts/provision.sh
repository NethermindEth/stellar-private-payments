#!/usr/bin/env bash
# Provision and snapshot a Freighter profile for e2e tests.
#
# Usage: provision.sh [--snapshot|--restore|--verify] [--force] [--add-account]
#
#   --snapshot       Tar the working profile into profile-snapshot.tar.gz (default)
#   --restore        Restore the snapshot into a fresh temp dir, print path on stdout
#   --verify         Verify the snapshot without rebuilding
#   --force          Rebuild the profile even if one verifies fine
#   --add-account    Also import account B (E2E_ACCOUNT_D_SECRET) during provisioning
#
# Merges the former snapshot-profile.sh, prepare-profile.sh, and the
# provisioning orchestration from setup.sh into a single script.

set -euo pipefail

die() { echo "provision.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
step() { echo "==> $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SNAPSHOT_FILE="$PKG_ROOT/profile-snapshot.tar.gz"
PROFILE_DIR="$PKG_ROOT/.chrome-profile"
MODE="snapshot"
FORCE=0
ADD_ACCOUNT_FLAG=""
VERIFY_FLAG=""

usage() {
  cat >&2 <<'USAGE'
Usage: provision.sh [OPTIONS]

Provision, snapshot, restore, or verify the Freighter Chrome profile for e2e tests.

Options:
  --snapshot       Tar the working profile into profile-snapshot.tar.gz (default)
  --restore        Restore the snapshot into a fresh temp dir, print path on stdout
  --verify         Verify the snapshot without rebuilding
  --force          Rebuild the profile even if one verifies fine
  --add-account    Also import account B (E2E_ACCOUNT_D_SECRET) during provisioning
  -h, --help       Show this help

Examples:
  provision.sh                         # provision + snapshot
  provision.sh --restore               # restore snapshot to temp dir
  provision.sh --verify                # verify existing snapshot
  provision.sh --force                 # rebuild from scratch
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --snapshot) MODE="snapshot"; shift ;;
    --restore) MODE="restore"; shift ;;
    --verify) MODE="verify"; shift ;;
    --force) FORCE=1; shift ;;
    --add-account) ADD_ACCOUNT_FLAG="--add-account"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument '$1'" ;;
  esac
done

case "$MODE" in
  snapshot)
    need node
    need tar

    if [ "$FORCE" -eq 0 ] && [ -s "$SNAPSHOT_FILE" ]; then
      step "snapshot exists; verifying instead of rebuilding (use --force to rebuild)"
      node "$SCRIPT_DIR/provision.mjs --verify"
      step "snapshot verified — nothing to do"
      exit 0
    fi

    # The wizard completion drives a headed browser
    if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
      die "no display available: the provisioning step must run headed"
    fi

    # Provision the profile
    step "provisioning the Freighter profile"
    node "$SCRIPT_DIR/provision.mjs $ADD_ACCOUNT_FLAG"

    # Snapshot the profile
    step "creating snapshot: $SNAPSHOT_FILE"
    need tar
    tar -czf "$SNAPSHOT_FILE" \
      --exclude='.chrome-profile/Default/Cache' \
      --exclude='.chrome-profile/Default/Code Cache' \
      --exclude='.chrome-profile/Default/Service Worker/CacheStorage' \
      --exclude='.chrome-profile/Default/Service Worker/ScriptCache' \
      --exclude='.chrome-profile/Default/Media Cache' \
      --exclude='.chrome-profile/Default/GPUCache' \
      -C "$PKG_ROOT" .chrome-profile

    step "snapshot created: $SNAPSHOT_FILE"
    ;;

  restore)
    need tar
    if [ ! -s "$SNAPSHOT_FILE" ]; then
      die "snapshot not found: $SNAPSHOT_FILE (run provision.sh first)"
    fi
    TMP_DIR="$(mktemp -d)"
    tar -xzf "$SNAPSHOT_FILE" -C "$TMP_DIR"
    # Print the profile subdirectory path on stdout for the caller
    echo "$TMP_DIR/.chrome-profile/Default"
    ;;

  verify)
    node "$SCRIPT_DIR/provision.mjs --verify"
    step "snapshot verified"
    ;;
esac