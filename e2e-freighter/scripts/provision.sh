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
      node "$SCRIPT_DIR/provision.mjs" --verify
      step "snapshot verified — nothing to do"
      exit 0
    fi

    # The wizard completion drives a headed browser
    if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
      die "no display available: the provisioning step must run headed"
    fi

    # Start from a clean profile. Without this, a rerun resumes a
    # half-provisioned wallet: the extension opens mid-state instead of at
    # #/welcome and the first-run controls are simply absent, so provisioning
    # fails on a selector that is actually correct. Only reached when
    # rebuilding — the --verify and --restore paths never get here.
    step "clearing any existing profile: $PROFILE_DIR"
    rm -rf "$PROFILE_DIR"

    # Provision the profile
    step "provisioning the Freighter profile"
    # $ADD_ACCOUNT_FLAG is intentionally unquoted: when empty it must expand to
    # no argument at all, whereas "$ADD_ACCOUNT_FLAG" would pass an empty string
    # as a positional argument.
    # shellcheck disable=SC2086
    node "$SCRIPT_DIR/provision.mjs" $ADD_ACCOUNT_FLAG

    # Snapshot the profile.
    #
    # Patterns, not anchored paths: the caches that matter are not all under
    # Default/ — component_crx_cache and extensions_crx_cache sit at the
    # profile root, and an anchored list silently lets them through.
    #
    # The two crx caches are the load-bearing exclusions. They hold Chrome's
    # machine-specific view of installed extensions; restoring them into a
    # fresh profile that is simultaneously being given --load-extension leaves
    # the extension undetectable to the page ("Freighter not detected").
    #
    # Singleton* are Chrome's single-instance locks. A stale one makes Chrome
    # treat the restored profile as already in use and quietly fall back to a
    # throwaway profile — no wallet, no extension state.
    #
    # Do NOT exclude by a bare "*.log" pattern: LevelDB's write-ahead logs
    # (e.g. "Local Extension Settings/<id>/000003.log") share that extension
    # and hold not-yet-compacted writes, so excluding them silently drops
    # recent extension storage. Chrome's own debug log has a literal name, so
    # exclude that exactly.
    step "creating snapshot: $SNAPSHOT_FILE"
    need tar
    # Do NOT add "Service Worker/ScriptCache" or "CacheStorage" here. Freighter
    # is MV3: its background service worker script lives in ScriptCache, and
    # excluding it leaves the worker unable to start in a restored profile.
    # The extension then answers "Could not establish connection. Receiving end
    # does not exist.", injects no provider, and the app reports Freighter as
    # not detected — with the wallet sitting intact in storage the whole time.
    tar -czf "$SNAPSHOT_FILE" \
      --exclude='GPUCache' \
      --exclude='Code Cache' \
      --exclude='ShaderCache' \
      --exclude='GrShaderCache' \
      --exclude='component_crx_cache' \
      --exclude='extensions_crx_cache' \
      --exclude='chrome_debug.log' \
      --exclude='SingletonLock' \
      --exclude='SingletonSocket' \
      --exclude='SingletonCookie' \
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
    node "$SCRIPT_DIR/provision.mjs" --verify
    step "snapshot verified"
    ;;
esac