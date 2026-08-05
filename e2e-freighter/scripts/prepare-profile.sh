#!/usr/bin/env bash
# Restore a Freighter profile snapshot into a fresh temp directory for one run.
#
# Never restore against the live/shared profile dir or run two restores into
# the same target: Chrome's profile storage (LevelDB) is single-writer, so
# concurrent runs need their own directory. Prints, on stdout, the path to
# the restored Chrome *profile* subdirectory (e.g. ".../Default" — the one
# directly holding "Local Extension Settings", "Local Storage", etc.). The
# --user-data-dir to pass to chromium is that path's parent:
#   profile_subdir=$(prepare-profile.sh)
#   chromium --user-data-dir="$(dirname "$profile_subdir")" ...
#
# Usage: prepare-profile.sh [--snapshot FILE]

set -euo pipefail

die() { echo "prepare-profile.sh: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
step() { echo "==> $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SNAPSHOT_FILE="$PKG_ROOT/profile-snapshot.tar.gz"

usage() {
  cat >&2 <<'USAGE'
Usage: prepare-profile.sh [OPTIONS]

Restores a Freighter profile snapshot (from scripts/snapshot-profile.sh) into
a fresh temp directory and prints the restored Chrome profile subdirectory's
path on stdout (e.g. ".../Default"). Each call gets its own temp directory —
never point two concurrent runs at the same restored profile, since Chrome's
LevelDB profile storage is single-writer.

Options:
  --snapshot FILE   Snapshot archive to restore (default: profile-snapshot.tar.gz)
  -h, --help        Show this help

Example:
  profile_subdir=$(e2e-freighter/scripts/prepare-profile.sh)
  chromium --user-data-dir="$(dirname "$profile_subdir")" ...
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --snapshot) [ $# -ge 2 ] || die "--snapshot needs a value"; SNAPSHOT_FILE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument '$1'" ;;
  esac
done

need tar
need mktemp
need find

[ -s "$SNAPSHOT_FILE" ] || die "snapshot '$SNAPSHOT_FILE' not found; run scripts/snapshot-profile.sh first"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/e2e-freighter-profile.XXXXXX")"
step "restoring '$SNAPSHOT_FILE' -> '$TMP_DIR'"
tar -xzf "$SNAPSHOT_FILE" -C "$TMP_DIR"

# The archive holds the user-data-dir (e.g. ".chrome-profile") with a nested
# per-profile subdirectory ("Default" for a single-profile setup); find it
# by its "Local Extension Settings" marker rather than assuming a name.
PROFILE_SUBDIR="$(find "$TMP_DIR" -maxdepth 3 -type d -iname 'Local Extension Settings' -exec dirname {} \; | head -n1)"
[ -n "$PROFILE_SUBDIR" ] || die "restored snapshot has no recognizable Chrome profile subdirectory (no 'Local Extension Settings' found under $TMP_DIR)"

echo "$PROFILE_SUBDIR"
