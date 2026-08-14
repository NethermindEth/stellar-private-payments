#!/usr/bin/env bash
# Fetch the pinned Freighter extension build from the upstream project's
# GitHub release (stellar/freighter) and install it as
# e2e-freighter/vendor/freighter.
#
# vendor/ is git-ignored on purpose (third-party build output does not
# belong in this repo), so every fresh checkout — locally and in CI —
# needs this step before scripts/setup.sh can provision a profile.
#
# The upstream release zip's manifest.json lacks the "key" field, so an
# unpacked load would derive a path-dependent extension id. The runner and
# setup scripts address the extension by its stable Web Store id, which
# Chrome derives from the developer's public key. That key (public — it is
# present in every Web Store install) is patched into the manifest here,
# and the script verifies the key really derives to the expected id before
# installing anything.
#
# Usage: fetch-extension.sh [--force]

set -euo pipefail

die() { echo "fetch-extension.sh: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDOR_DIR="$PKG_ROOT/vendor/freighter"

# Pinned upstream version. Bump deliberately: the auto-approve logic
# drives Freighter's DOM by text and is version-sensitive.
FREIGHTER_VERSION="5.44.0"
EXPECTED_EXT_ID="bcacfldlkkdogcmkkibnjlakofdplcbk"
DOWNLOAD_URL="https://github.com/stellar/freighter/releases/download/${FREIGHTER_VERSION}/build-${FREIGHTER_VERSION}.zip"

# Developer public key from the Web Store build (public, not a secret).
MANIFEST_KEY="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnZVggwOXfOvqp8Ah5Vpd29xgsM5Y0gvaMAesSLQDk4DAEoZIlUkq6biihDuxEoJAQ97fb7+iOWDoZZW3esOI+6zLBQSvJiOmTPghr2eN9nf8D/8u8mPtnQPsu3lKz+Jf2zLEwNvjQAorgq+fTmyS0IIKWLxJQ3W0ByywzIZOJk/gz7qke1xWUxdLtPlMc1YK8vHWOhrpoH7bMdy60/poEkcRGsWTclV/uCAbVUAuX1wJU4VVpvOqrbJmE95ZwQg1Q3bGGpKmtPLeQ4kEj5uxan0mvlrlC+YaJUCK08TrnlcIalRxFqUciuNvK339z3Ru5MwI3WoPSqfTKOCiezi6tQIDAQAB"

FORCE=0
case "${1:-}" in
  --force) FORCE=1 ;;
  "") ;;
  *) die "unknown argument '$1' (want --force or nothing)" ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'"; }
need curl
need unzip
need node

if [ "$FORCE" -eq 0 ] && [ -f "$VENDOR_DIR/manifest.json" ]; then
  have="$(node -p "JSON.parse(require('fs').readFileSync('$VENDOR_DIR/manifest.json','utf8')).version || ''")"
  if [ "$have" = "$FREIGHTER_VERSION" ]; then
    step "vendored Freighter $FREIGHTER_VERSION already present — nothing to do"
    exit 0
  fi
  die "vendored Freighter is version '$have', want '$FREIGHTER_VERSION' — re-run with --force to replace it"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

step "downloading Freighter $FREIGHTER_VERSION from stellar/freighter releases"
curl -fsSL -o "$TMP/freighter.zip" "$DOWNLOAD_URL" \
  || die "download failed: $DOWNLOAD_URL"

step "unpacking"
unzip -q "$TMP/freighter.zip" -d "$TMP/unpacked"
[ -f "$TMP/unpacked/manifest.json" ] || die "zip has no top-level manifest.json — upstream layout changed?"

step "patching manifest key and verifying the derived extension id"
MANIFEST_KEY="$MANIFEST_KEY" EXPECTED_EXT_ID="$EXPECTED_EXT_ID" PIN="$FREIGHTER_VERSION" \
  node - "$TMP/unpacked/manifest.json" <<'NODE'
const fs = require('fs');
const crypto = require('crypto');
const p = process.argv[2];
const m = JSON.parse(fs.readFileSync(p, 'utf8'));
if (m.version !== process.env.PIN)
  throw new Error(`manifest version ${m.version} != pin ${process.env.PIN}`);
m.key = process.env.MANIFEST_KEY;
const der = Buffer.from(m.key, 'base64');
const id = crypto.createHash('sha256').update(der).digest('hex').slice(0, 32)
  .split('').map(c => String.fromCharCode(97 + parseInt(c, 16))).join('');
if (id !== process.env.EXPECTED_EXT_ID)
  throw new Error(`embedded key derives to ${id}, expected ${process.env.EXPECTED_EXT_ID}`);
fs.writeFileSync(p, JSON.stringify(m, null, 2) + '\n');
console.log(`    manifest ${m.version}, extension id ${id} verified`);
NODE

step "patching background script to open approvals in a tab instead of a popup"
# Freighter's background.min.js uses chrome.windows.create with type:"popup" for
# approvals. In headed runs that popup is a separate OS window that Playwright
# sometimes struggles to attach to promptly. Opening it as a normal browser
# window/tab makes it a first-class Playwright page target.
BG="$TMP/unpacked/background.min.js"
if [ -f "$BG" ]; then
  sed -i 's/He={type:"popup",width:360,height:632}/He={type:"normal"}/g' "$BG"
  if grep -q 'He={type:"normal"}' "$BG"; then
    echo "    background.min.js patched to open approvals as normal windows"
  else
    die "background.min.js popup patch failed — upstream code may have changed"
  fi
else
  die "background.min.js not found in unpacked extension"
fi

rm -rf "$VENDOR_DIR"
mkdir -p "$(dirname "$VENDOR_DIR")"
mv "$TMP/unpacked" "$VENDOR_DIR"
step "installed $VENDOR_DIR ($FREIGHTER_VERSION)"
