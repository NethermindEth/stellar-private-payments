#!/usr/bin/env sh
# Installer for the `spp` CLI (Stellar Private Payments).
#
#   curl -fsSL https://nethermindeth.github.io/stellar-private-payments/install.sh | sh
#
# Picks the release binary for this platform, installs it, and provisions the
# data dir (circuits, policy proving keys, license/notice texts, deployment
# config) that the CLI reads at runtime.
#
# Environment overrides:
#   SPP_VERSION    release tag to install (default: latest non-prerelease)
#   SPP_BIN_DIR    where to install the `spp` binary (default: $HOME/.local/bin)
#   SPP_DATA_DIR   data dir root (default: $HOME/.local/share/stellar-private-payments)
#   SPP_DEPLOYMENT_REF git ref to take deployments.json from main
# Flags:
#   --pre          allow installing the latest prerelease
#   --version TAG  same as SPP_VERSION=TAG

set -eu

REPO="NethermindEth/stellar-private-payments"
BIN_DIR="${SPP_BIN_DIR:-$HOME/.local/bin}"
DATA_DIR="${SPP_DATA_DIR:-$HOME/.local/share/stellar-private-payments}"
VERSION="${SPP_VERSION:-}"
ALLOW_PRE="${SPP_PRERELEASE:-0}"
DEPLOYMENT_REF="${SPP_DEPLOYMENT_REF:-main}"

while [ $# -gt 0 ]; do
  case "$1" in
    --pre) ALLOW_PRE=1 ;;
    --version) VERSION="${2:-}"; shift ;;
    --version=*) VERSION="${1#--version=}" ;;
    -h|--help)
      sed -n '2,17p' "$0"
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

err() { echo "error: $*" >&2; exit 1; }

# --- download helpers (curl or wget) ---------------------------------------
if command -v curl >/dev/null 2>&1; then
  dl() { curl -fsSL "$1" -o "$2"; }
  dl_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  dl() { wget -qO "$2" "$1"; }
  dl_stdout() { wget -qO- "$1"; }
else
  err "need curl or wget"
fi

# --- detect target triple ---------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)  os_part="unknown-linux-musl" ;;
  Darwin) os_part="apple-darwin" ;;
  *) err "unsupported OS: $os (supported: Linux, macOS)" ;;
esac
case "$arch" in
  x86_64|amd64) arch_part="x86_64" ;;
  aarch64|arm64) arch_part="aarch64" ;;
  *) err "unsupported architecture: $arch (supported: x86_64, aarch64)" ;;
esac
TARGET="${arch_part}-${os_part}"

# --- resolve release tag ----------------------------------------------------
api="https://api.github.com/repos/$REPO"
resolve_latest_cli_tag() {
  # Only CLI publishes GitHub Releases (newest-first). Prefer stable cli-vX.Y.Z;
  # with --pre take any cli-v*.
  tags="$(dl_stdout "$api/releases?per_page=100" \
    | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"cli-v[^"]+"' \
    | sed -E 's/.*"([^"]+)".*/\1/')"
  if [ -z "$tags" ]; then
    return 1
  fi
  if [ "$ALLOW_PRE" = "1" ]; then
    printf '%s\n' "$tags" | head -1
    return 0
  fi
  printf '%s\n' "$tags" | grep -E '^cli-v[0-9]+\.[0-9]+\.[0-9]+$' | head -1
}
if [ -z "$VERSION" ]; then
  VERSION="$(resolve_latest_cli_tag || true)"
fi
[ -n "$VERSION" ] || err "could not resolve a cli-v* release tag (try --pre or SPP_VERSION)"
case "$VERSION" in
  cli-v*) ;;
  v*) err "legacy tag $VERSION is unsupported; use cli-vX.Y.Z (e.g. cli-v0.1.1)" ;;
  *) err "expected a cli-vX.Y.Z release tag, got: $VERSION" ;;
esac

base="https://github.com/$REPO/releases/download/$VERSION"
bin_asset="spp-${TARGET}.tar.gz"

echo "Installing spp $VERSION ($TARGET)"

# --- workspace --------------------------------------------------------------
tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT INT TERM

verify_sha256() {
  # $1 = file, $2 = sha256 sidecar file (format: "<hex>  <name>")
  expected="$(awk '{print $1}' "$2")"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$1" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$1" | awk '{print $1}')"
  else
    echo "warning: no sha256 tool found; skipping checksum verification" >&2
    return 0
  fi
  [ "$actual" = "$expected" ] || err "checksum mismatch for $(basename "$1")"
}

fetch_verified() {
  # $1 = asset name -> downloads asset + .sha256 into $tmp and verifies
  dl "$base/$1" "$tmp/$1"
  dl "$base/$1.sha256" "$tmp/$1.sha256"
  verify_sha256 "$tmp/$1" "$tmp/$1.sha256"
}

# --- install binary ---------------------------------------------------------
fetch_verified "$bin_asset"
tar -xzf "$tmp/$bin_asset" -C "$tmp"
[ -f "$tmp/spp" ] || err "binary 'spp' not found in $bin_asset"
mkdir -p "$BIN_DIR"
install -m 0755 "$tmp/spp" "$BIN_DIR/spp" 2>/dev/null || {
  cp "$tmp/spp" "$BIN_DIR/spp"; chmod 0755 "$BIN_DIR/spp";
}

# --- install runtime data into the data dir ---------------------------------
fetch_verified "dist.tar.gz"
mkdir -p "$DATA_DIR"
tar -xzf "$tmp/dist.tar.gz" -C "$DATA_DIR"

# --- deployment config ------------------------------------------------------
deployment_url="https://raw.githubusercontent.com/$REPO/$DEPLOYMENT_REF/deployments/testnet/deployments.json"
deployment_status="$DEPLOYMENT_REF"
if dl "$deployment_url" "$tmp/deployments.json"; then
  mv "$tmp/deployments.json" "$DATA_DIR/deployments.json"
else
  deployment_status="unavailable"
  echo "warning: could not download deployment config from $deployment_url" >&2
fi

echo "Installed:"
echo "  binary: $BIN_DIR/spp"
echo "  data:   $DATA_DIR"
echo "  config: $deployment_status"
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) echo "note: $BIN_DIR is not on your PATH; add it, e.g. export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
if ! command -v stellar >/dev/null 2>&1; then
  echo "note: Stellar CLI is required by 'spp' but was not found. Install it with:"
  echo "  curl -fsSL https://github.com/stellar/stellar-cli/raw/main/install.sh | sh"
fi
echo "Try: spp --help   |   spp license"
