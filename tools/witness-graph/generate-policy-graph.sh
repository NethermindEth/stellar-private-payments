#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out_file=${1:-"$repo_root/deployments/testnet/circuit_keys/policy_tx_2_2.graph.bin"}
manifest_file=${out_file%.graph.bin}.graph.manifest
work_dir="$repo_root/target/witness-graph-builder"
graph_src_dir="$work_dir/circuits-src"
manifest_work_file="$work_dir/policy_tx_2_2.graph.manifest"
patched_witness_rs_dir="$work_dir/vendor/circom-witness-rs"
circomlib_dir="$graph_src_dir/circomlib"
comparators_file="$circomlib_dir/circuits/comparators.circom"
bitify_file="$circomlib_dir/circuits/bitify.circom"
expected_circom_version="2.2.3"

mkdir -p "$work_dir/src" "$graph_src_dir" "$(dirname -- "$out_file")"
rm -rf "$graph_src_dir"
mkdir -p "$graph_src_dir"

cat > "$work_dir/Cargo.toml" <<'EOF'
[package]
name = "policy-witness-graph-builder"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
circom-witness-rs = { version = "0.2.3", default-features = false, features = ["build-witness"] }
eyre = "0.6"

[workspace]
EOF

cat > "$work_dir/src/main.rs" <<'EOF'
fn main() -> eyre::Result<()> {
    circom_witness_rs::generate::build_witness()
}
EOF

prepare_patched_witness_builder() {
    (
        cd "$work_dir"
        cargo fetch
    )

    crate_src=$(
        find "${CARGO_HOME:-$HOME/.cargo}/registry/src" \
            -path "*/circom-witness-rs-0.2.3" \
            -type d \
            -print \
            -quit
    )
    if [ -z "$crate_src" ]; then
        echo "circom-witness-rs 0.2.3 source not found after cargo fetch" >&2
        exit 1
    fi

    rm -rf "$patched_witness_rs_dir"
    mkdir -p "$(dirname -- "$patched_witness_rs_dir")"
    cp -R "$crate_src" "$patched_witness_rs_dir"

    # Match circuits/build.rs, which builds R1CS/WASM with reduced
    # simplification. circom-witness-rs defaults its graph builder to --O2.
    python3 - "$patched_witness_rs_dir/build.rs" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
content = path.read_text()
old = '.arg("--O2");'
new = '.arg("--O1");'
if old not in content:
    raise SystemExit("expected circom-witness-rs build.rs to pass --O2")
path.write_text(content.replace(old, new))
PY

    cat > "$work_dir/Cargo.toml" <<'EOF'
[package]
name = "policy-witness-graph-builder"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
circom-witness-rs = { path = "vendor/circom-witness-rs", default-features = false, features = ["build-witness"] }
eyre = "0.6"

[workspace]
EOF
}

if ! command -v circom >/dev/null 2>&1; then
    echo "circom is required on PATH to generate the witness graph" >&2
    exit 1
fi

circom_version=$(circom --version | awk '{print $NF}')
if [ "$circom_version" != "$expected_circom_version" ]; then
    echo "circom $expected_circom_version is required to generate the witness graph (found $circom_version)" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to generate the witness graph manifest" >&2
    exit 1
fi

prepare_patched_witness_builder
(
    cd "$work_dir"
    cargo generate-lockfile
)

locked_rev=$(tr -d '\r\n' < "$repo_root/circuits/circomlib.lock")

(
    cd "$repo_root/circuits/src"
    find . -path "./circomlib" -prune -o -type f -print
) | while IFS= read -r rel_path; do
    mkdir -p "$graph_src_dir/$(dirname -- "$rel_path")"
    cp "$repo_root/circuits/src/$rel_path" "$graph_src_dir/$rel_path"
done

mkdir -p "$circomlib_dir"
git -C "$circomlib_dir" init
git -C "$circomlib_dir" remote add origin https://github.com/iden3/circomlib.git
git -C "$circomlib_dir" fetch --depth 1 origin "$locked_rev"
git -C "$circomlib_dir" checkout --detach FETCH_HEAD

python3 - "$repo_root" "$graph_src_dir" "$manifest_work_file" "$out_file" "$circom_version" "$work_dir/Cargo.lock" <<'PY'
import hashlib
import os
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
graph_src_dir = Path(sys.argv[2]).resolve()
manifest_file = Path(sys.argv[3]).resolve()
out_file = Path(sys.argv[4]).resolve()
circom_version = sys.argv[5]
builder_lock = Path(sys.argv[6]).resolve()
entry = graph_src_dir / "policy_tx_2_2.circom"
include_re = re.compile(r'^\s*include\s+["\']([^"\']+)["\']')
search_dirs = [graph_src_dir]
seen = set()
deps = []
stack = [entry]

def resolve_include(include_path: str, current_dir: Path) -> Path:
    candidates = []
    if include_path.startswith("./") or include_path.startswith("../"):
        candidates.append(current_dir / include_path)
    else:
        candidates.append(current_dir / include_path)
        candidates.extend(base / include_path for base in search_dirs)
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    raise SystemExit(f"Could not resolve include {include_path!r} from {current_dir}")

while stack:
    current = stack.pop().resolve()
    if current in seen:
        continue
    seen.add(current)
    deps.append(current)
    for line in current.read_text().splitlines():
        match = include_re.match(line)
        if match:
            stack.append(resolve_include(match.group(1), current.parent))

sources = sorted(
    deps
    + [
        repo_root / "Cargo.lock",
        repo_root / "circuits/Cargo.toml",
        repo_root / "circuits/circomlib.lock",
        repo_root / "circuits/build.rs",
        repo_root / "circuits/build_support.rs",
        repo_root / "tools/witness-graph/generate-policy-graph.sh",
    ],
    key=lambda path: str(path),
)

def repo_rel(path: Path) -> str:
    path = path.resolve()
    if path.is_relative_to(graph_src_dir):
        return "circuits/src/" + path.relative_to(graph_src_dir).as_posix()
    return path.relative_to(repo_root).as_posix()

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

manifest_file.parent.mkdir(parents=True, exist_ok=True)
with manifest_file.open("w", encoding="utf-8") as manifest:
    manifest.write("version 1\n")
    manifest.write(f"graph_sha256 {sha256(out_file) if out_file.exists() else 'pending'}\n")
    manifest.write(f"circom_version {circom_version}\n")
    manifest.write(f"builder_lock_sha256 {sha256(builder_lock)}\n")
    for source in sources:
        manifest.write(f"source_sha256 {sha256(source)} {repo_rel(source)}\n")
PY

if ! grep -q "function bbf_inv" "$comparators_file"; then
    tmp_file="$comparators_file.tmp"
    awk '
        /^include "binsum\.circom";/ && !inserted {
            print;
            print "";
            print "function bbf_inv(in) {";
            print "    return in!=0 ? 1/in : 0;";
            print "}";
            inserted = 1;
            next;
        }
        /inv <-- in!=0 \? 1\/in : 0;/ {
            print "    inv <-- bbf_inv(in);";
            next;
        }
        { print }
    ' "$comparators_file" > "$tmp_file"
    mv "$tmp_file" "$comparators_file"
fi

if ! grep -q "function bbf_bit" "$bitify_file"; then
    tmp_file="$bitify_file.tmp"
    awk '
        /^include "aliascheck\.circom";/ && !inserted {
            print;
            print "";
            print "function bbf_bit(in, bit) {";
            print "    return (in >> bit) & 1;";
            print "}";
            inserted = 1;
            next;
        }
        /out\[i\] <-- \(in >> i\) & 1;/ {
            print "        out[i] <-- bbf_bit(in, i);";
            next;
        }
        /out\[i\] <-- \(neg >> i\) & 1;/ {
            print "        out[i] <-- bbf_bit(neg, i);";
            next;
        }
        { print }
    ' "$bitify_file" > "$tmp_file"
    mv "$tmp_file" "$bitify_file"
fi

(
    cd "$work_dir"
    rm -f graph.bin
    cargo clean -p circom-witness-rs -p policy-witness-graph-builder >/dev/null 2>&1 || true
    WITNESS_CPP="$graph_src_dir/policy_tx_2_2.circom" \
        CIRCOM_LIBRARY_PATH="$graph_src_dir" \
        cargo run --release
)

python3 - "$manifest_work_file" "$work_dir/graph.bin" <<'PY'
import hashlib
import sys
from pathlib import Path

manifest_file = Path(sys.argv[1])
out_file = Path(sys.argv[2])
graph_hash = hashlib.sha256(out_file.read_bytes()).hexdigest()
lines = manifest_file.read_text(encoding="utf-8").splitlines()
with manifest_file.open("w", encoding="utf-8") as manifest:
    for line in lines:
        if line.startswith("graph_sha256 "):
            manifest.write(f"graph_sha256 {graph_hash}\n")
        else:
            manifest.write(line + "\n")
PY
mv "$work_dir/graph.bin" "$out_file"
mv "$manifest_work_file" "$manifest_file"
printf '%s\n' "$out_file"
printf '%s\n' "$manifest_file"
