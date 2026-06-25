#!/bin/sh
# Generate a circom-witness-rs operation graph.
#
# This is a maintainer tool, NOT part of `cargo build`: it needs a circom 2.2.3
# CLI binary plus a C++ toolchain, neither of which the normal Rust-only build
# requires. It produces a single artifact, `<circuit>.graph.bin`,
# which the prover worker then verifies by SHA-256.
#
# It builds a throwaway crate that drives circom-witness-rs's `build-witness`
# path, patched to use --O1 so the graph's wire layout matches the R1CS emitted
# by circuits/build.rs (BuildConfig { no_rounds: 1 }). It also injects the
# black-box hint functions (bbf_inv / bbf_bit) the graph runtime binds at
# evaluation time.
#
# Usage:
#   scripts/generate-witness-graph.sh [CIRCUIT_STEM] [OUTPUT.graph.bin]
# Examples:
#   scripts/generate-witness-graph.sh                       # policy_tx_2_2
#   scripts/generate-witness-graph.sh selectiveDisclosure_1
# Requirements on PATH: circom 2.2.3, a C++ compiler, cargo, git.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
circuit=${1:-policy_tx_2_2}
out_file=${2:-"$repo_root/deployments/testnet/circuit_keys/$circuit.graph.bin"}
work_dir="$repo_root/target/witness-graph-builder"
graph_src_dir="$work_dir/circuits-src"
patched_witness_rs_dir="$work_dir/vendor/circom-witness-rs"
circomlib_dir="$graph_src_dir/circomlib"
comparators_file="$circomlib_dir/circuits/comparators.circom"
bitify_file="$circomlib_dir/circuits/bitify.circom"
expected_circom_version="2.2.3"

if [ ! -f "$repo_root/circuits/src/$circuit.circom" ]; then
    echo "no entry circuit at circuits/src/$circuit.circom" >&2
    exit 1
fi

mkdir -p "$work_dir/src" "$(dirname -- "$out_file")"
rm -rf "$graph_src_dir"
mkdir -p "$graph_src_dir"

# Minimal builder crate: a binary whose only job is to invoke build_witness().
cat > "$work_dir/Cargo.toml" <<'EOF'
[package]
name = "witness-graph-builder"
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

# circom-witness-rs hardcodes --O2 in its build.rs. We need --O1 to match the
# repo's R1CS simplification, so vendor the crate source and patch it.
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
    chmod -R u+w "$patched_witness_rs_dir"

    build_rs="$patched_witness_rs_dir/build.rs"
    if ! grep -q '\.arg("--O2");' "$build_rs"; then
        echo "expected circom-witness-rs build.rs to pass --O2" >&2
        exit 1
    fi
    sed 's/\.arg("--O2");/.arg("--O1");/' "$build_rs" > "$build_rs.tmp"
    mv "$build_rs.tmp" "$build_rs"

    cat > "$work_dir/Cargo.toml" <<'EOF'
[package]
name = "witness-graph-builder"
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

prepare_patched_witness_builder
(
    cd "$work_dir"
    cargo generate-lockfile
)

locked_rev=$(tr -d '\r\n' < "$repo_root/circuits/circomlib.lock")

# Copy the circuit sources (everything except the circomlib checkout).
(
    cd "$repo_root/circuits/src"
    find . -path "./circomlib" -prune -o -type f -print
) | while IFS= read -r rel_path; do
    mkdir -p "$graph_src_dir/$(dirname -- "$rel_path")"
    cp "$repo_root/circuits/src/$rel_path" "$graph_src_dir/$rel_path"
done

# Vendor circomlib at the pinned revision for deterministic generation.
mkdir -p "$circomlib_dir"
git -C "$circomlib_dir" init
git -C "$circomlib_dir" remote add origin https://github.com/iden3/circomlib.git
git -C "$circomlib_dir" fetch --depth 1 origin "$locked_rev"
git -C "$circomlib_dir" checkout --detach FETCH_HEAD

# Inject the bbf_inv black-box hint and route the non-quadratic inverse through
# it (circomlib comparators IsZero).
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

# Inject the bbf_bit black-box hint and route the bit-decomposition <-- through
# it (circomlib bitify Num2Bits / Num2Bits_strict).
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

# Build the C++ generator and emit the graph.
(
    cd "$work_dir"
    rm -f graph.bin
    cargo clean -p circom-witness-rs -p witness-graph-builder >/dev/null 2>&1 || true
    WITNESS_CPP="$graph_src_dir/$circuit.circom" \
        CIRCOM_LIBRARY_PATH="$graph_src_dir" \
        cargo run --release
)

mv "$work_dir/graph.bin" "$out_file"
printf '%s\n' "$out_file"
