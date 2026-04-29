# Merkle Prefix Tree Benchmark

This directory contains the `criterion` benchmark for the prover crate's
append-only Merkle prefix tree.

It measures:

1. Building a `MerklePrefixTreeBuilt` from ordered leaves.
2. Generating a membership proof from a pre-built tree.

## Running

Native:

```sh
cargo bench -p prover --bench merkle_prefix_tree
```

WASI, following the Criterion WASI guide:

```sh
rustup target add wasm32-wasip1
cargo bench -p prover --bench merkle_prefix_tree --target wasm32-wasip1 --no-run
wasmtime run target/wasm32-wasip1/release/deps/merkle_prefix_tree-*.wasm
```

At the moment this flow is documented but not validated in this repository's
current development environment, because `wasm32-wasip1` and `wasmtime` were
not installed when this benchmark was added.

The benchmark uses Merkle depth `32` and leaf counts:

- `16`
- `64`
- `256`
- `1_024`
- `4_096`
- `16_384`
