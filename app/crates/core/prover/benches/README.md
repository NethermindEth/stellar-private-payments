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

Browser, following the Criterion WASI guide:

```sh
rustup target add wasm32-wasip1
cargo bench -p prover --bench merkle_prefix_tree --target wasm32-wasip1 --no-run
```

Then open `https://webassembly.sh/` in a browser and run:

1. `wapm upload`
2. Upload the generated benchmark artifact from
   `target/wasm32-wasip1/release/deps/merkle_prefix_tree-*.wasm`
3. Run the installed command, which is the uploaded wasm filename without the
   `.wasm` suffix

Validated locally on June 11, 2026 in `webassembly.sh`:

- `merkle_prefix_tree_build/16` through `merkle_prefix_tree_build/16384` reported `Success`
- `merkle_prefix_tree_proof/16` through `merkle_prefix_tree_proof/16384` reported `Success`

In this browser shell run, the benchmark completed successfully for all cases,
but no timing numbers were printed to the terminal output.

The benchmark uses Merkle depth `32` and leaf counts:

- `16`
- `64`
- `256`
- `1_024`
- `4_096`
- `16_384`
