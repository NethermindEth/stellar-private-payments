# Merkle Prefix Tree Benchmark

The benchmark page at `/merkle-benchmark.html` measures the current
storage-worker approach for membership proof preparation in the browser's
single-threaded WASM runtime:

1. Construct `MerklePrefixTree` from an ordered leaf prefix.
2. Build cached tree levels with `into_built`.
3. Generate membership proof(s) from the built tree.

Run it with:

```sh
env -u NO_COLOR trunk build --dist /tmp/merkle-bench-dist --public-url /
python3 -m http.server 8787 --directory /tmp/merkle-bench-dist
```

Then open `http://127.0.0.1:8787/merkle-benchmark.html`.

## Baseline

Measured on April 29, 2026 with a release Trunk build in headless Google
Chrome. Parameters: depth 32, 5 rounds, 1 proof per round.

| Leaves | new avg ms | build avg ms | proof avg ms | total avg ms |
|---:|---:|---:|---:|---:|
| 16 | 3.4 | 3.4 | 0.2 | 7.0 |
| 64 | 1.2 | 3.8 | 0.0 | 5.0 |
| 256 | 1.2 | 11.4 | 0.0 | 12.6 |
| 1,024 | 1.4 | 43.8 | 0.0 | 45.2 |
| 4,096 | 1.4 | 152.2 | 0.0 | 153.6 |
| 16,384 | 1.6 | 578.2 | 0.0 | 579.8 |

The build step dominates as leaf count grows; proof generation from the built
tree is below timer resolution for a single proof at these sizes.
