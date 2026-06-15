# Testnet circuit keys

This directory contains the Groth16 key material that was used to deploy the
testnet contracts for the `policy_tx_2_2` circuit, plus the generated witness
graph used by the browser and native prover paths.

Notes:
- `testdata/` remains a local/generated workspace directory (and is
  ignored by git). Tests may still read keys from there.
- `policy_tx_2_2.graph.bin` and `policy_tx_2_2.graph.manifest` are generated
  with `tools/witness-graph/generate-policy-graph.sh` and are required for
  browser and native witness generation.
- The policy browser prover fetches the generated graph and R1CS artifacts at
  runtime. Circom WASM artifacts may still be produced by circuit tooling and
  reference tests, but they are no longer staged or used by the policy browser
  witness runtime path.
- Changing these keys requires redeploying the on-chain verifier and any
  dependent contracts.

## Trusted ceremonies (chronological order)

- https://github.com/NethermindEth/stellar-private-payments/issues/177
