# Testnet circuit keys

This directory contains the Groth16 key material that was used to deploy the
testnet contracts for the `policy_tx_2_2` circuit, plus the generated witness
graph used by the native prover path.

Notes:
- `testdata/` remains a local/generated workspace directory (and is
  ignored by git). Tests may still read keys from there.
- `policy_tx_2_2.graph.bin` and `policy_tx_2_2.graph.manifest` are generated
  with `tools/witness-graph/generate-policy-graph.sh` and are required for
  native witness generation. Browser builds continue to use the Circom WASM
  artifact.
- Changing these keys requires redeploying the on-chain verifier and any
  dependent contracts.

## Trusted ceremonies (chronological order)

- https://github.com/NethermindEth/stellar-private-payments/issues/177
