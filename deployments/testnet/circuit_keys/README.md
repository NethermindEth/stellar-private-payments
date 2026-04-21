# Testnet circuit keys

This directory contains the Groth16 key material that was used to deploy the
testnet contracts for the `policy_tx_2_2` circuit.

Notes:
- `testdata/` remains a local/generated workspace directory (and is
  ignored by git). Tests may still read keys from there.
- Changing these keys requires redeploying the on-chain verifier and any
  dependent contracts.
