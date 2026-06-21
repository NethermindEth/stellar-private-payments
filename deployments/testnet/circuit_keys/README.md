# Testnet circuit keys

This directory contains the Groth16 key material used by the testnet deployment.

- `policy_tx_2_2_*` — keys for the on-chain transaction circuit (used by the pool contract).
- `selectiveDisclosure_1_*` — keys for the off-chain selective-disclosure receipt circuit.
- `policy_tx_2_2.graph.bin` and `policy_tx_2_2.graph.manifest` — generated witness graph artifacts used by the browser and native policy prover paths.

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
- Changing the `policy_tx_2_2` keys requires redeploying the on-chain verifier
  and any dependent contracts.
- Changing the `selectiveDisclosure_1` keys requires a web app rebuild and an
  updated pinned `vk_hash`; it does not require a contract redeploy.

## Selective disclosure circuit (`selectiveDisclosure_1`)

Files:
- `selectiveDisclosure_1_proving_key.bin` — compressed arkworks Groth16 proving key.
- `selectiveDisclosure_1_vk.json` — snarkjs-compatible verifying key exported from the proving key above.

**Provenance caveat:** Unlike `policy_tx_2_2`, this disclosure key pair was **locally generated** (not produced by a trusted ceremony). It is suitable for testnet/off-chain disclosure receipts only.

**Canonical `vk_hash`:** `0xe8c9879c1239deeaab3cda366419e3536a6f66502f88c3eec09da1e52843e5af`

This hash is `disclosure::vk_hash_hex` over the **compressed arkworks verifying-key bytes** (`VerifyingKey::serialize_compressed`), not the SHA-256 of the JSON file. The same value is pinned in `app/js/disclosure.js` and `docs/src/disclosure.md`; see `docs/src/disclosure.md` for the full derivation steps and file checksums.

**Operational note:** Disclosure proof verification is entirely off-chain. Rotating this key requires rebuilding the web app and updating the pinned `vk_hash` in the UI/docs; it does **not** require a pool contract redeploy.

## Trusted ceremonies (chronological order)

- `policy_tx_2_2`: https://github.com/NethermindEth/stellar-private-payments/issues/177
