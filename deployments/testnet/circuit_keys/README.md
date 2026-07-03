# Testnet circuit keys

This directory contains the Groth16 key material used by the testnet deployment.

- `policy_tx_2_2_*` — keys for the on-chain transaction circuit (used by the pool contract).
- `selectiveDisclosure_{1,2,3,4}_*` — keys for the off-chain selective-disclosure receipt circuits (one per supported note count).

Notes:
- `testdata/` remains a local/generated workspace directory (and is
  ignored by git). Tests may still read keys from there.
- Changing the `policy_tx_2_2` keys requires redeploying the on-chain verifier
  and any dependent contracts.
- Changing any `selectiveDisclosure_N` keys requires a web app rebuild and an
  updated pinned `vk_hash`; it does not require a contract redeploy.

## Selective disclosure circuits (`selectiveDisclosure_1` through `selectiveDisclosure_4`)

Files (one set per supported note count):
- `selectiveDisclosure_1_proving_key.bin` — compressed arkworks Groth16 proving key for one-note receipts.
- `selectiveDisclosure_1_vk.json` — snarkjs-compatible verifying key exported from the proving key above.
- `selectiveDisclosure_2_proving_key.bin` — proving key for two-note receipts.
- `selectiveDisclosure_3_proving_key.bin` — proving key for three-note receipts.
- `selectiveDisclosure_4_proving_key.bin` — proving key for four-note receipts.

**Provenance caveat:** Unlike `policy_tx_2_2`, the `selectiveDisclosure_*` key pairs were **locally generated** (not produced by a trusted ceremony). They are suitable for testnet/off-chain disclosure receipts only.

**Canonical `vk_hash` values (one per supported note count):**

| Circuit | `vk_hash` |
|---|---|
| `selectiveDisclosure_1` | `0xe8c9879c1239deeaab3cda366419e3536a6f66502f88c3eec09da1e52843e5af` |
| `selectiveDisclosure_2` | `0xfb94f1a99c96bd4f0bcde813acdf23af25bcf7a292a9d77f0046b94d3cd028c1` |
| `selectiveDisclosure_3` | `0x0902ecd9e05270b8f68073d8b05b44c1a9bfd2ebd349699374ab3e6f614d7f73` |
| `selectiveDisclosure_4` | `0xfc1f2648fba94e325de3022ec380401b617ef0653f12acb91d2e5f9431d5134c` |

Each hash is `disclosure::vk_hash_hex` over the **compressed arkworks verifying-key bytes** (`VerifyingKey::serialize_compressed`) for that circuit, not the SHA-256 of the JSON file. The same values are pinned in `app/js/disclosure.js` and `docs/src/disclosure.md`.

**Operational note:** Disclosure proof verification is entirely off-chain. Rotating any `selectiveDisclosure_N` key requires rebuilding the web app and updating the pinned `vk_hash` in the UI/docs; it does **not** require a pool contract redeploy.

## Trusted ceremonies (chronological order)

- `policy_tx_2_2`: https://github.com/NethermindEth/stellar-private-payments/issues/177
