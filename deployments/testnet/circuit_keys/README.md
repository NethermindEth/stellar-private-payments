# Testnet circuit keys

This directory contains the Groth16 key material used by the testnet deployment.

- `policy_tx_2_2_permissioned_*` — permissioned pools (`PolicyMode::Permissioned`, allowlist + blocklist).
- `policy_tx_2_2_open_*` — open pools (`PolicyMode::Open`, blocklist only).
- `selectiveDisclosure_{1,2,3,4}_*` — keys for the off-chain selective-disclosure receipt circuits (one per supported note count).

Notes:
- `testdata/` remains a local/generated workspace directory (and is
  ignored by git). Tests may still read keys from there.
- Changing the `policy_tx_2_2_permissioned` keys requires redeploying the on-chain verifier
  and any dependent contracts.
- Changing the `policy_tx_2_2_open` keys requires redeploying the on-chain verifier
  and any dependent contracts.
- Changing any `selectiveDisclosure_N` keys requires a web app rebuild and an
  updated pinned `vk_hash`; it does not require a contract redeploy.

## Policy transaction open (`policy_tx_2_2_open`)

Files:
- `policy_tx_2_2_open_proving_key.bin` — compressed arkworks Groth16 proving key.
- `policy_tx_2_2_open_vk.json` — snarkjs-compatible verifying key.
- `policy_tx_2_2_open_vk_soroban.bin` — VK serialized for the on-chain verifier.

**Provenance caveat:** Unlike `policy_tx_2_2_permissioned`, the `policy_tx_2_2_open` key pair was **locally generated** (not produced by a trusted ceremony). Regenerate with `REGEN_KEYS=1 cargo build -p circuits --release`. Suitable for testnet only.

## Selective disclosure circuits (`selectiveDisclosure_1` through `selectiveDisclosure_4`)

Files (one set per supported note count):
- `selectiveDisclosure_1_proving_key.bin` — compressed arkworks Groth16 proving key for one-note receipts.
- `selectiveDisclosure_1_vk.json` — snarkjs-compatible verifying key exported from the proving key above.
- `selectiveDisclosure_2_proving_key.bin` — proving key for two-note receipts.
- `selectiveDisclosure_3_proving_key.bin` — proving key for three-note receipts.
- `selectiveDisclosure_4_proving_key.bin` — proving key for four-note receipts.

**Provenance caveat:** Unlike `policy_tx_2_2_permissioned`, the `selectiveDisclosure_*` key pairs were **locally generated** (not produced by a trusted ceremony). They are suitable for testnet/off-chain disclosure receipts only.

**Canonical `vk_hash` values (one per supported note count):**

| Circuit | `vk_hash` |
|---|---|
| `selectiveDisclosure_1` | `0xdd3c59093d4d75ff72dc63cdc8385d35db8f90f0b66c98c533084bd60c3e456e` |
| `selectiveDisclosure_2` | `0x5b53adca376d68cd3dc83a02ab9113b3f52cffffe329fdb788d6fe983153584d` |
| `selectiveDisclosure_3` | `0x46c216ed017af23d5cdd17ce825ebf3180aa3e26481cd2314720f6bac5a49c62` |
| `selectiveDisclosure_4` | `0xf1346d412fcf9943ccf6774b8648d248918055c68a4d7d9c2a4e417bac5b7cc9` |

Each hash is `disclosure::vk_hash_hex` over the **compressed arkworks verifying-key bytes** (`VerifyingKey::serialize_compressed`) for that circuit, not the SHA-256 of the JSON file. The same values are pinned in `app/js/disclosure.js` and `docs/src/disclosure.md`.

**Operational note:** Disclosure proof verification is entirely off-chain. Rotating any `selectiveDisclosure_N` key requires rebuilding the web app and updating the pinned `vk_hash` in the UI/docs; it does **not** require a pool contract redeploy.

## Trusted ceremonies (chronological order)

- `policy_tx_2_2_permissioned`: https://github.com/NethermindEth/stellar-private-payments/issues/177
