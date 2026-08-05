# Testnet circuit keys

This directory contains the Groth16 key material used by the testnet deployment.

- `policy_tx_2_2` — unrestricted pools (no ASP policy flags).
- `policy_tx_2_2_A` — allowlist-only pools (`PolicyFlags::ALLOWLIST`).
- `policy_tx_2_2_B` — blocklist-only pools (`PolicyFlags::BLOCKLIST`).
- `policy_tx_2_2_AB` — allowlist + blocklist pools (`PolicyFlags::ALLOWLIST | PolicyFlags::BLOCKLIST`).
- `selectiveDisclosure_{1,2,3,4}_*` — off-chain selective-disclosure receipt circuits.

## Witness graphs (`*.graph.bin`)

Native and browser witness generation uses committed `circom-witness-rs` operation
graphs (not Circom WASM / Wasmer). Regenerate with `make witness-graphs`.
The Circom CLI must match `circuits/circom.lock` (pinned to the same release as
the Rust circom crates used for R1CS).

Committed for all production stems: `policy_tx_2_2`, `policy_tx_2_2_{A,B,AB}`,
and `selectiveDisclosure_{1..4}`.

Policy entry points (`policy_tx_2_2*.circom`) compose a shared base transact circuit
(`policyTransaction.circom`) with optional ASP modules (`aspMembership.circom`,
`aspNonMembership.circom`).

**Do not use `policyTransaction.circom` as a main component.** The base
template exposes `inPublicKey` outputs for ASP wiring; when embedded as a
subcomponent they remain private, but promoting `PolicyTransaction` to `component main`
would make those note public keys public inputs. Always use a wrapper entry point
(`policy_tx_2_2*.circom` / `policyTransactionOpen.circom`, etc.).

## Policy transact keys (`policy_tx_2_2*`)

**All circuits stems are locally generated** (`REGEN_KEYS=1 cargo build -p circuits`).
None of the committed `policy_tx_2_2_*` key pairs in this directory were produced by a
trusted ceremony on the current R1CS.

Notes:

- `testdata/` remains a local/generated workspace directory (and is ignored by git). Tests may still read keys from there.
- Changing any `policy_tx_2_2_*` keys requires redeploying the matching on-chain verifier.
- Before mainnet, run a new trusted ceremony on `policy_tx_2_2_AB.r1cs` (see
  `tools/ceremony-cli/README.md`) and replace the AB artifacts here.

## Selective disclosure circuits (`selectiveDisclosure_1` through `selectiveDisclosure_4`)

Files (one set per supported note count):

- `selectiveDisclosure_1_proving_key.bin` — compressed arkworks Groth16 proving key for one-note receipts.
- `selectiveDisclosure_1_vk.json` — snarkjs-compatible verifying key exported from the proving key above.
- `selectiveDisclosure_2_proving_key.bin` — proving key for two-note receipts.
- `selectiveDisclosure_3_proving_key.bin` — proving key for three-note receipts.
- `selectiveDisclosure_4_proving_key.bin` — proving key for four-note receipts.

**Provenance caveat:** The `selectiveDisclosure_*` key pairs were also **locally
generated** (not produced by a trusted ceremony). They are suitable for testnet/off-chain
disclosure receipts only.

- Changing any `selectiveDisclosure_N` keys requires a web app rebuild and an updated pinned `vk_hash`; it does **not** require a pool contract redeploy.

**Canonical `vk_hash` values (one per supported note count):**

| Circuit | `vk_hash` |
|---|---|
| `selectiveDisclosure_1` | `0x561b78d5dacb2f33de35c637b80c54f590ebf4b738f7af79e49375c6e4631107` |
| `selectiveDisclosure_2` | `0x29851a709399b2b96c7ce542954bd057a3ce6c042dfeb7d856d02e4624bab9fd` |
| `selectiveDisclosure_3` | `0x3f2cf64a334b4dbd143b4be11597d84b79c7a7b97a60ddd0c99710f657b8970f` |
| `selectiveDisclosure_4` | `0xfd612d1c6cd81288e23ef14bd82040e337279debdfa208da5c11ce149d16d8c0` |

Each hash is `disclosure::vk_hash_hex` over the **compressed arkworks verifying-key bytes** (`VerifyingKey::serialize_compressed`) for that circuit, not the SHA-256 of the JSON file. The same values are pinned in `app/js/disclosure.js` and `docs/src/disclosure.md`.

**Operational note:** Disclosure proof verification is entirely off-chain. Rotating any `selectiveDisclosure_N` key requires rebuilding the web app and updating the pinned `vk_hash` in the UI/docs; it does **not** require a pool contract redeploy.

## Trusted ceremonies (historical)

- **Issue #177** ([NethermindEth/stellar-private-payments#177](https://github.com/NethermindEth/stellar-private-payments/issues/177)): trusted setup for the **pre-refactor monolithic** `policy_tx_2_2` circuit (single `PolicyTransaction` template with inline ASP proofs).

That ceremony output does **not** apply to the current composed circuits or to the keys
committed here. Treat it as historical transcript only until a new ceremony is run on
`policy_tx_2_2_AB.r1cs`.
