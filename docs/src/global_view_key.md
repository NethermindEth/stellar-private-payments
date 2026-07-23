# Global View Key

The Global View Key (GVK) lets a pool administrator audit notes on demand. The
administrator publishes a Baby JubJub public key `D`, and each note is
accompanied by an in-circuit encryption of its secrets `(pk, amount, blinding)`
under `D`. Only the holder of the administrator's private scalar `d` can decrypt
the memo.

Encryption is performed **inside the circuit** as an ECIES-style one-time pad
over Baby JubJub (whose base field is BN254's scalar field, so point operations
are cheap) with Poseidon2 as the KDF. This avoids the foreign-field arithmetic
that verifying an off-circuit X25519 ciphertext would require.

> **Scope**: This page documents the circuits and the cryptographic scheme.
> Contract deployment of `D`, emitting `R/c1/c2/c3` on-chain, and admin
> decryption tooling are follow-ups and are not part of these circuits. The Rust
> reference implementation used by the tests lives in
> `circuits/src/test/utils/global_view_key.rs`.

---

## Modes

| Mode | What is encrypted |
|---|---|
| **View-only** | output notes only |
| **Traceable** | input **and** output notes |

Encrypting input notes as well lets the administrator link a transaction's
inputs to the outputs of earlier transactions, tracing a note across hops.

GVK composes with the policy transaction, so every ASP policy configuration is
available in both modes:

| Policy config | View-only entry | Traceable entry |
|---|---|---|
| Open (no ASP proofs) | `policy_tx_gvk_2_2_viewonly` | `policy_tx_gvk_2_2_traceable` |
| Allowlist | `policy_tx_gvk_2_2_A_viewonly` | `policy_tx_gvk_2_2_A_traceable` |
| Blocklist | `policy_tx_gvk_2_2_B_viewonly` | `policy_tx_gvk_2_2_B_traceable` |
| Allowlist + Blocklist | `policy_tx_gvk_2_2_AB_viewonly` | `policy_tx_gvk_2_2_AB_traceable` |

All entry points are 2-in/2-out. An output note's ciphertext is identical in
both modes (outputs are always encrypted at `idx = nIns + k`), so switching
modes never changes what an output memo looks like.

## Circuit inventory

| Circuit | Description |
|---|---|
| `globalViewKey.circom` | `GlobalViewKeyEncryption()` (single-note primitive), `GlobalViewKey(nNotes)` (flat batch, used by the test circuits) and `GvkNotes(nIns, nOuts, encryptInputs)` (grouped batch used by the policy wrappers). |
| `policyTransaction{Open,Allowlist,Blocklist,Both}Gvk.circom` | Policy transaction + GVK wrappers: each instantiates the `PolicyTransaction` core, its ASP module(s) and `GvkNotes`, feeding the encryptors the same note signals the transaction constrains (input public keys are reused from the core, not recomputed). |
| `policy_tx_gvk_2_2*` | The 8 entry points listed above. |
| `test/circuits/globalViewKey_{2,4}_test.circom` | Standalone encryption-only circuits for the known-answer/roundtrip tests (built with `BUILD_TESTS=1`). |

`D` and `nonce` are public inputs; the note plaintexts stay private and
`R, c1, c2, c3` are public outputs.

---

## Cryptographic scheme

For a note `(pk, amount, blinding)`, public key `D`, `nonce`, and per-note index
`idx`:

1. **Validate `D`.** `BabyCheck(D)` enforces that the untrusted public input `D`
   is on the curve.
2. **Derive the ephemeral scalar `r`** by a chained Poseidon2 absorb (Poseidon2
   supports at most `t = 4`, so a single wide hash is not possible):
   - `h1 = Poseidon2(pk, amount, blinding)`
   - `h2 = Poseidon2(h1, D.x, D.y)`
   - `r  = Poseidon2(h2, nonce, idx)`

   Binding every field plus `idx` prevents keystream reuse.
3. **Ephemeral key** `R = r · BASE8`.
4. **Shared secret** `S = r · (8·D)`. The cofactor `8` is cleared on the possibly
   untrusted `D` (three doublings) so `S` lands in the prime-order subgroup.
   - **Low-order guard:** `x(8·D) ≠ 0` is enforced. `8·D` is always in the
     prime-order subgroup, so `x(8·D) = 0` iff `8·D` is the identity, i.e. `D`
     has order dividing 8. Without this guard circomlib's `EscalarMulAny` would
     silently return `S = (0, 1)` and the keystream would be publicly
     computable. `BabyCheck` does not catch this — low-order points are on-curve.
5. **Keystream (KDF):** a single width-4 Poseidon2 permutation over
   `(S.x, S.y, 0, 0x06)`. The three rate lanes are the pads `k1, k2, k3`; the
   fourth (capacity) lane is never exposed.
6. **Encrypt:** `c1 = pk + k1`, `c2 = amount + k2`, `c3 = blinding + k3`.

### Domain-separation tags

Extends the existing `0x01`–`0x04` registry (commitment, nullifier, keypair,
signature):

| Tag | Use |
|---|---|
| `0x05` | ephemeral scalar `r` derivation chain |
| `0x06` | keystream KDF |

---

## Admin decryption (cofactor `8d`)

The circuit computes `S = r · (8·D)`. With `D = d · BASE8` this equals
`8dr · BASE8`, so the administrator recovers the shared secret with the
**effective scalar `8d`**, not `d`:

```
S = 8d · R          (equivalently 8 · (d · R))
```

The reference `decrypt_note` computes `8 · (d · R)` to keep `d` in range, then
re-derives the keystream and subtracts it from `c1, c2, c3`. Any decryption
tooling built on top of these circuits must use `8d`, not `d`. This is asserted
by the round-trip tests.

---

## Security notes

- **The verifier must bind `D` to the registered authority key.** `D` is a
  public *input*: the circuit proves the memos are encrypted under whatever `D`
  the prover supplied. A prover could otherwise use their own key and produce a
  valid proof whose memos the administrator cannot decrypt, silently evading
  the audit. The contract must compare the public `D` signals against the
  registered global view key.
- **`nonce` must be unique per transaction.** A reused nonce makes identical
  notes produce identical `(R, c)` and therefore publicly linkable. This cannot
  be enforced in-circuit and must be guaranteed by the contract (e.g. by
  deriving the nonce from an already-unique value such as an input nullifier).
- **Every encryptor sharing a nonce must get a distinct `idx`.** In the combined
  circuit, inputs use `idx = 0..nIns-1` and outputs use `idx = nIns..nIns+nOuts-1`
  so keystreams never collide (in particular, never two encryptors at `idx = 0`).
- **Determinism.** Because `r` is derived deterministically from the note and
  context, confidentiality also rests on the entropy of `blinding`. This applies
  to **dummy notes too**: padding notes with predictable contents (known key,
  constant blinding) make their ciphertexts publicly recomputable, letting an
  observer identify which slots are dummies and fingerprint the transaction's
  real arity. Every note fed to an encryptor must carry fresh random blinding.

---

## Key material provenance

The proving/verifying keys for the GVK circuits are locally generated (see
`REGEN_KEYS=1 BUILD_TESTS=1 cargo build`) and land in the gitignored `testdata/`.
As with the other circuits, a trusted ceremony would be required before any
mainnet deployment.
