# Selective Disclosure

Selective disclosure lets a privacy-pool note owner prove ownership of one or more unspent notes to a third-party authority without revealing the notes' secret spending keys or linking the proof to any other transaction.

The result is a portable JSON **DisclosureReceipt** that can be inspected and verified offline by anyone with the receipt file and the canonical verifying-key hash for the circuit named in the receipt.

> **Scope**: This page documents the disclosure receipt format, the **Disclosure** view in the main app, the `spp disclosure` CLI commands, and the four-check verification semantics. Circuit and cryptography details are in the [API Reference](./api.md) and crate-level rustdocs.

---

## Disclosure Receipt Format

A receipt is a JSON object with the following schema:

```json
{
  "version": 1,
  "circuit": {
    "name": "selectiveDisclosure_2",
    "levels": 20,
    "nNotes": 2,
    "vkHash": "0x937c4ee647d7747f90ec6eff0dcc67f4b00772e8239a87a973267ff15f2dd327"
  },
  "context": {
    "network": "testnet",
    "poolAddress": "C…",
    "authorityLabel": "KYC Provider",
    "authorityIdentityPayloadHex": "0x…",
    "purpose": "identity-verification",
    "contextNonce": "0x…"
  },
  "publicInputs": {
    "roots": ["0x…"],
    "noteCommitments": ["0x…"],
    "extContextHash": "0x…",
    "nullifiers": ["0x…"],
    "amounts": ["10000000"]
  },
  "proofCompressedHex": "0x…",
  "issuedAt": "2026-06-10T12:00:00Z"
}
```

### Field meanings

| Field | Meaning |
|---|---|
| `circuit` | Metadata binding the proof to a specific registered circuit and verifying key. |
| `context` | Human-readable authority, purpose, and nonce bound into `extContextHash`. |
| `publicInputs` | Values the proof commits to: the Merkle roots, the note commitments, the hashed context, note nullifiers, and disclosed amounts. |
| `proofCompressedHex` | A 128-byte compressed Groth16 proof (BN254) encoded as `0x`-prefixed hex. |
| `issuedAt` | ISO-8601 timestamp when the receipt was created. |

The `extContextHash` is a SHA-256 hash of all context fields (network, pool address, authority label, identity payload, purpose, nonce) reduced modulo the BN254 prime. Any change to any context field invalidates the context check while leaving the cryptographic proof intact.

---

## Generating a Receipt

Note owners generate receipts through the **Disclosure** view in the main app, reached via the **Disclosure** tab (`/#disclosure`).

### Prerequisites
- Freighter wallet extension installed and switched to testnet.
- The account has completed onboarding in the main app (privacy keys derived and stored in the shared OPFS database).
- The account has at least one **unspent** note in the pool.

### Steps
1. Click the **Disclosure** tab (or navigate to `/#disclosure`) and connect your wallet.
2. The page loads your unspent notes automatically from local storage.
3. Select 1–4 notes you want to disclose.
4. Fill in the context form:
   - **Authority label** — human-readable name of the requesting party.
   - **Authority identity payload** — an arbitrary `0x`-prefixed hex payload the authority can use to identify the request.
   - **Purpose** — describes why the disclosure is being made.
   - **Context nonce** — an anti-replay nonce. The "Random" button generates a fresh field-element nonce via `crypto.getRandomValues()`.
5. Click **Generate Disclosure Receipt**.
6. Wait for the progress indicator to advance through sync, witness construction, and proving.
7. Download the receipt JSON.

### Generating from the CLI

The CLI uses the same local wallet database and native Rust SDK as the other
`spp` commands. Pass one `--commitment` for each note to disclose, up to four.

```bash
spp disclosure generate CPOOL… \
  --account alice \
  --commitment 0x<note-commitment> \
  --authority-label "KYC Provider" \
  --authority-identity 0x<identity-payload> \
  --purpose identity-verification \
  --output receipt.json
```

Omit `--output` to write the receipt JSON to standard
output. Repeat `--commitment` to disclose two, three, or four notes in one
receipt.

### Preselection via URL
A per-row **Disclose** button in the main app's notes table (Advanced tab → Actions column) links to:

```
/#disclosure?commitment=0x<note-commitment>
```

This pre-selects the matching notes if they are owned and unspent. Multiple `commitment` parameters may be provided to select up to four notes.

---

## Verifying a Receipt

Anyone with the receipt JSON can verify it in the **Disclosure** view's Verify section, **no wallet required**.

### Prerequisites
- The canonical `expected_vk_hash` for the circuit named in the receipt.

### Steps
1. Scroll to the **Verify Disclosure Receipt** section (or open `/#disclosure?verify=1`).
2. Upload the receipt JSON via the file picker, or paste it into the textarea and click **Load Receipt**.
3. Review the receipt context summary to confirm *what* is being attested.
4. Confirm the **Expected VK hash** field. It defaults to the canonical hash published in this documentation and in `deployments/testnet/circuit_keys/README.md`. Authorities who pin a different key can click **Override** and paste their own hash.
5. Click **Verify Receipt**.

### Verifying from the CLI

Verification does not require `--account` or a wallet signer. The CLI pins the
canonical verifying-key hash for the circuit named by the receipt, loads the
matching bundled circuit artifacts, and queries the configured Stellar network
for root and nullifier status.

```bash
spp disclosure verify receipt.json
```

Use `--expected-vk-hash 0x…` together with alternate artifacts supplied through
`--circuits-dir` when verifying against a deliberately different disclosure
key. Use `--require-unspent` when spent notes must make the command fail.

### Canonical `vk_hash` values

| Circuit | Canonical `vk_hash` |
|---|---|
| `selectiveDisclosure_1` | `0x6fc11e281a749639762df720450be1182051c93d83e6cff36248896508d85ee2` |
| `selectiveDisclosure_2` | `0xc057dc17d370429a81a9e0fb1a81d7e7d7dd1af8ca373639db9a651c1a8d3464` |
| `selectiveDisclosure_3` | `0x20a0ec3d1b71c3f9978234116dd1f25c8a6711e5fcfdf37da181d6c0edf79a69` |
| `selectiveDisclosure_4` | `0x53dd821a22db9919d05f6175505291d2c44c94477ec0b92cb06da399f6f56d6f` |
| `deployments/testnet/circuit_keys/README.md` | Canonical hashes + artifact provenance |
| `app/js/disclosure.js` | `CANONICAL_SELECTIVE_DISCLOSURE_VK_HASHES` lookup table |
| `sdk/native/src/zk/disclosure/mod.rs` | `RegisteredCircuit::canonical_vk_hash` used by the CLI |

The verifier **must not** trust the `vkHash` value embedded inside the receipt itself. The canonical hash must come from an out-of-band source such as the table above.

---

## Runbook

### For note owners: generating a receipt

1. Open the main app and connect your Freighter wallet on Testnet.
2. Scroll to **Your Notes** and find an unspent note you want to disclose.
3. Click **Disclose** in the note's Actions column. This opens `/#disclosure?commitment=0x<note-commitment>` with the note preselected. To preselect multiple notes, repeat the `commitment` query parameter.
4. Enter the context requested by the authority:
   - **Authority label** — e.g. the company or regulator name.
   - **Authority identity payload** — an `0x`-prefixed hex string the authority associates with you.
   - **Purpose** — e.g. `kyc-review`, `aml-check`.
   - **Context nonce** — use the **Random** button for a fresh anti-replay nonce.
5. Click **Generate Disclosure Receipt** and wait for the proof to finish.
6. Download or copy the receipt JSON and send it to the authority.

> Keep a copy of the receipt. The authority needs the exact JSON file to verify it.

### For authorities: verifying a receipt walletlessly

1. Open `/#disclosure?verify=1` (or click the **Disclosure** tab in the main app header, then scroll to Verify).
2. No wallet is required. The page connects to a public Testnet RPC automatically when you click Verify.
3. Upload the receipt JSON or paste it into the import area and click **Load Receipt**.
4. Confirm the **Expected VK hash** field matches the canonical hash for the receipt's `circuit.name`. If you pin a different disclosure key, click **Override** and enter your hash.
5. Review the receipt context summary to ensure it describes the attestation you requested.
6. Click **Verify Receipt**.
7. Read the four independent checks:
   - **Proof valid** — the cryptography is correct.
   - **Context valid** — the authority/purpose/nonce context was not altered.
   - **Root fresh** — the note's root is still in the pool's on-chain history.
   - **Nullifiers unspent** — none of the disclosed notes have been spent since the receipt was issued.
8. Trust the receipt **only when all four checks are green** and the **Fully verified** badge appears.

### Interpreting partial failures

| Result | Meaning | Action |
|---|---|---|
| Proof green, Context red | The proof is mathematically valid, but the context was tampered with after generation. | Reject the receipt and ask the owner to regenerate it with the correct context. |
| Proof green, Context green, Root red | The proof and context are intact, but the receipt is stale (root rolled out of history) or points to the wrong pool. | Ask the owner to generate a fresh receipt against the current pool root. |
| Proof red | The proof is forged, corrupted, or verified against the wrong key. | Reject the receipt and confirm the expected VK hash. |
| Proof, Context, Root green; Unspent amber | The receipt is cryptographically sound, but at least one disclosed note has since been spent. | A policy decision, not a validity failure. Accept if you only needed proof of past ownership; request a fresh receipt if current holdings matter. |
| Any check "could not be completed" | Network or RPC failure prevented that check. | Retry; do not treat inconclusive checks as passes. |

---

## The Four Verification Checks

A receipt is trustworthy **only when all four checks pass**. Each check can fail independently, and each failure has a distinct meaning.

| Check | What it means | Pass wording | Failure meaning |
|---|---|---|---|
| **Proof valid** | The Groth16 proof verifies cryptographically against the registered circuit's verifying key and the receipt's public inputs. | "The cryptographic proof verifies against the registered circuit's verifying key." | The proof is forged, tampered with, or the verifier is using a mismatched verifying key. |
| **Context valid** | The declared context (authority, purpose, nonce, network, pool address) re-derives to the `extContextHash` committed in the public inputs. | "The declared authority/purpose/nonce context re-derives to the hash the proof committed to." | The context was altered or re-bound after the proof was created. The authority/purpose may have been swapped without invalidating the cryptographic proof. |
| **Root fresh** | Every Merkle root in the receipt is still present in the pool contract's on-chain root history (`is_known_root`). | "Every root in the receipt is still in the pool's on-chain root history." | The receipt is stale (a root rolled out of history) or refers to a different pool entirely. |
| **Nullifiers unspent** | No nullifier in the receipt appears in the pool's spent-nullifier history (`is_nullifier_spent`). Reported alongside `spentNullifierIndices`, naming which notes were spent. | "None of the disclosed nullifiers appear in the pool's spent-nullifier event history." | At least one disclosed note has been spent since issuance. Rendered amber rather than red - the proof remains valid. |

### Interpretation

- **All four green** → The receipt is fully verified and trustworthy. A green badge is shown.
- **Proof green, Context red** → The proof is mathematically valid but the context was tampered with. Do not trust the authority/purpose claims.
- **Proof green, Context green, Root red** → The proof and context are intact but the pool state has moved on and the root is no longer in history. The receipt is outdated.
- **Proof, Context, Root green; Unspent amber** → The receipt is cryptographically valid and the notes were owned when it was issued, but at least one has since been spent.
- **Any single check inconclusive due to network error** → The check renders as "could not be completed", never as a pass. Retry or verify under better network conditions.

---

## Receipt Security Properties

- **No secret exposure** — The receipt contains only public commitments, roots, and context. The note's spending key, blinding factor, and Merkle path remain secret.
- **Binding** — The proof is bound to the specific context hash. Changing any context field invalidates the context check.
- **Non-transferable** — A receipt proves ownership of specific note commitments at specific roots. It cannot be replayed against different notes or a different pool.
- **Correlation** — A multi-note receipt attests that all selected notes are controlled by the same prover for the same context. Verifiers should consider this correlation when interpreting the receipt.
- **Off-chain only** — Disclosure verification is entirely off-chain. No contract call is required beyond the root-history check, which reads public pool state.

---

## Key Material Provenance

The disclosure proving key (`selectiveDisclosure_1_proving_key.bin`) and its corresponding verifying key are **locally generated, not ceremony-derived**. This is acceptable for testnet evaluation but would require a trusted ceremony before any mainnet deployment. See `deployments/testnet/circuit_keys/README.md` for the full provenance note and artifact inventory.

---

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| "Account not registered with the ASP" | The account has privacy keys but has never deposited or registered its public key with the pool. | Use the main app to make a deposit or register your public key. |
| "Waiting to sync N ledger(s)…" | The local indexer has not yet caught up to the current chain head. | Wait for the sync to complete; the page will retry automatically. |
| "Note not found, already spent, or not owned" | The `?commitment=` URL param does not match an owned unspent note. | Check the commitment hex and ensure the note has not been spent. |
| "VK hash mismatch" during verify | The `expected_vk_hash` does not match the key embedded in the prover. | Confirm you are using the canonical hash published above, or override with the hash the receipt was generated against. |
| Root check fails | The pool has advanced and the receipt's root is no longer in history. | Generate a fresh receipt against the current pool root. |
