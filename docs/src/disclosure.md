# Selective Disclosure

Selective disclosure lets a privacy-pool note owner prove ownership of a specific unspent note to a third-party authority without revealing the note's secret spending key or linking the proof to any other transaction.

The result is a portable JSON **DisclosureReceipt** that can be inspected and verified offline by anyone with the receipt file and the canonical verifying-key hash.

> **Scope**: This page documents the disclosure receipt format, the standalone `disclosure.html` page, and the three-check verification semantics. Circuit and cryptography details are in the [API Reference](./api.md) and crate-level rustdocs.

---

## Disclosure Receipt Format

A receipt is a JSON object with the following schema:

```json
{
  "version": 1,
  "circuit": {
    "name": "selectiveDisclosure_1",
    "levels": 10,
    "nNotes": 1,
    "vkHash": "0xe8c9879c1239deeaab3cda366419e3536a6f66502f88c3eec09da1e52843e5af"
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
    "extContextHash": "0x…"
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
| `publicInputs` | Values the proof commits to: the Merkle root, the note commitment, and the hashed context. |
| `proofCompressedHex` | A 128-byte compressed Groth16 proof (BN254) encoded as `0x`-prefixed hex. |
| `issuedAt` | ISO-8601 timestamp when the receipt was created. |

The `extContextHash` is a SHA-256 hash of all context fields (network, pool address, authority label, identity payload, purpose, nonce) reduced modulo the BN254 prime. Any change to any context field invalidates the context check while leaving the cryptographic proof intact.

---

## Generating a Receipt

Note owners generate receipts through the standalone **Disclosure** page at `/disclosure.html`.

### Prerequisites
- Freighter wallet extension installed and switched to testnet.
- The account has completed onboarding in the main app (privacy keys derived and stored in the shared OPFS database).
- The account has at least one **unspent** note in the pool.

### Steps
1. Open `/disclosure.html` and connect your wallet.
2. The page loads your unspent notes automatically from local storage.
3. Select the note you want to disclose.
4. Fill in the context form:
   - **Authority label** — human-readable name of the requesting party.
   - **Authority identity payload** — an arbitrary `0x`-prefixed hex payload the authority can use to identify the request.
   - **Purpose** — describes why the disclosure is being made.
   - **Context nonce** — an anti-replay nonce. The "Random" button generates a fresh field-element nonce via `crypto.getRandomValues()`.
5. Click **Generate Disclosure Receipt**.
6. Wait for the progress indicator to advance through sync, witness construction, and proving.
7. Download the receipt JSON.

### Preselection via URL
A per-row "Disclose" button in the main app's notes table links to:

```
/disclosure.html?commitment=0x<note-commitment>
```

This pre-selects the matching note if it is owned and unspent.

---

## Verifying a Receipt

Anyone with the receipt JSON can verify it at `/disclosure.html`, **no wallet required**.

### Prerequisites
- The canonical `expected_vk_hash` for the circuit named in the receipt.

### Steps
1. Scroll to the **Verify Disclosure Receipt** section (or open `/disclosure.html?verify=1`).
2. Upload the receipt JSON via the file picker, or paste it into the textarea and click **Load Receipt**.
3. Review the receipt context summary to confirm *what* is being attested.
4. Confirm the **Expected VK hash** field. It defaults to the canonical hash published in this documentation and in `deployments/testnet/circuit_keys/README.md`. Authorities who pin a different key can click **Override** and paste their own hash.
5. Click **Verify Receipt**.

### Where the canonical `vk_hash` is published

| Location | Contents |
|---|---|
| This page | `0xe8c9879c1239deeaab3cda366419e3536a6f66502f88c3eec09da1e52843e5af` |
| `deployments/testnet/circuit_keys/README.md` | Canonical hash + artifact provenance |
| `app/js/disclosure.js` | Hard-coded constant `CANONICAL_SELECTIVE_DISCLOSURE_1_VK_HASH` |

The verifier **must not** trust the `vkHash` value embedded inside the receipt itself. The canonical hash must come from an out-of-band source such as the table above.

---

## Runbook

### For note owners: generating a receipt

1. Open the main app and connect your Freighter wallet on Testnet.
2. Scroll to **Your Notes** and find an unspent note you want to disclose.
3. Click **Disclose** in the note's Actions column. This opens `/disclosure.html?commitment=0x<note-commitment>` with the note preselected.
4. Enter the context requested by the authority:
   - **Authority label** — e.g. the company or regulator name.
   - **Authority identity payload** — an `0x`-prefixed hex string the authority associates with you.
   - **Purpose** — e.g. `kyc-review`, `aml-check`.
   - **Context nonce** — use the **Random** button for a fresh anti-replay nonce.
5. Click **Generate Disclosure Receipt** and wait for the proof to finish.
6. Download or copy the receipt JSON and send it to the authority.

> Keep a copy of the receipt. The authority needs the exact JSON file to verify it.

### For authorities: verifying a receipt walletlessly

1. Open `/disclosure.html?verify=1` (or click **Verify** in the main app header).
2. No wallet is required. The page initializes against the Testnet RPC automatically.
3. Upload the receipt JSON or paste it into the import area and click **Load Receipt**.
4. Confirm the **Expected VK hash** field matches the canonical hash published above. If you pin a different disclosure key, click **Override** and enter your hash.
5. Review the receipt context summary to ensure it describes the attestation you requested.
6. Click **Verify Receipt**.
7. Read the three independent checks:
   - **Proof valid** — the cryptography is correct.
   - **Context valid** — the authority/purpose/nonce context was not altered.
   - **Root fresh** — the note's root is still in the pool's on-chain history.
8. Trust the receipt **only when all three checks are green** and the **Fully verified** badge appears.

### Interpreting partial failures

| Result | Meaning | Action |
|---|---|---|
| Proof green, Context red | The proof is mathematically valid, but the context was tampered with after generation. | Reject the receipt and ask the owner to regenerate it with the correct context. |
| Proof green, Context green, Root red | The proof and context are intact, but the receipt is stale (root rolled out of history) or points to the wrong pool. | Ask the owner to generate a fresh receipt against the current pool root. |
| Proof red | The proof is forged, corrupted, or verified against the wrong key. | Reject the receipt and confirm the expected VK hash. |
| Any check "could not be completed" | Network or RPC failure prevented that check. | Retry; do not treat inconclusive checks as passes. |

---

## The Three Verification Checks

A receipt is trustworthy **only when all three checks pass**. Each check can fail independently, and each failure has a distinct meaning.

| Check | What it means | Pass wording | Failure meaning |
|---|---|---|---|
| **Proof valid** | The Groth16 proof verifies cryptographically against the registered circuit's verifying key and the receipt's public inputs. | "The cryptographic proof verifies against the registered circuit's verifying key." | The proof is forged, tampered with, or the verifier is using a mismatched verifying key. |
| **Context valid** | The declared context (authority, purpose, nonce, network, pool address) re-derives to the `extContextHash` committed in the public inputs. | "The declared authority/purpose/nonce context re-derives to the hash the proof committed to." | The context was altered or re-bound after the proof was created. The authority/purpose may have been swapped without invalidating the cryptographic proof. |
| **Root fresh** | Every Merkle root in the receipt is still present in the pool contract's on-chain root history (`is_known_root`). | "Every root in the receipt is still in the pool's on-chain root history." | The receipt is stale (root rolled out of history) or refers to a different pool entirely. |

### Interpretation

- **All three green** → The receipt is fully verified and trustworthy. A green badge is shown.
- **Proof green, Context red** → The proof is mathematically valid but the context was tampered with. Do not trust the authority/purpose claims.
- **Proof green, Context green, Root red** → The proof and context are intact but the note may have been spent or the pool state has moved on. The receipt is outdated.
- **Any single check inconclusive due to network error** → The check renders as "could not be completed", never as a pass. Retry or verify under better network conditions.

---

## Receipt Security Properties

- **No secret exposure** — The receipt contains only public commitments, roots, and context. The note's spending key, blinding factor, and Merkle path remain secret.
- **Binding** — The proof is bound to the specific context hash. Changing any context field invalidates the context check.
- **Non-transferable** — A receipt proves ownership of a specific note commitment at a specific root. It cannot be replayed against a different note or a different pool.
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
