//! Note discovery via encrypted output scanning and nullifier checking.
//! Port of `app/js/state/note-scanner.js`.
//!
//! Scans pool encrypted outputs to find notes addressed to the user,
//! verifies commitments via Poseidon2, and checks spent status via nullifiers.

use crypto_secretbox::{KeyInit, Nonce, XSalsa20Poly1305, aead::Aead};
use notes_store::{NewNote, NotesStore};
use pool_store::PoolStore;
use utils::{
    field_to_hex, hex_to_bytes, hex_to_bytes_for_tree,
    merkle::{FIELD_SIZE, le_bytes_to_scalar, scalar_to_array},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zkhash::{
    fields::bn256::FpBN256 as Scalar,
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS_4},
};

/// Minimum encrypted output size: ephemeral pubkey (32) + nonce (24) +
/// ciphertext (40) + tag (16).
const MIN_ENCRYPTED_SIZE: usize = 112;

/// Decrypted note data.
pub struct DecryptedNote {
    /// Note amount (from first 8 LE bytes of plaintext).
    pub amount: u64,
    /// Blinding factor (32 bytes, LE field element).
    pub blinding: [u8; FIELD_SIZE],
}

/// Result of scanning encrypted outputs.
pub struct ScanResult {
    /// Total outputs scanned.
    pub scanned: u32,
    /// New notes found for this user.
    pub found: u32,
    /// Outputs already known (existing notes).
    pub already_known: u32,
}

/// Result of checking spent notes.
pub struct SpentCheckResult {
    /// Total unspent notes checked.
    pub checked: u32,
    /// Notes newly marked as spent.
    pub marked_spent: u32,
}

// ---------------------------------------------------------------------------
// Poseidon2 crypto (matches prover/src/crypto.rs domain separators)
// ---------------------------------------------------------------------------

/// Poseidon2 hash with 3 inputs + domain separator (width-4 permutation).
fn poseidon2_hash3(a: Scalar, b: Scalar, c: Scalar, domain: Scalar) -> Scalar {
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_4);
    let input = vec![a, b, c, domain];
    let perm = poseidon2.permutation(&input);
    perm[0]
}

/// Computes a note commitment: `Poseidon2(amount, publicKey, blinding,
/// domain=1)`.
pub fn compute_commitment(
    amount: &[u8],
    public_key: &[u8],
    blinding: &[u8],
) -> anyhow::Result<[u8; FIELD_SIZE]> {
    let amt = le_bytes_to_scalar(amount)?;
    let pk = le_bytes_to_scalar(public_key)?;
    let blind = le_bytes_to_scalar(blinding)?;
    let commitment = poseidon2_hash3(amt, pk, blind, Scalar::from(1u64));
    Ok(scalar_to_array(&commitment))
}

/// Computes a signature: `Poseidon2(privateKey, commitment, pathIndices,
/// domain=4)`.
pub fn compute_signature(
    private_key: &[u8],
    commitment: &[u8],
    path_indices: &[u8],
) -> anyhow::Result<[u8; FIELD_SIZE]> {
    let sk = le_bytes_to_scalar(private_key)?;
    let comm = le_bytes_to_scalar(commitment)?;
    let path = le_bytes_to_scalar(path_indices)?;
    let sig = poseidon2_hash3(sk, comm, path, Scalar::from(4u64));
    Ok(scalar_to_array(&sig))
}

/// Computes a nullifier: `Poseidon2(commitment, pathIndices, signature,
/// domain=2)`.
pub fn compute_nullifier(
    commitment: &[u8],
    path_indices: &[u8],
    signature: &[u8],
) -> anyhow::Result<[u8; FIELD_SIZE]> {
    let comm = le_bytes_to_scalar(commitment)?;
    let indices = le_bytes_to_scalar(path_indices)?;
    let sig = le_bytes_to_scalar(signature)?;
    let nullifier = poseidon2_hash3(comm, indices, sig, Scalar::from(2u64));
    Ok(scalar_to_array(&nullifier))
}

// ---------------------------------------------------------------------------
// X25519 + XSalsa20-Poly1305 decryption
// ---------------------------------------------------------------------------

/// Attempts to decrypt an encrypted output using the user's X25519 private key.
/// Returns `None` if decryption fails (output not addressed to this user).
pub fn try_decrypt_note(
    encryption_private_key: &[u8; FIELD_SIZE],
    encrypted_data: &[u8],
) -> Option<DecryptedNote> {
    if encrypted_data.len() < MIN_ENCRYPTED_SIZE {
        return None;
    }

    let ephemeral_pubkey = &encrypted_data[0..32];
    let nonce_bytes = &encrypted_data[32..56];
    let ciphertext_with_tag = &encrypted_data[56..];

    let our_secret = StaticSecret::from(*encryption_private_key);
    let ephemeral_public = PublicKey::from(<[u8; 32]>::try_from(ephemeral_pubkey).ok()?);
    let shared_secret = our_secret.diffie_hellman(&ephemeral_public);

    let cipher = XSalsa20Poly1305::new(shared_secret.as_bytes().into());
    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(nonce_bytes);
    let nonce = Nonce::from(nonce_array);

    let plaintext = cipher.decrypt(&nonce, ciphertext_with_tag).ok()?;
    if plaintext.len() != 40 {
        return None;
    }

    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&plaintext[0..8]);
    let amount = u64::from_le_bytes(amount_bytes);

    let mut blinding = [0u8; FIELD_SIZE];
    blinding.copy_from_slice(&plaintext[8..40]);

    Some(DecryptedNote { amount, blinding })
}

// ---------------------------------------------------------------------------
// Scanning orchestration
// ---------------------------------------------------------------------------

/// Derives the nullifier for a note given its private key, commitment, and
/// leaf index.
pub fn derive_nullifier_for_note(
    private_key_le: &[u8],
    commitment_le: &[u8],
    leaf_index: u32,
) -> anyhow::Result<[u8; FIELD_SIZE]> {
    let path_indices_le = scalar_to_array(&Scalar::from(u64::from(leaf_index)));
    let signature = compute_signature(private_key_le, commitment_le, &path_indices_le)?;
    compute_nullifier(commitment_le, &path_indices_le, &signature)
}

/// User keypairs needed for scanning (pre-derived from Freighter signatures).
pub struct ScanKeys<'a> {
    /// X25519 encryption private key (32 bytes).
    pub encryption_private_key: &'a [u8; FIELD_SIZE],
    /// BN254 note private key (LE bytes).
    pub note_private_key_le: &'a [u8],
    /// BN254 note public key (LE bytes).
    pub note_public_key_le: &'a [u8],
}

/// Decodes, decrypts, and verifies a single encrypted output.
/// Returns `None` if the output is malformed, not for this user, a dummy
/// zero-value note, or fails commitment verification.
fn try_decrypt_and_verify(
    encrypted_output_hex: &str,
    commitment_hex: &str,
    keys: &ScanKeys<'_>,
) -> Option<DecryptedNote> {
    let enc_bytes = hex_to_bytes(encrypted_output_hex).ok()?;
    let decrypted = try_decrypt_note(keys.encryption_private_key, &enc_bytes)?;
    if decrypted.amount == 0 {
        return None;
    }
    let amount_le = scalar_to_array(&Scalar::from(decrypted.amount));
    let computed =
        compute_commitment(&amount_le, keys.note_public_key_le, &decrypted.blinding).ok()?;
    let expected = utils::normalize_hex(commitment_hex).to_lowercase();
    if field_to_hex(&computed) != expected {
        return None;
    }
    Some(decrypted)
}

/// Scans pool encrypted outputs to discover notes addressed to this user.
pub fn scan_for_notes(
    pool: &PoolStore,
    notes: &NotesStore,
    keys: &ScanKeys<'_>,
    owner: &str,
    created_at: &str,
    from_ledger: Option<u32>,
) -> anyhow::Result<ScanResult> {
    let outputs = pool.get_encrypted_outputs(from_ledger)?;
    let mut result = ScanResult {
        scanned: 0,
        found: 0,
        already_known: 0,
    };

    for output in &outputs {
        result.scanned = result.scanned.saturating_add(1);

        if notes.get_by_commitment(&output.commitment)?.is_some() {
            result.already_known = result.already_known.saturating_add(1);
            continue;
        }

        let Some(decrypted) =
            try_decrypt_and_verify(&output.encrypted_output, &output.commitment, keys)
        else {
            continue;
        };

        // Re-check before saving (guards against concurrent scanners).
        if notes.get_by_commitment(&output.commitment)?.is_some() {
            result.already_known = result.already_known.saturating_add(1);
            continue;
        }

        notes.save_note(&NewNote {
            commitment: &output.commitment,
            owner,
            private_key: &field_to_hex(keys.note_private_key_le),
            blinding: &field_to_hex(&decrypted.blinding),
            amount: &decrypted.amount.to_string(),
            leaf_index: Some(output.leaf_index),
            ledger: output.ledger,
            created_at,
            is_received: true,
        })?;

        result.found = result.found.saturating_add(1);
    }

    Ok(result)
}

/// Checks unspent notes against pool nullifiers, marking spent ones.
pub fn check_spent_notes(
    pool: &PoolStore,
    notes: &NotesStore,
    owner: &str,
) -> anyhow::Result<SpentCheckResult> {
    let unspent = notes.get_unspent(owner)?;
    let mut result = SpentCheckResult {
        checked: 0,
        marked_spent: 0,
    };

    for note in &unspent {
        result.checked = result.checked.saturating_add(1);

        let Some(leaf_index) = note.leaf_index else {
            continue;
        };

        // Convert hex keys to LE bytes for hashing
        let Ok(private_key_le) = hex_to_bytes_for_tree(&note.private_key) else {
            continue;
        };
        let Ok(commitment_le) = hex_to_bytes_for_tree(&note.id) else {
            continue;
        };

        if private_key_le.len() != FIELD_SIZE || commitment_le.len() != FIELD_SIZE {
            continue;
        }

        let nullifier_le = derive_nullifier_for_note(&private_key_le, &commitment_le, leaf_index)?;
        let nullifier_hex = field_to_hex(&nullifier_le);

        if let Some(nullifier_record) = pool.get_nullifier(&nullifier_hex)? {
            notes.mark_spent(&note.id, nullifier_record.ledger)?;
            result.marked_spent = result.marked_spent.saturating_add(1);
        }
    }

    Ok(result)
}
