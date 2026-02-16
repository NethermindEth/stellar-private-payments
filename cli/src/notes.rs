//! Note scanning, decryption, import/export.

use anyhow::{Context, Result};

use crate::crypto;
use crate::db::{Database, UserNote};
use crate::keys;

/// Scan encrypted outputs for notes belonging to the given identity.
///
/// Decrypts each encrypted output with the identity's X25519 private key.
/// If decryption succeeds, the note belongs to this identity.
///
/// Returns the number of new notes found.
pub fn scan_notes(db: &Database, identity: &str, network: &str) -> Result<u64> {
    let note_privkey = keys::derive_note_private_key(identity, network)?;
    let (_enc_pub, enc_priv) = keys::derive_encryption_keypair(identity, network)?;
    scan_notes_inner(db, &note_privkey, &enc_priv)
}

/// Core note scanning logic shared by `scan_notes` and `scan_notes_with_keys`.
///
/// Iterates over all encrypted outputs, attempts decryption, verifies the
/// commitment, checks nullifier status, and upserts discovered notes.
fn scan_notes_inner(
    db: &Database,
    note_privkey: &zkhash::fields::bn256::FpBN256,
    enc_priv: &[u8; 32],
) -> Result<u64> {
    let note_pubkey = crypto::derive_public_key(note_privkey);
    let pubkey_hex = crypto::scalar_to_hex_be(&note_pubkey);
    let privkey_le_hex = crypto::scalar_to_hex_le(note_privkey);

    let encrypted_outputs = db.get_encrypted_outputs()?;
    let mut found: u64 = 0;

    for (commitment_hex, idx, encrypted_data, ledger) in &encrypted_outputs {
        // Skip if we already know this note
        if db.get_note(commitment_hex)?.is_some() {
            continue;
        }

        // Try to decrypt
        if let Some((amount, blinding)) = crypto::decrypt_note(enc_priv, encrypted_data)? {
            // Verify commitment matches
            let expected_commitment =
                crypto::commitment(zkhash::fields::bn256::FpBN256::from(amount), note_pubkey, blinding);
            let expected_hex = crypto::scalar_to_hex_be(&expected_commitment);

            if *commitment_hex != expected_hex {
                // Commitment doesn't match — might be for a different pubkey
                continue;
            }

            let blinding_hex = crypto::scalar_to_hex_le(&blinding);

            // Check if already spent by checking nullifier
            let path_indices = zkhash::fields::bn256::FpBN256::from(*idx);
            let sig = crypto::sign(*note_privkey, expected_commitment, path_indices);
            let nul = crypto::nullifier(expected_commitment, path_indices, sig);
            let nul_hex = crypto::scalar_to_hex_be(&nul);
            let spent = if db.has_nullifier(&nul_hex)? { 1u64 } else { 0u64 };

            db.upsert_note(&UserNote {
                id: commitment_hex.clone(),
                owner: pubkey_hex.clone(),
                private_key: privkey_le_hex.clone(),
                blinding: blinding_hex,
                amount,
                leaf_index: *idx,
                spent,
                is_received: 1,
                ledger: Some(*ledger),
            })?;

            found = found.saturating_add(1);
        }
    }

    Ok(found)
}

/// Export a note to JSON and print to stdout.
pub fn export_note(note_id: &str) -> Result<()> {
    // We need a database connection but don't know the network.
    // Try testnet by default.
    let db = Database::open("testnet")?;
    let note = db
        .get_note(note_id)?
        .ok_or_else(|| anyhow::anyhow!("Note not found: {note_id}"))?;

    let json = serde_json::json!({
        "id": note.id,
        "owner": note.owner,
        "private_key": note.private_key,
        "blinding": note.blinding,
        "amount": note.amount,
        "leaf_index": note.leaf_index,
        "spent": note.spent,
        "is_received": note.is_received,
        "ledger": note.ledger,
    });

    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

/// Import a note from a JSON file.
pub fn import_note(file: &str) -> Result<()> {
    let contents = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read {file}"))?;

    #[derive(serde::Deserialize)]
    struct NoteJson {
        id: String,
        owner: String,
        private_key: String,
        blinding: String,
        amount: u64,
        leaf_index: u64,
        spent: Option<u64>,
        is_received: Option<u64>,
        ledger: Option<u64>,
    }

    let parsed: NoteJson =
        serde_json::from_str(&contents).context("Failed to parse note JSON")?;

    let db = Database::open("testnet")?;
    db.migrate()?;

    db.upsert_note(&UserNote {
        id: parsed.id,
        owner: parsed.owner,
        private_key: parsed.private_key,
        blinding: parsed.blinding,
        amount: parsed.amount,
        leaf_index: parsed.leaf_index,
        spent: parsed.spent.unwrap_or(0),
        is_received: parsed.is_received.unwrap_or(1),
        ledger: parsed.ledger,
    })?;

    println!("Note imported successfully.");
    Ok(())
}

/// Scan notes using provided key material and database (for testing).
///
/// This variant avoids calling the `stellar` CLI for key resolution.
#[cfg(test)]
pub fn scan_notes_with_keys(
    db: &Database,
    note_privkey: &zkhash::fields::bn256::FpBN256,
    enc_priv: &[u8; 32],
) -> Result<u64> {
    scan_notes_inner(db, note_privkey, enc_priv)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crypto;
    use zkhash::fields::bn256::FpBN256 as Scalar;

    fn test_db() -> Database {
        Database::open_in_memory().expect("in-memory DB")
    }

    #[test]
    fn test_scan_finds_own_notes() {
        let db = test_db();

        // Generate keypair
        let note_privkey = Scalar::from(12345u64);
        let note_pubkey = crypto::derive_public_key(&note_privkey);

        // Generate encryption keypair
        let mut enc_priv_bytes = [0u8; 32];
        getrandom::getrandom(&mut enc_priv_bytes).unwrap();
        let enc_secret = x25519_dalek::StaticSecret::from(enc_priv_bytes);
        let enc_public = x25519_dalek::PublicKey::from(&enc_secret);

        // Create a note and encrypt it
        let amount = 5000u64;
        let blinding = Scalar::from(99999u64);
        let commitment_val = crypto::commitment(Scalar::from(amount), note_pubkey, blinding);
        let commitment_hex = crypto::scalar_to_hex_be(&commitment_val);

        let encrypted = crypto::encrypt_note(enc_public.as_bytes(), amount, &blinding).unwrap();

        // Store encrypted output in DB
        db.insert_encrypted_output(&commitment_hex, 0, &encrypted, 100)
            .unwrap();

        // Scan
        let found = scan_notes_with_keys(&db, &note_privkey, &enc_secret.to_bytes()).unwrap();
        assert_eq!(found, 1, "should find 1 note");

        // Verify the note was stored
        let note = db.get_note(&commitment_hex).unwrap().expect("note exists");
        assert_eq!(note.amount, 5000);
        assert_eq!(note.spent, 0);
        assert_eq!(note.is_received, 1);
    }

    #[test]
    fn test_scan_ignores_others_notes() {
        let db = test_db();

        // Our key
        let our_privkey = Scalar::from(111u64);

        // Someone else's keys
        let other_privkey = Scalar::from(222u64);
        let other_pubkey = crypto::derive_public_key(&other_privkey);

        // Someone else's encryption key
        let mut other_enc_bytes = [0u8; 32];
        getrandom::getrandom(&mut other_enc_bytes).unwrap();
        let other_enc_secret = x25519_dalek::StaticSecret::from(other_enc_bytes);
        let other_enc_public = x25519_dalek::PublicKey::from(&other_enc_secret);

        // Our encryption key
        let mut our_enc_bytes = [0u8; 32];
        getrandom::getrandom(&mut our_enc_bytes).unwrap();

        // Create a note encrypted for someone else
        let amount = 1000u64;
        let blinding = Scalar::from(42u64);
        let commitment_val = crypto::commitment(Scalar::from(amount), other_pubkey, blinding);
        let commitment_hex = crypto::scalar_to_hex_be(&commitment_val);

        let encrypted =
            crypto::encrypt_note(other_enc_public.as_bytes(), amount, &blinding).unwrap();

        db.insert_encrypted_output(&commitment_hex, 0, &encrypted, 50)
            .unwrap();

        // Scan with our keys — should find nothing
        let found = scan_notes_with_keys(&db, &our_privkey, &our_enc_bytes).unwrap();
        assert_eq!(found, 0, "should not find notes encrypted for others");
    }

    #[test]
    fn test_scan_skips_already_known() {
        let db = test_db();

        let note_privkey = Scalar::from(333u64);
        let note_pubkey = crypto::derive_public_key(&note_privkey);

        let mut enc_priv_bytes = [0u8; 32];
        getrandom::getrandom(&mut enc_priv_bytes).unwrap();
        let enc_secret = x25519_dalek::StaticSecret::from(enc_priv_bytes);
        let enc_public = x25519_dalek::PublicKey::from(&enc_secret);

        let amount = 2000u64;
        let blinding = Scalar::from(7777u64);
        let commitment_val = crypto::commitment(Scalar::from(amount), note_pubkey, blinding);
        let commitment_hex = crypto::scalar_to_hex_be(&commitment_val);

        let encrypted = crypto::encrypt_note(enc_public.as_bytes(), amount, &blinding).unwrap();
        db.insert_encrypted_output(&commitment_hex, 0, &encrypted, 100)
            .unwrap();

        // First scan — finds the note
        let found1 = scan_notes_with_keys(&db, &note_privkey, &enc_secret.to_bytes()).unwrap();
        assert_eq!(found1, 1);

        // Second scan — should skip (already known)
        let found2 = scan_notes_with_keys(&db, &note_privkey, &enc_secret.to_bytes()).unwrap();
        assert_eq!(found2, 0, "should skip already known notes");
    }

    #[test]
    fn test_scan_detects_spent_notes() {
        let db = test_db();

        let note_privkey = Scalar::from(444u64);
        let note_pubkey = crypto::derive_public_key(&note_privkey);

        let mut enc_priv_bytes = [0u8; 32];
        getrandom::getrandom(&mut enc_priv_bytes).unwrap();
        let enc_secret = x25519_dalek::StaticSecret::from(enc_priv_bytes);
        let enc_public = x25519_dalek::PublicKey::from(&enc_secret);

        let amount = 3000u64;
        let blinding = Scalar::from(8888u64);
        let commitment_val = crypto::commitment(Scalar::from(amount), note_pubkey, blinding);
        let commitment_hex = crypto::scalar_to_hex_be(&commitment_val);

        let encrypted = crypto::encrypt_note(enc_public.as_bytes(), amount, &blinding).unwrap();
        db.insert_encrypted_output(&commitment_hex, 0, &encrypted, 100)
            .unwrap();

        // Compute and store the nullifier to simulate spending
        let path_indices = Scalar::from(0u64);
        let sig = crypto::sign(note_privkey, commitment_val, path_indices);
        let nul = crypto::nullifier(commitment_val, path_indices, sig);
        let nul_hex = crypto::scalar_to_hex_be(&nul);
        db.insert_nullifier(&nul_hex, 101).unwrap();

        // Scan — should find note and mark it as spent
        let found = scan_notes_with_keys(&db, &note_privkey, &enc_secret.to_bytes()).unwrap();
        assert_eq!(found, 1);

        let note = db.get_note(&commitment_hex).unwrap().unwrap();
        assert_eq!(note.spent, 1, "note should be marked as spent");
    }
}

