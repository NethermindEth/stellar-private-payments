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
    let note_pubkey = crypto::derive_public_key(&note_privkey);
    let pubkey_hex = crypto::scalar_to_hex_be(&note_pubkey);
    let privkey_le_hex = hex::encode(crypto::scalar_to_le_bytes(&note_privkey));

    let (_enc_pub, enc_priv) = keys::derive_encryption_keypair(identity, network)?;

    let encrypted_outputs = db.get_encrypted_outputs()?;
    let mut found: u64 = 0;

    for (commitment_hex, idx, encrypted_data, ledger) in &encrypted_outputs {
        // Skip if we already know this note
        if db.get_note(commitment_hex)?.is_some() {
            continue;
        }

        // Try to decrypt
        match crypto::decrypt_note(&enc_priv, encrypted_data)? {
            Some((amount, blinding)) => {
                // Verify commitment matches
                let expected_commitment =
                    crypto::commitment(zkhash::fields::bn256::FpBN256::from(amount), note_pubkey, blinding);
                let expected_hex = crypto::scalar_to_hex_be(&expected_commitment);

                if *commitment_hex != expected_hex {
                    // Commitment doesn't match — might be for a different pubkey
                    continue;
                }

                let blinding_hex = hex::encode(crypto::scalar_to_le_bytes(&blinding));

                // Check if already spent by checking nullifier
                let path_indices = zkhash::fields::bn256::FpBN256::from(*idx);
                let sig = crypto::sign(note_privkey, expected_commitment, path_indices);
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
            None => {
                // Not for us, skip
            }
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

