//! Deposit/withdraw/transfer transaction building.
//!
//! Constructs Proof and ExtData arguments and invokes via `stellar contract invoke`.

use anyhow::{Result, bail};
use ark_ff::{BigInteger, PrimeField, Zero};
use num_bigint::BigInt;
use sha3::{Digest, Keccak256};
use zkhash::fields::bn256::FpBN256 as Scalar;

use crate::config::DeploymentConfig;
use crate::crypto;
use crate::db::{Database, UserNote};
use crate::keys;
use crate::merkle;
use crate::proof::{self, InputNote, OutputNote};
use crate::stellar;

/// BN256 field modulus.
fn bn256_modulus() -> num_bigint::BigUint {
    let bytes: [u8; 32] = [
        48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93, 40, 51, 232, 72,
        121, 185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 1,
    ];
    num_bigint::BigUint::from_bytes_be(&bytes)
}

/// Register public keys on-chain.
pub fn register(
    cfg: &DeploymentConfig,
    network: &str,
    source: &str,
    address: &str,
    note_pubkey: &Scalar,
    enc_pubkey: &[u8; 32],
) -> Result<()> {
    let note_key_hex = hex::encode(note_pubkey.into_bigint().to_bytes_be());
    let enc_key_hex = hex::encode(enc_pubkey);

    // Build the Account struct as JSON for stellar contract invoke
    // The register function takes an Account { owner, encryption_key, note_key }
    let account_json = format!(
        r#"{{"owner":"{}","encryption_key":"{}","note_key":"{}"}}"#,
        address, enc_key_hex, note_key_hex
    );

    stellar::contract_invoke(
        &cfg.pool,
        source,
        network,
        "register",
        &["--account", &account_json],
    )?;

    Ok(())
}

/// Deposit tokens into the privacy pool.
pub fn deposit(
    db: &Database,
    cfg: &DeploymentConfig,
    network: &str,
    source: &str,
    amount: u64,
) -> Result<()> {
    let note_privkey = keys::derive_note_private_key(source, network)?;
    let note_pubkey = crypto::derive_public_key(&note_privkey);
    let (enc_pub, _enc_priv) = keys::derive_encryption_keypair(source, network)?;
    let address = stellar::keys_address(source, network)?;

    // Generate random blindings for the two output notes
    let blinding0 = crypto::random_blinding()?;
    let blinding1 = crypto::random_blinding()?;

    // Output 0: the deposit note (amount)
    // Output 1: zero-value change note
    let out0 = OutputNote {
        pub_key: note_pubkey,
        blinding: blinding0,
        amount: Scalar::from(amount),
    };
    let out1 = OutputNote {
        pub_key: note_pubkey,
        blinding: blinding1,
        amount: Scalar::from(0u64),
    };

    // Input notes: two zero-value dummy inputs
    let in0 = InputNote {
        leaf_index: 0,
        priv_key: note_privkey,
        blinding: Scalar::from(0u64),
        amount: Scalar::from(0u64),
    };
    let in1 = InputNote {
        leaf_index: 1,
        priv_key: note_privkey,
        blinding: Scalar::from(0u64),
        amount: Scalar::from(0u64),
    };

    // Build pool leaves
    let pool_leaves = merkle::build_pool_leaves(db)?;
    let asp_leaves = merkle::build_asp_leaves(db)?;

    // Public amount = deposit amount (positive)
    let public_amount = Scalar::from(amount);

    // Encrypt outputs
    let encrypted0 = crypto::encrypt_note(&enc_pub, amount, &blinding0)?;
    let encrypted1 = crypto::encrypt_note(&enc_pub, 0, &blinding1)?;

    // Compute ext_data_hash (Keccak256 of ext data, reduced mod BN256)
    let ext_amount_i128 = i128::from(amount);
    let ext_data_hash = compute_ext_data_hash(
        &address,
        ext_amount_i128,
        &encrypted0,
        &encrypted1,
    )?;

    // Find ASP membership index for this user (or use index 0 for deposit)
    let asp_membership_index = find_asp_membership_index(db, &note_pubkey)?;
    let asp_membership_blinding = Scalar::zero();

    // Non-membership key placeholder
    let non_membership_key = BigInt::from(0u32);

    // Generate proof
    let proof_result = proof::generate_proof(
        &[in0, in1],
        &[out0, out1],
        &pool_leaves,
        public_amount,
        Some(ext_data_hash),
        &asp_leaves,
        asp_membership_index,
        asp_membership_blinding,
        &non_membership_key,
    )?;

    // Serialize proof and invoke contract
    let proof_hex = serialize_proof_for_invoke(&proof_result)?;
    let ext_data_hex = serialize_ext_data_for_invoke(
        &address,
        ext_amount_i128,
        &encrypted0,
        &encrypted1,
    )?;

    stellar::contract_invoke(
        &cfg.pool,
        source,
        network,
        "transact",
        &[
            "--proof",
            &proof_hex,
            "--ext_data",
            &ext_data_hex,
            "--sender",
            &address,
        ],
    )?;

    // Save note to database
    let commitment = crypto::commitment(Scalar::from(amount), note_pubkey, blinding0);
    let commitment_hex = crypto::scalar_to_hex_be(&commitment);
    let pubkey_hex = crypto::scalar_to_hex_be(&note_pubkey);
    let privkey_hex = hex::encode(crypto::scalar_to_le_bytes(&note_privkey));
    let blinding_hex = hex::encode(crypto::scalar_to_le_bytes(&blinding0));

    // Get the next leaf index from the pool
    let next_idx = db.pool_leaf_count()?;

    db.upsert_note(&UserNote {
        id: commitment_hex,
        owner: pubkey_hex,
        private_key: privkey_hex,
        blinding: blinding_hex,
        amount,
        leaf_index: next_idx,
        spent: 0,
        is_received: 0,
        ledger: None,
    })?;

    Ok(())
}

/// Withdraw tokens from the privacy pool.
pub fn withdraw(
    db: &Database,
    cfg: &DeploymentConfig,
    network: &str,
    source: &str,
    to: &str,
    amount: u64,
) -> Result<()> {
    let note_privkey = keys::derive_note_private_key(source, network)?;
    let note_pubkey = crypto::derive_public_key(&note_privkey);
    let pubkey_hex = crypto::scalar_to_hex_be(&note_pubkey);
    let (enc_pub, _enc_priv) = keys::derive_encryption_keypair(source, network)?;
    let recipient_address = stellar::keys_address(to, network)?;

    // Select unspent notes
    let unspent = db.list_unspent_notes(&pubkey_hex)?;
    let (selected, total) = select_notes_for_amount(&unspent, amount)?;

    let change = total.checked_sub(amount).ok_or_else(|| {
        anyhow::anyhow!("Insufficient balance")
    })?;

    // Build input notes from selected
    let input_notes: Vec<InputNote> = selected
        .iter()
        .map(|n| {
            let blinding_bytes = hex::decode(&n.blinding)?;
            let blinding = crypto::le_bytes_to_scalar(&blinding_bytes);
            Ok(InputNote {
                leaf_index: usize::try_from(n.leaf_index)
                    .map_err(|_| anyhow::anyhow!("leaf index overflow"))?,
                priv_key: note_privkey,
                blinding,
                amount: Scalar::from(n.amount),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Pad to 2 inputs if needed
    let mut inputs: Vec<InputNote> = input_notes;
    while inputs.len() < 2 {
        inputs.push(InputNote {
            leaf_index: 0,
            priv_key: note_privkey,
            blinding: Scalar::from(0u64),
            amount: Scalar::from(0u64),
        });
    }

    // Output 0: change note (back to self)
    let blinding0 = crypto::random_blinding()?;
    let blinding1 = crypto::random_blinding()?;
    let out0 = OutputNote {
        pub_key: note_pubkey,
        blinding: blinding0,
        amount: Scalar::from(change),
    };
    let out1 = OutputNote {
        pub_key: note_pubkey,
        blinding: blinding1,
        amount: Scalar::from(0u64),
    };

    let pool_leaves = merkle::build_pool_leaves(db)?;
    let asp_leaves = merkle::build_asp_leaves(db)?;

    // Public amount = negative (withdrawal)
    // In the field: FIELD_SIZE - amount
    let modulus = bn256_modulus();
    let amount_bu = num_bigint::BigUint::from(amount);
    #[allow(clippy::arithmetic_side_effects)] // BigUint modular subtraction; modulus > amount_bu is guaranteed
    let field_amount = modulus - amount_bu;
    let public_amount = Scalar::from(field_amount);

    let ext_amount_i128 = i128::from(amount)
        .checked_neg()
        .expect("negation of u64 always fits in i128");

    let encrypted0 = crypto::encrypt_note(&enc_pub, change, &blinding0)?;
    let encrypted1 = crypto::encrypt_note(&enc_pub, 0, &blinding1)?;

    let ext_data_hash = compute_ext_data_hash(
        &recipient_address,
        ext_amount_i128,
        &encrypted0,
        &encrypted1,
    )?;

    let asp_membership_index = find_asp_membership_index(db, &note_pubkey)?;
    let non_membership_key = BigInt::from(0u32);

    let proof_result = proof::generate_proof(
        &inputs,
        &[out0, out1],
        &pool_leaves,
        public_amount,
        Some(ext_data_hash),
        &asp_leaves,
        asp_membership_index,
        Scalar::zero(),
        &non_membership_key,
    )?;

    let proof_hex = serialize_proof_for_invoke(&proof_result)?;
    let ext_data_hex = serialize_ext_data_for_invoke(
        &recipient_address,
        ext_amount_i128,
        &encrypted0,
        &encrypted1,
    )?;
    let sender_address = stellar::keys_address(source, network)?;

    stellar::contract_invoke(
        &cfg.pool,
        source,
        network,
        "transact",
        &[
            "--proof",
            &proof_hex,
            "--ext_data",
            &ext_data_hex,
            "--sender",
            &sender_address,
        ],
    )?;

    // Mark input notes as spent
    for note in &selected {
        db.mark_note_spent(&note.id)?;
    }

    // Save change note
    if change > 0 {
        let change_commitment = crypto::commitment(Scalar::from(change), note_pubkey, blinding0);
        let commitment_hex = crypto::scalar_to_hex_be(&change_commitment);
        let privkey_hex = hex::encode(crypto::scalar_to_le_bytes(&note_privkey));
        let blinding_hex = hex::encode(crypto::scalar_to_le_bytes(&blinding0));
        let next_idx = db.pool_leaf_count()?;

        db.upsert_note(&UserNote {
            id: commitment_hex,
            owner: pubkey_hex,
            private_key: privkey_hex,
            blinding: blinding_hex,
            amount: change,
            leaf_index: next_idx,
            spent: 0,
            is_received: 0,
            ledger: None,
        })?;
    }

    Ok(())
}

/// Transfer tokens privately within the pool.
pub fn transfer(
    db: &Database,
    cfg: &DeploymentConfig,
    network: &str,
    source: &str,
    to: &str,
    amount: u64,
) -> Result<()> {
    let note_privkey = keys::derive_note_private_key(source, network)?;
    let note_pubkey = crypto::derive_public_key(&note_privkey);
    let pubkey_hex = crypto::scalar_to_hex_be(&note_pubkey);
    let (enc_pub_self, _) = keys::derive_encryption_keypair(source, network)?;
    let sender_address = stellar::keys_address(source, network)?;

    // Resolve recipient keys
    let recipient_address = stellar::keys_address(to, network)?;
    let recipient_keys = db
        .get_public_key(&recipient_address)?
        .ok_or_else(|| anyhow::anyhow!("Recipient {to} not found in registered keys. They must register first."))?;
    let recipient_note_pubkey = crypto::hex_be_to_scalar(&recipient_keys.note_key)?;
    let recipient_enc_pub: [u8; 32] = hex::decode(&recipient_keys.encryption_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid recipient encryption key length"))?;

    // Select unspent notes
    let unspent = db.list_unspent_notes(&pubkey_hex)?;
    let (selected, total) = select_notes_for_amount(&unspent, amount)?;

    let change = total.checked_sub(amount).ok_or_else(|| {
        anyhow::anyhow!("Insufficient balance")
    })?;

    let input_notes: Vec<InputNote> = selected
        .iter()
        .map(|n| {
            let blinding_bytes = hex::decode(&n.blinding)?;
            let blinding = crypto::le_bytes_to_scalar(&blinding_bytes);
            Ok(InputNote {
                leaf_index: usize::try_from(n.leaf_index)
                    .map_err(|_| anyhow::anyhow!("leaf index overflow"))?,
                priv_key: note_privkey,
                blinding,
                amount: Scalar::from(n.amount),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut inputs: Vec<InputNote> = input_notes;
    while inputs.len() < 2 {
        inputs.push(InputNote {
            leaf_index: 0,
            priv_key: note_privkey,
            blinding: Scalar::from(0u64),
            amount: Scalar::from(0u64),
        });
    }

    // Output 0: to recipient
    // Output 1: change back to self
    let blinding0 = crypto::random_blinding()?;
    let blinding1 = crypto::random_blinding()?;
    let out0 = OutputNote {
        pub_key: recipient_note_pubkey,
        blinding: blinding0,
        amount: Scalar::from(amount),
    };
    let out1 = OutputNote {
        pub_key: note_pubkey,
        blinding: blinding1,
        amount: Scalar::from(change),
    };

    let pool_leaves = merkle::build_pool_leaves(db)?;
    let asp_leaves = merkle::build_asp_leaves(db)?;

    // Transfer: public_amount = 0 (no external funds flow)
    let public_amount = Scalar::from(0u64);

    // Encrypt outputs: out0 for recipient, out1 for self
    let encrypted0 = crypto::encrypt_note(&recipient_enc_pub, amount, &blinding0)?;
    let encrypted1 = crypto::encrypt_note(&enc_pub_self, change, &blinding1)?;

    let ext_data_hash = compute_ext_data_hash(
        &sender_address,
        0i128, // no external amount for transfers
        &encrypted0,
        &encrypted1,
    )?;

    let asp_membership_index = find_asp_membership_index(db, &note_pubkey)?;
    let non_membership_key = BigInt::from(0u32);

    let proof_result = proof::generate_proof(
        &inputs,
        &[out0, out1],
        &pool_leaves,
        public_amount,
        Some(ext_data_hash),
        &asp_leaves,
        asp_membership_index,
        Scalar::zero(),
        &non_membership_key,
    )?;

    let proof_hex = serialize_proof_for_invoke(&proof_result)?;
    let ext_data_hex = serialize_ext_data_for_invoke(
        &sender_address,
        0i128,
        &encrypted0,
        &encrypted1,
    )?;

    stellar::contract_invoke(
        &cfg.pool,
        source,
        network,
        "transact",
        &[
            "--proof",
            &proof_hex,
            "--ext_data",
            &ext_data_hex,
            "--sender",
            &sender_address,
        ],
    )?;

    // Mark input notes as spent
    for note in &selected {
        db.mark_note_spent(&note.id)?;
    }

    // Save change note
    if change > 0 {
        let change_commitment = crypto::commitment(Scalar::from(change), note_pubkey, blinding1);
        let commitment_hex = crypto::scalar_to_hex_be(&change_commitment);
        let privkey_hex = hex::encode(crypto::scalar_to_le_bytes(&note_privkey));
        let blinding_hex = hex::encode(crypto::scalar_to_le_bytes(&blinding1));
        let next_idx = db.pool_leaf_count()?;

        db.upsert_note(&UserNote {
            id: commitment_hex,
            owner: pubkey_hex,
            private_key: privkey_hex,
            blinding: blinding_hex,
            amount: change,
            leaf_index: next_idx.saturating_add(1), // output1 is at next_idx+1
            spent: 0,
            is_received: 0,
            ledger: None,
        })?;
    }

    Ok(())
}

// ==================== Helpers ====================

/// Select unspent notes to cover the requested amount.
/// Returns (selected_notes, total_amount).
fn select_notes_for_amount(unspent: &[UserNote], amount: u64) -> Result<(Vec<UserNote>, u64)> {
    if unspent.is_empty() {
        bail!("No unspent notes available");
    }

    let mut selected = Vec::new();
    let mut total: u64 = 0;

    // Simple greedy: pick notes until we have enough
    for note in unspent {
        selected.push(note.clone());
        total = total.saturating_add(note.amount);
        if total >= amount {
            break;
        }
    }

    if total < amount {
        bail!("Insufficient balance: have {total} stroops, need {amount}");
    }

    // We need exactly 2 inputs for the circuit
    if selected.len() > 2 {
        bail!(
            "Need to consolidate notes first: selected {} notes but circuit supports max 2 inputs",
            selected.len()
        );
    }

    Ok((selected, total))
}

/// Find ASP membership index for a given note public key.
fn find_asp_membership_index(db: &Database, note_pubkey: &Scalar) -> Result<usize> {
    let expected_leaf = crypto::membership_leaf(*note_pubkey, Scalar::zero());
    let expected_hex = crypto::scalar_to_hex_be(&expected_leaf);

    let asp_leaves = db.get_asp_leaves()?;
    for (idx, leaf_hex) in &asp_leaves {
        if *leaf_hex == expected_hex {
            return usize::try_from(*idx).map_err(|_| anyhow::anyhow!("index overflow"));
        }
    }

    // Default to index 0 if not found (for deposits with dummy membership)
    Ok(0)
}

/// Compute ExtDataHash: Keccak256 of ext data, reduced mod BN256 field.
fn compute_ext_data_hash(
    recipient: &str,
    ext_amount: i128,
    encrypted_output0: &[u8],
    encrypted_output1: &[u8],
) -> Result<BigInt> {
    // Build the data to hash — we concatenate the fields
    let mut data = Vec::new();
    data.extend_from_slice(recipient.as_bytes());
    data.extend_from_slice(&ext_amount.to_be_bytes());
    data.extend_from_slice(encrypted_output0);
    data.extend_from_slice(encrypted_output1);

    let mut hasher = Keccak256::new();
    hasher.update(&data);
    let digest = hasher.finalize();

    // Reduce mod BN256 field
    let digest_uint = num_bigint::BigUint::from_bytes_be(&digest);
    let modulus = bn256_modulus();
    #[allow(clippy::arithmetic_side_effects)] // BigUint modulo; modulus is non-zero
    let reduced = digest_uint % modulus;

    Ok(BigInt::from(reduced))
}

/// Serialize proof for stellar contract invoke (placeholder — actual XDR serialization needed).
fn serialize_proof_for_invoke(result: &proof::ProofResult) -> Result<String> {
    // For now, serialize the proof components as hex
    // In production, this would produce proper Soroban XDR
    let mut buf = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&result.proof, &mut buf)
        .map_err(|e| anyhow::anyhow!("Proof serialization failed: {e}"))?;
    Ok(hex::encode(&buf))
}

/// Serialize ExtData for stellar contract invoke (placeholder).
fn serialize_ext_data_for_invoke(
    recipient: &str,
    ext_amount: i128,
    encrypted_output0: &[u8],
    encrypted_output1: &[u8],
) -> Result<String> {
    // JSON representation for stellar contract invoke
    let json = serde_json::json!({
        "recipient": recipient,
        "ext_amount": ext_amount.to_string(),
        "encrypted_output0": hex::encode(encrypted_output0),
        "encrypted_output1": hex::encode(encrypted_output1),
    });
    Ok(json.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_note(id: &str, amount: u64, leaf_index: u64) -> UserNote {
        UserNote {
            id: id.to_string(),
            owner: "owner".to_string(),
            private_key: "pk".to_string(),
            blinding: hex::encode([0u8; 32]),
            amount,
            leaf_index,
            spent: 0,
            is_received: 0,
            ledger: Some(1),
        }
    }

    // ========== select_notes_for_amount ==========

    #[test]
    fn test_select_exact_amount() {
        let notes = vec![make_note("a", 500, 0), make_note("b", 300, 1)];
        let (selected, total) = select_notes_for_amount(&notes, 500).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(total, 500);
    }

    #[test]
    fn test_select_two_notes() {
        let notes = vec![make_note("a", 300, 0), make_note("b", 400, 1)];
        let (selected, total) = select_notes_for_amount(&notes, 600).unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(total, 700);
    }

    #[test]
    fn test_select_insufficient_balance() {
        let notes = vec![make_note("a", 100, 0)];
        let result = select_notes_for_amount(&notes, 500);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Insufficient"), "error: {msg}");
    }

    #[test]
    fn test_select_empty_notes() {
        let notes: Vec<UserNote> = vec![];
        let result = select_notes_for_amount(&notes, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_select_too_many_notes() {
        let notes = vec![
            make_note("a", 100, 0),
            make_note("b", 100, 1),
            make_note("c", 100, 2),
        ];
        let result = select_notes_for_amount(&notes, 300);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("consolidate"), "error: {msg}");
    }

    // ========== compute_ext_data_hash ==========

    #[test]
    fn test_ext_data_hash_deterministic() {
        let enc0 = vec![0u8; 112];
        let enc1 = vec![1u8; 112];

        let h1 = compute_ext_data_hash("GABC", 1000, &enc0, &enc1).unwrap();
        let h2 = compute_ext_data_hash("GABC", 1000, &enc0, &enc1).unwrap();
        assert_eq!(h1, h2, "ext_data_hash should be deterministic");
    }

    #[test]
    fn test_ext_data_hash_changes_with_recipient() {
        let enc0 = vec![0u8; 112];
        let enc1 = vec![1u8; 112];

        let h1 = compute_ext_data_hash("GABC", 1000, &enc0, &enc1).unwrap();
        let h2 = compute_ext_data_hash("GXYZ", 1000, &enc0, &enc1).unwrap();
        assert_ne!(h1, h2, "different recipients should produce different hashes");
    }

    #[test]
    fn test_ext_data_hash_changes_with_amount() {
        let enc0 = vec![0u8; 112];
        let enc1 = vec![1u8; 112];

        let h1 = compute_ext_data_hash("GABC", 1000, &enc0, &enc1).unwrap();
        let h2 = compute_ext_data_hash("GABC", 2000, &enc0, &enc1).unwrap();
        assert_ne!(h1, h2, "different amounts should produce different hashes");
    }

    #[test]
    fn test_ext_data_hash_negative_amount() {
        let enc0 = vec![0u8; 112];
        let enc1 = vec![1u8; 112];

        // Should not panic with negative amount (withdrawal case)
        let result = compute_ext_data_hash("GABC", -500, &enc0, &enc1);
        assert!(result.is_ok());
    }

    // ========== bn256_modulus ==========

    #[test]
    fn test_bn256_modulus_is_prime_field_order() {
        let modulus = bn256_modulus();
        // BN254 scalar field order (well-known value)
        // = 21888242871839275222246405745257275088548364400416034343698204186575808495617
        let expected_hex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
        let expected = num_bigint::BigUint::parse_bytes(expected_hex.as_bytes(), 16).unwrap();
        assert_eq!(modulus, expected, "BN256 modulus should match known value");
    }

    // ========== find_asp_membership_index ==========

    #[test]
    fn test_find_asp_membership_index_default() {
        let db = Database::open_in_memory().unwrap();
        let pubkey = Scalar::from(42u64);
        // No ASP leaves — should default to 0
        let idx = find_asp_membership_index(&db, &pubkey).unwrap();
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_find_asp_membership_index_found() {
        let db = Database::open_in_memory().unwrap();
        let pubkey = Scalar::from(42u64);
        let leaf = crypto::membership_leaf(pubkey, Scalar::zero());
        let leaf_hex = crypto::scalar_to_hex_be(&leaf);

        db.insert_asp_leaf(7, &leaf_hex, 100).unwrap();

        let idx = find_asp_membership_index(&db, &pubkey).unwrap();
        assert_eq!(idx, 7);
    }

    // ========== Serialization helpers ==========

    #[test]
    fn test_serialize_ext_data_for_invoke() {
        let enc0 = vec![0xABu8; 4];
        let enc1 = vec![0xCDu8; 4];

        let result = serialize_ext_data_for_invoke("GABC", -100, &enc0, &enc1).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(parsed["recipient"], "GABC");
        assert_eq!(parsed["ext_amount"], "-100");
        assert_eq!(parsed["encrypted_output0"], "abababab");
        assert_eq!(parsed["encrypted_output1"], "cdcdcdcd");
    }
}
