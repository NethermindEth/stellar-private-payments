//! Note discovery helpers (decrypt + verify + derive nullifier).
//!
//! This encapsulates the logic required to turn a pool commitment row into a
//! `user_notes` row, given an account's keypairs.

use crate::types::{EncryptionPrivateKey, Field, NoteAmount, NoteKeyPair};
use anyhow::{Result, anyhow};

use crate::zk::{crypto, encryption};

/// Data derived from a decryptable pool commitment for a specific user.
#[derive(Debug, Clone)]
pub struct DerivedUserNote {
    /// Decrypted note amount.
    pub amount: NoteAmount,
    /// Decrypted note blinding factor.
    pub blinding: Field,
    /// Expected nullifier for this note (matches on-chain nullifier event when
    /// spent).
    pub expected_nullifier: Field,
}

/// Try to decrypt a commitment's encrypted output for a given account and, if
/// it is addressed to that account, derive the expected nullifier.
///
/// Returns `Ok(None)` if:
/// - the ciphertext isn't for this account (decryption fails), or
/// - the decrypted plaintext doesn't match the on-chain commitment, or
/// - the note is a dummy 0-amount output.
pub fn try_decrypt_and_derive_user_note(
    note_keypair: &NoteKeyPair,
    encryption_private_key: &EncryptionPrivateKey,
    commitment: &Field,
    leaf_index: u32,
    encrypted_output: &[u8],
) -> Result<Option<DerivedUserNote>> {
    let Some((amount, blinding)) =
        encryption::decrypt_output_note(encryption_private_key, encrypted_output)?
    else {
        return Ok(None);
    };

    if amount.is_zero() {
        return Ok(None);
    }

    // Verify that (amount, blinding) corresponds to the claimed on-chain
    // commitment.
    let amount_field_le = Field::from(amount).to_le_bytes();
    let computed = crypto::compute_commitment(
        &amount_field_le,
        note_keypair.public.as_ref(),
        &blinding.to_le_bytes(),
    )?;
    let computed: [u8; 32] = computed
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("commitment: expected 32 bytes, got {}", v.len()))?;

    if computed != commitment.to_le_bytes() {
        return Ok(None);
    }

    // Expected nullifier derivation matches the circuits:
    // path_indices = leaf_index packed into LE field bytes.
    let commitment_le = commitment.to_le_bytes();
    let mut path_indices_le = [0u8; 32];
    path_indices_le[..8].copy_from_slice(&(u64::from(leaf_index)).to_le_bytes());

    let signature =
        crypto::compute_signature(&note_keypair.private.0, &commitment_le, &path_indices_le)?;
    let expected_nullifier =
        crypto::compute_nullifier(&commitment_le, &path_indices_le, &signature)?;
    let expected_nullifier: [u8; 32] = expected_nullifier
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("nullifier: expected 32 bytes, got {}", v.len()))?;
    let expected_nullifier = Field::try_from_le_bytes(expected_nullifier)?;

    Ok(Some(DerivedUserNote {
        amount,
        blinding,
        expected_nullifier,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KeyDerivationSignature;

    /// A zero-amount output that decrypts and matches its commitment still
    /// yields no note. The same output carrying 5 yields one.
    #[test]
    fn zero_amount_note_is_not_a_spendable_note() -> Result<()> {
        let (note_keypair, enc_keypair) =
            encryption::derive_encryption_and_note_keypairs(KeyDerivationSignature(vec![1u8; 64]))?;
        let blinding = Field::from(NoteAmount::from(7u128));
        let derive = |amount: NoteAmount| {
            let commitment: [u8; 32] = crypto::compute_commitment(
                &Field::from(amount).to_le_bytes(),
                note_keypair.public.as_ref(),
                &blinding.to_le_bytes(),
            )?
            .try_into()
            .map_err(|_| anyhow!("commitment: expected 32 bytes"))?;
            let encrypted_output =
                encryption::encrypt_output_note(&enc_keypair.public, amount, &blinding)?;
            try_decrypt_and_derive_user_note(
                &note_keypair,
                &enc_keypair.private,
                &Field::try_from_le_bytes(commitment)?,
                0,
                &encrypted_output,
            )
        };

        assert!(derive(NoteAmount::ZERO)?.is_none());
        assert!(derive(NoteAmount::from(5u128))?.is_some());
        Ok(())
    }
}
