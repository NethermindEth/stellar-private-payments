//! Client-facing crypto helpers that do not require a wallet session.

use prover::crypto::asp_membership_leaf;
use types::{Field, NotePublicKey};

use crate::Error;

/// Derive the ASP membership tree leaf for a note public key and membership
/// blinding.
///
/// `leaf = poseidon2_hash2(note_pubkey, membership_blinding, domain=1)`
pub fn derive_asp_user_leaf(
    note_public_key: &NotePublicKey,
    membership_blinding: &Field,
) -> Result<Field, Error> {
    asp_membership_leaf(note_public_key, membership_blinding)
        .map_err(|e| Error::Other(e.to_string()))
}
