//! Admin-side Global View Key audit over parsed pool events and local storage.

use anyhow::Result;
use std::collections::HashSet;

use crate::{
    state::Storage,
    types::{Field, NewCommitmentEvent, NewNullifierEvent},
    zk::gvk::{
        GvkAuditedNote, try_decrypt_against_commitment_set, try_decrypt_against_commitments,
    },
};

/// Decrypt and verify the output note carried by a `NewCommitmentEvent`.
///
/// Returns `None` when the event has no `gvk_ciphertext`, the pool is not
/// GVK-enabled, or the ciphertext does not match the on-chain commitment.
pub fn audit_commitment_event(
    admin_private_key: &Field,
    event: &NewCommitmentEvent,
) -> Option<GvkAuditedNote> {
    let ciphertext = event.gvk_ciphertext.as_ref()?;
    ciphertext.decrypt_audited_for_commitment(admin_private_key, &event.commitment)
}

/// Decrypt and verify a traceable-mode input note from a `NewNullifierEvent`.
///
/// Nullifier events do not carry the spent commitment, so the caller supplies
/// candidate commitments (typically every commitment observed for the pool).
/// Returns the first ciphertext whose recovered plaintext matches one of them.
pub fn audit_nullifier_event(
    admin_private_key: &Field,
    event: &NewNullifierEvent,
    candidate_commitments: impl IntoIterator<Item = Field>,
) -> Option<GvkAuditedNote> {
    let ciphertext = event.gvk_ciphertext.as_ref()?;
    try_decrypt_against_commitments(admin_private_key, ciphertext, candidate_commitments)
}

/// Audit every stored output-note GVK ciphertext for a pool.
pub fn audit_pool_output_notes(
    admin_private_key: &Field,
    storage: &Storage,
    pool_contract_id: i64,
) -> Result<Vec<GvkAuditedNote>> {
    let mut audited = Vec::new();
    for (commitment, ciphertext) in
        storage.list_pool_gvk_commitment_ciphertexts(pool_contract_id)?
    {
        if let Some(note) =
            ciphertext.decrypt_audited_for_commitment(admin_private_key, &commitment)
        {
            audited.push(note);
        }
    }
    Ok(audited)
}

/// Audit every stored spent-input GVK ciphertext for a traceable pool.
pub fn audit_pool_spent_input_notes(
    admin_private_key: &Field,
    storage: &Storage,
    pool_contract_id: i64,
) -> Result<Vec<GvkAuditedNote>> {
    let candidates: HashSet<Field> = storage
        .list_pool_commitment_hashes(pool_contract_id)?
        .into_iter()
        .collect();
    let mut audited = Vec::new();
    for (_nullifier, ciphertext) in storage.list_pool_gvk_nullifier_ciphertexts(pool_contract_id)? {
        if let Some(note) =
            try_decrypt_against_commitment_set(admin_private_key, &ciphertext, &candidates)
        {
            audited.push(note);
        }
    }
    Ok(audited)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        types::BabyJubJubPoint,
        zk::gvk::{GvkNote, generate_gvk_nonce},
    };

    fn field(value: u64) -> Field {
        Field(crate::types::U256::from(value))
    }

    #[test]
    fn audit_commitment_event_roundtrip() -> anyhow::Result<()> {
        let d_priv = field(0xA11CE);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv);
        let nonce = generate_gvk_nonce()?;
        let note = GvkNote::new(
            field(0xBEEF),
            5_000_000u128.into(),
            field(0x1234),
            field(99),
        );
        let ct = note.encrypt(&admin, &nonce, 2)?;

        let commitment_le = {
            let amount_field = note.amount;
            crate::zk::crypto::compute_commitment(
                &amount_field.to_le_bytes(),
                &note.pk.to_le_bytes(),
                &note.blinding.to_le_bytes(),
            )?
        };
        let commitment = Field::try_from_le_bytes(
            commitment_le
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("commitment hash is not 32 bytes"))?,
        )?;

        let event = NewCommitmentEvent {
            id: "test-event".into(),
            commitment,
            index: 7,
            encrypted_output: vec![],
            gvk_ciphertext: Some(ct),
        };

        let audited = audit_commitment_event(&d_priv, &event).expect("audit output note");
        assert_eq!(audited.note.pk, note.pk);
        assert_eq!(audited.note.amount(), 5_000_000u128.into());
        assert_eq!(audited.note.blinding, note.blinding);
        assert_eq!(audited.commitment, commitment);
        Ok(())
    }

    #[test]
    fn audit_commitment_event_rejects_tampered_ciphertext() -> anyhow::Result<()> {
        let d_priv = field(0xA11CE);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv);
        let note = GvkNote::new(field(1), 1u128.into(), field(2), field(3));
        let mut ct = note.encrypt(&admin, &field(4), 0)?;
        ct.c1 = field(0xFFFF);

        let event = NewCommitmentEvent {
            id: "test-event".into(),
            commitment: field(0xDEAD),
            index: 0,
            encrypted_output: vec![],
            gvk_ciphertext: Some(ct),
        };

        assert!(audit_commitment_event(&d_priv, &event).is_none());
        Ok(())
    }

    #[test]
    fn audit_nullifier_event_finds_matching_commitment() -> anyhow::Result<()> {
        let d_priv = field(0x510);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv);
        let note = GvkNote::new(field(0xABC), 42u128.into(), field(0xDEF), field(5));
        let ct = note.encrypt(&admin, &field(9), 0)?;

        let commitment_le = crate::zk::crypto::compute_commitment(
            &note.amount.to_le_bytes(),
            &note.pk.to_le_bytes(),
            &note.blinding.to_le_bytes(),
        )?;
        let commitment = Field::try_from_le_bytes(
            commitment_le
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("commitment hash is not 32 bytes"))?,
        )?;

        let event = NewNullifierEvent {
            id: "nullifier-event".into(),
            nullifier: field(0x999),
            gvk_ciphertext: Some(ct),
        };

        let audited = audit_nullifier_event(&d_priv, &event, [field(0x1111), commitment])
            .expect("match spent note");
        assert_eq!(audited.commitment, commitment);
        assert_eq!(audited.note.amount(), 42u128.into());
        Ok(())
    }
}
