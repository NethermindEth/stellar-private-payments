use prover::notes::try_decrypt_and_derive_user_note;
use state::{
    AccountKeys, DerivedUserNoteRow, PoolCommitmentRow, Storage, process_events, process_notes,
};

use crate::error::PoolError;

const PROCESS_FETCH_LIMIT: u32 = 50;

pub(crate) fn process_local_state(storage: &mut Storage) -> Result<(), PoolError> {
    while process_local_state_batch(storage).map_err(|e| PoolError::Other(e.to_string()))? {}
    Ok(())
}

/// Process one batch of raw events and note derivation. Returns `true` when
/// more work may remain.
pub fn process_local_state_batch(storage: &mut Storage) -> anyhow::Result<bool> {
    let did_raw = process_events(storage, PROCESS_FETCH_LIMIT)?;
    let mut derive = derive_user_note;
    let did_notes = process_notes(storage, PROCESS_FETCH_LIMIT, &mut derive)?;
    Ok(did_raw || did_notes)
}

fn derive_user_note(
    account: &AccountKeys,
    row: &PoolCommitmentRow,
) -> anyhow::Result<Option<DerivedUserNoteRow>> {
    let opt = try_decrypt_and_derive_user_note(
        &account.note_keypair,
        &account.encryption_keypair.private,
        &row.commitment,
        row.leaf_index,
        &row.encrypted_output,
    )?;
    Ok(opt.map(|d| DerivedUserNoteRow {
        amount: d.amount,
        blinding: d.blinding,
        expected_nullifier: d.expected_nullifier,
    }))
}
