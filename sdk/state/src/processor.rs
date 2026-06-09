use crate::{Storage, events_parsers::parse_event};
use anyhow::Result;
use types::ProcessedEvent;

pub fn process_events(storage: &mut Storage, limit: u32) -> Result<bool> {
    let mut unprocessed = storage.get_unprocessed_events(limit)?;
    if unprocessed.is_empty() {
        return Ok(false);
    }
    let mut nullifiers = vec![];
    let mut commitments = vec![];
    let mut pubkeys = vec![];
    let mut leaves = vec![];
    while let Some(event) = unprocessed.pop() {
        let parsed = match parse_event(event) {
            Ok(parsed) => parsed,
            Err(e) => {
                // we shouldn't delete broken events
                // we should fix the logic then
                // update the software and handle them
                log::error!("cannot process event: {e:?}");
                continue;
            }
        };
        match parsed {
            ProcessedEvent::Nullifier(ev) => nullifiers.push(ev),
            ProcessedEvent::Commitment(ev) => commitments.push(ev),
            ProcessedEvent::PublicKey(ev) => pubkeys.push(ev),
            ProcessedEvent::LeafAdded(ev) => leaves.push(ev),
            _ => log::warn!("event won't be saved to the storage: {parsed:?}"),
        }
    }
    storage.save_nullifier_events_batch(&nullifiers)?;
    storage.save_commitment_events_batch(&commitments)?;
    storage.save_public_key_events_batch(&pubkeys)?;
    storage.save_leaf_added_events_batch(&leaves)?;
    Ok(true)
}

/// Process already-parsed events (commitments/nullifiers) into local user
/// state.
///
/// This scans pool commitments for decryptable outputs (per account) and
/// reconciles pool nullifiers against locally-computed expected nullifiers.
pub fn process_notes(
    storage: &mut Storage,
    limit: u32,
    derive: &mut crate::storage::DeriveNoteFn<'_>,
) -> Result<bool> {
    let mut did_work = false;
    did_work |= storage.scan_commitments_for_user_notes(limit, derive)?;
    did_work |= storage.reconcile_nullifiers(limit)?;
    Ok(did_work)
}
