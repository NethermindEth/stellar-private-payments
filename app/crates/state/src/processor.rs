use anyhow::Result;
use crate::Storage;
use crate::events_parsers::parse_event;
use types::ProcessedEvent;


pub fn process_events(storage: &mut Storage, limit: u32) -> Result<()> {
    let mut unprocessed = vec![]; //storage.get_unprocessed_events(limit)?;
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
    Ok(())
}
