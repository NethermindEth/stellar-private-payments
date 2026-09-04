use super::{SqliteStorage, events_parsers::parse_event};
use crate::types::ProcessedEvent;
use anyhow::Result;

pub(crate) fn process_events(storage: &mut SqliteStorage, limit: u32) -> Result<bool> {
    let mut unprocessed = storage.get_unprocessed_events(limit)?;
    if unprocessed.is_empty() {
        return Ok(false);
    }
    let mut nullifiers = vec![];
    let mut commitments = vec![];
    let mut pubkeys = vec![];
    let mut leaves = vec![];
    let mut processed_ids = vec![];
    while let Some(event) = unprocessed.pop() {
        let parsed = match parse_event(event) {
            Ok(parsed) => parsed,
            Err(e) => {
                // we shouldn't delete broken events
                // we should fix the logic then
                // update the software and handle them
                tracing::error!("cannot process event: {e:?}");
                continue;
            }
        };
        match parsed {
            ProcessedEvent::Nullifier(ev) => nullifiers.push(ev),
            ProcessedEvent::Commitment(ev) => commitments.push(ev),
            ProcessedEvent::PublicKey(ev) => pubkeys.push(ev),
            ProcessedEvent::LeafAdded(ev) => leaves.push(ev),
            ProcessedEvent::AdminUpdated(ev) => processed_ids.push(ev.id),
            ProcessedEvent::PauseChanged(ev) => processed_ids.push(ev.id),
            _ => tracing::warn!("event won't be saved to the storage: {parsed:?}"),
        }
    }
    storage.save_nullifier_events_batch(&nullifiers)?;
    storage.save_commitment_events_batch(&commitments)?;
    storage.save_public_key_events_batch(&pubkeys)?;
    storage.save_leaf_added_events_batch(&leaves)?;
    storage.save_processed_event_ids(&processed_ids)?;
    Ok(true)
}

/// Process already-parsed events (commitments/nullifiers) into local user
/// state.
///
/// This scans pool commitments for decryptable outputs (per account) and
/// reconciles pool nullifiers against locally-computed expected nullifiers.
pub(crate) fn process_notes(
    storage: &mut SqliteStorage,
    limit: u32,
    derive: &mut super::storage::DeriveNoteFn<'_>,
) -> Result<bool> {
    let mut did_work = false;
    did_work |= storage.scan_commitments_for_user_notes(limit, derive)?;
    did_work |= storage.reconcile_nullifiers(limit)?;
    Ok(did_work)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContractEvent, ContractsEventData};
    use stellar_xdr::{self as xdr, WriteXdr};

    fn b64(val: &xdr::ScVal) -> String {
        val.to_xdr_base64(xdr::Limits::none())
            .expect("encode scval")
    }

    fn symbol(s: &str) -> xdr::ScVal {
        xdr::ScVal::Symbol(xdr::ScSymbol(s.try_into().expect("symbol")))
    }

    fn pause_changed_event() -> ContractEvent {
        let entries = vec![
            xdr::ScMapEntry {
                key: symbol("flags"),
                val: xdr::ScVal::U32(1),
            },
            xdr::ScMapEntry {
                key: symbol("until"),
                val: xdr::ScVal::Void,
            },
        ];
        ContractEvent {
            id: "0000000000000000004-0000000000".to_string(),
            ledger: 1,
            contract_id: "CPOOL".to_string(),
            topics: vec![b64(&symbol("pause_changed"))],
            value: b64(&xdr::ScVal::Map(Some(xdr::ScMap(
                entries.try_into().expect("data map"),
            )))),
        }
    }

    /// A pause event saves no row of its own, so only the `processed_events`
    /// table stops it from being read again on the next pass.
    #[test]
    fn a_pause_changed_event_is_read_once() -> Result<()> {
        let mut storage = SqliteStorage::connect_in_memory()?;
        storage.save_events_batch(&ContractsEventData {
            events: vec![pause_changed_event()],
            cursor: "cur".to_string(),
            latest_ledger: 1,
        })?;
        assert_eq!(storage.get_unprocessed_events(10)?.len(), 1);

        assert!(process_events(&mut storage, 10)?);

        assert!(storage.get_unprocessed_events(10)?.is_empty());
        Ok(())
    }
}
