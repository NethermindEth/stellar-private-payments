use super::{SqliteStorage, events_parsers::parse_event};
use crate::types::ProcessedEvent;
use anyhow::Result;

pub(crate) fn process_events(storage: &mut SqliteStorage, limit: u32) -> Result<bool> {
    let unprocessed = storage.get_unprocessed_events(limit)?;
    if unprocessed.is_empty() {
        return Ok(false);
    }
    let mut nullifiers = vec![];
    let mut commitments = vec![];
    let mut pubkeys = vec![];
    let mut leaves = vec![];
    let mut processed_ids = vec![];
    for event in unprocessed {
        processed_ids.push(event.id.clone());
        // The raw event stays in `raw_contract_events`; a later version replays
        // it by deleting its `processed_events` row.
        let parsed = match parse_event(event) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => continue,
            Err(e) => {
                tracing::error!("cannot process event: {e:?}");
                continue;
            }
        };
        match parsed {
            ProcessedEvent::Nullifier(ev) => nullifiers.push(ev),
            ProcessedEvent::Commitment(ev) => commitments.push(ev),
            ProcessedEvent::PublicKey(ev) => pubkeys.push(ev),
            ProcessedEvent::LeafAdded(ev) => leaves.push(ev),
            _ => tracing::warn!("event won't be saved to the storage: {parsed:?}"),
        }
    }
    storage.save_nullifier_events_batch(&nullifiers)?;
    storage.save_commitment_events_batch(&commitments)?;
    storage.save_public_key_events_batch(&pubkeys)?;
    storage.save_leaf_added_events_batch(&leaves)?;
    // Mark after saving the rows: a crash in between leaves an event unmarked,
    // never marked without its row.
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
    use crate::types::{ContractEvent, ContractsEventData, Field, U256};
    use stellar_xdr::{self as xdr, WriteXdr};

    const COMMITMENT: u64 = 99;

    fn b64(val: &xdr::ScVal) -> String {
        val.to_xdr_base64(xdr::Limits::none())
            .expect("encode scval")
    }

    fn symbol(s: &str) -> xdr::ScVal {
        xdr::ScVal::Symbol(xdr::ScSymbol(s.try_into().expect("symbol")))
    }

    fn raw_event(id: &str, topics: &[xdr::ScVal], entries: Vec<xdr::ScMapEntry>) -> ContractEvent {
        ContractEvent {
            id: id.to_string(),
            ledger: 1,
            contract_id: "CPOOL".to_string(),
            topics: topics.iter().map(b64).collect(),
            value: b64(&xdr::ScVal::Map(Some(xdr::ScMap(
                entries.try_into().expect("data map"),
            )))),
        }
    }

    fn commitment_event(id: &str, entries: Vec<xdr::ScMapEntry>) -> ContractEvent {
        let commitment = xdr::ScVal::U256(xdr::UInt256Parts {
            hi_hi: 0,
            hi_lo: 0,
            lo_hi: 0,
            lo_lo: COMMITMENT,
        });
        raw_event(id, &[symbol("new_commitment_event"), commitment], entries)
    }

    fn storage_with(events: Vec<ContractEvent>) -> Result<SqliteStorage> {
        let mut storage = SqliteStorage::connect_in_memory()?;
        storage.save_events_batch(&ContractsEventData {
            events,
            cursor: "cur".to_string(),
            latest_ledger: 1,
        })?;
        Ok(storage)
    }

    #[test]
    fn an_unknown_event_is_read_once() -> Result<()> {
        let mut storage = storage_with(vec![raw_event(
            "0000000000000000001-0000000000",
            &[symbol("unknown_future_event")],
            vec![],
        )])?;

        assert!(process_events(&mut storage, 10)?);
        assert!(!process_events(&mut storage, 10)?);
        Ok(())
    }

    #[test]
    fn an_unknown_event_parses_to_none() -> Result<()> {
        let event = raw_event(
            "0000000000000000001-0000000000",
            &[symbol("unknown_future_event")],
            vec![],
        );

        assert!(parse_event(event)?.is_none());
        Ok(())
    }

    #[test]
    fn an_event_that_fails_to_parse_is_read_once() -> Result<()> {
        let mut storage = storage_with(vec![commitment_event(
            "0000000000000000001-0000000000",
            vec![],
        )])?;

        assert!(process_events(&mut storage, 10)?);
        assert!(!process_events(&mut storage, 10)?);
        Ok(())
    }

    /// A repeated commitment leaves no row, so only its mark stops it being
    /// read on every pass.
    #[test]
    fn a_repeated_commitment_does_not_stall_processing() -> Result<()> {
        let entries = |index| {
            vec![
                xdr::ScMapEntry {
                    key: symbol("encrypted_output"),
                    val: xdr::ScVal::Bytes(xdr::ScBytes::default()),
                },
                xdr::ScMapEntry {
                    key: symbol("index"),
                    val: xdr::ScVal::U32(index),
                },
            ]
        };
        let mut storage = storage_with(vec![
            commitment_event("0000000000000000001-0000000000", entries(0)),
            commitment_event("0000000000000000001-0000000001", entries(1)),
        ])?;
        let commitment = Field(U256::from(COMMITMENT));

        assert!(process_events(&mut storage, 10)?);

        assert_eq!(
            storage.get_pool_commitment_leaves_ordered("CPOOL")?,
            vec![commitment]
        );
        assert!(!process_events(&mut storage, 10)?);
        Ok(())
    }
}
