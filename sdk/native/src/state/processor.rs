use super::{SqliteStorage, events_parsers::parse_event};
use crate::types::ProcessedEvent;
use anyhow::{Context, Result};

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
        let id = event.id.clone();
        // A known event that does not decode is an SDK bug. Stop rather than
        // save state without it.
        let parsed = parse_event(event).with_context(|| format!("cannot process event {id}"))?;
        processed_ids.push(id);
        let Some(parsed) = parsed else {
            // The raw event stays in `raw_contract_events`; a later version
            // replays it by deleting its `processed_events` row.
            continue;
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
    use crate::{
        state::test_events::{b64, commitment_entries, commitment_event, raw_event, symbol, u256},
        types::{ContractEvent, ContractsEventData},
    };
    use stellar_xdr as xdr;

    const COMMITMENT: u64 = 99;

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
            &[symbol("unknown_future_event")?],
            vec![],
        )?])?;

        assert!(process_events(&mut storage, 10)?);
        assert!(!process_events(&mut storage, 10)?);
        Ok(())
    }

    #[test]
    fn an_unknown_event_parses_to_none() -> Result<()> {
        let event = raw_event(
            "0000000000000000001-0000000000",
            &[symbol("unknown_future_event")?],
            vec![],
        )?;

        assert!(parse_event(event)?.is_none());
        Ok(())
    }

    #[test]
    fn an_event_that_fails_to_parse_stops_processing() -> Result<()> {
        let mut storage = storage_with(vec![
            commitment_event("0000000000000000001-0000000000", COMMITMENT, vec![])?,
            commitment_event(
                "0000000000000000001-0000000001",
                COMMITMENT,
                commitment_entries(0)?,
            )?,
        ])?;

        let err = process_events(&mut storage, 10).expect_err("bad event");

        assert!(format!("{err:#}").contains("0000000000000000001-0000000000"));
        assert_eq!(storage.get_unprocessed_events(10)?.len(), 2);
        assert!(
            storage
                .get_pool_commitment_leaves_ordered("CPOOL")?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn a_nullifier_event_with_non_map_data_fails_to_parse() -> Result<()> {
        let event = ContractEvent {
            value: b64(&xdr::ScVal::U32(1))?,
            ..raw_event(
                "0000000000000000001-0000000000",
                &[symbol("new_nullifier_event")?, u256(5)],
                vec![],
            )?
        };

        let err = parse_event(event).expect_err("non-map data");

        assert!(err.to_string().contains("should be a map"));
        Ok(())
    }

    #[test]
    fn an_unknown_event_with_non_map_data_is_read_once() -> Result<()> {
        let mut storage = storage_with(vec![ContractEvent {
            value: b64(&xdr::ScVal::U32(1))?,
            ..raw_event(
                "0000000000000000001-0000000000",
                &[symbol("unknown_future_event")?],
                vec![],
            )?
        }])?;

        assert!(process_events(&mut storage, 10)?);
        assert!(!process_events(&mut storage, 10)?);
        Ok(())
    }

    #[test]
    fn a_same_ledger_re_registration_resolves_to_the_later_key() -> Result<()> {
        let owner = xdr::ScVal::Address(xdr::ScAddress::Account(xdr::AccountId(
            xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256([7; 32])),
        )));
        let registration = |id, key: u8| -> Result<ContractEvent> {
            let bytes = xdr::ScVal::Bytes(xdr::ScBytes(vec![key; 32].try_into()?));
            let entries = vec![
                xdr::ScMapEntry {
                    key: symbol("encryption_key")?,
                    val: bytes.clone(),
                },
                xdr::ScMapEntry {
                    key: symbol("note_key")?,
                    val: bytes,
                },
            ];
            raw_event(id, &[symbol("public_key_event")?, owner.clone()], entries)
        };
        let mut storage = storage_with(vec![
            registration("0000000000000000001-0000000000", 1)?,
            registration("0000000000000000001-0000000001", 2)?,
        ])?;

        assert!(process_events(&mut storage, 1)?);
        assert!(process_events(&mut storage, 1)?);

        let entry = storage
            .lookup_public_key_by_address(&crate::chain::scval_to_address_string(&owner)?)?
            .expect("registered");
        assert_eq!(entry.encryption_key.0, [2; 32]);
        Ok(())
    }
}
