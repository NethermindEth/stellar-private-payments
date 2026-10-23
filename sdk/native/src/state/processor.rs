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
        types::{ContractEvent, ContractsEventData, EncryptionPrivateKey},
        zk::encryption::encryption_edwards_key,
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

    fn owner(seed: u8) -> xdr::ScVal {
        xdr::ScVal::Address(xdr::ScAddress::Account(xdr::AccountId(
            xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256([seed; 32])),
        )))
    }

    const REGISTRY: &str = "CREGISTRY";
    const OLD_REGISTRY: &str = "COLDREGISTRY";

    fn registered_key(
        storage: &SqliteStorage,
        registry: &str,
        owner_seed: u8,
    ) -> Result<Option<[u8; 32]>> {
        let address = crate::chain::scval_to_address_string(&owner(owner_seed))?;
        Ok(storage
            .lookup_public_key_by_address(&address, registry)?
            .map(|entry| entry.encryption_key.0))
    }

    /// A registration event as `registry` emits it, with `encryption_key` as
    /// given.
    fn registration(
        id: &str,
        registry: &str,
        owner_seed: u8,
        encryption_key: [u8; 32],
    ) -> Result<ContractEvent> {
        let bytes = |b: Vec<u8>| -> Result<xdr::ScVal> {
            Ok(xdr::ScVal::Bytes(xdr::ScBytes(b.try_into()?)))
        };
        let entries = vec![
            xdr::ScMapEntry {
                key: symbol("encryption_key")?,
                val: bytes(encryption_key.to_vec())?,
            },
            xdr::ScMapEntry {
                key: symbol("note_key")?,
                val: bytes(vec![owner_seed; 32])?,
            },
        ];
        Ok(ContractEvent {
            contract_id: registry.to_string(),
            ..raw_event(
                id,
                &[symbol("public_key_event")?, owner(owner_seed)],
                entries,
            )?
        })
    }

    fn edwards_key(secret: u8) -> [u8; 32] {
        encryption_edwards_key(&EncryptionPrivateKey([secret; 32]))
    }

    fn x25519_key(secret: u8) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([secret; 32])).to_bytes()
    }

    #[test]
    fn a_same_ledger_re_registration_resolves_to_the_later_key() -> Result<()> {
        let mut storage = storage_with(vec![
            registration(
                "0000000000000000001-0000000000",
                REGISTRY,
                7,
                edwards_key(1),
            )?,
            registration(
                "0000000000000000001-0000000001",
                REGISTRY,
                7,
                edwards_key(2),
            )?,
        ])?;

        assert!(process_events(&mut storage, 1)?);
        assert!(process_events(&mut storage, 1)?);

        assert_eq!(registered_key(&storage, REGISTRY, 7)?, Some(x25519_key(2)));
        Ok(())
    }

    /// An encoding that is not a curve point is skipped, and the events after
    /// it are still processed.
    #[test]
    fn a_registration_whose_key_is_not_a_point_is_skipped() -> Result<()> {
        let not_a_point = (2u8..)
            .map(|y| {
                let mut key = [0u8; 32];
                key[0] = y;
                key
            })
            .find(|key| ed25519_dalek::VerifyingKey::from_bytes(key).is_err())
            .expect("some y is not on the curve");
        let mut storage = storage_with(vec![
            registration("0000000000000000001-0000000000", REGISTRY, 7, not_a_point)?,
            registration(
                "0000000000000000002-0000000000",
                REGISTRY,
                8,
                edwards_key(1),
            )?,
        ])?;

        assert!(process_events(&mut storage, 10)?);
        assert!(!process_events(&mut storage, 10)?);

        assert_eq!(registered_key(&storage, REGISTRY, 7)?, None);
        assert_eq!(registered_key(&storage, REGISTRY, 8)?, Some(x25519_key(1)));
        Ok(())
    }

    /// Entries from another registry, such as one a deployment replaced, are
    /// never returned, even when they are newer.
    #[test]
    fn lookups_only_read_the_given_registry() -> Result<()> {
        let mut storage = storage_with(vec![
            registration(
                "0000000000000000001-0000000000",
                REGISTRY,
                7,
                edwards_key(1),
            )?,
            registration(
                "0000000000000000002-0000000000",
                OLD_REGISTRY,
                7,
                edwards_key(2),
            )?,
            registration(
                "0000000000000000003-0000000000",
                OLD_REGISTRY,
                8,
                edwards_key(3),
            )?,
        ])?;

        assert!(process_events(&mut storage, 10)?);

        assert_eq!(registered_key(&storage, REGISTRY, 7)?, Some(x25519_key(1)));
        assert_eq!(registered_key(&storage, REGISTRY, 8)?, None);
        assert_eq!(
            registered_key(&storage, OLD_REGISTRY, 8)?,
            Some(x25519_key(3))
        );
        Ok(())
    }
}
