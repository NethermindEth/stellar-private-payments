use crate::{
    chain::{
        ParsedContractEvent, parse_event_metadata, scval_to_address_string, scval_to_bytes,
        scval_to_u32, scval_to_u64, scval_to_u256,
    },
    types::{
        ContractEvent, Field, LeafAddedEvent, LeafDeletedEvent, LeafInsertedEvent,
        LeafUpdatedEvent, NewCommitmentEvent, NewNullifierEvent, ProcessedEvent, PublicKeyEvent,
    },
};
use anyhow::{Result, anyhow};

/// Field name emitted by `contracts/pool-gvk`'s pool events, carrying the
/// admin-decryptable ciphertext of the note.
const GVK_CIPHERTEXT_FIELD: &str = "gvk_ciphertext";

/// Warn when a pool event carries GVK data this SDK does not yet decode.
///
/// `pool-gvk` reuses `pool`'s event names and adds `gvk_ciphertext`. Event
/// data is a name-keyed map, so the extra field decodes harmlessly and the
/// parsers below simply ignore it — but ignoring it silently means a GVK pool
/// can be indexed with its audit data quietly discarded. This makes that
/// visible until the field is actually consumed.
fn warn_unconsumed_gvk_ciphertext(parsed: &ParsedContractEvent) {
    if parsed.values.contains_key(GVK_CIPHERTEXT_FIELD) {
        tracing::warn!(
            "event `{}` id {} from contract {} carries a `{GVK_CIPHERTEXT_FIELD}` field that is not yet parsed; GVK data is being dropped",
            parsed.name,
            parsed.id,
            parsed.contract_id,
        );
    }
}

pub fn parse_event(event: ContractEvent) -> Result<ProcessedEvent> {
    let parsed = parse_event_metadata(event)?;
    let ev = match parsed.name.as_str() {
        // Pool events contracts/pool/src/pool.rs
        "new_nullifier_event" | "NewNullifierEvent" => {
            ProcessedEvent::Nullifier(parse_new_nullifier_event(parsed)?)
        }
        "new_commitment_event" | "NewCommitmentEvent" => {
            ProcessedEvent::Commitment(parse_new_commitment_event(parsed)?)
        }
        // Public keys registry contracts/public-key-registry/src/lib.rs
        "public_key_event" | "PublicKeyEvent" => {
            ProcessedEvent::PublicKey(parse_public_key_event(parsed)?)
        }
        // ASP membership events contracts/asp-membership
        "leaf_added" | "LeafAdded" => ProcessedEvent::LeafAdded(parse_leaf_added(parsed)?),
        // ASP non-membership events contracts/asp-non-membership
        // for now they're not collected - check also sdk/native/src/chain/indexer.rs
        // if they should be collected then
        // sdk/native/src/state/processor.rs should be extended
        // (to avoid looping over the unprocessed events)
        "leaf_inserted" | "LeafInserted" => {
            ProcessedEvent::LeafInserted(parse_leaf_inserted(parsed)?)
        }
        "leaf_updated" | "LeafUpdated" => ProcessedEvent::LeafUpdated(parse_leaf_updated(parsed)?),
        "leaf_deleted" | "LeafDeleted" => ProcessedEvent::LeafDeleted(parse_leaf_deleted(parsed)?),
        _ => return Err(anyhow!("unhandled event {}", parsed.name)),
    };
    Ok(ev)
}

// #[contractevent]
// #[derive(Clone)]
// pub struct NewNullifierEvent {
//     /// The nullifier that was spent
//     #[topic]
//     pub nullifier: U256,
// }
fn parse_new_nullifier_event(parsed: ParsedContractEvent) -> Result<NewNullifierEvent> {
    warn_unconsumed_gvk_ciphertext(&parsed);
    let ParsedContractEvent {
        id, name, topics, ..
    } = parsed;
    let nullifier_scval = topics
        .first()
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have a nullifier topic value"))?;
    let nullifier = Field::try_from_u256(scval_to_u256(nullifier_scval)?)?;
    Ok(NewNullifierEvent { id, nullifier })
}

// #[contractevent]
// #[derive(Clone)]
// pub struct NewCommitmentEvent {
//     /// The commitment hash added to the tree
//     #[topic]
//     pub commitment: U256,
//     /// Index position in the Merkle tree
//     pub index: u32,
//     /// Encrypted output data (decryptable by the recipient)
//     pub encrypted_output: Bytes,
// }
fn parse_new_commitment_event(parsed: ParsedContractEvent) -> Result<NewCommitmentEvent> {
    warn_unconsumed_gvk_ciphertext(&parsed);
    let ParsedContractEvent {
        id,
        name,
        topics,
        values,
        ..
    } = parsed;
    let commitment_scval = topics
        .first()
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have a commitment topic value"))?;
    let commitment = Field::try_from_u256(scval_to_u256(commitment_scval)?)?;
    let index_scval = values
        .get("index")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an index value"))?;
    let index = scval_to_u32(index_scval)?;
    let encrypted_output_scval = values
        .get("encrypted_output")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an encrypted_output value"))?;
    let encrypted_output = scval_to_bytes(encrypted_output_scval)?;
    Ok(NewCommitmentEvent {
        id,
        commitment,
        index,
        encrypted_output,
    })
}

// #[contractevent]
// #[derive(Clone)]
// pub struct PublicKeyEvent {
//     /// Address of the account owner
//     #[topic]
//     pub owner: Address,
//     /// X25519 encryption public key
//     pub encryption_key: Bytes,
//     /// BN254 note public key
//     pub note_key: Bytes,
// }
fn parse_public_key_event(parsed: ParsedContractEvent) -> Result<PublicKeyEvent> {
    let ParsedContractEvent {
        id,
        name,
        topics,
        values,
        ..
    } = parsed;
    let owner_scval = topics
        .first()
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have a owner topic value"))?;
    let owner = scval_to_address_string(owner_scval)?;
    let encryption_key_scval = values
        .get("encryption_key")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an encryption_key value"))?;
    let encryption_key = scval_to_bytes(encryption_key_scval)?.try_into()?;
    let note_key_scval = values
        .get("note_key")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an note_key value"))?;
    let note_key = scval_to_bytes(note_key_scval)?.try_into()?;
    Ok(PublicKeyEvent {
        id,
        owner,
        encryption_key,
        note_key,
    })
}

// Event emitted when a new leaf is added to the Merkle tree
// #[contractevent(topics = ["LeafAdded"])]
// struct LeafAddedEvent {
//     /// The leaf value that was inserted
//     leaf: U256,
//     /// Index position where the leaf was inserted
//     index: u64,
//     /// New Merkle root after insertion
//     root: U256,
// }
fn parse_leaf_added(parsed: ParsedContractEvent) -> Result<LeafAddedEvent> {
    let ParsedContractEvent {
        id, name, values, ..
    } = parsed;
    let leaf_scval = values
        .get("leaf")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an leaf value"))?;
    let leaf = Field::try_from_u256(scval_to_u256(leaf_scval)?)?;
    let index_scval = values
        .get("index")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an index value"))?;
    // TODO we try to fit into u32
    // do we really need u64 here
    let index = scval_to_u64(index_scval)?.try_into()?;
    let root_scval = values
        .get("root")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an root value"))?;
    let root = Field::try_from_u256(scval_to_u256(root_scval)?)?;
    Ok(LeafAddedEvent {
        id,
        leaf,
        index,
        root,
    })
}

// #[contractevent(topics = ["LeafInserted"])]
// struct LeafInsertedEvent {
//     key: U256,
//     value: U256,
//     root: U256,
// }
fn parse_leaf_inserted(parsed: ParsedContractEvent) -> Result<LeafInsertedEvent> {
    let ParsedContractEvent {
        id, name, values, ..
    } = parsed;
    let key_scval = values
        .get("key")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an key value"))?;
    let key = Field::try_from_u256(scval_to_u256(key_scval)?)?;
    let value_scval = values
        .get("value")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an value value"))?;
    let value = Field::try_from_u256(scval_to_u256(value_scval)?)?;
    let root_scval = values
        .get("root")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an root value"))?;
    let root = Field::try_from_u256(scval_to_u256(root_scval)?)?;
    Ok(LeafInsertedEvent {
        id,
        key,
        value,
        root,
    })
}

// #[contractevent(topics = ["LeafUpdated"])]
// struct LeafUpdatedEvent {
//     key: U256,
//     old_value: U256,
//     new_value: U256,
//     root: U256,
// }
fn parse_leaf_updated(parsed: ParsedContractEvent) -> Result<LeafUpdatedEvent> {
    let ParsedContractEvent {
        id, name, values, ..
    } = parsed;
    let key_scval = values
        .get("key")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an key value"))?;
    let key = Field::try_from_u256(scval_to_u256(key_scval)?)?;
    let old_value_scval = values
        .get("old_value")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an old_value value"))?;
    let old_value = Field::try_from_u256(scval_to_u256(old_value_scval)?)?;
    let new_value_scval = values
        .get("new_value")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an new_value value"))?;
    let new_value = Field::try_from_u256(scval_to_u256(new_value_scval)?)?;
    let root_scval = values
        .get("root")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an root value"))?;
    let root = Field::try_from_u256(scval_to_u256(root_scval)?)?;
    Ok(LeafUpdatedEvent {
        id,
        key,
        old_value,
        new_value,
        root,
    })
}

// #[contractevent(topics = ["LeafDeleted"])]
// struct LeafDeletedEvent {
//     key: U256,
//     root: U256,
// }
fn parse_leaf_deleted(parsed: ParsedContractEvent) -> Result<LeafDeletedEvent> {
    let ParsedContractEvent {
        id, name, values, ..
    } = parsed;
    let key_scval = values
        .get("key")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an key value"))?;
    let key = Field::try_from_u256(scval_to_u256(key_scval)?)?;
    let root_scval = values
        .get("root")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an root value"))?;
    let root = Field::try_from_u256(scval_to_u256(root_scval)?)?;
    Ok(LeafDeletedEvent { id, key, root })
}

#[cfg(test)]
mod gvk_passthrough_tests {
    use super::*;
    use stellar_xdr::{self as xdr, WriteXdr};

    fn b64(val: &xdr::ScVal) -> String {
        val.to_xdr_base64(xdr::Limits::none())
            .expect("encode scval")
    }

    fn symbol(s: &str) -> xdr::ScVal {
        xdr::ScVal::Symbol(xdr::ScSymbol(s.try_into().expect("symbol")))
    }

    fn u256(v: u64) -> xdr::ScVal {
        xdr::ScVal::U256(xdr::UInt256Parts {
            hi_hi: 0,
            hi_lo: 0,
            lo_hi: 0,
            lo_lo: v,
        })
    }

    /// A `GvkCiphertext` as `pool-gvk` encodes it: a `#[contracttype]` struct
    /// serializes to an `ScVal::Map` keyed by field-name symbols.
    fn gvk_ciphertext() -> xdr::ScVal {
        let point = xdr::ScVal::Map(Some(xdr::ScMap(
            vec![
                xdr::ScMapEntry {
                    key: symbol("x"),
                    val: u256(11),
                },
                xdr::ScMapEntry {
                    key: symbol("y"),
                    val: u256(12),
                },
            ]
            .try_into()
            .expect("point map"),
        )));
        xdr::ScVal::Map(Some(xdr::ScMap(
            vec![
                xdr::ScMapEntry {
                    key: symbol("c1"),
                    val: u256(1),
                },
                xdr::ScMapEntry {
                    key: symbol("c2"),
                    val: u256(2),
                },
                xdr::ScMapEntry {
                    key: symbol("c3"),
                    val: u256(3),
                },
                xdr::ScMapEntry {
                    key: symbol("r"),
                    val: point,
                },
            ]
            .try_into()
            .expect("ciphertext map"),
        )))
    }

    fn commitment_event(with_gvk: bool) -> ContractEvent {
        let mut entries = vec![
            xdr::ScMapEntry {
                key: symbol("encrypted_output"),
                val: xdr::ScVal::Bytes(xdr::ScBytes(vec![7, 8, 9].try_into().expect("bytes"))),
            },
            xdr::ScMapEntry {
                key: symbol("index"),
                val: xdr::ScVal::U32(4),
            },
        ];
        if with_gvk {
            entries.push(xdr::ScMapEntry {
                key: symbol(GVK_CIPHERTEXT_FIELD),
                val: gvk_ciphertext(),
            });
        }
        // Soroban emits map entries in key order.
        entries.sort_by(|a, b| a.key.cmp(&b.key));

        ContractEvent {
            id: "0000000000000000001-0000000000".to_string(),
            ledger: 1,
            contract_id: "CPOOLGVK".to_string(),
            topics: vec![b64(&symbol("new_commitment_event")), b64(&u256(99))],
            value: b64(&xdr::ScVal::Map(Some(xdr::ScMap(
                entries.try_into().expect("data map"),
            )))),
        }
    }

    fn nullifier_event(with_gvk: bool) -> ContractEvent {
        let entries = if with_gvk {
            vec![xdr::ScMapEntry {
                key: symbol(GVK_CIPHERTEXT_FIELD),
                val: gvk_ciphertext(),
            }]
        } else {
            vec![]
        };

        ContractEvent {
            id: "0000000000000000002-0000000000".to_string(),
            ledger: 1,
            contract_id: "CPOOLGVK".to_string(),
            topics: vec![b64(&symbol("new_nullifier_event")), b64(&u256(55))],
            value: b64(&xdr::ScVal::Map(Some(xdr::ScMap(
                entries.try_into().expect("data map"),
            )))),
        }
    }

    /// Guards the two tests below from passing vacuously: if the fixture did
    /// not actually carry `gvk_ciphertext`, "parses identically" would be
    /// trivially true and would prove nothing.
    #[test]
    fn gvk_fixtures_really_carry_the_field() {
        for (event, expected) in [
            (commitment_event(true), true),
            (commitment_event(false), false),
            (nullifier_event(true), true),
            (nullifier_event(false), false),
        ] {
            let parsed = parse_event_metadata(event).expect("parse metadata");
            assert_eq!(
                parsed.values.contains_key(GVK_CIPHERTEXT_FIELD),
                expected,
                "fixture `{}` gvk presence",
                parsed.name
            );
        }
    }

    /// The deferral of GVK support rests on this: a `pool-gvk` commitment
    /// event must decode to exactly what the equivalent `pool` event decodes
    /// to, with the unknown field ignored rather than breaking the parse.
    #[test]
    fn commitment_event_parses_identically_with_and_without_gvk_ciphertext() {
        let ProcessedEvent::Commitment(without) =
            parse_event(commitment_event(false)).expect("parse pool event")
        else {
            panic!("expected a commitment event");
        };
        let ProcessedEvent::Commitment(with) =
            parse_event(commitment_event(true)).expect("parse pool-gvk event")
        else {
            panic!("expected a commitment event");
        };

        assert_eq!(with.commitment, without.commitment);
        assert_eq!(with.index, without.index);
        assert_eq!(with.encrypted_output, without.encrypted_output);
    }

    #[test]
    fn nullifier_event_parses_identically_with_and_without_gvk_ciphertext() {
        let ProcessedEvent::Nullifier(without) =
            parse_event(nullifier_event(false)).expect("parse pool event")
        else {
            panic!("expected a nullifier event");
        };
        let ProcessedEvent::Nullifier(with) =
            parse_event(nullifier_event(true)).expect("parse pool-gvk event")
        else {
            panic!("expected a nullifier event");
        };

        assert_eq!(with.nullifier, without.nullifier);
    }
}
