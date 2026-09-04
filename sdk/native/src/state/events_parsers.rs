use crate::{
    chain::{
        ParsedContractEvent, parse_event_metadata, scval_to_address_string, scval_to_bytes,
        scval_to_global_view_key_ciphertext, scval_to_optional_global_view_key_ciphertext,
        scval_to_u32, scval_to_u64, scval_to_u256,
    },
    types::{
        AdminUpdatedEvent, ContractEvent, Field, LeafAddedEvent, LeafDeletedEvent,
        LeafInsertedEvent, LeafUpdatedEvent, NewCommitmentEvent, NewNullifierEvent,
        PauseChangedEvent, ProcessedEvent, PublicKeyEvent,
    },
};
use anyhow::{Result, anyhow};
use stellar_xdr as xdr;

/// Field name emitted by `contracts/pool-gvk`'s pool events, carrying the
/// admin-decryptable ciphertext of the note.
const GVK_CIPHERTEXT_FIELD: &str = "gvk_ciphertext";

pub fn parse_event(event: ContractEvent) -> Result<ProcessedEvent> {
    let parsed = parse_event_metadata(event)?;
    let ev = match parsed.name.as_str() {
        // Pool events contracts/pool/src/pool.rs (pool-gvk adds `gvk_ciphertext`)
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
        // Governance events contracts/soroban-utils/src/{utils,pausable}.rs, emitted by
        // every contract that exposes an admin rotation or a pause
        "admin_updated" | "AdminUpdated" => {
            ProcessedEvent::AdminUpdated(parse_admin_updated(parsed)?)
        }
        "pause_changed" | "PauseChanged" => {
            ProcessedEvent::PauseChanged(parse_pause_changed(parsed)?)
        }
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
//     /// GVK ciphertext of the spent input (`pool-gvk`, TRACEABLE only)
//     pub gvk_ciphertext: Option<GvkCiphertext>,
// }
fn parse_new_nullifier_event(parsed: ParsedContractEvent) -> Result<NewNullifierEvent> {
    let ParsedContractEvent {
        id,
        name,
        topics,
        values,
        ..
    } = parsed;
    let nullifier_scval = topics
        .first()
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have a nullifier topic value"))?;
    let nullifier = Field::try_from_u256(scval_to_u256(nullifier_scval)?)?;
    let gvk_ciphertext = match values.get(GVK_CIPHERTEXT_FIELD) {
        None => None,
        Some(val) => scval_to_optional_global_view_key_ciphertext(val)
            .map_err(|e| anyhow!("event `{name}` id {id}: {e}"))?,
    };
    Ok(NewNullifierEvent {
        id,
        nullifier,
        gvk_ciphertext,
    })
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
//     /// GVK ciphertext of this output note (`pool-gvk` only)
//     pub gvk_ciphertext: GvkCiphertext,
// }
fn parse_new_commitment_event(parsed: ParsedContractEvent) -> Result<NewCommitmentEvent> {
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
    let gvk_ciphertext = values
        .get(GVK_CIPHERTEXT_FIELD)
        .map(|val| {
            scval_to_global_view_key_ciphertext(val)
                .map_err(|e| anyhow!("event `{name}` id {id}: {e}"))
        })
        .transpose()?;
    Ok(NewCommitmentEvent {
        id,
        commitment,
        index,
        encrypted_output,
        gvk_ciphertext,
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

// #[contractevent]
// #[derive(Clone, Debug, Eq, PartialEq)]
// pub struct AdminUpdated {
//     pub old_admin: Address,
//     pub new_admin: Address,
// }
fn parse_admin_updated(parsed: ParsedContractEvent) -> Result<AdminUpdatedEvent> {
    let ParsedContractEvent {
        id, name, values, ..
    } = parsed;
    let old_admin_scval = values
        .get("old_admin")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an old_admin value"))?;
    let old_admin = scval_to_address_string(old_admin_scval)?;
    let new_admin_scval = values
        .get("new_admin")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an new_admin value"))?;
    let new_admin = scval_to_address_string(new_admin_scval)?;
    Ok(AdminUpdatedEvent {
        id,
        old_admin,
        new_admin,
    })
}

// #[contractevent]
// #[derive(Clone, Debug, Eq, PartialEq)]
// pub struct PauseChanged {
//     pub flags: u32,
//     pub until: Option<u32>,
// }
fn parse_pause_changed(parsed: ParsedContractEvent) -> Result<PauseChangedEvent> {
    let ParsedContractEvent {
        id, name, values, ..
    } = parsed;
    let flags_scval = values
        .get("flags")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an flags value"))?;
    let flags = scval_to_u32(flags_scval)?;
    let until_scval = values
        .get("until")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an until value"))?;
    let until = match until_scval {
        xdr::ScVal::Void => None,
        xdr::ScVal::U32(ledger) => Some(*ledger),
        other => {
            return Err(anyhow!(
                "event `{name}` id {id} has an until value that is neither void nor u32: {other:?}"
            ));
        }
    };
    Ok(PauseChangedEvent { id, flags, until })
}

#[cfg(test)]
mod gvk_passthrough_tests {
    use super::*;
    use crate::types::{Field, U256};
    use stellar_xdr::{self as xdr, WriteXdr};

    pub(super) fn b64(val: &xdr::ScVal) -> String {
        val.to_xdr_base64(xdr::Limits::none())
            .expect("encode scval")
    }

    pub(super) fn symbol(s: &str) -> xdr::ScVal {
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
        assert!(without.gvk_ciphertext.is_none());
        let ct = with.gvk_ciphertext.expect("gvk ciphertext");
        assert_eq!(ct.c1, Field(U256::from(1)));
        assert_eq!(ct.r.x, Field(U256::from(11)));
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
        assert!(without.gvk_ciphertext.is_none());
        let ct = with.gvk_ciphertext.expect("gvk ciphertext");
        assert_eq!(ct.c2, Field(U256::from(2)));
    }
}

#[cfg(test)]
mod governance_event_tests {
    use super::{
        gvk_passthrough_tests::{b64, symbol},
        *,
    };
    use stellar_xdr as xdr;

    fn address(byte: u8) -> xdr::ScVal {
        xdr::ScVal::Address(xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(
            [byte; 32],
        ))))
    }

    fn event(name: &str, entries: Vec<xdr::ScMapEntry>) -> ContractEvent {
        let mut entries = entries;
        // Soroban emits map entries in key order.
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        ContractEvent {
            id: "0000000000000000003-0000000000".to_string(),
            ledger: 1,
            contract_id: "CPOOL".to_string(),
            topics: vec![b64(&symbol(name))],
            value: b64(&xdr::ScVal::Map(Some(xdr::ScMap(
                entries.try_into().expect("data map"),
            )))),
        }
    }

    fn admin_updated_event(with_new_admin: bool) -> ContractEvent {
        let mut entries = vec![xdr::ScMapEntry {
            key: symbol("old_admin"),
            val: address(1),
        }];
        if with_new_admin {
            entries.push(xdr::ScMapEntry {
                key: symbol("new_admin"),
                val: address(2),
            });
        }
        event("admin_updated", entries)
    }

    fn pause_changed_event(until: xdr::ScVal) -> ContractEvent {
        event(
            "pause_changed",
            vec![
                xdr::ScMapEntry {
                    key: symbol("flags"),
                    val: xdr::ScVal::U32(5),
                },
                xdr::ScMapEntry {
                    key: symbol("until"),
                    val: until,
                },
            ],
        )
    }

    #[test]
    fn admin_updated_parses_both_addresses() {
        let ProcessedEvent::AdminUpdated(ev) =
            parse_event(admin_updated_event(true)).expect("parse admin_updated")
        else {
            panic!("expected an admin updated event");
        };

        assert_eq!(ev.id, "0000000000000000003-0000000000");
        assert_eq!(
            ev.old_admin,
            "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526"
        );
        assert_eq!(
            ev.new_admin,
            "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ"
        );
    }

    #[test]
    fn admin_updated_without_new_admin_fails() {
        let err = parse_event(admin_updated_event(false))
            .expect_err("an admin_updated event without new_admin must not parse");

        assert!(err.to_string().contains("new_admin"), "{err}");
    }

    #[test]
    fn pause_changed_reads_an_untimed_pause_as_none() {
        let ProcessedEvent::PauseChanged(ev) =
            parse_event(pause_changed_event(xdr::ScVal::Void)).expect("parse pause_changed")
        else {
            panic!("expected a pause changed event");
        };

        assert_eq!(ev.flags, 5);
        assert_eq!(ev.until, None);
    }

    #[test]
    fn pause_changed_reads_a_timed_pause_as_some() {
        let ProcessedEvent::PauseChanged(ev) =
            parse_event(pause_changed_event(xdr::ScVal::U32(42))).expect("parse pause_changed")
        else {
            panic!("expected a pause changed event");
        };

        assert_eq!(ev.flags, 5);
        assert_eq!(ev.until, Some(42));
    }

    #[test]
    fn pause_changed_with_a_non_ledger_until_names_the_event_id() {
        let err = parse_event(pause_changed_event(xdr::ScVal::Bool(true)))
            .expect_err("an until that is neither void nor u32 must not parse");

        let message = err.to_string();
        assert!(
            message.contains("0000000000000000003-0000000000"),
            "{message}"
        );
        assert!(message.contains("until"), "{message}");
    }
}
