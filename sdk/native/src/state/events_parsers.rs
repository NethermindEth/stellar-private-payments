use crate::{
    chain::{
        ParsedContractEvent, event_name, parse_event_metadata, scval_to_address_string,
        scval_to_bytes, scval_to_global_view_key_ciphertext,
        scval_to_optional_global_view_key_ciphertext, scval_to_u32, scval_to_u64, scval_to_u256,
    },
    types::{
        ContractEvent, EncryptionPublicKey, Field, LeafAddedEvent, LeafDeletedEvent,
        LeafInsertedEvent, LeafUpdatedEvent, NewCommitmentEvent, NewNullifierEvent, ProcessedEvent,
        PublicKeyEvent,
    },
};
use anyhow::{Result, anyhow};
use ed25519_dalek::VerifyingKey;

/// Field name emitted by `contracts/pool-gvk`'s pool events, carrying the
/// admin-decryptable ciphertext of the note.
const GVK_CIPHERTEXT_FIELD: &str = "gvk_ciphertext";

/// Parses a contract event, or returns `None` for an event name this version
/// does not read.
///
/// # Errors
///
/// Returns an error if the event's topics or data do not decode into the
/// fields its name requires.
pub fn parse_event(event: ContractEvent) -> Result<Option<ProcessedEvent>> {
    // Decode the data of known events only, so an unknown one is skipped
    // whatever its shape.
    let name = event_name(&event.topics)?;
    let parsed = || parse_event_metadata(event);
    let ev = match name.as_str() {
        // Pool events contracts/pool/src/pool.rs (pool-gvk adds
        // `gvk_ciphertext`)
        "new_nullifier_event" | "NewNullifierEvent" => {
            ProcessedEvent::Nullifier(parse_new_nullifier_event(parsed()?)?)
        }
        "new_commitment_event" | "NewCommitmentEvent" => {
            ProcessedEvent::Commitment(parse_new_commitment_event(parsed()?)?)
        }
        // Public keys registry contracts/public-key-registry/src/lib.rs
        "public_key_event" | "PublicKeyEvent" => match parse_public_key_event(parsed()?)? {
            Some(ev) => ProcessedEvent::PublicKey(ev),
            None => return Ok(None),
        },
        // ASP membership events contracts/asp-membership
        "leaf_added" | "LeafAdded" => ProcessedEvent::LeafAdded(parse_leaf_added(parsed()?)?),
        // ASP non-membership events contracts/asp-non-membership
        // Parsed but not stored; the processor marks them processed.
        "leaf_inserted" | "LeafInserted" => {
            ProcessedEvent::LeafInserted(parse_leaf_inserted(parsed()?)?)
        }
        "leaf_updated" | "LeafUpdated" => {
            ProcessedEvent::LeafUpdated(parse_leaf_updated(parsed()?)?)
        }
        "leaf_deleted" | "LeafDeleted" => {
            ProcessedEvent::LeafDeleted(parse_leaf_deleted(parsed()?)?)
        }
        _ => {
            tracing::debug!(%name, "skipping an event this version does not read");
            return Ok(None);
        }
    };
    Ok(Some(ev))
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
//     /// Edwards encoding of the X25519 encryption public key
//     pub encryption_key: Bytes,
//     /// BN254 note public key
//     pub note_key: Bytes,
// }
//
// The encryption key is stored in its X25519 form. A key that is not a curve
// point skips the event, since a parse error stops all later processing.
fn parse_public_key_event(parsed: ParsedContractEvent) -> Result<Option<PublicKeyEvent>> {
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
    let edwards: [u8; 32] = scval_to_bytes(encryption_key_scval)?
        .try_into()
        .map_err(|_| anyhow!("event `{name}` id {id}: encryption_key is not 32 bytes"))?;
    let note_key_scval = values
        .get("note_key")
        .ok_or_else(|| anyhow!("event `{name}` id {id} should have an note_key value"))?;
    let note_key = scval_to_bytes(note_key_scval)?.try_into()?;
    let Ok(encryption_key) = VerifyingKey::from_bytes(&edwards) else {
        tracing::warn!(%id, "skipping a registration whose encryption key is not a curve point");
        return Ok(None);
    };
    Ok(Some(PublicKeyEvent {
        id,
        owner,
        encryption_key: EncryptionPublicKey(encryption_key.to_montgomery().to_bytes()),
        note_key,
    }))
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
    use crate::types::{Field, U256};
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
        let Some(ProcessedEvent::Commitment(without)) =
            parse_event(commitment_event(false)).expect("parse pool event")
        else {
            panic!("expected a commitment event");
        };
        let Some(ProcessedEvent::Commitment(with)) =
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
        let Some(ProcessedEvent::Nullifier(without)) =
            parse_event(nullifier_event(false)).expect("parse pool event")
        else {
            panic!("expected a nullifier event");
        };
        let Some(ProcessedEvent::Nullifier(with)) =
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
mod asp_non_membership_tests {
    use super::*;
    use crate::{
        state::test_events::{leaf_event, u256},
        types::U256,
    };
    use stellar_xdr as xdr;

    const ID: &str = "0000000000000000001-0000000000";

    type Fields = Vec<(&'static str, xdr::ScVal)>;

    fn field(v: u64) -> Field {
        Field(U256::from(v))
    }

    fn inserted() -> Fields {
        vec![("key", u256(1)), ("value", u256(42)), ("root", u256(7))]
    }

    fn updated() -> Fields {
        vec![
            ("key", u256(1)),
            ("old_value", u256(42)),
            ("new_value", u256(43)),
            ("root", u256(8)),
        ]
    }

    fn deleted() -> Fields {
        vec![("key", u256(1)), ("root", u256(9))]
    }

    /// Each event's contract name, its snake_case name, and its fields.
    fn leaf_events() -> [(&'static str, &'static str, Fields); 3] {
        [
            ("LeafInserted", "leaf_inserted", inserted()),
            ("LeafUpdated", "leaf_updated", updated()),
            ("LeafDeleted", "leaf_deleted", deleted()),
        ]
    }

    /// Parses every event built by replacing one field of each leaf event with
    /// `val`, and returns the error message for each.
    fn errors_with_each_field_replaced_by(val: &xdr::ScVal) -> Result<Vec<(String, String)>> {
        let mut errors = vec![];
        for (name, _, fields) in leaf_events() {
            for (replaced, _) in &fields {
                let fields: Fields = fields
                    .iter()
                    .map(|(k, v)| {
                        (
                            *k,
                            if k == replaced {
                                val.clone()
                            } else {
                                v.clone()
                            },
                        )
                    })
                    .collect();
                let err = parse_event(leaf_event(ID, name, &fields)?)
                    .expect_err("a field of the wrong shape");
                errors.push((format!("{name}.{replaced}"), err.to_string()));
            }
        }
        Ok(errors)
    }

    #[test]
    fn leaf_inserted_parses_its_key_value_and_root() -> Result<()> {
        let Some(ProcessedEvent::LeafInserted(ev)) =
            parse_event(leaf_event(ID, "LeafInserted", &inserted())?)?
        else {
            panic!("expected a LeafInserted event");
        };

        assert_eq!(ev.id, ID);
        assert_eq!(ev.key, field(1));
        assert_eq!(ev.value, field(42));
        assert_eq!(ev.root, field(7));
        Ok(())
    }

    /// The contract no longer emits `LeafUpdated` (removed in #253), but the
    /// SDK still decodes it.
    #[test]
    fn leaf_updated_parses_its_key_both_values_and_root() -> Result<()> {
        let Some(ProcessedEvent::LeafUpdated(ev)) =
            parse_event(leaf_event(ID, "LeafUpdated", &updated())?)?
        else {
            panic!("expected a LeafUpdated event");
        };

        assert_eq!(ev.id, ID);
        assert_eq!(ev.key, field(1));
        assert_eq!(ev.old_value, field(42));
        assert_eq!(ev.new_value, field(43));
        assert_eq!(ev.root, field(8));
        Ok(())
    }

    #[test]
    fn leaf_deleted_parses_its_key_and_root() -> Result<()> {
        let Some(ProcessedEvent::LeafDeleted(ev)) =
            parse_event(leaf_event(ID, "LeafDeleted", &deleted())?)?
        else {
            panic!("expected a LeafDeleted event");
        };

        assert_eq!(ev.id, ID);
        assert_eq!(ev.key, field(1));
        assert_eq!(ev.root, field(9));
        Ok(())
    }

    #[test]
    fn snake_case_leaf_event_names_parse_like_the_contract_names() -> Result<()> {
        for (name, snake_name, fields) in leaf_events() {
            let parsed = format!("{:?}", parse_event(leaf_event(ID, name, &fields)?)?);
            let snake_parsed = format!("{:?}", parse_event(leaf_event(ID, snake_name, &fields)?)?);

            // The variants are named after the contract events.
            assert!(parsed.starts_with(&format!("Some({name}(")), "{parsed}");
            assert_eq!(snake_parsed, parsed);
        }
        Ok(())
    }

    #[test]
    fn a_leaf_event_missing_a_field_fails_naming_the_field() -> Result<()> {
        for (name, _, fields) in leaf_events() {
            for (missing, _) in &fields {
                let fields: Fields = fields
                    .iter()
                    .filter(|(k, _)| k != missing)
                    .cloned()
                    .collect();

                let err = parse_event(leaf_event(ID, name, &fields)?).expect_err("missing field");

                let message = err.to_string();
                assert!(
                    message.contains(ID) && message.contains(&format!("{missing} value")),
                    "{name} without {missing}: {message}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn a_leaf_event_field_that_is_not_a_u256_fails() -> Result<()> {
        for (field, message) in errors_with_each_field_replaced_by(&xdr::ScVal::U32(1))? {
            assert!(
                message.contains("Unexpected ScVal") && message.contains("U32(1)"),
                "{field}: {message}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_leaf_event_field_outside_the_scalar_field_fails() -> Result<()> {
        let too_large = xdr::ScVal::U256(xdr::UInt256Parts {
            hi_hi: u64::MAX,
            hi_lo: 0,
            lo_hi: 0,
            lo_lo: 0,
        });

        for (field, message) in errors_with_each_field_replaced_by(&too_large)? {
            assert!(
                message.contains("field element out of range"),
                "{field}: {message}"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod asp_membership_tests {
    use super::*;
    use crate::{
        state::test_events::{membership_event, u256},
        types::U256,
    };
    use stellar_xdr as xdr;

    const ID: &str = "0000000000000000001-0000000000";

    fn fields(index: xdr::ScVal) -> Vec<(&'static str, xdr::ScVal)> {
        vec![("leaf", u256(42)), ("index", index), ("root", u256(7))]
    }

    fn parse(fields: &[(&str, xdr::ScVal)]) -> Result<Option<ProcessedEvent>> {
        parse_event(membership_event(ID, "LeafAdded", fields)?)
    }

    fn parsed_index(index: u64) -> Result<u32> {
        let Some(ProcessedEvent::LeafAdded(ev)) = parse(&fields(xdr::ScVal::U64(index)))? else {
            panic!("expected a LeafAdded event");
        };
        Ok(ev.index)
    }

    #[test]
    fn leaf_added_parses_its_leaf_index_and_root() -> Result<()> {
        let Some(ProcessedEvent::LeafAdded(ev)) = parse(&fields(xdr::ScVal::U64(5)))? else {
            panic!("expected a LeafAdded event");
        };

        assert_eq!(ev.id, ID);
        assert_eq!(ev.leaf, Field(U256::from(42)));
        assert_eq!(ev.index, 5);
        assert_eq!(ev.root, Field(U256::from(7)));
        Ok(())
    }

    #[test]
    fn snake_case_leaf_added_parses_like_the_contract_name() -> Result<()> {
        let fields = fields(xdr::ScVal::U64(5));
        let parsed = format!("{:?}", parse(&fields)?);
        let snake_parsed = format!(
            "{:?}",
            parse_event(membership_event(ID, "leaf_added", &fields)?)?
        );

        assert!(parsed.starts_with("Some(LeafAdded("), "{parsed}");
        assert_eq!(snake_parsed, parsed);
        Ok(())
    }

    #[test]
    fn a_leaf_added_event_missing_a_field_fails_naming_the_field() -> Result<()> {
        for missing in ["leaf", "index", "root"] {
            let fields: Vec<_> = fields(xdr::ScVal::U64(5))
                .into_iter()
                .filter(|(k, _)| *k != missing)
                .collect();

            let err = parse(&fields).expect_err("missing field");

            let message = err.to_string();
            assert!(
                message.contains(ID) && message.contains(&format!("{missing} value")),
                "LeafAdded without {missing}: {message}"
            );
        }
        Ok(())
    }

    /// The contract caps the tree at 32 levels, so every index it emits fits
    /// in the `u32` the SDK stores.
    #[test]
    fn a_leaf_added_index_of_u32_max_parses() -> Result<()> {
        assert_eq!(parsed_index(u64::from(u32::MAX))?, u32::MAX);
        Ok(())
    }

    #[test]
    fn a_leaf_added_index_above_u32_max_fails_instead_of_truncating() -> Result<()> {
        let too_large = u64::from(u32::MAX).checked_add(1).expect("fits in u64");

        let err = parse(&fields(xdr::ScVal::U64(too_large))).expect_err("index above u32");

        assert!(
            err.to_string()
                .contains("out of range integral type conversion"),
            "{err}"
        );
        Ok(())
    }

    #[test]
    fn a_leaf_added_index_that_is_not_a_u64_fails() -> Result<()> {
        let err = parse(&fields(xdr::ScVal::U32(5))).expect_err("u32 index");

        let message = err.to_string();
        assert!(
            message.contains("Unexpected ScVal") && message.contains("U32(5)"),
            "{message}"
        );
        Ok(())
    }

    #[test]
    fn a_leaf_added_leaf_or_root_outside_the_scalar_field_fails() -> Result<()> {
        let too_large = xdr::ScVal::U256(xdr::UInt256Parts {
            hi_hi: u64::MAX,
            hi_lo: 0,
            lo_hi: 0,
            lo_lo: 0,
        });

        for replaced in ["leaf", "root"] {
            let fields: Vec<_> = fields(xdr::ScVal::U64(5))
                .into_iter()
                .map(|(k, v)| (k, if k == replaced { too_large.clone() } else { v }))
                .collect();

            let err = parse(&fields).expect_err("out-of-range field element");

            let message = err.to_string();
            assert!(
                message.contains("field element out of range"),
                "{replaced}: {message}"
            );
        }
        Ok(())
    }
}
