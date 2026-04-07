use types::{ContractEvent, ProcessedEvent, NewNullifierEvent, NewCommitmentEvent, EncryptionPublicKey, NotePublicKey, PublicKeyEvent, LeafAddedEvent, LeafInsertedEvent, LeafUpdatedEvent, LeafDeletedEvent};
use stellar::{parse_event_metadata, ParsedContractEvent, scval_to_u32, scval_to_u64, scval_to_u256, scval_to_bytes, scval_to_address_string};
use anyhow::{anyhow, Result};

pub fn parse_event(event: ContractEvent) -> Result<ProcessedEvent> {
    let parsed = parse_event_metadata(event)?;
    let ev = match parsed.name.as_str() {
        // Pool events contracts/pool/src/pool.rs
        "new_nullifier_event" => ProcessedEvent::Nullifier(parse_new_nullifier_event(parsed)?),
        "public_key_event" => ProcessedEvent::PublicKey(parse_public_key_event(parsed)?),
        "new_commitment_event" => ProcessedEvent::Commitment(parse_new_commitment_event(parsed)?),
        // ASP membership events contracts/asp-membership
        "leaf_added" => ProcessedEvent::LeafAdded(parse_leaf_added(parsed)?),
        // ASP non-membership events contracts/asp-non-membership
        "leaf_inserted" => ProcessedEvent::LeafInserted(parse_leaf_inserted(parsed)?),
        "leaf_updated" => ProcessedEvent::LeafUpdated(parse_leaf_updated(parsed)?),
        "leaf_deleted" => ProcessedEvent::LeafDeleted(parse_leaf_deleted(parsed)?),
        _ => return Err(anyhow!("unhandled event {}", parsed.name))
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
    let ParsedContractEvent{id, name, topics, values, ..} = parsed;
    let nullifier_scval = topics.first().ok_or_else(|| anyhow!("event `{name}` id {id} should have a nullifier topic value"))?;
    let nullifier = format!("0x{:064x}", scval_to_u256(nullifier_scval)?);
    Ok(NewNullifierEvent{
        id,
        nullifier
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
// }
fn parse_new_commitment_event(parsed: ParsedContractEvent) -> Result<NewCommitmentEvent> {
    let ParsedContractEvent{id, name, topics, values, ..} = parsed;
    let commitment_scval = topics.first().ok_or_else(|| anyhow!("event `{name}` id {id} should have a commitment topic value"))?;
    let commitment = format!("0x{:064x}", scval_to_u256(commitment_scval)?);
    let index_scval = values.get("index").ok_or_else(|| anyhow!("event `{name}` id {id} should have an index value"))?;
    let index = scval_to_u32(index_scval)?;
    let encrypted_output_scval = values.get("encrypted_output").ok_or_else(|| anyhow!("event `{name}` id {id} should have an encrypted_output value"))?;
    let encrypted_output = scval_to_bytes(encrypted_output_scval)?;
    Ok(NewCommitmentEvent{
        id,
        commitment,
        index,
        encrypted_output
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
    let ParsedContractEvent{id, name, topics, values, ..} = parsed;
    let owner_scval = topics.first().ok_or_else(|| anyhow!("event `{name}` id {id} should have a owner topic value"))?;
    let owner = scval_to_address_string(owner_scval)?;
    let encryption_key_scval = values.get("encryption_key").ok_or_else(|| anyhow!("event `{name}` id {id} should have an encryption_key value"))?;
    let encryption_key = scval_to_bytes(encryption_key_scval)?.try_into()?;
    let note_key_scval = values.get("note_key").ok_or_else(|| anyhow!("event `{name}` id {id} should have an note_key value"))?;
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
    let ParsedContractEvent{id, name, topics, values, ..} = parsed;
    let leaf_scval = values.get("leaf").ok_or_else(|| anyhow!("event `{name}` id {id} should have an leaf value"))?;
    let leaf = format!("0x{:064x}", scval_to_u256(leaf_scval)?);
    let index_scval = values.get("index").ok_or_else(|| anyhow!("event `{name}` id {id} should have an index value"))?;
    // TODO we try to fit into u32
    // do we really need u64 here
    let index = scval_to_u64(index_scval)?.try_into()?;
    let root_scval = values.get("root").ok_or_else(|| anyhow!("event `{name}` id {id} should have an root value"))?;
    let root = format!("0x{:064x}", scval_to_u256(root_scval)?);
    Ok(LeafAddedEvent{
        id,
        leaf,
        index,
        root
    })
}

// #[contractevent(topics = ["LeafInserted"])]
// struct LeafInsertedEvent {
//     key: U256,
//     value: U256,
//     root: U256,
// }
fn parse_leaf_inserted(parsed: ParsedContractEvent) -> Result<LeafInsertedEvent> {
    let ParsedContractEvent{id, name, topics, values, ..} = parsed;
    let key_scval = values.get("key").ok_or_else(|| anyhow!("event `{name}` id {id} should have an key value"))?;
    let key = format!("0x{:064x}", scval_to_u256(key_scval)?);
    let value_scval = values.get("value").ok_or_else(|| anyhow!("event `{name}` id {id} should have an value value"))?;
    let value = format!("0x{:064x}", scval_to_u256(value_scval)?);
    let root_scval = values.get("root").ok_or_else(|| anyhow!("event `{name}` id {id} should have an root value"))?;
    let root = format!("0x{:064x}", scval_to_u256(root_scval)?);
    Ok(LeafInsertedEvent{
        id,
        key,
        value,
        root
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
    let ParsedContractEvent{id, name, topics, values, ..} = parsed;
    let key_scval = values.get("key").ok_or_else(|| anyhow!("event `{name}` id {id} should have an key value"))?;
    let key = format!("0x{:064x}", scval_to_u256(key_scval)?);
    let old_value_scval = values.get("old_value").ok_or_else(|| anyhow!("event `{name}` id {id} should have an old_value value"))?;
    let old_value = format!("0x{:064x}", scval_to_u256(old_value_scval)?);
    let new_value_scval = values.get("new_value").ok_or_else(|| anyhow!("event `{name}` id {id} should have an new_value value"))?;
    let new_value = format!("0x{:064x}", scval_to_u256(new_value_scval)?);
    let root_scval = values.get("root").ok_or_else(|| anyhow!("event `{name}` id {id} should have an root value"))?;
    let root = format!("0x{:064x}", scval_to_u256(root_scval)?);
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
    let ParsedContractEvent{id, name, topics, values, ..} = parsed;
    let key_scval = values.get("key").ok_or_else(|| anyhow!("event `{name}` id {id} should have an key value"))?;
    let key = format!("0x{:064x}", scval_to_u256(key_scval)?);
    let root_scval = values.get("root").ok_or_else(|| anyhow!("event `{name}` id {id} should have an root value"))?;
    let root = format!("0x{:064x}", scval_to_u256(root_scval)?);
    Ok(LeafDeletedEvent {
        id,
        key,
        root,
    })
}
