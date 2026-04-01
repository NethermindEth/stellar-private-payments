

// ASP membership
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

// ASP non membership
// #[contractevent(topics = ["LeafInserted"])]
// struct LeafInsertedEvent {
//     key: U256,
//     value: U256,
//     root: U256,
// }

// #[contractevent(topics = ["LeafUpdated"])]
// struct LeafUpdatedEvent {
//     key: U256,
//     old_value: U256,
//     new_value: U256,
//     root: U256,
// }

// #[contractevent(topics = ["LeafDeleted"])]
// struct LeafDeletedEvent {
//     key: U256,
//     root: U256,
// }

// Pool
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

// Event emitted when a nullifier is spent
//
// This event allows off-chain observers to track which UTXOs have been spent.
// #[contractevent]
// #[derive(Clone)]
// pub struct NewNullifierEvent {
//     /// The nullifier that was spent
//     #[topic]
//     pub nullifier: U256,
// }

// Event emitted when a user registers their public keys
//
// This event allows other users to discover keys for sending private
// transfers. Two key types are required:
// - encryption_key: X25519 key for encrypting note data (amount, blinding)
// - note_key: BN254 key for creating commitments in the ZK circuit
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

// const pageEvents = (result.events || []).map(event => ({
//     id: event.id,
//     ledger: event.ledger,
//     type: event.type,
//     contractId: event.contractId,
//     topic: event.topic.map(t => scValToNative(xdr.ScVal.fromXDR(t, 'base64'))),
//     value: scValToNative(xdr.ScVal.fromXDR(event.value, 'base64')),
// }));
//
pub struct EventData {
    pub id: String,
    pub ledger: u32,
    pub typ: String,
    pub contract_id: String,
    pub topic: String,
    pub value: String,
}
