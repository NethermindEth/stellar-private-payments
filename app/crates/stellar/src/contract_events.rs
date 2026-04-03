

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
