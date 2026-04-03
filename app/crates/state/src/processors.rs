// * Note Scanner - discovers notes addressed to the user by scanning encrypted outputs.
// *
// * When someone sends a private transfer:
// * 1. They encrypt (amount, blinding) with the recipient's X25519 encryption public key
// * 2. The encrypted output is emitted as an event on-chain
// * 3. The recipient scans all outputs, trying to decrypt each one
// * 4. Successful decryption means the note is addressed to them
// * 5. They verify the commitment matches and save the note
// *
// * This module uses the deterministic keys from notes-store.js:
// * - Encryption keypair: For decrypting note data
// * - Note identity keypair: For verifying commitments and deriving nullifiers
// *
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
//
//// Get user's encryption keypair (derived from Freighter signature)
// const encKeypair = await notesStore.getUserEncryptionKeypair();
// if (!encKeypair) {
//     console.warn('[NoteScanner] No encryption keypair available - user must sign message');
//     return null;
// }

// // Attempt decryption
// const decrypted = decryptNoteData(encKeypair.privateKey, encrypted);
//
use types::{ContractConfig, ContractEvent, ContractsEventData, SyncMetadata};

fn process_commitment_event(event: ContractEvent) {

}


// * Public Key Store - manages registered public keys for the address book.
// * Syncs from Pool contract events (PublicKeyEvent).
// *
// * Stores two key types per user:
// * - encryptionKey: X25519 key for encrypting note data (amount, blinding)
// * - noteKey: BN254 key for creating commitments in the ZK circuit
// *
// // Event emitted when a user registers their public keys
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
//
// event_type = "public_key_event"
fn process_pubkey_event(event: ContractEvent) {

}
