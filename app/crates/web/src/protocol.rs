use serde::{Deserialize, Serialize};
use types::{AspNonMembershipProof, PublicKeyEntry, SpendingSignature, EncryptionSignature, EncryptionKeyPair, NoteKeyPair, NoteAmount};
pub type Address = String;
pub type MerkleRootBE = [u8; 32];

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserKeys{
    pub note_keypair: NoteKeyPair,
    pub encryption_keypair: EncryptionKeyPair
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerRequest {
    Ping,
    SyncState,
    SaveEvents(types::ContractsEventData),
    DeriveSaveUserKeys(Address, SpendingSignature, EncryptionSignature),
    UserKeys(Address),
    RecentPubKeys(u32),
    //Deposit(Deposit)
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    Pong,
    SyncState(Option<types::SyncMetadata>),
    Saved,
    Error(String),
    UserKeys(Option<UserKeys>),
    PubKeys(Vec<PublicKeyEntry>)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deposit{
    pub user_address: Address,
    pub amount_stroops: NoteAmount,
    pub pool_root: [u8; 32],
    pub pool_address: String,
    pub output_amounts: [NoteAmount; 2],
    pub tree_depth: u32,
    pub non_membership_proof: AspNonMembershipProof,
}
