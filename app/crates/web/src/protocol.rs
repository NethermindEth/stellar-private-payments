use serde::{Deserialize, Serialize};
use types::{PublicKeyEntry, SpendingSignature, EncryptionSignature, EncryptionKeyPair, NoteKeyPair};

pub type Address = String;

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
    RecentPubKeys(u32)
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
