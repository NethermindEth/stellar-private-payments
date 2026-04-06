use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SpendingKey(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionKey(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerRequest {
    Ping,
    SyncState,
    SaveEvents(types::ContractsEventData),
    SaveUserKeys(SpendingKey, EncryptionKey),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    Pong,
    SyncState(Option<types::SyncMetadata>),
    Saved,
    Error(String),
}
