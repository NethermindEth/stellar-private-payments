use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerRequest {
    SyncState,
    SaveEvents(types::ContractsEventData),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    SyncState(Option<types::SyncMetadata>),
    Saved,
    Error(String),
}
