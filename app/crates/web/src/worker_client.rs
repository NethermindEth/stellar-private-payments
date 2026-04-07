use crate::worker::Worker;
use gloo_worker::oneshot::OneshotBridge;
use gloo_worker::Spawnable;
use crate::protocol::{WorkerRequest, WorkerResponse, UserKeys};
use prover::encryption::{ENCRYPTION_MESSAGE, SPENDING_KEY_MESSAGE};
use types::{SpendingSignature, EncryptionSignature, NoteKeyPair, EncryptionKeyPair};
use wasm_bindgen::prelude::*;
use futures::FutureExt;
use gloo_timers::future::TimeoutFuture;
use anyhow::anyhow;

#[wasm_bindgen]
pub struct WorkerClient {
    bridge: OneshotBridge<Worker>,
}

impl Clone for WorkerClient {
    fn clone(&self) -> Self {
        Self {
            bridge: self.bridge.fork()
        }
    }
}

async fn with_timeout<T>(
    ms: u32,
    fut: impl std::future::Future<Output = T>,
) -> anyhow::Result<T> {
    let fut = fut.fuse();
    let timeout = TimeoutFuture::new(ms).fuse();

    futures::pin_mut!(fut, timeout);

    futures::select! {
        value = fut => Ok(value),
        _ = timeout => Err(anyhow!("operation timed out after {} ms", ms)),
    }
}

impl WorkerClient {
    pub fn new() -> Self {
        Self {
            bridge: Worker::spawner().spawn("./js/worker.js"),
        }
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        let mut bridge = self.bridge.fork();
        let resp = with_timeout(5_000, bridge.run(WorkerRequest::Ping)).await?;
        match resp {
            WorkerResponse::Pong => Ok(()),
            WorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
        }
    }


}

#[wasm_bindgen]
impl WorkerClient {

    async fn request(&self, req: WorkerRequest, timeout_ms: u32) -> Result<WorkerResponse, JsError> {
        let mut bridge = self.bridge.fork();

        // Handle transport/timeout errors
        let resp = with_timeout(timeout_ms, bridge.run(req))
            .await
            .map_err(|e| JsError::new(&format!("Worker Communication Error: {}", e)))?;

        match resp {
            WorkerResponse::Error(e) => Err(JsError::new(&e)),
            _ => Ok(resp),
        }
    }

    #[wasm_bindgen(js_name = encryptionDerivationMessage)]
    pub fn encryption_derivation_message(&self) -> String {
        ENCRYPTION_MESSAGE.to_string()
    }

    #[wasm_bindgen(js_name = spendingKeyMessage)]
    pub fn spending_key_message(&self) -> String {
        SPENDING_KEY_MESSAGE.to_string()
    }

    #[wasm_bindgen(js_name = deriveAndSaveUserKeys)]
    pub async fn derive_save_user_keys(&self, address: String, spending_sig: Vec<u8>, encryption_sig: Vec<u8>) -> Result<(), JsError> {
        let req = WorkerRequest::DeriveSaveUserKeys(
            address,
            SpendingSignature(spending_sig),
            EncryptionSignature(encryption_sig)
        );

        match self.request(req, 5_000).await? {
            WorkerResponse::Saved => Ok(()),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getUserKeys)]
    pub async fn get_user_keys(&self, address: String) -> Result<JsValue, JsError> {
        let req = WorkerRequest::UserKeys(
            address,
        );

        match self.request(req, 1_000).await? {
            WorkerResponse::UserKeys(keys) => Ok(serde_wasm_bindgen::to_value(&keys)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getRecentPublicKeys)]
    pub async fn get_recent_public_keys(&self, limit: u32) -> Result<JsValue, JsError> {
        let req = WorkerRequest::RecentPubKeys(
            limit,
        );

        match self.request(req, 1_000).await? {
            WorkerResponse::UserKeys(keys) => Ok(serde_wasm_bindgen::to_value(&keys)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl stellar::ContractDataStorage for WorkerClient {
    async fn get_sync_state(&self) -> anyhow::Result<Option<types::SyncMetadata>> {
        let mut bridge = self.bridge.fork();
        let resp = with_timeout(5_000, bridge.run(WorkerRequest::SyncState)).await?;
        match resp {
            WorkerResponse::SyncState(state) => Ok(state),
            WorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
        }
    }

    async fn save_events_batch(&self, data: types::ContractsEventData) -> anyhow::Result<()> {
        let mut bridge = self.bridge.fork();
        let resp = with_timeout(10_000, bridge.run(WorkerRequest::SaveEvents(data))).await?;
        match resp {
            WorkerResponse::Saved => Ok(()),
            WorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
        }
    }
}
