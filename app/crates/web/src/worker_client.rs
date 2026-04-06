use crate::worker::Worker;
use gloo_worker::oneshot::OneshotBridge;
use gloo_worker::Spawnable;
use crate::protocol::{WorkerRequest, WorkerResponse, EncryptionKey, SpendingKey};
use wasm_bindgen::prelude::wasm_bindgen;
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
            bridge: Worker::spawner().as_module(true).spawn("./js/worker.js"),
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

    #[wasm_bindgen(js_name = saveUserKeys)]
    pub async fn save_user_keys(&self, spending_key: Vec<u8>, encryption_key: Vec<u8>) -> anyhow::Result<()> {
        let mut bridge = self.bridge.fork();
        let resp = with_timeout(5_000, bridge.run(WorkerRequest::SaveUserKeys(SpendingKey(spending_key), EncryptionKey(encryption_key)))).await?;
        match resp {
            WorkerResponse::Pong => Ok(()),
            WorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
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
