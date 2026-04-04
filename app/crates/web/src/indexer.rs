use crate::worker::Worker;
use gloo_worker::oneshot::OneshotBridge;
use gloo_worker::Spawnable;
use crate::protocol::{WorkerRequest, WorkerResponse};


pub struct StorageBridge {
    bridge: OneshotBridge<Worker>,
}

impl StorageBridge {
    pub fn new() -> Self {
        Self {
            bridge: Worker::spawner().as_module(true).spawn("./js/worker.js"),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl stellar::ContractDataStorage for StorageBridge {
    async fn get_sync_state(&self) -> anyhow::Result<Option<types::SyncMetadata>> {
        log::debug!("before bridge fork");
        let mut bridge = self.bridge.fork();
        log::debug!("before bridge run");
        let resp = bridge.run(WorkerRequest::SyncState).await;
        log::debug!("after bridge run");
        match resp {
            WorkerResponse::SyncState(state) => Ok(state),
            WorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
        }
    }

    async fn save_events_batch(&self, data: types::ContractsEventData) -> anyhow::Result<()> {
        let mut bridge = self.bridge.fork();
        let resp = bridge.run(WorkerRequest::SaveEvents(data)).await;
        match resp {
            WorkerResponse::Saved => Ok(()),
            WorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
        }
    }
}
