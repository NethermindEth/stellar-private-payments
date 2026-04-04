use web::{Worker, WorkerRequest, WorkerResponse};
use gloo_worker::oneshot::OneshotBridge;
use gloo_worker::Spawnable;
use stellar::Indexer;
use gloo_timers::future::TimeoutFuture;
use wasm_bindgen_futures::spawn_local;
use std::rc::Rc;
use wasm_bindgen::JsError;

fn main() {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
    spawn_local(async {
        if let Err(e) = init().await {
            log::error!("[WORKER] init failed: {e:?}");
        }
    });
}

struct StorageBridge {
    bridge: OneshotBridge<Worker>,
}

impl StorageBridge {
    fn new() -> Self {
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

async fn init() -> Result<(), JsError> {
    let storage = StorageBridge::new();
    // TODO make it dependent on the network during the compilation
    let indexer = Indexer::new(
            "https://soroban-testnet.stellar.org",
            storage,
        )
        .map_err(|e| JsError::new(&e.to_string()))?;
    log::debug!("[MAIN THREAD] initialized");
    start_indexer_loop(indexer, 5_000);
    Ok(())
}

fn start_indexer_loop(indexer: Indexer<StorageBridge>, interval_ms: u32) {
    let indexer = Rc::new(indexer);

    let indexer_cloned = Rc::clone(&indexer);
    spawn_local(async move {
        log::debug!("[INDEXER] looping");
        loop {
            if let Err(e) = indexer_cloned.fetch_contract_events().await {
                log::error!("[INDEXER] round failed: {e}");
            }

            TimeoutFuture::new(interval_ms).await;
        }
    });
}
